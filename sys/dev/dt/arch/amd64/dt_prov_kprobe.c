/*	$OpenBSD$	*/

/*
 * Copyright (c) 2024 Martin Pieuchot <mpi@openbsd.org>
 * Copyright (c) 2020 Tom Rollet <tom.rollet@epita.fr>
 * Copyright (c) 2026 Brent Cook <bcook@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * amd64-specific pieces of the kprobe provider: prologue/epilogue
 * byte-pattern recognition, breakpoint patching, and trapframe register
 * access.  The provider bookkeeping shared with i386 lives in
 * dev/dt/dt_prov_kprobe_x86.c.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/exec_elf.h>

#include <ddb/db_elf.h>
#include <machine/db_machdep.h>
#include <ddb/db_extern.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_interface.h>

#include <dev/dt/dtvar.h>

/*
 * IBT endbr64 prefix: f3 0f 1e fa (4 bytes)
 */
#define	IBT_SIZE	4

/*
 * RetGuard prefix:
 *   4c 8b 1d xx xx xx xx	mov off(%rip), %r11  (7 bytes)
 *   4c 33 1c xx		xorq off(%rsp), %r11 (4 bytes)
 */
#define	RTGD_MOV_SIZE	7
#define	RTGD_XOR_SIZE	4

#define	PUSH_RBP	0x55		/* push %rbp */
#define	RET_INST	0xc3		/* ret */
#define	RET_SIZE	1
#define	RET_IMM16	0xc2		/* ret $imm16 */

/*
 * Find the offset of the frame pointer setup in a function's prologue.
 *
 * First try the fast path: push %rbp immediately after known IBT and
 * RetGuard prefixes.  If that fails, do a wider scan for the full
 * frame setup sequence "push %rbp; mov %rsp, %rbp" (55 48 89 e5).
 * The 4-byte sequence is safe to search for even in shrink-wrapped
 * functions where the compiler may place early-exit code before the
 * frame pointer setup.
 *
 * Returns the offset of push %rbp from the function start, or -1 if
 * not found within a reasonable distance.
 */
int
db_prologue_validate(Elf_Sym *symp)
{
	uint8_t *inst = (uint8_t *)symp->st_value;
	int size = symp->st_size;
	int off = 0;
	int limit;

	if (size < 1)
		return -1;

	limit = (size < 32) ? size : 32;

	/*
	 * Fast path: skip known prefix instructions and expect
	 * push %rbp immediately after.
	 *
	 * IBT (endbr64): f3 0f 1e fa
	 */
	if (off + IBT_SIZE <= limit &&
	    inst[off] == 0xf3 && inst[off + 1] == 0x0f &&
	    inst[off + 2] == 0x1e && inst[off + 3] == 0xfa)
		off += IBT_SIZE;

	/* RetGuard mov: 4c 8b 1d xx xx xx xx */
	if (off + RTGD_MOV_SIZE <= limit &&
	    inst[off] == 0x4c && inst[off + 1] == 0x8b &&
	    inst[off + 2] == 0x1d)
		off += RTGD_MOV_SIZE;

	/* RetGuard xor: 4c 33 1c xx */
	if (off + RTGD_XOR_SIZE <= limit &&
	    inst[off] == 0x4c && inst[off + 1] == 0x33 &&
	    inst[off + 2] == 0x1c)
		off += RTGD_XOR_SIZE;

	if (off < limit && inst[off] == PUSH_RBP)
		return off;

	/*
	 * Slow path: the compiler may have shrink-wrapped the function,
	 * placing early-exit code before the frame setup.  Scan for the
	 * full "push %rbp; mov %rsp, %rbp" sequence (55 48 89 e5) which
	 * is unlikely to appear as operands of other instructions.
	 */
	limit = (size < 256) ? size : 256;
	for (off = 0; off + 3 < limit; off++) {
		if (inst[off] == PUSH_RBP &&
		    inst[off + 1] == 0x48 &&
		    inst[off + 2] == 0x89 &&
		    inst[off + 3] == 0xe5)
			return off;
	}

	return -1;
}

/*
 * Insert a breakpoint or restore `pushq %rbp'.
 */
void
db_prologue_patch(vaddr_t addr, int restore)
{
	uint8_t patch;
	size_t size;
	unsigned s;

	CTASSERT(SSF_SIZE == BKPT_SIZE);
	if (restore) {
		patch = SSF_INST;
		size = SSF_SIZE;
	} else {
		patch = BKPT_INST;
		size = BKPT_SIZE;
	}

	s = intr_disable();
	db_write_bytes(addr, size, &patch);
	intr_restore(s);
}

/*
 * Heuristic: check if a 0xc3 byte at `off' in a function might actually
 * be part of an embedded pointer value (e.g., in a jump table) rather
 * than a true ret instruction.
 *
 * If treating any byte sequence around `off' as a pointer yields an
 * address within the function body, the 0xc3 is likely not a real ret.
 */
static int
kprobe_ret_is_jump_table(uint8_t *text, int off, int size)
{
	uintptr_t funcstart = (uintptr_t)text;
	uintptr_t funclimit = funcstart + size;
	int j;

	for (j = 0; j < (int)sizeof(uintptr_t); j++) {
		int check = off - j;
		uintptr_t ptr;

		if (check < 0)
			break;
		if (check + (int)sizeof(uintptr_t) > size)
			continue;

		memcpy(&ptr, &text[check], sizeof(ptr));
		if (ptr >= funcstart && ptr < funclimit)
			return 1;
	}

	return 0;
}

/*
 * Find the next ret instruction at or after offset `start' in the
 * function described by `symp'.  Returns the offset of the ret byte,
 * or -1 when none is found.  Call repeatedly with start = previous + 1
 * to enumerate all return sites.
 */
int
db_epilogue_validate(Elf_Sym *symp, int start)
{
	uint8_t *inst = (uint8_t *)symp->st_value;
	int size = symp->st_size;
	int off;

	for (off = start; off < size; off++) {
		/* Skip ret-with-immediate (0xc2 imm16): 3 bytes total. */
		if (inst[off] == RET_IMM16) {
			off += 2;
			continue;
		}

		if (inst[off] != RET_INST)
			continue;

		/* Filter out 0xc3 bytes embedded in jump tables. */
		if (kprobe_ret_is_jump_table(inst, off, size))
			continue;

		return off;
	}

	return -1;
}

void
db_epilogue_patch(vaddr_t addr, int restore)
{
	uint8_t patch;
	size_t size;
	unsigned s;

	CTASSERT(RET_SIZE == BKPT_SIZE);
	if (restore) {
		patch = RET_INST;
		size = RET_SIZE;
	} else {
		patch = BKPT_INST;
		size = BKPT_SIZE;
	}

	s = intr_disable();
	db_write_bytes(addr, size, &patch);
	intr_restore(s);
}

/*
 * SysV AMD64 ABI: first 6 integer/pointer arguments passed in registers.
 */
void
dt_prov_kprobe_getargs(struct trapframe *tf, register_t *args)
{
	args[0] = tf->tf_rdi;
	args[1] = tf->tf_rsi;
	args[2] = tf->tf_rdx;
	args[3] = tf->tf_rcx;
	args[4] = tf->tf_r8;
	args[5] = tf->tf_r9;
}

register_t
dt_prov_kprobe_getretval(struct trapframe *tf)
{
	return tf->tf_rax;
}
