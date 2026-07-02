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
 * i386-specific pieces of the kprobe provider: prologue/epilogue
 * byte-pattern recognition, breakpoint patching, and trapframe register
 * access.  The provider bookkeeping shared with amd64 lives in
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

#define	POP_RBP_INST	0x5d
#define	POP_RBP_SIZE	1

int
db_prologue_validate(Elf_Sym *symp)
{
	uint8_t *inst = (uint8_t *)symp->st_value;

	/* No retguard or IBT on i386 */
	if (*inst != SSF_INST)
		return -1;

	return 0;
}

/*
 * Insert a breakpoint or restore `push %ebp'.
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
 * Find the next "pop %ebp; ret" (0x5d 0xc3) epilogue at or after
 * offset `start'.  Returns the offset of the pop instruction, or -1.
 * Call repeatedly to enumerate multiple return sites.
 */
int
db_epilogue_validate(Elf_Sym *symp, int start)
{
	uint8_t *inst = (uint8_t *)symp->st_value;
	int size = symp->st_size;
	int off;

	if (size < 2)
		return -1;

	for (off = start; off < size - 1; off++) {
		if (inst[off] == POP_RBP_INST && inst[off + 1] == 0xc3)
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

	CTASSERT(SSF_SIZE == BKPT_SIZE);
	if (restore) {
		patch = POP_RBP_INST;
		size = POP_RBP_SIZE;
	} else {
		patch = BKPT_INST;
		size = BKPT_SIZE;
	}

	s = intr_disable();
	db_write_bytes(addr, size, &patch);
	intr_restore(s);
}

/*
 * On i386 kernel-mode traps (no ring change), hardware does not push
 * ESP/SS.  tf_esp overlaps the return address and tf_ss overlaps the
 * first argument.  Use &tf->tf_ss as the argument base.
 */
void
dt_prov_kprobe_getargs(struct trapframe *tf, register_t *args)
{
	register_t *sargs;
	int i;

	sargs = (register_t *)&tf->tf_ss;
	for (i = 0; i < DTMAXFUNCARGS; i++)
		args[i] = sargs[i];
}

register_t
dt_prov_kprobe_getretval(struct trapframe *tf)
{
	return tf->tf_eax;
}
