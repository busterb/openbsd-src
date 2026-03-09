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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/exec_elf.h>

#include <ddb/db_elf.h>
#include <machine/db_machdep.h>
#include <ddb/db_extern.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_interface.h>

#include <dev/dt/dtvar.h>
#include <dev/dt/dt_prov_kprobe_common.h>

extern db_symtab_t	db_symtab;
extern char		__kutext_end[];

extern vaddr_t	db_get_probe_addr(struct trapframe *);

/* Lists of probes per ELF symbol. */
SLIST_HEAD(, dt_probe) *dtpf_entry;
SLIST_HEAD(, dt_probe) *dtpf_return;

int	dt_prov_kprobe_alloc(struct dt_probe *, struct dt_softc *,
	    struct dt_pcb_list *, struct dtioc_req *);
int	dt_prov_kprobe_dealloc(struct dt_probe *, struct dt_softc *,
	    struct dtioc_req *);

struct dt_provider dt_prov_kprobe = {
	.dtpv_name    = "kprobe",
	.dtpv_alloc   = dt_prov_kprobe_alloc,
	.dtpv_enter   = NULL,
	.dtpv_leave   = NULL,
	.dtpv_dealloc = dt_prov_kprobe_dealloc,
};

struct dt_provider dt_prov_kretprobe = {
	.dtpv_name    = "kretprobe",
	.dtpv_alloc   = dt_prov_kprobe_alloc,
	.dtpv_enter   = NULL,
	.dtpv_leave   = NULL,
	.dtpv_dealloc = dt_prov_kprobe_dealloc,
};

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

/* Initialize all entry and return probes and store them in global arrays */
int
dt_prov_kprobe_init(void)
{
	struct dt_probe *dtp;
	Elf_Sym *symp, *symtab_start, *symtab_end;
	const char *strtab, *name;
	vaddr_t inst;
	int entryoff, retoff, nb_sym, nb_probes = 0;

	nb_sym = (db_symtab.end - db_symtab.start) / sizeof (Elf_Sym);

	dtpf_entry = malloc(PPTSIZE, M_DT, M_NOWAIT|M_ZERO);
	if (dtpf_entry == NULL)
		return 0;

	dtpf_return = malloc(PPTSIZE, M_DT, M_NOWAIT|M_ZERO);
	if (dtpf_return == NULL) {
		free(dtpf_entry, M_DT, PPTSIZE);
		return 0;
	}

	db_symtab_t *stab = &db_symtab;

	symtab_start = STAB_TO_SYMSTART(stab);
	symtab_end = STAB_TO_SYMEND(stab);
	strtab = db_elf_find_strtab(stab);

	for (symp = symtab_start; symp < symtab_end; symp++) {
		if (ELF_ST_TYPE(symp->st_info) != STT_FUNC)
			continue;

		inst = symp->st_value;
		name = strtab + symp->st_name;

		/* Filter function that are not mapped in memory */
		if (inst < KERNBASE || inst >= (vaddr_t)&__kutext_end)
			continue;

		/* Remove some functions to avoid recursive tracing */
		if (kprobe_excluded(name))
			continue;

		entryoff = db_prologue_validate(symp);
		if (entryoff < 0)
			continue;

		dtp = dt_dev_alloc_probe(name, "", &dt_prov_kprobe);
		if (dtp == NULL)
			break;

		dtp->dtp_addr = inst + entryoff;
		dtp->dtp_type = KPROBE_ENTRY;
		dtp->dtp_nargs = db_ctf_func_numargs(symp);
		SLIST_INSERT_HEAD(&dtpf_entry[INSTTOIDX(dtp->dtp_addr)],
		    dtp, dtp_knext);
		dt_dev_register_probe(dtp);
		nb_probes++;

		for (retoff = entryoff + 1;
		    (retoff = db_epilogue_validate(symp, retoff)) >= 0;
		    retoff++) {
			dtp = dt_dev_alloc_probe(name, "",
			    &dt_prov_kretprobe);
			if (dtp == NULL)
				goto done;

			dtp->dtp_addr = inst + retoff;
			dtp->dtp_type = KPROBE_RETURN;
			SLIST_INSERT_HEAD(
			    &dtpf_return[INSTTOIDX(dtp->dtp_addr)],
			    dtp, dtp_knext);
			dt_dev_register_probe(dtp);
			nb_probes++;
		}
	}
done:

	return nb_probes;
}

int
dt_prov_kprobe_alloc(struct dt_probe *dtp, struct dt_softc *sc,
    struct dt_pcb_list *plist, struct dtioc_req *dtrq)
{
	struct dt_pcb *dp;

	dp = dt_pcb_alloc(dtp, sc);
	if (dp == NULL)
		return ENOMEM;

	dtp->dtp_ref++;
	if (dtp->dtp_ref == 1) {
		switch (dtp->dtp_type) {
		case KPROBE_ENTRY:
			db_prologue_patch(dtp->dtp_addr, 0);
			break;
		case KPROBE_RETURN:
			db_epilogue_patch(dtp->dtp_addr, 0);
			break;
		default:
			panic("unknown probe type %d", dtp->dtp_type);
		}
	}

	dp->dp_evtflags = dtrq->dtrq_evtflags & DTEVT_PROV_KPROBE;
	dp->dp_strargs = dtrq->dtrq_strargs;
	dp->dp_strlen = dtrq->dtrq_strlen;
	TAILQ_INSERT_HEAD(plist, dp, dp_snext);
	return 0;
}

int
dt_prov_kprobe_dealloc(struct dt_probe *dtp, struct dt_softc *sc,
   struct dtioc_req *dtrq)
{
	dtp->dtp_ref--;
	if (dtp->dtp_ref > 0)
		return 0;

	switch (dtp->dtp_type) {
	case KPROBE_ENTRY:
		db_prologue_patch(dtp->dtp_addr, 1);
		break;
	case KPROBE_RETURN:
		db_epilogue_patch(dtp->dtp_addr, 1);
		break;
	default:
		panic("unknown probe type %d", dtp->dtp_type);
	}

	/* Deallocation of PCB is done by dt_pcb_purge when closing the dev */
	return 0;
}

/*
 * Breakpoint hook called directly from the int3 trap handler.
 *
 * Return values (consumed by the trap handler for instruction emulation):
 *   0 - not a dt breakpoint; fall through to normal trap handling
 *   1 - entry probe fired (emulate the patched prologue instruction)
 *   2 - return probe fired (emulate the patched ret instruction)
 */
int
dt_prov_bkpt_hook(struct trapframe *tf)
{
	struct dt_probe *dtp;
	struct dt_pcb *dp;
	int is_dt_bkpt = 0;
	vaddr_t addr;

	addr = db_get_probe_addr(tf);

	if (dtpf_entry == NULL)
		return 0;

	SLIST_FOREACH(dtp, &dtpf_entry[INSTTOIDX(addr)], dtp_knext) {
		if (dtp->dtp_addr != addr)
			continue;

		is_dt_bkpt = 1;

		if (!dtp->dtp_recording)
			continue;

		smr_read_enter();
		SMR_SLIST_FOREACH(dp, &dtp->dtp_pcbs, dp_pnext) {
			struct dt_evt *dtev;

			dtev = dt_pcb_ring_get(dp, 0);
			if (dtev == NULL)
				continue;

			if (ISSET(dp->dp_evtflags, DTEVT_FUNCARGS)) {
				/*
				 * SysV AMD64 ABI: first 6 integer/pointer
				 * arguments passed in registers.
				 */
				dtev->dtev_args[0] = tf->tf_rdi;
				dtev->dtev_args[1] = tf->tf_rsi;
				dtev->dtev_args[2] = tf->tf_rdx;
				dtev->dtev_args[3] = tf->tf_rcx;
				dtev->dtev_args[4] = tf->tf_r8;
				dtev->dtev_args[5] = tf->tf_r9;
			}

			if (ISSET(dp->dp_evtflags, DTEVT_STRARGS))
				dt_copy_strargs(dtev, dp->dp_strargs,
				    dp->dp_strlen);
			dt_pcb_ring_consume(dp, dtev);
		}
		smr_read_leave();
	}

	if (is_dt_bkpt)
		return is_dt_bkpt;

	SLIST_FOREACH(dtp, &dtpf_return[INSTTOIDX(addr)], dtp_knext) {
		if (dtp->dtp_addr != addr)
			continue;

		is_dt_bkpt = 2;

		if (!dtp->dtp_recording)
			continue;

		smr_read_enter();
		SMR_SLIST_FOREACH(dp, &dtp->dtp_pcbs, dp_pnext) {
			struct dt_evt *dtev;

			dtev = dt_pcb_ring_get(dp, 0);
			if (dtev == NULL)
				continue;

			dtev->dtev_retval[0] = tf->tf_rax;
			dtev->dtev_retval[1] = 0;
			dtev->dtev_error = 0;

			dt_pcb_ring_consume(dp, dtev);
		}
		smr_read_leave();
	}
	return is_dt_bkpt;
}

/* Called by ddb to patch all functions without allocating 1 pcb per probe */
void
dt_prov_kprobe_patch_all_entry(void)
{
	struct dt_probe *dtp;
	size_t i;

	if (dtpf_entry == NULL)
		return;

	for (i = 0; i < PPTMASK; ++i) {
		SLIST_FOREACH(dtp, &dtpf_entry[i], dtp_knext) {
			dtp->dtp_ref++;
			if (dtp->dtp_ref != 1)
				continue;

			db_prologue_patch(dtp->dtp_addr, 0);
		}
	}
}

/* Called by ddb to patch all functions without allocating 1 pcb per probe */
void
dt_prov_kprobe_depatch_all_entry(void)
{
	struct dt_probe *dtp;
	size_t i;

	if (dtpf_entry == NULL)
		return;

	for (i = 0; i < PPTMASK; ++i) {
		SLIST_FOREACH(dtp, &dtpf_entry[i], dtp_knext) {
			dtp->dtp_ref--;
			if (dtp->dtp_ref != 0)
				continue;

			db_prologue_patch(dtp->dtp_addr, 1);
		}

	}
}
