/*	$OpenBSD$	*/

/*
 * Copyright (c) 2026 Brent Cook <bcook@openbsd.org>
 * Copyright (c) 2024 Martin Pieuchot <mpi@openbsd.org>
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
 * Dynamic kernel function tracing via the kprobe provider for arm64.
 *
 * Instruments kernel function entry and return points using brk #0
 * breakpoint patching.  arm64 has fixed 4-byte instructions, so
 * prologue detection and return scanning are straightforward with
 * no variable-length decoding or jump-table heuristics needed.
 *
 * Probe naming:
 *   kprobe:function:entry  - function entry
 *   kprobe:function:return - function return (captures retval)
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
extern char		etext[];

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

/*
 * Instruction constants.
 */
#define KPROBE_RET_INSN		0xd65f03c0	/* ret */
#define KPROBE_BTI_C		0xd503245f	/* bti c */
#define KPROBE_PATCHVAL		BKPT_INST	/* brk #0 = 0xd4200000 */

/*
 * stp x29, x30, [sp, #imm7*8]! -- mask zeroes imm7 field (bits 21:15).
 */
#define KPROBE_STP_MASK		0xffc07fff
#define KPROBE_STP_MATCH	0xa9807bfd

/*
 * stp x29, x30, [sp, #offset] (signed offset, no writeback)
 * Same mask as pre-indexed but different opc in bits 25:23.
 */
#define KPROBE_STP_OFF_MATCH	0xa9007bfd

/*
 * Per-CPU saved instruction for entry probe emulation.
 * Set in dt_prov_bkpt_hook(), read in trap.c emulation.
 * Safe because both run sequentially on the same CPU in the trap handler.
 */
uint32_t dt_prov_bkpt_savedinsn[MAXCPUS];

/*
 * Find the offset of the frame pointer setup in a function's prologue.
 *
 * Scan the first few instructions for "stp x29, x30, [sp, #-N]!"
 * (pre-indexed) or "stp x29, x30, [sp, #N]" (signed offset).
 * Skip leading "bti c" if present.
 *
 * Returns the byte offset of the stp instruction, or -1 if not found.
 * Stores the matched instruction word in *insn_out for later emulation.
 */
static int
kprobe_find_entry(uint32_t *inst, int ninsn, uint32_t *insn_out)
{
	int i, limit;

	if (ninsn < 1)
		return -1;

	limit = (ninsn < 8) ? ninsn : 8;

	for (i = 0; i < limit; i++) {
		/* Skip bti c prefix. */
		if (inst[i] == KPROBE_BTI_C)
			continue;

		/* Pre-indexed: stp x29, x30, [sp, #-N]! */
		if ((inst[i] & KPROBE_STP_MASK) == KPROBE_STP_MATCH) {
			*insn_out = inst[i];
			return i * 4;
		}

		/* Signed offset: stp x29, x30, [sp, #N] */
		if ((inst[i] & KPROBE_STP_MASK) == KPROBE_STP_OFF_MATCH) {
			*insn_out = inst[i];
			return i * 4;
		}

		/* Continue scanning past other prologue instructions. */
	}

	return -1;
}

/*
 * Patch a 4-byte instruction in kernel text.
 *
 * Uses db_write_bytes() which handles pmap_page_rw/pmap_page_ro
 * and I-cache synchronization.
 */
static void
kprobe_patch(vaddr_t addr, uint32_t val)
{
	unsigned s;

	s = intr_disable();
	db_write_bytes(addr, sizeof(val), &val);
	intr_restore(s);
}

/* Initialize all entry and return probes and store them in global arrays */
int
dt_prov_kprobe_init(void)
{
	struct dt_probe *dtp;
	Elf_Sym *symp, *symtab_start, *symtab_end;
	const char *strtab, *name;
	uint32_t *inst, insn;
	vaddr_t funcaddr;
	int entryoff, off, size, ninsn;
	int nb_probes = 0, nb_kret = 0;
	int nfuncs = 0, nskip_text = 0, nskip_size = 0;
	int nskip_excl = 0, nskip_entry = 0;

	dtpf_entry = malloc(PPTSIZE, M_DT, M_NOWAIT|M_ZERO);
	if (dtpf_entry == NULL)
		return 0;

	dtpf_return = malloc(PPTSIZE, M_DT, M_NOWAIT|M_ZERO);
	if (dtpf_return == NULL) {
		free(dtpf_entry, M_DT, PPTSIZE);
		return 0;
	}

	symtab_start = STAB_TO_SYMSTART(&db_symtab);
	symtab_end = STAB_TO_SYMEND(&db_symtab);
	strtab = db_elf_find_strtab(&db_symtab);

	for (symp = symtab_start; symp < symtab_end; symp++) {
		if (ELF_ST_TYPE(symp->st_info) != STT_FUNC)
			continue;
		nfuncs++;

		funcaddr = symp->st_value;
		size = symp->st_size;
		name = strtab + symp->st_name;

		/* Skip functions not mapped in kernel text. */
		if (funcaddr < KERNBASE ||
		    funcaddr >= (vaddr_t)&etext) {
			nskip_text++;
			continue;
		}

		/* Skip empty or very small functions. */
		if (size < 8) {
			nskip_size++;
			continue;
		}

		/* Skip functions that could cause recursive tracing. */
		if (kprobe_excluded(name)) {
			nskip_excl++;
			continue;
		}

		inst = (uint32_t *)funcaddr;
		ninsn = size / 4;

		/*
		 * Find the entry point (stp x29, x30, [sp, #-N]!).
		 */
		entryoff = kprobe_find_entry(inst, ninsn, &insn);
		if (entryoff < 0) {
			nskip_entry++;
			continue;
		}

		/*
		 * Create the entry probe.
		 */
		dtp = dt_dev_alloc_probe(name, "entry", &dt_prov_kprobe);
		if (dtp == NULL)
			break;

		dtp->dtp_addr = funcaddr + entryoff;
		dtp->dtp_savedinsn = insn;
		dtp->dtp_type = KPROBE_ENTRY;
		dtp->dtp_nargs = db_ctf_func_numargs(symp);
		SLIST_INSERT_HEAD(&dtpf_entry[INSTTOIDX(dtp->dtp_addr)],
		    dtp, dtp_knext);
		dt_dev_register_probe(dtp);
		nb_probes++;

		/*
		 * Scan the function body for ALL ret instructions.
		 * Fixed-width instructions: no jump-table heuristic needed.
		 */
		for (off = (entryoff / 4) + 1; off < ninsn; off++) {
			if (inst[off] != KPROBE_RET_INSN)
				continue;

			/*
			 * Create a return probe for this ret site.
			 */
			dtp = dt_dev_alloc_probe(name, "return",
			    &dt_prov_kprobe);
			if (dtp == NULL)
				goto done;

			dtp->dtp_addr = funcaddr + off * 4;
			dtp->dtp_savedinsn = KPROBE_RET_INSN;
			dtp->dtp_type = KPROBE_RETURN;
			SLIST_INSERT_HEAD(
			    &dtpf_return[INSTTOIDX(dtp->dtp_addr)],
			    dtp, dtp_knext);
			dt_dev_register_probe(dtp);
			nb_probes++;
			nb_kret++;
		}
	}
done:
	printf("kprobe: %d entry + %d ret probes from %d functions "
	    "(skip: %d text, %d size, %d excl, %d entry)\n",
	    nb_probes - nb_kret, nb_kret, nfuncs, nskip_text, nskip_size,
	    nskip_excl, nskip_entry);
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
		/* First consumer: patch the instruction with brk #0. */
		kprobe_patch(dtp->dtp_addr, KPROBE_PATCHVAL);
	}

	dp->dp_evtflags = dtrq->dtrq_evtflags & DTEVT_PROV_KPROBE;
	dp->dp_strargs = dtrq->dtrq_strargs;
	dp->dp_strlen = dtrq->dtrq_strlen;
	dp->dp_memargs = dtrq->dtrq_memargs;
	memcpy(dp->dp_memcap, dtrq->dtrq_memcap, sizeof(dp->dp_memcap));
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

	/* Last consumer: restore original instruction. */
	kprobe_patch(dtp->dtp_addr, dtp->dtp_savedinsn);
	return 0;
}

/*
 * Breakpoint hook called from the brk trap handler (do_el1h_sync in trap.c).
 *
 * Return values (consumed by trap.c instruction emulation):
 *   0 - not a dt breakpoint, fall through to DDB
 *   1 - entry probe (emulate stp x29, x30, [sp, #imm]!)
 *   2 - return probe (emulate ret)
 */
int
dt_prov_bkpt_hook(struct trapframe *tf)
{
	struct dt_probe *dtp;
	struct dt_pcb *dp;
	uint32_t savedinsn = 0;
	int is_dt_bkpt = 0;
	vaddr_t addr;

	addr = db_get_probe_addr(tf);

	if (dtpf_entry == NULL)
		return 0;

	SLIST_FOREACH(dtp, &dtpf_entry[INSTTOIDX(addr)], dtp_knext) {
		if (dtp->dtp_addr != addr)
			continue;

		is_dt_bkpt = 1;
		savedinsn = dtp->dtp_savedinsn;

		if (!dtp->dtp_recording)
			continue;

		smr_read_enter();
		SMR_SLIST_FOREACH(dp, &dtp->dtp_pcbs, dp_pnext) {
			struct dt_evt *dtev;

			dtev = dt_pcb_ring_get(dp, 0);
			if (dtev == NULL)
				continue;

			if (ISSET(dp->dp_evtflags, DTEVT_FUNCARGS)) {
				/* AAPCS64: first 8 args in x0-x7. */
				dtev->dtev_args[0] = tf->tf_x[0];
				dtev->dtev_args[1] = tf->tf_x[1];
				dtev->dtev_args[2] = tf->tf_x[2];
				dtev->dtev_args[3] = tf->tf_x[3];
				dtev->dtev_args[4] = tf->tf_x[4];
				dtev->dtev_args[5] = tf->tf_x[5];
			}

			if (ISSET(dp->dp_evtflags, DTEVT_STRARGS))
				dt_copy_strargs(dtev, dp->dp_strargs,
				    dp->dp_strlen);
			if (ISSET(dp->dp_evtflags, DTEVT_MEMARGS))
				dt_copy_memargs(dtev, dp->dp_memargs,
				    dp->dp_memcap);
			dt_pcb_ring_consume(dp, dtev);
		}
		smr_read_leave();
	}

	if (is_dt_bkpt) {
		dt_prov_bkpt_savedinsn[cpu_number()] = savedinsn;
		return is_dt_bkpt;
	}

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

			dtev->dtev_retval[0] = tf->tf_x[0];
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

			kprobe_patch(dtp->dtp_addr, KPROBE_PATCHVAL);
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

			kprobe_patch(dtp->dtp_addr, dtp->dtp_savedinsn);
		}
	}
}
