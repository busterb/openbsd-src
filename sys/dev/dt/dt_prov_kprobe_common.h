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
 * Shared constants and helpers for kprobe/kretprobe implementations.
 * Included by each architecture-specific dt_prov_kprobe_${ARCH}.c file.
 */

#ifndef _DT_PROV_KPROBE_COMMON_H_
#define _DT_PROV_KPROBE_COMMON_H_

#define KPROBE_ENTRY	0x1
#define KPROBE_RETURN	0x2

#define DTEVT_PROV_KPROBE (DTEVT_COMMON|DTEVT_FUNCARGS|DTEVT_STRARGS|DTEVT_MEMARGS)

/* Bob Jenkin's public domain 32-bit integer hashing function.
 * Original at https://burtleburtle.net/bob/hash/integer.html.
 */
static inline uint32_t
ptr_hash(uint32_t a) {
	a = (a + 0x7ed55d16) + (a<<12);
	a = (a ^ 0xc761c23c) ^ (a>>19);
	a = (a + 0x165667b1) + (a<<5);
	a = (a + 0xd3a2646c) ^ (a<<9);
	a = (a + 0xfd7046c5) + (a<<3);
	a = (a ^ 0xb55a4f09) ^ (a>>16);
	return a;
}

#define	PPTSIZE		(PAGE_SIZE * 30) /* XXX */
#define	PPTMASK		((PPTSIZE / sizeof(struct dt_probe)) - 1)
#define	INSTTOIDX(inst)	(ptr_hash(inst) & PPTMASK)

/*
 * Check if a function name should be excluded from instrumentation
 * to avoid recursive tracing and other hazards.
 */
static int
kprobe_excluded(const char *name)
{
	/* DT framework */
	if (strncmp(name, "dt_", 3) == 0)
		return 1;

	/* Trap and interrupt handling */
	if (strncmp(name, "trap", 4) == 0)
		return 1;

	/* DDB debugger */
	if (strncmp(name, "db_", 3) == 0)
		return 1;
	if (strncmp(name, "ddb_", 4) == 0)
		return 1;

	/* Low-level CPU and interrupt functions */
	if (strncmp(name, "intr_", 5) == 0)
		return 1;

	/* Softintr (used by dt_wakeup) */
	if (strncmp(name, "softintr_", 9) == 0)
		return 1;

	/* SMR read-side (used in probe firing path) */
	if (strcmp(name, "smr_read_enter") == 0 ||
	    strcmp(name, "smr_read_leave") == 0)
		return 1;

	/* Nanotime (called during event recording) */
	if (strcmp(name, "nanotime") == 0 ||
	    strcmp(name, "nanouptime") == 0)
		return 1;

	/* arm64 exception entry handlers */
	if (strncmp(name, "do_el", 5) == 0)
		return 1;

	return 0;
}

#endif /* _DT_PROV_KPROBE_COMMON_H_ */
