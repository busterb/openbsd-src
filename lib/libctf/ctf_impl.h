/*	$OpenBSD$	*/

/*
 * Copyright (c) 2016-2017 Martin Pieuchot
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

#ifndef _CTF_IMPL_H_
#define _CTF_IMPL_H_

#include <sys/ctf.h>
#include <gelf.h>
#include <libelf.h>

struct ctf_file {
	struct ctf_header	 cth;
	char			*data;		/* decompressed CTF data */
	size_t			 dlen;		/* decompressed data length */
	int			 needfree;	/* data was malloc'd */

	/* ELF state for symbol table lookups */
	Elf			*elf;
	int			 fd;
	Elf_Scn			*symtab;
	size_t			 strtabndx;
	size_t			 strtabsz;
	size_t			 nsymb;

	/* Raw CTF file state (non-ELF) */
	char			*rawmap;	/* mmap'd raw data */
	size_t			 rawmaplen;
};

/* ctf_subr.c */
uint32_t		 ctf_type_len(ctf_file_t *, const struct ctf_type *);
const struct ctf_type	*ctf_type_by_index(ctf_file_t *, uint16_t);

#endif /* _CTF_IMPL_H_ */
