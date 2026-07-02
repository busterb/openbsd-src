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

#ifndef _CTF_H_
#define _CTF_H_

#include <sys/types.h>
#include <sys/ctf.h>
#include <stdint.h>

typedef struct ctf_file ctf_file_t;

/* Open/close */
ctf_file_t	*ctf_open(const char *);
void		 ctf_close(ctf_file_t *);

/* Raw data access */
const struct ctf_header	*ctf_header(ctf_file_t *);
const char		*ctf_data(ctf_file_t *, size_t *);

/* String/symbol table utilities */
const char	*ctf_stroff2name(ctf_file_t *, uint32_t);
const char	*ctf_symbol_name(ctf_file_t *, size_t *, uint8_t);

/* Kind/encoding name formatting */
const char	*ctf_kind2name(uint16_t);
const char	*ctf_enc2name(uint16_t);
const char	*ctf_fpenc2name(uint16_t);

/* Type queries */
const char	*ctf_type_name(ctf_file_t *, uint16_t);
uint16_t	 ctf_type_kind(ctf_file_t *, uint16_t);
ssize_t		 ctf_type_size(ctf_file_t *, uint16_t);
uint16_t	 ctf_type_reference(ctf_file_t *, uint16_t);
uint32_t	 ctf_type_encoding(ctf_file_t *, uint16_t);
uint16_t	 ctf_type_by_name(ctf_file_t *, const char *);

/* Function signatures */
int		 ctf_func_info(ctf_file_t *, const char *,
		     uint16_t *, uint16_t *, int);

/* Enum value lookup */
const char	*ctf_enum_name(ctf_file_t *, uint16_t, int);

/* Struct member iteration */
typedef int (*ctf_member_f)(const char *, uint16_t, unsigned long, void *);
int		 ctf_member_iter(ctf_file_t *, uint16_t,
		     ctf_member_f, void *);

#endif /* _CTF_H_ */
