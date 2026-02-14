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

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>

#include "ctf.h"
#include "ctf_impl.h"

const char *
ctf_type_name(ctf_file_t *cf, uint16_t id)
{
	const struct ctf_type	*ctt;

	ctt = ctf_type_by_index(cf, id);
	if (ctt == NULL)
		return NULL;

	return ctf_stroff2name(cf, ctt->ctt_name);
}

uint16_t
ctf_type_kind(ctf_file_t *cf, uint16_t id)
{
	const struct ctf_type	*ctt;

	ctt = ctf_type_by_index(cf, id);
	if (ctt == NULL)
		return CTF_K_UNKNOWN;

	return CTF_INFO_KIND(ctt->ctt_info);
}

ssize_t
ctf_type_size(ctf_file_t *cf, uint16_t id)
{
	const struct ctf_type	*ctt;
	const struct ctf_type	*ref;
	const struct ctf_array	*arr;
	uint16_t		 kind;
	uint32_t		 toff;
	uint64_t		 size;

	ctt = ctf_type_by_index(cf, id);
	if (ctt == NULL)
		return -1;

	kind = CTF_INFO_KIND(ctt->ctt_info);

	if (ctt->ctt_size <= CTF_MAX_SIZE) {
		size = ctt->ctt_size;
		toff = sizeof(struct ctf_stype);
	} else {
		size = CTF_TYPE_LSIZE(ctt);
		toff = sizeof(struct ctf_type);
	}

	switch (kind) {
	case CTF_K_UNKNOWN:
	case CTF_K_FORWARD:
		return 0;
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
	case CTF_K_STRUCT:
	case CTF_K_UNION:
	case CTF_K_ENUM:
		return (ssize_t)size;
	case CTF_K_ARRAY:
		arr = (const struct ctf_array *)((const char *)ctt + toff);
		ref = ctf_type_by_index(cf, arr->cta_contents);
		if (ref == NULL)
			return -1;
		return arr->cta_nelems * ctf_type_size(cf, arr->cta_contents);
	case CTF_K_FUNCTION:
		return 0;
	case CTF_K_POINTER:
		return sizeof(void *);
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
		return ctf_type_size(cf, ctt->ctt_type);
	default:
		return -1;
	}
}

uint16_t
ctf_type_reference(ctf_file_t *cf, uint16_t id)
{
	const struct ctf_type	*ctt;
	uint16_t		 kind;

	ctt = ctf_type_by_index(cf, id);
	if (ctt == NULL)
		return 0;

	kind = CTF_INFO_KIND(ctt->ctt_info);

	switch (kind) {
	case CTF_K_POINTER:
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
		return ctt->ctt_type;
	default:
		return 0;
	}
}

/*
 * Return the integer/float encoding word for the given type id.
 * Only valid for CTF_K_INTEGER and CTF_K_FLOAT kinds.
 */
uint32_t
ctf_type_encoding(ctf_file_t *cf, uint16_t id)
{
	const struct ctf_type	*ctt;
	const char		*p;
	uint16_t		 kind;
	uint32_t		 toff;

	ctt = ctf_type_by_index(cf, id);
	if (ctt == NULL)
		return 0;

	kind = CTF_INFO_KIND(ctt->ctt_info);
	if (kind != CTF_K_INTEGER && kind != CTF_K_FLOAT)
		return 0;

	if (ctt->ctt_size <= CTF_MAX_SIZE)
		toff = sizeof(struct ctf_stype);
	else
		toff = sizeof(struct ctf_type);

	p = (const char *)ctt + toff;
	return *(const uint32_t *)p;
}
