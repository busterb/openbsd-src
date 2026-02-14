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

/*
 * Given an enum type id and an integer value, return the name of
 * the corresponding enum constant, or NULL if not found.
 */
const char *
ctf_enum_name(ctf_file_t *cf, uint16_t id, int value)
{
	const struct ctf_type	*ctt;
	const char		*p;
	struct ctf_enum		*cte;
	uint16_t		 kind, vlen, i;
	uint32_t		 toff;

	ctt = ctf_type_by_index(cf, id);
	if (ctt == NULL)
		return NULL;

	kind = CTF_INFO_KIND(ctt->ctt_info);
	if (kind != CTF_K_ENUM)
		return NULL;

	vlen = CTF_INFO_VLEN(ctt->ctt_info);
	toff = sizeof(struct ctf_stype);

	p = (const char *)ctt;
	for (i = 0; i < vlen; i++) {
		cte = (struct ctf_enum *)(p + toff);
		toff += sizeof(*cte);

		if (cte->cte_value == value)
			return ctf_stroff2name(cf, cte->cte_name);
	}

	return NULL;
}
