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
 * Iterate over members of a struct or union type.  Calls the callback
 * for each member with its name, type id, bit offset, and user arg.
 * Returns 0 on success, -1 if the type is not a struct/union.
 */
int
ctf_member_iter(ctf_file_t *cf, uint16_t id, ctf_member_f func, void *arg)
{
	const struct ctf_type	*ctt;
	const char		*p, *name;
	uint16_t		 kind, vlen, i;
	uint32_t		 toff;
	uint64_t		 size;

	ctt = ctf_type_by_index(cf, id);
	if (ctt == NULL)
		return -1;

	kind = CTF_INFO_KIND(ctt->ctt_info);
	if (kind != CTF_K_STRUCT && kind != CTF_K_UNION)
		return -1;

	vlen = CTF_INFO_VLEN(ctt->ctt_info);

	if (ctt->ctt_size <= CTF_MAX_SIZE) {
		size = ctt->ctt_size;
		toff = sizeof(struct ctf_stype);
	} else {
		size = CTF_TYPE_LSIZE(ctt);
		toff = sizeof(struct ctf_type);
	}

	p = (const char *)ctt;

	if (size < CTF_LSTRUCT_THRESH) {
		for (i = 0; i < vlen; i++) {
			struct ctf_member	*ctm;

			ctm = (struct ctf_member *)(p + toff);
			toff += sizeof(struct ctf_member);

			name = ctf_stroff2name(cf, ctm->ctm_name);
			if (func(name, ctm->ctm_type,
			    ctm->ctm_offset, arg) != 0)
				return -1;
		}
	} else {
		for (i = 0; i < vlen; i++) {
			struct ctf_lmember	*ctlm;

			ctlm = (struct ctf_lmember *)(p + toff);
			toff += sizeof(struct ctf_lmember);

			name = ctf_stroff2name(cf, ctlm->ctlm_name);
			if (func(name, ctlm->ctlm_type,
			    CTF_LMEM_OFFSET(ctlm), arg) != 0)
				return -1;
		}
	}

	return 0;
}
