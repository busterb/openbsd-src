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
#include <string.h>

#include <sys/exec_elf.h>

#include "ctf.h"
#include "ctf_impl.h"

/*
 * Look up a function by name in the CTF function section.
 * Returns the number of arguments, fills in ret_type and argv[].
 * Returns -1 if the function is not found.
 */
int
ctf_func_info(ctf_file_t *cf, const char *name,
    uint16_t *ret_type, uint16_t *argv, int argc)
{
	uint16_t	*fstart, *fend;
	uint16_t	*fsp, kind, vlen;
	const char	*sym;
	size_t		 idx = 0;
	int		 i;

	fstart = (uint16_t *)(cf->data + cf->cth.cth_funcoff);
	fend = (uint16_t *)(cf->data + cf->cth.cth_typeoff);

	fsp = fstart;
	while (fsp < fend) {
		sym = ctf_symbol_name(cf, &idx, STT_FUNC);
		if (sym == NULL)
			break;

		kind = CTF_INFO_KIND(*fsp);
		vlen = CTF_INFO_VLEN(*fsp);
		fsp++;

		if (kind == CTF_K_UNKNOWN && vlen == 0)
			continue;

		if (strcmp(sym, name) != 0) {
			/* Skip return type */
			fsp++;
			/* Skip argument types */
			for (i = 0; i < vlen; i++)
				fsp++;
			continue;
		}

		/* Found the function */
		if (ret_type != NULL)
			*ret_type = *fsp;
		fsp++;

		for (i = 0; i < vlen && i < argc; i++)
			argv[i] = fsp[i];

		return vlen;
	}

	return -1;
}
