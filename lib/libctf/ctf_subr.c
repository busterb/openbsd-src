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

#include "ctf.h"
#include "ctf_impl.h"

/*
 * Return a const pointer to the parsed CTF header.
 */
const struct ctf_header *
ctf_header(ctf_file_t *cf)
{
	return &cf->cth;
}

/*
 * Return the decompressed CTF data pointer and its length.
 */
const char *
ctf_data(ctf_file_t *cf, size_t *len)
{
	if (len != NULL)
		*len = cf->dlen;
	return cf->data;
}

/*
 * Convert a CTF name offset to a string.
 */
const char *
ctf_stroff2name(ctf_file_t *cf, uint32_t offset)
{
	const char	*name;

	if (CTF_NAME_STID(offset) != CTF_STRTAB_0)
		return NULL;

	if (CTF_NAME_OFFSET(offset) >= cf->cth.cth_strlen)
		return NULL;

	if (cf->cth.cth_stroff + CTF_NAME_OFFSET(offset) >= cf->dlen)
		return NULL;

	name = cf->data + cf->cth.cth_stroff + CTF_NAME_OFFSET(offset);
	if (*name == '\0')
		return NULL;

	return name;
}

/*
 * Return the length of the type record in the CTF section.
 */
uint32_t
ctf_type_len(ctf_file_t *cf, const struct ctf_type *ctt)
{
	uint16_t	 kind, vlen;
	uint32_t	 tlen;
	uint64_t	 size;

	kind = CTF_INFO_KIND(ctt->ctt_info);
	vlen = CTF_INFO_VLEN(ctt->ctt_info);

	if (ctt->ctt_size <= CTF_MAX_SIZE) {
		size = ctt->ctt_size;
		tlen = sizeof(struct ctf_stype);
	} else {
		size = CTF_TYPE_LSIZE(ctt);
		tlen = sizeof(struct ctf_type);
	}

	switch (kind) {
	case CTF_K_UNKNOWN:
	case CTF_K_FORWARD:
		break;
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
		tlen += sizeof(uint32_t);
		break;
	case CTF_K_ARRAY:
		tlen += sizeof(struct ctf_array);
		break;
	case CTF_K_FUNCTION:
		tlen += (vlen + (vlen & 1)) * sizeof(uint16_t);
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		if (size < CTF_LSTRUCT_THRESH)
			tlen += vlen * sizeof(struct ctf_member);
		else
			tlen += vlen * sizeof(struct ctf_lmember);
		break;
	case CTF_K_ENUM:
		tlen += vlen * sizeof(struct ctf_enum);
		break;
	case CTF_K_POINTER:
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
		break;
	default:
		return 0;
	}

	return tlen;
}

/*
 * Return the CTF type corresponding to a given index in the type section.
 */
const struct ctf_type *
ctf_type_by_index(ctf_file_t *cf, uint16_t index)
{
	uint32_t	 offset = cf->cth.cth_typeoff;
	uint16_t	 idx = 1;

	if (index == 0)
		return NULL;

	while (offset < cf->cth.cth_stroff) {
		const struct ctf_type	*ctt;
		uint32_t		 toff;

		ctt = (const struct ctf_type *)(cf->data + offset);
		if (idx == index)
			return ctt;

		toff = ctf_type_len(cf, ctt);
		if (toff == 0)
			break;
		offset += toff;
		idx++;
	}

	return NULL;
}

/*
 * Iterate through the ELF symbol table, returning the next symbol of
 * the given type.  Maintains state through *idx.
 */
const char *
ctf_symbol_name(ctf_file_t *cf, size_t *idx, uint8_t type)
{
	GElf_Sym	 sym;
	Elf_Data	*data;
	char		*name;
	size_t		 i;

	if (cf->symtab == NULL || cf->strtabndx == 0)
		return NULL;

	data = NULL;
	while ((data = elf_rawdata(cf->symtab, data)) != NULL) {
		for (i = *idx + 1; i < cf->nsymb; i++) {
			if (gelf_getsym(data, i, &sym) != &sym)
				continue;
			if (GELF_ST_TYPE(sym.st_info) != type)
				continue;
			if (sym.st_name >= cf->strtabsz)
				break;
			name = elf_strptr(cf->elf, cf->strtabndx,
			    sym.st_name);
			if (name == NULL)
				continue;

			*idx = i;
			return name;
		}
	}

	return NULL;
}
