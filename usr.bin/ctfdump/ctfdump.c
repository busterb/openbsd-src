/*	$OpenBSD: ctfdump.c,v 1.28 2024/02/22 13:21:03 claudio Exp $ */

/*
 * Copyright (c) 2016 Martin Pieuchot <mpi@openbsd.org>
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
#include <sys/ctf.h>
#include <sys/exec_elf.h>

#include <ctf.h>

#include <err.h>
#include <locale.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DUMP_OBJECT	(1 << 0)
#define DUMP_FUNCTION	(1 << 1)
#define DUMP_HEADER	(1 << 2)
#define DUMP_LABEL	(1 << 3)
#define DUMP_STRTAB	(1 << 4)
#define DUMP_STATISTIC	(1 << 5)
#define DUMP_TYPE	(1 << 6)

int		 dump(const char *, uint8_t);
__dead void	 usage(void);

int		 ctf_dump(ctf_file_t *, uint8_t);
void		 ctf_dump_type(ctf_file_t *, uint32_t *, uint32_t);

static const char *
namestr(ctf_file_t *cf, uint32_t offset)
{
	const char	*name;

	name = ctf_stroff2name(cf, offset);
	if (name == NULL)
		return "(anon)";
	return name;
}

int
main(int argc, char *argv[])
{
	const char *filename;
	uint8_t flags = 0;
	int ch, error = 0;

	setlocale(LC_ALL, "");

	if (pledge("stdio rpath", NULL) == -1)
		err(1, "pledge");

	while ((ch = getopt(argc, argv, "dfhlst")) != -1) {
		switch (ch) {
		case 'd':
			flags |= DUMP_OBJECT;
			break;
		case 'f':
			flags |= DUMP_FUNCTION;
			break;
		case 'h':
			flags |= DUMP_HEADER;
			break;
		case 'l':
			flags |= DUMP_LABEL;
			break;
		case 's':
			flags |= DUMP_STRTAB;
			break;
		case 't':
			flags |= DUMP_TYPE;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc <= 0)
		usage();

	/* Dump everything by default */
	if (flags == 0)
		flags = 0xff;

	while ((filename = *argv++) != NULL)
		error |= dump(filename, flags);

	return error;
}

int
dump(const char *path, uint8_t flags)
{
	ctf_file_t	*cf;
	int		 error;

	cf = ctf_open(path);
	if (cf == NULL) {
		warnx("failed to open %s", path);
		return 1;
	}

	error = ctf_dump(cf, flags);
	ctf_close(cf);

	return error;
}

int
ctf_dump(ctf_file_t *cf, uint8_t flags)
{
	const struct ctf_header	*cth;
	const char		*data;
	size_t			 dlen;

	cth = ctf_header(cf);
	data = ctf_data(cf, &dlen);

	if (flags & DUMP_HEADER) {
		printf("  cth_magic    = 0x%04x\n", cth->cth_magic);
		printf("  cth_version  = %u\n", cth->cth_version);
		printf("  cth_flags    = 0x%02x\n", cth->cth_flags);
		printf("  cth_parlabel = %s\n",
		    namestr(cf, cth->cth_parlabel));
		printf("  cth_parname  = %s\n",
		    namestr(cf, cth->cth_parname));
		printf("  cth_lbloff   = %u\n", cth->cth_lbloff);
		printf("  cth_objtoff  = %u\n", cth->cth_objtoff);
		printf("  cth_funcoff  = %u\n", cth->cth_funcoff);
		printf("  cth_typeoff  = %u\n", cth->cth_typeoff);
		printf("  cth_stroff   = %u\n", cth->cth_stroff);
		printf("  cth_strlen   = %u\n", cth->cth_strlen);
		printf("\n");
	}

	if (flags & DUMP_LABEL) {
		uint32_t		 lbloff = cth->cth_lbloff;
		struct ctf_lblent	*ctl;

		while (lbloff < cth->cth_objtoff) {
			ctl = (struct ctf_lblent *)(data + lbloff);

			printf("  %5u %s\n", ctl->ctl_typeidx,
			    namestr(cf, ctl->ctl_label));

			lbloff += sizeof(*ctl);
		}
		printf("\n");
	}

	if (flags & DUMP_OBJECT) {
		uint32_t		 objtoff = cth->cth_objtoff;
		size_t			 idx = 0, i = 0;
		uint16_t		*dsp;
		const char		*s;
		int			 l;

		while (objtoff < cth->cth_funcoff) {
			dsp = (uint16_t *)(data + objtoff);

			l = printf("  [%zu] %u", i++, *dsp);
			if ((s = ctf_symbol_name(cf, &idx,
			    STT_OBJECT)) != NULL)
				printf("%*s %s (%zu)\n", (14 - l), "", s, idx);
			else
				printf("\n");

			objtoff += sizeof(*dsp);
		}
		printf("\n");
	}

	if (flags & DUMP_FUNCTION) {
		uint16_t		*fsp, kind, vlen;
		uint16_t		*fstart, *fend;
		size_t			 idx = 0, i = -1;
		const char		*s;
		int			 l;

		fstart = (uint16_t *)(data + cth->cth_funcoff);
		fend = (uint16_t *)(data + cth->cth_typeoff);

		fsp = fstart;
		while (fsp < fend) {
			kind = CTF_INFO_KIND(*fsp);
			vlen = CTF_INFO_VLEN(*fsp);
			s = ctf_symbol_name(cf, &idx, STT_FUNC);
			fsp++;
			i++;

			if (kind == CTF_K_UNKNOWN && vlen == 0)
				continue;

			l = printf("  [%zu] FUNC ", i);
			if (s != NULL)
				printf("(%s) ", s);
			printf("returns: %u args: (", *fsp++);
			while (vlen-- > 0 && fsp < fend)
				printf("%u%s", *fsp++, (vlen > 0) ? ", " : "");
			printf(")\n");
		}
		printf("\n");
	}

	if (flags & DUMP_TYPE) {
		uint32_t		 idx = 1, offset = cth->cth_typeoff;
		uint32_t		 stroff = cth->cth_stroff;

		while (offset < stroff) {
			ctf_dump_type(cf, &offset, idx++);
		}
		printf("\n");
	}

	if (flags & DUMP_STRTAB) {
		uint32_t		 offset = 0;
		const char		*str;

		while (offset < cth->cth_strlen) {
			str = ctf_stroff2name(cf, offset);

			printf("  [%u] ", offset);
			if (str != NULL)
				offset += printf("%s\n", str);
			else {
				printf("\\0\n");
				offset++;
			}
		}
		printf("\n");
	}

	return 0;
}

void
ctf_dump_type(ctf_file_t *cf, uint32_t *offset, uint32_t idx)
{
	const struct ctf_header	*cth;
	const char		*data;
	size_t			 dlen;
	const char		*p;
	const struct ctf_type	*ctt;
	const struct ctf_array	*cta;
	uint16_t		*argp, i, kind, vlen, root;
	uint32_t		 eob, toff, stroff;
	uint64_t		 size;
	const char		*name, *kname;

	cth = ctf_header(cf);
	data = ctf_data(cf, &dlen);
	stroff = cth->cth_stroff;

	p = data + *offset;
	ctt = (const struct ctf_type *)p;

	kind = CTF_INFO_KIND(ctt->ctt_info);
	vlen = CTF_INFO_VLEN(ctt->ctt_info);
	root = CTF_INFO_ISROOT(ctt->ctt_info);
	name = namestr(cf, ctt->ctt_name);

	if (root)
		printf("  <%u> ", idx);
	else
		printf("  [%u] ", idx);

	if ((kname = ctf_kind2name(kind)) != NULL)
		printf("%s %s", kname, name);

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
		break;
	case CTF_K_INTEGER:
		eob = *((uint32_t *)(p + toff));
		toff += sizeof(uint32_t);
		printf(" encoding=%s offset=%u bits=%u (%llu bytes)",
		    ctf_enc2name(CTF_INT_ENCODING(eob)), CTF_INT_OFFSET(eob),
		    CTF_INT_BITS(eob), size);
		break;
	case CTF_K_FLOAT:
		eob = *((uint32_t *)(p + toff));
		toff += sizeof(uint32_t);
		printf(" encoding=%s offset=%u bits=%u (%llu bytes)",
		    ctf_fpenc2name(CTF_FP_ENCODING(eob)), CTF_FP_OFFSET(eob),
		    CTF_FP_BITS(eob), size);
		break;
	case CTF_K_ARRAY:
		cta = (struct ctf_array *)(p + toff);
		printf(" content: %u index: %u nelems: %u\n", cta->cta_contents,
		    cta->cta_index, cta->cta_nelems);
		toff += sizeof(struct ctf_array);
		break;
	case CTF_K_FUNCTION:
		argp = (uint16_t *)(p + toff);
		printf(" returns: %u args: (%u", ctt->ctt_type, *argp);
		for (i = 1; i < vlen; i++) {
			argp++;
			if ((const char *)argp > data + dlen)
				errx(1, "offset exceeds CTF section");

			printf(", %u", *argp);
		}
		printf(")");
		toff += (vlen + (vlen & 1)) * sizeof(uint16_t);
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		printf(" (%llu bytes)\n", size);

		if (size < CTF_LSTRUCT_THRESH) {
			for (i = 0; i < vlen; i++) {
				struct ctf_member	*ctm;

				if (p + toff > data + dlen)
					errx(1, "offset exceeds CTF section");

				if (toff > (stroff - sizeof(*ctm)))
					break;

				ctm = (struct ctf_member *)(p + toff);
				toff += sizeof(struct ctf_member);

				printf("\t%s type=%u off=%u\n",
				    namestr(cf, ctm->ctm_name),
				    ctm->ctm_type, ctm->ctm_offset);
			}
		} else {
			for (i = 0; i < vlen; i++) {
				struct ctf_lmember	*ctlm;

				if (p + toff > data + dlen)
					errx(1, "offset exceeds CTF section");

				if (toff > (stroff - sizeof(*ctlm)))
					break;

				ctlm = (struct ctf_lmember *)(p + toff);
				toff += sizeof(struct ctf_lmember);

				printf("\t%s type=%u off=%llu\n",
				    namestr(cf, ctlm->ctlm_name),
				    ctlm->ctlm_type, CTF_LMEM_OFFSET(ctlm));
			}
		}
		break;
	case CTF_K_ENUM:
		printf(" (%llu bytes)\n", size);

		for (i = 0; i < vlen; i++) {
			struct ctf_enum	*cte;

			if (p + toff > data + dlen)
				errx(1, "offset exceeds CTF section");

			if (toff > (stroff - sizeof(*cte)))
				break;

			cte = (struct ctf_enum *)(p + toff);
			toff += sizeof(struct ctf_enum);

			printf("\t%s = %d\n",
			    namestr(cf, cte->cte_name),
			    cte->cte_value);
		}
		break;
	case CTF_K_POINTER:
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
		printf(" refers to %u", ctt->ctt_type);
		break;
	default:
		errx(1, "incorrect type %u at offset %u", kind, *offset);
	}

	printf("\n");

	*offset += toff;
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-dfhlst] file ...\n",
	    getprogname());
	exit(1);
}
