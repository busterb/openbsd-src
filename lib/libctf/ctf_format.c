/*	$OpenBSD$	*/

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

#include <stdint.h>
#include <stdio.h>

#include "ctf.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

const char *
ctf_kind2name(uint16_t kind)
{
	static const char *kind_name[] = { NULL, "INTEGER", "FLOAT", "POINTER",
	   "ARRAY", "FUNCTION", "STRUCT", "UNION", "ENUM", "FORWARD",
	   "TYPEDEF", "VOLATILE", "CONST", "RESTRICT" };

	if (kind >= nitems(kind_name))
		return NULL;

	return kind_name[kind];
}

const char *
ctf_enc2name(uint16_t enc)
{
	static const char *enc_name[] = { "SIGNED", "CHAR", "SIGNED CHAR",
	    "BOOL", "SIGNED BOOL" };
	static char invalid[7];

	if (enc == CTF_INT_VARARGS)
		return "VARARGS";

	if (enc > 0 && enc <= nitems(enc_name))
		return enc_name[enc - 1];

	snprintf(invalid, sizeof(invalid), "0x%x", enc);
	return invalid;
}

const char *
ctf_fpenc2name(uint16_t enc)
{
	static const char *enc_name[] = { "SINGLE", "DOUBLE", NULL, NULL,
	    NULL, "LDOUBLE" };
	static char invalid[7];

	if (enc > 0 && enc <= nitems(enc_name) && enc_name[enc - 1] != NULL)
		return enc_name[enc - 1];

	snprintf(invalid, sizeof(invalid), "0x%x", enc);
	return invalid;
}
