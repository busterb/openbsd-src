/*	$OpenBSD$	*/

/*
 * Copyright (c) 2020 Martin Pieuchot <mpi@openbsd.org>
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

#ifndef MAP_H
#define MAP_H

#include <sys/tree.h>

#include "bt_parser.h"
#include "btrace.h"

struct map {
	struct mentry		*rbh_root;	/* RB_HEAD(map, mentry) */
	size_t			 nentries;
};

struct mentry {
	RB_ENTRY(mentry)	 mlink;
	char			 mkey[KLEN];
	struct bt_arg		*mval;
};

struct hist {
	struct map		 hmap;
	int			 hstep;
};

RB_PROTOTYPE(map, mentry, mlink, mcmp);

#endif /* MAP_H */
