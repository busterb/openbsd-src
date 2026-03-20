/*	$OpenBSD: map.c,v 1.24 2023/09/11 19:01:26 mpi Exp $ */

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

/*
 * Associative array implemented with RB-Tree.
 */

#include <sys/queue.h>
#include <sys/tree.h>

#include <assert.h>
#include <err.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

int		 mcmp(const struct mentry *, const struct mentry *);
struct mentry	*mget(struct map *, const char *);

RB_GENERATE(map, mentry, mlink, mcmp);

int
mcmp(const struct mentry *me0, const struct mentry *me1)
{
	return strncmp(me0->mkey, me1->mkey, KLEN - 1);
}

struct mentry *
mget(struct map *map, const char *key)
{
	struct mentry me, *mep;

	strlcpy(me.mkey, key, KLEN);
	mep = RB_FIND(map, map, &me);
	if (mep == NULL) {
		mep = calloc(1, sizeof(struct mentry));
		if (mep == NULL)
			err(1, "mentry: calloc");

		strlcpy(mep->mkey, key, KLEN);
		RB_INSERT(map, map, mep);
		map->nentries++;
	}

	return mep;
}

struct map *
map_new(void)
{
	struct map *map;

	map = calloc(1, sizeof(struct map));
	if (map == NULL)
		err(1, "map: calloc");

	return map;
}

size_t
map_len(struct map *map)
{
	return map->nentries;
}

void
map_clear(struct map *map)
{
	struct mentry *mep;

	while ((mep = RB_MIN(map, map)) != NULL) {
		RB_REMOVE(map, map, mep);
		free(mep);
	}

	assert(RB_EMPTY(map));
	free(map);
}

void
map_delete(struct map *map, const char *key)
{
	struct mentry me, *mep;

	strlcpy(me.mkey, key, KLEN);
	mep = RB_FIND(map, map, &me);
	if (mep != NULL) {
		RB_REMOVE(map, map, mep);
		free(mep);
		map->nentries--;
	}
}

struct bt_arg *
map_get(struct map *map, const char *key)
{
	struct mentry *mep;

	mep = mget(map, key);
	if (mep->mval == NULL)
		mep->mval = ba_new(0, B_AT_LONG);

	return mep->mval;
}

void
map_insert(struct map *map, const char *key, void *cookie)
{
	struct mentry *mep;

	mep = mget(map, key);
	free(mep->mval);
	mep->mval = cookie;
}

static int
map_cmp(const void *a, const void *b)
{
	const struct mentry *ma = *(const struct mentry **)a;
	const struct mentry *mb = *(const struct mentry **)b;
	long rv;

	rv = bacmp(ma->mval, mb->mval);
	if (rv != 0)
		return (rv > 0 ? -1 : 1);
	return mcmp(ma, mb);
}

/* Print at most `top' entries of the map ordered by value. */
void
map_print(struct map *map, size_t top, const char *name)
{
	struct mentry **elms, *mep;
	size_t i, count = 0;

	if (map == NULL)
		return;

	RB_FOREACH(mep, map, map)
		count++;

	elms = calloc(count, sizeof(*elms));
	if (elms == NULL)
		err(1, NULL);

	count = 0;
	RB_FOREACH(mep, map, map)
		elms[count++] = mep;

	qsort(elms, count, sizeof(*elms), map_cmp);

	for (i = 0; i < top && i < count; i++) {
		mep = elms[i];
		printf("@%s[%s]: %s\n", name, mep->mkey,
		    ba2str(mep->mval, NULL));
	}

	free(elms);
}

/*
 * Iterate all entries in the map in key order, calling cb(key, val, arg)
 * for each.  If cb returns non-zero, iteration stops early.
 */
void
map_foreach(struct map *map, int (*cb)(const char *, struct bt_arg *, void *),
    void *arg)
{
	struct mentry *mep;

	if (map == NULL)
		return;

	RB_FOREACH(mep, map, map) {
		if (cb(mep->mkey, mep->mval, arg))
			break;
	}
}

void
map_zero(struct map *map)
{
	struct mentry *mep;

	RB_FOREACH(mep, map, map) {
		mep->mval->ba_value = 0;
		mep->mval->ba_type = B_AT_LONG;
	}
}

/*
 * Histogram implemented with map.
 */
struct hist {
	struct map	hmap;
	int		hstep;
};

struct hist *
hist_new(long step)
{
	struct hist *hist;

	hist = calloc(1, sizeof(struct hist));
	if (hist == NULL)
		err(1, "hist: calloc");
	hist->hstep = step;

	return hist;
}

void
hist_increment(struct hist *hist, const char *bucket)
{
	struct bt_arg *ba;
	long val;

	ba = map_get(&hist->hmap, bucket);

	assert(ba->ba_type == B_AT_LONG);
	val = (long)ba->ba_value;
	val++;
	ba->ba_value = (void *)val;
}

long long
hist_get_bin_suffix(long long bin, char **suffix)
{
#define EXA	(PETA * 1024)
#define PETA	(TERA * 1024)
#define TERA	(GIGA * 1024)
#define GIGA	(MEGA * 1024)
#define MEGA	(KILO * 1024)
#define KILO	(1024LL)

	*suffix = "";
	if (bin >= EXA) {
		bin /= EXA;
		*suffix = "E";
	}
	if (bin >= PETA) {
		bin /= PETA;
		*suffix = "P";
	}
	if (bin >= TERA) {
		bin /= TERA;
		*suffix = "T";
	}
	if (bin >= GIGA) {
		bin /= GIGA;
		*suffix = "G";
	}
	if (bin >= MEGA) {
		bin /= MEGA;
		*suffix = "M";
	}
	if (bin >= KILO) {
		bin /= KILO;
		*suffix = "K";
	}
	return bin;
}

/*
 * Print bucket header where `upb' is the upper bound of the interval
 * and `hstep' the width of the interval.
 */
static inline int
hist_print_bucket(char *buf, size_t buflen, long long upb, long long hstep)
{
	int l;

	if (hstep != 0) {
		/* Linear histogram */
		l = snprintf(buf, buflen, "[%llu, %llu)", upb - hstep, upb);
	} else {
		/* Power-of-two histogram */
		if (upb < 0) {
			l = snprintf(buf, buflen, "(..., 0)");
		} else if (upb == 0) {
			l = snprintf(buf, buflen, "[%llu]", upb);
		} else {
			long long lob = upb / 2;
			char *lsuf, *usuf;

			upb = hist_get_bin_suffix(upb, &usuf);
			lob = hist_get_bin_suffix(lob, &lsuf);

			l = snprintf(buf, buflen, "[%llu%s, %llu%s)",
			    lob, lsuf, upb, usuf);
		}
	}

	if (l < 0 || (size_t)l > buflen)
		warn("string too long %d > %lu", l, sizeof(buf));

	return l;
}

static void
hist_print_inner(struct hist *hist, const char *header)
{
	struct map *map = &hist->hmap;
	static char buf[80];
	struct mentry *mep, *mcur;
	long long bmin, bprev, bin;
	long val, max = 0;
	int i, l, length = 52;

	if (map == NULL)
		return;

	bprev = 0;
	RB_FOREACH(mep, map, map) {
		val = ba2long(mep->mval, NULL);
		if (val > max)
			max = val;
	}
	printf("%s:\n", header);

	/*
	 * Sort by ascending key.
	 */
	bprev = -1;
	for (;;) {
		mcur = NULL;
		bmin = LLONG_MAX;

		RB_FOREACH(mep, map, map) {
			bin = atoll(mep->mkey);
			if ((bin <= bmin) && (bin > bprev)) {
				mcur = mep;
				bmin = bin;
			}
		}
		if (mcur == NULL)
			break;

		bin = atoll(mcur->mkey);
		val = ba2long(mcur->mval, NULL);
		i = (length * val) / max;
		l = hist_print_bucket(buf, sizeof(buf), bin, hist->hstep);
		snprintf(buf + l, sizeof(buf) - l, "%*ld |%.*s%*s|",
		    20 - l, val,
		    i, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
		    length - i, "");
		printf("%s\n", buf);

		bprev = bin;
	}
}

void
hist_print(struct hist *hist, const char *name)
{
	char header[KLEN + 2];

	snprintf(header, sizeof(header), "@%s", name);
	hist_print_inner(hist, header);
}

/*
 * Increment the bucket for 'key' in the per-slot histogram.
 * Creates a new hist for 'key' on first use.
 */
void
map_hist_bucket(struct map *map, const char *key, const char *bucket, long step)
{
	struct mentry *mep;
	struct hist *hist;

	mep = mget(map, key);
	hist = (struct hist *)mep->mval;
	if (hist == NULL) {
		hist = hist_new(step);
		mep->mval = (struct bt_arg *)hist;
	}
	hist_increment(hist, bucket);
}

/*
 * Print all per-key histograms in the map, in key order.
 */
void
map_hist_print(struct map *map, const char *name)
{
	struct mentry *mep;
	char header[KLEN + KLEN + 4];

	if (map == NULL)
		return;

	RB_FOREACH(mep, map, map) {
		struct hist *hist = (struct hist *)mep->mval;

		if (hist == NULL)
			continue;
		snprintf(header, sizeof(header), "@%s[%s]", name, mep->mkey);
		hist_print_inner(hist, header);
	}
}
