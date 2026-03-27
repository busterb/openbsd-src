/*	$OpenBSD$	*/

/*
 * Copyright (c) 2026 Brent Cook <bcook@openbsd.org>
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
 * Built-in TUI visualizer for btrace (-V flag).
 *
 * Each print() call renders its variable to a per-name section buffer via
 * open_memstream(3), updates the section list, then redraws all sections.
 * Multiple print() calls per interval accumulate naturally.
 *
 * maphist (@map[k] = hist(v)):  2-D heatmap — rows=outer keys, cols=buckets
 * hist    (@h = hist(v)):       horizontal bar chart
 * map     (@map[k] = count()):  bar chart sorted by value
 *
 * Column width is fixed at TUI_COL_W display columns.  Unicode block chars
 * are exactly 1 display column wide; we emit them with explicit surrounding
 * spaces so the byte width of each cell string is constant and alignment
 * works without wcwidth(3).
 */

#include <sys/queue.h>
#include <sys/tree.h>

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bt_parser.h"
#include "btrace.h"
#include "map.h"

/* ANSI sequences */
#define TUI_CLEAR	"\033[2J\033[H"
#define TUI_BOLD	"\033[1m"
#define TUI_RESET	"\033[0m"

/*
 * Heatmap cell strings, each exactly TUI_COL_W display columns wide.
 * Unicode block chars are 3 UTF-8 bytes but 1 display column; we pad with
 * 2 spaces on each side so the total is 1+3+1 = 5 display columns.
 */
#define TUI_COL_W	5
static const char *tui_cells[] = {
	"  .  ",			/* 0% — ASCII dot, 5 bytes, 5 cols */
	"  \xe2\x96\x91  ",		/* <5%  ░ U+2591, 7 bytes, 5 display cols */
	"  \xe2\x96\x92  ",		/* <20% ▒ U+2592 */
	"  \xe2\x96\x93  ",		/* <60% ▓ U+2593 */
	"  \xe2\x96\x88  ",		/* max  █ U+2588 */
};

/*
 * Section list: one entry per named variable, in insertion order.
 * Each section holds the last rendered content as a heap string.
 */
struct tui_section {
	char			*ts_name;
	char			*ts_buf;
	struct tui_section	*ts_next;
};
static struct tui_section *tui_head;

static struct tui_section *
tui_section_get(const char *name)
{
	struct tui_section *ts, **pp;

	for (ts = tui_head; ts != NULL; ts = ts->ts_next)
		if (strcmp(ts->ts_name, name) == 0)
			return ts;

	ts = calloc(1, sizeof(*ts));
	if (ts == NULL || (ts->ts_name = strdup(name)) == NULL)
		err(1, NULL);

	for (pp = &tui_head; *pp != NULL; pp = &(*pp)->ts_next)
		;
	*pp = ts;
	return ts;
}

static void
tui_section_update(const char *name, char *buf)
{
	struct tui_section *ts = tui_section_get(name);

	free(ts->ts_buf);
	ts->ts_buf = buf;
}

static void
tui_redraw(void)
{
	struct tui_section *ts;

	printf(TUI_CLEAR);
	for (ts = tui_head; ts != NULL; ts = ts->ts_next) {
		if (ts->ts_buf != NULL) {
			fputs(ts->ts_buf, stdout);
			putchar('\n');
		}
	}
	fflush(stdout);
}

/* Map intensity fraction to a fixed-width cell string. */
static const char *
tui_intensity(long val, long row_max)
{
	double r;

	if (row_max == 0 || val == 0)
		return tui_cells[0];
	r = (double)val / row_max;
	if (r < 0.05)  return tui_cells[1];
	if (r < 0.20)  return tui_cells[2];
	if (r < 0.60)  return tui_cells[3];
	return tui_cells[4];
}

/*
 * Format a power-of-2 histogram bucket label.
 * Returns number of bytes written (excluding NUL).
 */
static int
tui_bucket_fmt(char *buf, size_t len, long long upb, int step)
{
	static const struct { long long div; char sfx; } units[] = {
		{ 1LL << 60, 'E' }, { 1LL << 50, 'P' }, { 1LL << 40, 'T' },
		{ 1LL << 30, 'G' }, { 1LL << 20, 'M' }, { 1LL << 10, 'K' },
	};
	size_t i;

	if (step != 0)
		return snprintf(buf, len, "[%lld,%lld)", upb - step, upb);
	if (upb < 0)
		return snprintf(buf, len, "<0");
	if (upb == 0)
		return snprintf(buf, len, "0");
	for (i = 0; i < sizeof(units) / sizeof(units[0]); i++)
		if (upb >= units[i].div)
			return snprintf(buf, len, "%lld%c",
			    upb / units[i].div, units[i].sfx);
	return snprintf(buf, len, "%lld", upb);
}

/*
 * Sort comparator for outer map keys: numeric when both keys are integers
 * (e.g. CPU IDs "0".."11"), lexicographic otherwise.
 */
static int
tui_key_cmp(const void *a, const void *b)
{
	const struct mentry *ma = *(const struct mentry * const *)a;
	const struct mentry *mb = *(const struct mentry * const *)b;
	char *ea, *eb;
	long long ia = strtoll(ma->mkey, &ea, 10);
	long long ib = strtoll(mb->mkey, &eb, 10);

	if (*ea == '\0' && *eb == '\0')
		return (ia > ib) - (ia < ib);
	return strncmp(ma->mkey, mb->mkey, KLEN);
}

/*
 * Sort comparator for map entries by value descending, then key.
 * Mirrors map_cmp() in map.c.
 */
static int
tui_val_cmp(const void *a, const void *b)
{
	const struct mentry *ma = *(const struct mentry * const *)a;
	const struct mentry *mb = *(const struct mentry * const *)b;
	long rv = bacmp(ma->mval, mb->mval);

	if (rv != 0)
		return (rv > 0) ? -1 : 1;
	return strncmp(ma->mkey, mb->mkey, KLEN);
}

/*
 * Render a single histogram as a horizontal bar chart.
 * Uses the same sorted iteration as hist_print_inner().
 */
static void
tui_hist_render(FILE *fp, struct hist *hist, int bar_w)
{
	struct map *map = &hist->hmap;
	struct mentry *mep, *mcur;
	long long bprev, bmin, bin;
	long val, max = 0;
	char label[32], bar[80];
	int i;

	if (bar_w > (int)(sizeof(bar) - 1))
		bar_w = sizeof(bar) - 1;

	RB_FOREACH(mep, map, map) {
		val = ba2long(mep->mval, NULL);
		if (val > max)
			max = val;
	}

	bprev = LLONG_MIN;
	for (;;) {
		mcur = NULL;
		bmin = LLONG_MAX;
		RB_FOREACH(mep, map, map) {
			bin = atoll(mep->mkey);
			if (bin <= bmin && bin > bprev) {
				mcur = mep;
				bmin = bin;
			}
		}
		if (mcur == NULL)
			break;

		bin = atoll(mcur->mkey);
		val = ba2long(mcur->mval, NULL);
		tui_bucket_fmt(label, sizeof(label), bin, hist->hstep);
		i = (max > 0) ? (bar_w * val / max) : 0;
		memset(bar, '#', i);
		memset(bar + i, ' ', bar_w - i);
		bar[bar_w] = '\0';
		fprintf(fp, "%8s %8ld |%s|\n", label, val, bar);

		bprev = bin;
	}
}

/*
 * Render a 2-D heatmap for a maphist.
 *
 * Collect all bucket keys across all outer entries, sort numerically,
 * and emit a grid where each cell shows the per-row-normalized intensity
 * using Unicode block characters (TUI_COL_W display columns each).
 */
static void
tui_maphist_render(FILE *fp, struct map *map, int step)
{
	struct mentry *omep;
	struct mentry **orows = NULL;
	long long *buckets = NULL;
	size_t nbuckets = 0, bcap = 0;
	size_t nrows = 0;
	char label[32];
	int key_w;
	size_t i;

	/* Collect outer rows and all inner bucket keys. */
	RB_FOREACH(omep, map, map) {
		struct hist *h = (struct hist *)omep->mval;
		struct mentry *imep;
		struct mentry **tmp;

		tmp = reallocarray(orows, nrows + 1, sizeof(*orows));
		if (tmp == NULL)
			err(1, NULL);
		orows = tmp;
		orows[nrows++] = omep;

		if (h == NULL)
			continue;

		RB_FOREACH(imep, map, &h->hmap) {
			long long bin = atoll(imep->mkey);
			size_t j;

			for (j = 0; j < nbuckets; j++)
				if (buckets[j] == bin)
					break;
			if (j < nbuckets)
				continue;

			if (nbuckets >= bcap) {
				bcap = bcap ? bcap * 2 : 16;
				buckets = reallocarray(buckets, bcap,
				    sizeof(*buckets));
				if (buckets == NULL)
					err(1, NULL);
			}
			buckets[nbuckets++] = bin;
		}
	}

	if (nrows == 0 || nbuckets == 0) {
		free(orows);
		free(buckets);
		return;
	}

	/* Sort outer rows numerically by key. */
	qsort(orows, nrows, sizeof(*orows), tui_key_cmp);

	/* Sort buckets numerically. */
	for (i = 1; i < nbuckets; i++) {
		long long key = buckets[i];
		size_t j = i;
		while (j > 0 && buckets[j - 1] > key) {
			buckets[j] = buckets[j - 1];
			j--;
		}
		buckets[j] = key;
	}

	/* Key column width: max key string length, at least 3. */
	key_w = 3;
	for (i = 0; i < nrows; i++) {
		int l = (int)strlen(orows[i]->mkey);
		if (l > key_w)
			key_w = l;
	}

	/* Header row: one TUI_COL_W-display-col label per bucket. */
	fprintf(fp, "%*s |", key_w, "");
	for (i = 0; i < nbuckets; i++) {
		tui_bucket_fmt(label, sizeof(label), buckets[i], step);
		fprintf(fp, "%*s", TUI_COL_W, label);
	}
	fprintf(fp, "  total\n");

	/* Separator. */
	fprintf(fp, "%.*s-+",
	    key_w, "-------------------------------------------------");
	for (i = 0; i < nbuckets; i++)
		fprintf(fp, "%.*s",
		    TUI_COL_W, "-------------------------------------------------");
	fprintf(fp, "---------\n");

	/* One row per outer key. */
	for (i = 0; i < nrows; i++) {
		struct hist *h = (struct hist *)orows[i]->mval;
		long row_max = 0, total = 0;
		struct mentry *imep;
		size_t j;

		if (h != NULL) {
			RB_FOREACH(imep, map, &h->hmap) {
				long v = ba2long(imep->mval, NULL);
				if (v > row_max)
					row_max = v;
				total += v;
			}
		}

		fprintf(fp, "%*s |", key_w, orows[i]->mkey);
		for (j = 0; j < nbuckets; j++) {
			char bkey[32];
			long v = 0;

			if (h != NULL) {
				struct bt_arg *bval;
				snprintf(bkey, sizeof(bkey), "%lld", buckets[j]);
				bval = map_get(&h->hmap, bkey);
				v = ba2long(bval, NULL);
			}
			/* Each tui_intensity() string is TUI_COL_W display cols. */
			fputs(tui_intensity(v, row_max), fp);
		}
		fprintf(fp, "  %ld\n", total);
	}

	free(orows);
	free(buckets);
}

void
tui_hist_print(struct hist *hist, const char *name)
{
	char *buf;
	size_t bufsz;
	FILE *fp;

	fp = open_memstream(&buf, &bufsz);
	if (fp == NULL)
		err(1, "open_memstream");

	fprintf(fp, TUI_BOLD "@%s" TUI_RESET "\n", name);
	tui_hist_render(fp, hist, 48);
	fclose(fp);

	tui_section_update(name, buf);
	tui_redraw();
}

void
tui_map_print(struct map *map, size_t top, const char *name)
{
	struct mentry **elms, *mep;
	size_t i, count = 0;
	char *buf;
	size_t bufsz;
	FILE *fp;
	long max = 0;
	int bar_w = 48;

	if (map == NULL)
		return;

	fp = open_memstream(&buf, &bufsz);
	if (fp == NULL)
		err(1, "open_memstream");

	RB_FOREACH(mep, map, map)
		count++;

	elms = calloc(count, sizeof(*elms));
	if (elms == NULL)
		err(1, NULL);
	count = 0;
	RB_FOREACH(mep, map, map)
		elms[count++] = mep;

	qsort(elms, count, sizeof(*elms), tui_val_cmp);

	if (count > top)
		count = top;
	for (i = 0; i < count; i++) {
		long v = ba2long(elms[i]->mval, NULL);
		if (v > max)
			max = v;
	}

	fprintf(fp, TUI_BOLD "@%s" TUI_RESET "\n", name);
	for (i = 0; i < count; i++) {
		char bar[80];
		long v = ba2long(elms[i]->mval, NULL);
		int j = (max > 0) ? (bar_w * v / max) : 0;

		memset(bar, '#', j);
		memset(bar + j, ' ', bar_w - j);
		bar[bar_w] = '\0';
		fprintf(fp, "%16s %8ld |%s|\n", elms[i]->mkey, v, bar);
	}

	free(elms);
	fclose(fp);

	tui_section_update(name, buf);
	tui_redraw();
}

void
tui_map_hist_print(struct map *map, const char *name)
{
	struct mentry *mep;
	char *buf;
	size_t bufsz;
	FILE *fp;
	int step = 0;

	if (map == NULL)
		return;

	RB_FOREACH(mep, map, map) {
		struct hist *h = (struct hist *)mep->mval;
		if (h != NULL) {
			step = h->hstep;
			break;
		}
	}

	fp = open_memstream(&buf, &bufsz);
	if (fp == NULL)
		err(1, "open_memstream");

	fprintf(fp, TUI_BOLD "@%s" TUI_RESET "\n", name);
	tui_maphist_render(fp, map, step);
	fclose(fp);

	tui_section_update(name, buf);
	tui_redraw();
}
