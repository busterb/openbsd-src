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
 * maphist  (@map[k] = hist(v)):    2-D heatmap — rows=outer keys, cols=buckets
 * hist     (@h = hist(v)):         horizontal bar chart
 * map      (@map[k] = count()):    bar chart sorted by value
 * stackmap (@map[kstack] = count()): icicle chart (flame graph), width adapts
 *
 * Column width is fixed at TUI_COL_W display columns.  Unicode block chars
 * are exactly 1 display column wide; we emit them with explicit surrounding
 * spaces so the byte width of each cell string is constant and alignment
 * works without wcwidth(3).
 */

#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

/*
 * Flame graph (icicle chart) for stack trace maps (@map[kstack] = count()).
 *
 * A prefix tree is built from the newline-delimited frame strings stored as
 * map keys (btrace format: "\nfunc+0xNN\n..." innermost-first).  Frames are
 * inserted outermost-first so the root represents the whole call tree.
 * The tree is then rendered level-by-level; each node's box width is
 * proportional to its share of total samples.
 */

struct flame_node {
	char			*fn_name;
	long			 fn_total;
	struct flame_node	**fn_children;
	size_t			 fn_nchildren;
	size_t			 fn_childcap;
};

/* One rendered box at a given tree level. */
struct flame_box {
	int			 fb_x;
	int			 fb_w;
	struct flame_node	*fb_node;
};

static struct flame_node *
flame_node_new(const char *name, size_t namelen)
{
	struct flame_node *fn;

	fn = calloc(1, sizeof(*fn));
	if (fn == NULL)
		err(1, NULL);
	fn->fn_name = strndup(name, namelen);
	if (fn->fn_name == NULL)
		err(1, NULL);
	return fn;
}

static void
flame_node_free(struct flame_node *fn)
{
	size_t i;

	for (i = 0; i < fn->fn_nchildren; i++)
		flame_node_free(fn->fn_children[i]);
	free(fn->fn_children);
	free(fn->fn_name);
	free(fn);
}

/* Find or create a child of fn with the given name. */
static struct flame_node *
flame_child_get(struct flame_node *fn, const char *name, size_t namelen)
{
	struct flame_node *child, **tmp;
	size_t i;

	for (i = 0; i < fn->fn_nchildren; i++) {
		if (strncmp(fn->fn_children[i]->fn_name, name, namelen) == 0 &&
		    fn->fn_children[i]->fn_name[namelen] == '\0')
			return fn->fn_children[i];
	}
	child = flame_node_new(name, namelen);
	if (fn->fn_nchildren >= fn->fn_childcap) {
		fn->fn_childcap = fn->fn_childcap ? fn->fn_childcap * 2 : 4;
		tmp = reallocarray(fn->fn_children, fn->fn_childcap,
		    sizeof(*tmp));
		if (tmp == NULL)
			err(1, NULL);
		fn->fn_children = tmp;
	}
	fn->fn_children[fn->fn_nchildren++] = child;
	return child;
}

/*
 * Parse key (btrace kstack/ustack: "\nfunc+0xNN\n..." innermost-first)
 * and insert into the prefix tree outermost-first, accumulating count.
 */
static void
flame_insert(struct flame_node *root, const char *key, long count)
{
	const char	*frames[64];
	size_t		 framelens[64];
	int		 nframes = 0, i;
	const char	*p = key;

	while (*p != '\0' && nframes < 64) {
		while (*p == '\n')
			p++;
		if (*p == '\0')
			break;
		const char *end = p;
		while (*end != '\0' && *end != '\n')
			end++;
		size_t len = end - p;
		/* strip +0xOFFSET */
		const char *plus = memchr(p, '+', len);
		if (plus != NULL)
			len = plus - p;
		if (len > 0) {
			frames[nframes] = p;
			framelens[nframes] = len;
			nframes++;
		}
		p = end;
	}

	/* Walk outermost-first (reversed) to build root-down tree. */
	root->fn_total += count;
	struct flame_node *node = root;
	for (i = nframes - 1; i >= 0; i--) {
		node = flame_child_get(node, frames[i], framelens[i]);
		node->fn_total += count;
	}
}

static int
flame_node_cmp(const void *a, const void *b)
{
	const struct flame_node *fa = *(const struct flame_node * const *)a;
	const struct flame_node *fb = *(const struct flame_node * const *)b;

	return (fa->fn_total < fb->fn_total) - (fa->fn_total > fb->fn_total);
}

/*
 * Render the icicle chart level-by-level into fp.
 * Each box: '|' + label (truncated) + percentage, proportional width.
 */
static void
tui_flame_render(FILE *fp, struct flame_node *root, int width)
{
	struct flame_box	*cur = NULL, *nxt = NULL;
	size_t			 ncur, nnxt, nxtcap;
	char			*row;
	long			 total = root->fn_total;
	size_t			 i;

	if (total == 0 || width < 2)
		return;

	row = malloc(width + 1);
	if (row == NULL)
		err(1, NULL);

	cur = calloc(1, sizeof(*cur));
	if (cur == NULL)
		err(1, NULL);
	cur[0].fb_x    = 0;
	cur[0].fb_w    = width;
	cur[0].fb_node = root;
	ncur   = 1;
	nnxt   = 0;
	nxtcap = 0;

	while (ncur > 0) {
		/* Render this level. */
		memset(row, ' ', width);
		row[width] = '\0';
		for (i = 0; i < ncur; i++) {
			int x = cur[i].fb_x, w = cur[i].fb_w;
			struct flame_node *fn = cur[i].fb_node;
			int inner, pct, l;
			char label[128];

			if (x >= width || w < 1)
				continue;
			row[x] = '|';
			if (w < 3)
				continue;
			inner = (x + w > width) ? width - x - 1 : w - 1;
			pct   = (int)(fn->fn_total * 100 / total);
			l = snprintf(label, sizeof(label), "%s %d%%",
			    fn->fn_name, pct);
			if (l < 0 || l > inner)
				l = snprintf(label, sizeof(label), "%s",
				    fn->fn_name);
			if (l < 0)
				l = 0;
			if (l > inner)
				l = inner;
			memcpy(row + x + 1, label, l);
		}
		fprintf(fp, "%s\n", row);

		/* Build next level. */
		nnxt = 0;
		for (i = 0; i < ncur; i++) {
			int x = cur[i].fb_x, w = cur[i].fb_w;
			struct flame_node *fn = cur[i].fb_node;
			int cx = x, rem = w;
			size_t j;

			if (fn->fn_nchildren == 0)
				continue;
			qsort(fn->fn_children, fn->fn_nchildren,
			    sizeof(*fn->fn_children), flame_node_cmp);
			for (j = 0; j < fn->fn_nchildren && rem > 0; j++) {
				struct flame_node *child = fn->fn_children[j];
				struct flame_box  *tmp;
				int cw = (int)((long)w * child->fn_total /
				    fn->fn_total);
				if (cw < 1)
					cw = 1;
				if (cw > rem)
					cw = rem;
				if (nnxt >= nxtcap) {
					nxtcap = nxtcap ? nxtcap * 2 : 8;
					tmp = reallocarray(nxt, nxtcap,
					    sizeof(*tmp));
					if (tmp == NULL)
						err(1, NULL);
					nxt = tmp;
				}
				nxt[nnxt].fb_x    = cx;
				nxt[nnxt].fb_w    = cw;
				nxt[nnxt].fb_node = child;
				nnxt++;
				cx  += cw;
				rem -= cw;
			}
		}

		free(cur);
		cur    = nxt;
		ncur   = nnxt;
		nxt    = NULL;
		nnxt   = 0;
		nxtcap = 0;
	}
	free(row);
	/* cur == NULL here (was swapped from nxt which was reset) */
}

static void
tui_flame_print(struct map *map, const char *name)
{
	struct flame_node *root;
	struct mentry *mep;
	struct winsize ws;
	char *buf;
	size_t bufsz;
	FILE *fp;
	int width = 80;

	fp = open_memstream(&buf, &bufsz);
	if (fp == NULL)
		err(1, "open_memstream");

	root = flame_node_new("all", 3);
	RB_FOREACH(mep, map, map)
		flame_insert(root, mep->mkey, ba2long(mep->mval, NULL));

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 1)
		width = (int)ws.ws_col - 1;

	fprintf(fp, TUI_BOLD "@%s" TUI_RESET "\n", name);
	tui_flame_render(fp, root, width);
	fclose(fp);

	flame_node_free(root);
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

	/* kstack/ustack keys contain '\n'-separated frames. */
	RB_FOREACH(mep, map, map) {
		if (strchr(mep->mkey, '\n') != NULL) {
			tui_flame_print(map, name);
			return;
		}
		break;
	}

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
