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
 * stackmap (@map[kstack] = count()): vertical icicle chart — columns=depth,
 *                                    cell height ∝ count, 256-color branches
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
	int			 ts_is_flame;	/* 1 if this is a stack/flame map */
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
 * Vertical icicle chart: each column is a call-stack depth level.
 * Cell height is proportional to sample count.  The largest child at
 * each split inherits the parent's color; other siblings get a new
 * color from ic_name_color().  All cells use bright-white foreground.
 */
static const int ic_palette[] = {
	22, 18, 52, 58, 23, 53, 88, 130,
	28, 24, 54, 94, 30, 19, 89, 100,
};
#define IC_NPALETTE	(sizeof(ic_palette) / sizeof(ic_palette[0]))
#define IC_EMPTY_BG	234	/* near-black for unused cells */
#define IC_SEP_BG	232	/* darkest gray for column separators */
#define IC_FG		231	/* bright white text */
#define IC_COL_W	20	/* total column width (cell + 1-char separator) */
#define IC_CELL_W	(IC_COL_W - 1)

/* Stable per-name color via djb2 hash → palette index. */
static int
ic_name_color(const char *name)
{
	unsigned long	h = 5381;
	unsigned char	c;

	while ((c = (unsigned char)*name++) != '\0')
		h = h * 33 ^ c;
	return ic_palette[h % IC_NPALETTE];
}

/*
 * Recursively fill the grid for `node' starting at column `depth'.
 * y_lo/y_hi are fractional row positions in [0.0, 1.0).
 */
static void
ic_collect(struct flame_node *node, int depth, double y_lo, double y_hi,
    int bg, int height, int width, int max_cols,
    int *bg_grid, char *ch_grid, long total)
{
	char	text[IC_CELL_W + 1];
	double	span, cum, cf;
	long	pct;
	int	y0, y1, cell_h, x0, x1, row, col, textlen, i;
	size_t	j;

	if (depth >= max_cols || (y_hi - y_lo) * height < 0.5)
		return;

	y0     = (int)(y_lo * height);
	y1     = (int)(y_hi * height);
	cell_h = (y1 > y0) ? y1 - y0 : 1;

	x0 = depth * IC_COL_W;
	x1 = x0 + IC_CELL_W;
	if (x0 >= width)
		return;
	if (x1 > width)
		x1 = width;

	for (row = y0; row < y0 + cell_h && row < height; row++)
		for (col = x0; col < x1; col++)
			bg_grid[row * width + col] = bg;

	pct     = node->fn_total * 100 / total;
	textlen = snprintf(text, sizeof(text), "%3ld%% %s", pct,
	    node->fn_name);
	if (textlen < 0)
		textlen = 0;
	if (textlen > IC_CELL_W)
		textlen = IC_CELL_W;
	if (y0 < height)
		for (i = 0; i < textlen && x0 + i < x1; i++)
			ch_grid[y0 * width + x0 + i] = text[i];

	if (node->fn_nchildren == 0)
		return;
	qsort(node->fn_children, node->fn_nchildren,
	    sizeof(*node->fn_children), flame_node_cmp);

	span = y_hi - y_lo;
	cum  = y_lo;
	for (j = 0; j < node->fn_nchildren; j++) {
		struct flame_node *child = node->fn_children[j];
		cf = span * (double)child->fn_total / node->fn_total;
		ic_collect(child, depth + 1, cum, cum + cf,
		    j == 0 ? bg : ic_name_color(child->fn_name),
		    height, width, max_cols, bg_grid, ch_grid, total);
		cum += cf;
	}
}

/*
 * Render the vertical icicle chart into fp.
 * Columns = call-stack depth levels; cell height ∝ sample count.
 * Skips the boring single-child prefix (e.g. all→kernel→...) so the
 * first visible column is the first level with multiple branches.
 */
static void
tui_flame_render(FILE *fp, struct flame_node *root, int width, int height)
{
	struct flame_node	*display_root;
	int			*bg_grid = NULL;
	char			*ch_grid = NULL;
	int			 max_cols, row, col, d, sep;
	double			 cum, cf;
	size_t			 i, gridsize;

	if (root->fn_total == 0 || width < IC_COL_W || height < 1)
		return;

	/* Skip boring single-child prefix (always 100%, no information). */
	display_root = root;
	while (display_root->fn_nchildren == 1)
		display_root = display_root->fn_children[0];
	if (display_root->fn_nchildren == 0)
		return;

	max_cols = width / IC_COL_W;
	if (max_cols < 1)
		max_cols = 1;

	gridsize = (size_t)height * width;
	bg_grid  = calloc(gridsize, sizeof(*bg_grid));
	ch_grid  = calloc(gridsize, sizeof(*ch_grid));
	if (bg_grid == NULL || ch_grid == NULL)
		goto out;

	for (i = 0; i < gridsize; i++) {
		bg_grid[i] = IC_EMPTY_BG;
		ch_grid[i] = ' ';
	}

	/* Separator columns. */
	for (d = 1; d <= max_cols; d++) {
		sep = d * IC_COL_W - 1;
		if (sep >= width)
			break;
		for (row = 0; row < height; row++)
			bg_grid[row * width + sep] = IC_SEP_BG;
	}

	/* Seed top-level branches; each gets its own stable color. */
	qsort(display_root->fn_children, display_root->fn_nchildren,
	    sizeof(*display_root->fn_children), flame_node_cmp);
	cum = 0.0;
	for (i = 0; i < display_root->fn_nchildren; i++) {
		struct flame_node *child = display_root->fn_children[i];
		cf = (double)child->fn_total / display_root->fn_total;
		ic_collect(child, 0, cum, cum + cf,
		    ic_name_color(child->fn_name),
		    height, width, max_cols, bg_grid, ch_grid,
		    root->fn_total);
		cum += cf;
	}

	/* Emit grid with ANSI 256-color backgrounds. */
	for (row = 0; row < height; row++) {
		int prev_bg = -1;
		for (col = 0; col < width; col++) {
			int bg = bg_grid[row * width + col];
			if (bg != prev_bg) {
				fprintf(fp, "\033[48;5;%dm\033[38;5;%dm",
				    bg, IC_FG);
				prev_bg = bg;
			}
			fputc((unsigned char)ch_grid[row * width + col], fp);
		}
		fputs(TUI_RESET "\n", fp);
	}
out:
	free(bg_grid);
	free(ch_grid);
}

static void
tui_flame_print(struct map *map, const char *name)
{
	struct tui_section	*ts;
	struct flame_node	*root;
	struct mentry		*mep;
	struct winsize		 ws;
	char			*buf;
	size_t			 bufsz;
	FILE			*fp;
	int			 width = 80, height = 24;

	/* Remember that this section is a flame/stack map. */
	ts = tui_section_get(name);
	ts->ts_is_flame = 1;

	/*
	 * If the map is empty (cleared between intervals), preserve the
	 * previous render rather than replacing it with a blank chart.
	 */
	if (RB_EMPTY(map)) {
		tui_redraw();
		return;
	}

	fp = open_memstream(&buf, &bufsz);
	if (fp == NULL)
		err(1, "open_memstream");

	root = flame_node_new("all", 3);
	RB_FOREACH(mep, map, map)
		flame_insert(root, mep->mkey, ba2long(mep->mval, NULL));

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
		if (ws.ws_col > 0)
			width = (int)ws.ws_col;
		if (ws.ws_row > 4)
			height = (int)ws.ws_row - 4;
	}

	fprintf(fp, TUI_BOLD "@%s" TUI_RESET "\n", name);
	tui_flame_render(fp, root, width, height);
	fclose(fp);

	flame_node_free(root);
	tui_section_update(name, buf);
	tui_redraw();
}

void
tui_map_print(struct map *map, size_t top, const char *name)
{
	struct tui_section	*ts;
	struct mentry		**elms, *mep;
	size_t			 i, count = 0;
	char			*buf;
	size_t			 bufsz;
	FILE			*fp;
	long			 max = 0;
	int			 bar_w = 48;

	if (map == NULL)
		return;

	ts = tui_section_get(name);

	/* kstack/ustack keys contain '\n'-separated frames. */
	RB_FOREACH(mep, map, map) {
		if (strchr(mep->mkey, '\n') != NULL) {
			tui_flame_print(map, name);
			return;
		}
		break;
	}

	/*
	 * If this section was previously rendered as a flame chart and the
	 * map is now empty (cleared between intervals), route through
	 * tui_flame_print which will preserve the last render.
	 */
	if (ts->ts_is_flame) {
		tui_flame_print(map, name);
		return;
	}

	/* For regular maps, skip the update when there's nothing to show. */
	if (RB_EMPTY(map))
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
