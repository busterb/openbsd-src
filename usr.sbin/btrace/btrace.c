/*	$OpenBSD: btrace.c,v 1.99 2025/10/05 22:31:54 sashan Exp $ */

/*
 * Copyright (c) 2019 - 2023 Martin Pieuchot <mpi@openbsd.org>
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

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/queue.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <locale.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <dev/dt/dtvar.h>

#include <gelf.h>

#include <sys/ctf.h>
#include <ctf.h>

#include "btrace.h"
#include "bt_parser.h"

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))

/* stmt_eval() return codes */
#define STMT_NORMAL	0	/* normal completion */
#define STMT_EXIT	1	/* exit() was called */
#define STMT_BREAK	2	/* break statement */
#define STMT_CONT	3	/* continue statement */

/* Per-key state for avg() and stats() aggregations. */
struct avgstate {
	long		 count;
	long		 sum;
};

/*
 * Combined allocation: bt_arg header immediately followed by avgstate.
 * ba.ba_value points to the embedded state field, so freeing ba also
 * frees the state without a separate allocation.
 */
struct bt_avg {
	struct bt_arg	 ba;
	struct avgstate	 state;
};

/*
 * Maximum number of operands an arithmetic operation can have.  This
 * is necessary to stop infinite recursion when evaluating expressions.
 */
#define __MAXOPERANDS	5

#define __PATH_DEVDT "/dev/dt"

__dead void		 usage(void);
char			*read_btfile(const char *, size_t *);

/*
 * Retrieve & parse probe information.
 */
void			 dtpi_cache(int);
void			 dtpi_print_list(int);
const char		*dtpi_func(struct dtioc_probe_info *);
size_t			 dtpi_get_by_pattern(const char *, const char *,
			     const char *, struct dtioc_probe_info **, size_t);

/*
 * Main loop and rule evaluation.
 */
void			 probe_bail(struct bt_probe *);
const char		*probe_name(struct bt_probe *);
void			 rules_do(int);
int			 rules_setup(int);
int			 rules_apply(int, struct dt_evt *);
void			 rules_teardown(int);
int			 rule_eval(struct bt_rule *, struct dt_evt *);
void			 rule_printmaps(struct bt_rule *);

/*
 * Language builtins & functions.
 */
uint64_t		 builtin_nsecs(struct dt_evt *);
uint64_t		 builtin_elapsed(struct dt_evt *);
const char		*builtin_arg(struct dt_evt *, enum bt_argtype);
struct bt_arg		*fn_str(struct bt_arg *, struct dt_evt *, char *);
uint16_t		 ba2strargs(struct bt_arg *);
uint16_t		 rules_strargs_scan(struct bt_stmt *);
uint16_t		 ba_strlen(struct bt_arg *);
uint16_t		 rules_strlen_scan(struct bt_stmt *);
static int		 ctf_deref_field(uint16_t, const char *,
			     uint32_t *, uint16_t *, uint16_t *);
int			 ctf_resolve_deref(const char *, int, const char *,
			     uint32_t *, uint16_t *, uint16_t *);
static int		 ctf_subscript_stride(uint16_t, uint16_t *, uint32_t *);
static int		 fill_deref_node(struct bt_deref *,
			     struct dtioc_probe_info *, struct dtioc_req *);
static int		 fill_subscript_node(struct bt_subscript *,
			     struct dtioc_probe_info *, struct dtioc_req *);
void			 ba_fill_deref(struct bt_arg *, struct dtioc_probe_info *,
			     struct dtioc_req *);
void			 fill_memcap(struct bt_stmt *, struct dtioc_probe_info *,
			     struct dtioc_req *);
int			 stmt_eval(struct bt_stmt *, struct dt_evt *);
void			 stmt_bucketize(struct bt_stmt *, struct dt_evt *);
void			 stmt_map_bucketize(struct bt_stmt *, struct dt_evt *);
int			 stmt_map_foreach(struct bt_stmt *, struct dt_evt *);
void			 stmt_clear(struct bt_stmt *);
void			 stmt_delete(struct bt_stmt *, struct dt_evt *);
void			 stmt_insert(struct bt_stmt *, struct dt_evt *);
void			 stmt_print(struct bt_stmt *, struct dt_evt *);
void			 stmt_store(struct bt_stmt *, struct dt_evt *);
bool			 stmt_test(struct bt_stmt *, struct dt_evt *);
void			 stmt_time(struct bt_stmt *, struct dt_evt *);
void			 stmt_zero(struct bt_stmt *);
struct bt_arg		*ba_read(struct bt_arg *);
struct bt_arg		*baeval(struct bt_arg *, struct dt_evt *);
const char		*ba2hash(struct bt_arg *, struct dt_evt *);
long			 baexpr2long(struct bt_arg *, struct dt_evt *);
const char		*ba2bucket(struct bt_arg *, struct bt_arg *,
			     struct dt_evt *, long *);
int			 ba2dtflags(struct bt_arg *);

/*
 * Debug routines.
 */
__dead void		 xabort(const char *, ...);
void			 debug(const char *, ...);
void			 debugx(const char *, ...);
void			 debug_dump_term(struct bt_arg *);
void			 debug_dump_expr(struct bt_arg *);
void			 debug_dump_filter(struct bt_rule *);

struct dtioc_probe_info	*dt_dtpis;	/* array of available probes */
size_t			 dt_ndtpi;	/* # of elements in the array */
struct dtioc_arg_info  **dt_args;	/* array of probe arguments */

struct dt_evt		 bt_devt;	/* fake event for BEGIN/END */
#define EVENT_BEGIN	 0
#define EVENT_END	 (unsigned int)(-1)
uint64_t		 bt_filtered;	/* # of events filtered out */

struct syms		*kelf;
ctf_file_t		*ctf_handle;	/* CTF data from /bsd */

#define __PATH_BSD "/bsd"

char			**vargs;
int			 nargs = 0;
int			 verbose = 0;
int			 quiet = 0;
int			 dtfd;
uint64_t		 g_start_nsecs;
volatile sig_atomic_t	 quit_pending;

static void
signal_handler(int sig)
{
	quit_pending = sig;
}


int
main(int argc, char *argv[])
{
	int fd = -1, ch, error = 0;
	const char *filename = NULL, *btscript = NULL;
	int showprobes = 0, noaction = 0;
	size_t btslen = 0;

	setlocale(LC_ALL, "");

	while ((ch = getopt(argc, argv, "e:lnp:qv")) != -1) {
		switch (ch) {
		case 'e':
			btscript = optarg;
			btslen = strlen(btscript);
			break;
		case 'l':
			showprobes = 1;
			break;
		case 'n':
			noaction = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0 && btscript == NULL)
		filename = argv[0];

	 /* Cannot pledge due to special ioctl()s */
	if (unveil(__PATH_DEVDT, "r") == -1)
		err(1, "unveil %s", __PATH_DEVDT);
	if (unveil(_PATH_KSYMS, "r") == -1)
		err(1, "unveil %s", _PATH_KSYMS);
	if (unveil(__PATH_BSD, "r") == -1)
		err(1, "unveil %s", __PATH_BSD);
	if (filename != NULL) {
		if (unveil(filename, "r") == -1)
			err(1, "unveil %s", filename);
	}
	if (unveil(NULL, NULL) == -1)
		err(1, "unveil");

	if (filename != NULL) {
		btscript = read_btfile(filename, &btslen);
		argc--;
		argv++;
	}

	nargs = argc;
	vargs = argv;

	if (btscript == NULL && !showprobes)
		usage();

	if (btscript != NULL) {
		error = btparse(btscript, btslen, filename, 1);
		if (error)
			return error;
	}

	if (noaction)
		return error;

	if (showprobes || g_nprobes > 0) {
		fd = open(__PATH_DEVDT, O_RDONLY);
		if (fd == -1)
			err(1, "could not open %s", __PATH_DEVDT);
		dtfd = fd;
	}

	if (showprobes) {
		dtpi_cache(fd);
		dtpi_print_list(fd);
	}

	if (!TAILQ_EMPTY(&g_rules)) {
		ctf_handle = ctf_open(__PATH_BSD);
		rules_do(fd);
		ctf_close(ctf_handle);
		ctf_handle = NULL;
	}

	if (fd != -1)
		close(fd);

	return error;
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-lnqv] "
	    "programfile | -e program [argument ...]\n", getprogname());
	exit(1);
}

char *
read_btfile(const char *filename, size_t *len)
{
	FILE *fp;
	char *fcontent;
	struct stat st;
	size_t fsize;

	if (stat(filename, &st))
		err(1, "can't stat '%s'", filename);

	fsize = st.st_size;
	fcontent = malloc(fsize + 1);
	if (fcontent == NULL)
		err(1, "malloc");

	fp = fopen(filename, "r");
	if (fp == NULL)
		err(1, "can't open '%s'", filename);

	if (fread(fcontent, 1, fsize, fp) != fsize)
		err(1, "can't read '%s'", filename);
	fcontent[fsize] = '\0';

	fclose(fp);
	*len = fsize;
	return fcontent;
}

void
dtpi_cache(int fd)
{
	struct dtioc_probe dtpr;

	if (dt_dtpis != NULL)
		return;

	memset(&dtpr, 0, sizeof(dtpr));
	if (ioctl(fd, DTIOCGPLIST, &dtpr))
		err(1, "DTIOCGPLIST");

	dt_ndtpi = dtpr.dtpr_size / sizeof(*dt_dtpis);
	dt_dtpis = reallocarray(NULL, dt_ndtpi, sizeof(*dt_dtpis));
	if (dt_dtpis == NULL)
		err(1, NULL);

	dtpr.dtpr_probes = dt_dtpis;
	if (ioctl(fd, DTIOCGPLIST, &dtpr))
		err(1, "DTIOCGPLIST");
}

void
dtai_cache(int fd, struct dtioc_probe_info *dtpi)
{
	struct dtioc_arg dtar;

	if (dt_args == NULL) {
		dt_args = calloc(dt_ndtpi, sizeof(*dt_args));
		if (dt_args == NULL)
			err(1, NULL);
	}

	if (dt_args[dtpi->dtpi_pbn - 1] != NULL)
		return;

	dt_args[dtpi->dtpi_pbn - 1] = reallocarray(NULL, dtpi->dtpi_nargs,
	    sizeof(**dt_args));
	if (dt_args[dtpi->dtpi_pbn - 1] == NULL)
		err(1, NULL);

	dtar.dtar_pbn = dtpi->dtpi_pbn;
	dtar.dtar_size = dtpi->dtpi_nargs * sizeof(**dt_args);
	dtar.dtar_args = dt_args[dtpi->dtpi_pbn - 1];
	if (ioctl(fd, DTIOCGARGS, &dtar))
		err(1, "DTIOCGARGS");
}

void
dtpi_print_list(int fd)
{
	struct dtioc_probe_info *dtpi, *prev = NULL;
	struct dtioc_arg_info *dtai;
	size_t i, j;

	dtpi = dt_dtpis;
	for (i = 0; i < dt_ndtpi; i++, dtpi++) {
		/*
		 * Skip duplicate entries.  kretprobe creates one probe
		 * per ret instruction; only show the function once.
		 */
		if (prev != NULL &&
		    strncmp(prev->dtpi_prov, dtpi->dtpi_prov,
		        DTNAMESIZE) == 0 &&
		    strncmp(prev->dtpi_func, dtpi->dtpi_func,
		        DTNAMESIZE) == 0 &&
		    strncmp(prev->dtpi_name, dtpi->dtpi_name,
		        DTNAMESIZE) == 0) {
			continue;
		}
		prev = dtpi;

		if (dtpi->dtpi_name[0] == '\0')
			printf("%s:%s", dtpi->dtpi_prov, dtpi_func(dtpi));
		else
			printf("%s:%s:%s", dtpi->dtpi_prov, dtpi_func(dtpi),
			    dtpi->dtpi_name);
		if (strncmp(dtpi->dtpi_prov, "tracepoint", DTNAMESIZE) == 0) {
			dtai_cache(fd, dtpi);
			dtai = dt_args[dtpi->dtpi_pbn - 1];
			printf("(");
			for (j = 0; j < dtpi->dtpi_nargs; j++, dtai++) {
				if (j > 0)
					printf(", ");
				printf("%s", dtai->dtai_argtype);
			}
			printf(")");
		}
		printf("\n");
	}
}

const char *
dtpi_func(struct dtioc_probe_info *dtpi)
{
	char *sysnb, func[DTNAMESIZE];
	const char *errstr;
	int idx;

	if (strncmp(dtpi->dtpi_prov, "syscall", DTNAMESIZE))
		return dtpi->dtpi_func;

	/* Translate syscall names */
	strlcpy(func, dtpi->dtpi_func, sizeof(func));
	sysnb = func;
	strsep(&sysnb, "%");
	if (sysnb == NULL)
		return dtpi->dtpi_func;

	idx = strtonum(sysnb, 1, SYS_MAXSYSCALL, &errstr);
	if (errstr != NULL)
		return dtpi->dtpi_func;

	return syscallnames[idx];
}

size_t
dtpi_get_by_pattern(const char *prov, const char *func, const char *name,
    struct dtioc_probe_info **resultp, size_t resultsz)
{
	struct dtioc_probe_info *dtpi;
	size_t i, nmatch = 0;

	dtpi = dt_dtpis;
	for (i = 0; i < dt_ndtpi; i++, dtpi++) {
		if (prov != NULL &&
		    fnmatch(prov, dtpi->dtpi_prov, 0) != 0)
			continue;
		if (func != NULL && name != NULL) {
			if (fnmatch(func, dtpi_func(dtpi), 0) != 0)
				continue;
			if (name[0] != '\0' &&
			    fnmatch(name, dtpi->dtpi_name, 0) != 0)
				continue;
		}

		if (nmatch >= resultsz) {
			resultsz = resultsz ? resultsz * 2 : 64;
			*resultp = reallocarray(*resultp, resultsz,
			    sizeof(**resultp));
			if (*resultp == NULL)
				err(1, "reallocarray");
		}
		(*resultp)[nmatch++] = *dtpi;
	}

	return nmatch;
}

static uint64_t
bp_nsecs_to_unit(struct bt_probe *bp)
{
	static const struct {
		const char *name;
		enum { UNIT_HZ, UNIT_US, UNIT_MS, UNIT_S } id;
	} units[] = {
		{ .name = "hz", .id = UNIT_HZ },
		{ .name = "us", .id = UNIT_US },
		{ .name = "ms", .id = UNIT_MS },
		{ .name = "s", .id = UNIT_S },
	};
	size_t i;

	for (i = 0; i < nitems(units); i++) {
		if (strcmp(units[i].name, bp->bp_unit) == 0) {
			switch (units[i].id) {
			case UNIT_HZ:
				return (1000000000LLU / bp->bp_nsecs);
			case UNIT_US:
				return (bp->bp_nsecs / 1000LLU);
			case UNIT_MS:
				return (bp->bp_nsecs / 1000000LLU);
			case UNIT_S:
				return (bp->bp_nsecs / 1000000000LLU);
			}
		}
	}
	return 0;
}

void
probe_bail(struct bt_probe *bp)
{
	errx(1, "Cannot register multiple probes of the same type: '%s'",
	    probe_name(bp));
}

const char *
probe_name(struct bt_probe *bp)
{
	static char buf[64];

	if (bp->bp_type == B_PT_BEGIN)
		return "BEGIN";

	if (bp->bp_type == B_PT_END)
		return "END";

	assert(bp->bp_type == B_PT_PROBE);

	if (bp->bp_nsecs) {
		snprintf(buf, sizeof(buf), "%s:%s:%llu", bp->bp_prov,
		    bp->bp_unit, bp_nsecs_to_unit(bp));
	} else if (bp->bp_name == NULL || bp->bp_name[0] == '\0') {
		snprintf(buf, sizeof(buf), "%s:%s", bp->bp_prov,
		    bp->bp_func);
	} else {
		snprintf(buf, sizeof(buf), "%s:%s:%s", bp->bp_prov,
		    bp->bp_func, bp->bp_name);
	}

	return buf;
}

void
rules_do(int fd)
{
	struct sigaction sa;
	int halt = 0;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sa, NULL))
		err(1, "sigaction");
	if (sigaction(SIGTERM, &sa, NULL))
		err(1, "sigaction");

	halt = rules_setup(fd);
	g_start_nsecs = builtin_nsecs(NULL);

	if (!quiet && g_nprobes > 0)
		fprintf(stderr, "Attaching %d probe%s...\n",
		    g_nprobes, g_nprobes > 1 ? "s" : "");

	while (!quit_pending && !halt && g_nprobes > 0) {
		static struct dt_evt devtbuf[1024];
		ssize_t rlen;
		size_t i;

		rlen = read(fd, devtbuf, sizeof(devtbuf));
		if (rlen == -1) {
			if (errno == EINTR && quit_pending) {
				printf("\n");
				break;
			}
			err(1, "read");
		}

		if ((rlen % sizeof(struct dt_evt)) != 0)
			err(1, "incorrect read");

		for (i = 0; i < rlen / sizeof(struct dt_evt); i++) {
			halt = rules_apply(fd, &devtbuf[i]);
			if (halt)
				break;
		}
	}

	rules_teardown(fd);

	if (verbose && fd != -1) {
		struct dtioc_stat dtst;

		memset(&dtst, 0, sizeof(dtst));
		if (ioctl(fd, DTIOCGSTATS, &dtst))
			warn("DTIOCGSTATS");

		fprintf(stderr, "%llu events read\n", dtst.dtst_readevt);
		fprintf(stderr, "%llu events dropped\n", dtst.dtst_dropevt);
		fprintf(stderr, "%llu events filtered\n", bt_filtered);
		fprintf(stderr, "%llu clock ticks skipped\n",
			dtst.dtst_skiptick);
		fprintf(stderr, "%llu recursive events dropped\n",
			dtst.dtst_recurevt);
	}
}

static uint64_t
rules_action_scan(struct bt_stmt *bs)
{
	struct bt_arg *ba;
	struct bt_cond *bc;
	uint64_t evtflags = 0;

	while (bs != NULL) {
		SLIST_FOREACH(ba, &bs->bs_args, ba_next)
			evtflags |= ba2dtflags(ba);

		/* Also check the value for map/hist insertion */
		switch (bs->bs_act) {
		case B_AC_BUCKETIZE:
		case B_AC_INSERT:
		case B_AC_MAPHIST:
			ba = (struct bt_arg *)bs->bs_var;
			evtflags |= ba2dtflags(ba);
			break;
		case B_AC_TEST:
			bc = (struct bt_cond *)bs->bs_var;
			if (bc != NULL) {
				evtflags |= rules_action_scan(bc->bc_condbs);
				evtflags |= rules_action_scan(bc->bc_elsebs);
			}
			break;
		case B_AC_FORMAP: {
			struct bt_for *bfor = (struct bt_for *)bs->bs_var;
			if (bfor != NULL)
				evtflags |= rules_action_scan(bfor->bfor_body);
			break;
		}
		case B_AC_WHILE: {
			struct bt_while *bwh = (struct bt_while *)bs->bs_var;
			if (bwh != NULL)
				evtflags |= rules_action_scan(bwh->bwh_body);
			break;
		}
		default:
			break;
		}

		bs = SLIST_NEXT(bs, bs_next);
	}

	return evtflags;
}

/*
 * Scan a bt_arg tree for str(argN) calls and return a bitmask of which
 * arg indices (0..DTMAXFUNCARGS-1) need to be captured as strings.
 */
uint16_t
ba2strargs(struct bt_arg *ba)
{
	uint16_t mask = 0;
	struct bt_arg *inner;

	do {
		switch (ba->ba_type) {
		case B_AT_FN_STR:
			inner = (struct bt_arg *)ba->ba_value;
			if (inner != NULL &&
			    inner->ba_type >= B_AT_BI_ARG0 &&
			    inner->ba_type <= B_AT_BI_ARG9)
				mask |= (1u << (inner->ba_type - B_AT_BI_ARG0));
			break;
		case B_AT_MAP:
			if (ba->ba_key != NULL)
				mask |= ba2strargs(ba->ba_key);
			break;
		case B_AT_TUPLE:
			if (ba->ba_value != NULL)
				mask |= ba2strargs(ba->ba_value);
			break;
		case B_AT_OP_PLUS ... B_AT_OP_SHR:
			if (ba->ba_value != NULL)
				mask |= ba2strargs(ba->ba_value);
			break;
		case B_AT_OP_TERN: {
			struct bt_ternary *btr = ba->ba_value;
			mask |= ba2strargs(btr->btr_cond);
			mask |= ba2strargs(btr->btr_then);
			mask |= ba2strargs(btr->btr_else);
			break;
		}
		default:
			break;
		}
	} while ((ba = SLIST_NEXT(ba, ba_next)) != NULL);

	return mask;
}

uint16_t
rules_strargs_scan(struct bt_stmt *bs)
{
	struct bt_arg *ba;
	struct bt_cond *bc;
	uint16_t mask = 0;

	while (bs != NULL) {
		SLIST_FOREACH(ba, &bs->bs_args, ba_next)
			mask |= ba2strargs(ba);

		switch (bs->bs_act) {
		case B_AC_BUCKETIZE:
		case B_AC_INSERT:
		case B_AC_MAPHIST:
			ba = (struct bt_arg *)bs->bs_var;
			mask |= ba2strargs(ba);
			break;
		case B_AC_TEST:
			bc = (struct bt_cond *)bs->bs_var;
			if (bc != NULL) {
				mask |= rules_strargs_scan(bc->bc_condbs);
				mask |= rules_strargs_scan(bc->bc_elsebs);
			}
			break;
		case B_AC_FORMAP: {
			struct bt_for *bfor = (struct bt_for *)bs->bs_var;
			if (bfor != NULL)
				mask |= rules_strargs_scan(bfor->bfor_body);
			break;
		}
		case B_AC_WHILE: {
			struct bt_while *bwh = (struct bt_while *)bs->bs_var;
			if (bwh != NULL)
				mask |= rules_strargs_scan(bwh->bwh_body);
			break;
		}
		default:
			break;
		}

		bs = SLIST_NEXT(bs, bs_next);
	}

	return mask;
}

/*
 * Return the maximum str(argN) capture length needed from a bt_arg tree.
 * A str(argN) with no explicit length contributes STRLEN.
 * Returns 0 if no str(argN) calls are found.
 */
uint16_t
ba_strlen(struct bt_arg *ba)
{
	uint16_t maxlen = 0, l;
	struct bt_arg *inner, *lenarg;

	do {
		switch (ba->ba_type) {
		case B_AT_FN_STR:
			inner = (struct bt_arg *)ba->ba_value;
			if (inner == NULL)
				break;
			lenarg = SLIST_NEXT(inner, ba_next);
			if (lenarg == NULL) {
				/* No explicit length: use default STRLEN. */
				l = STRLEN;
			} else if (lenarg->ba_type == B_AT_LONG) {
				long v = (long)lenarg->ba_value;
				l = (v > 0 && v < UINT16_MAX) ? (uint16_t)v :
				    STRLEN;
			} else {
				/* Non-constant length; use default STRLEN. */
				l = STRLEN;
			}
			if (l > maxlen)
				maxlen = l;
			break;
		case B_AT_MAP:
			if (ba->ba_key != NULL) {
				l = ba_strlen(ba->ba_key);
				if (l > maxlen)
					maxlen = l;
			}
			break;
		case B_AT_TUPLE:
			if (ba->ba_value != NULL) {
				l = ba_strlen((struct bt_arg *)ba->ba_value);
				if (l > maxlen)
					maxlen = l;
			}
			break;
		case B_AT_OP_PLUS ... B_AT_OP_SHR:
			if (ba->ba_value != NULL) {
				l = ba_strlen((struct bt_arg *)ba->ba_value);
				if (l > maxlen)
					maxlen = l;
			}
			break;
		case B_AT_OP_TERN: {
			struct bt_ternary *btr = ba->ba_value;
			l = ba_strlen(btr->btr_then);
			if (l > maxlen) maxlen = l;
			l = ba_strlen(btr->btr_else);
			if (l > maxlen) maxlen = l;
			break;
		}
		default:
			break;
		}
	} while ((ba = SLIST_NEXT(ba, ba_next)) != NULL);

	return maxlen;
}

uint16_t
rules_strlen_scan(struct bt_stmt *bs)
{
	struct bt_arg *ba;
	struct bt_cond *bc;
	uint16_t maxlen = 0, l;

	while (bs != NULL) {
		SLIST_FOREACH(ba, &bs->bs_args, ba_next) {
			l = ba_strlen(ba);
			if (l > maxlen)
				maxlen = l;
		}

		switch (bs->bs_act) {
		case B_AC_BUCKETIZE:
		case B_AC_INSERT:
		case B_AC_MAPHIST:
			ba = (struct bt_arg *)bs->bs_var;
			l = ba_strlen(ba);
			if (l > maxlen)
				maxlen = l;
			break;
		case B_AC_TEST:
			bc = (struct bt_cond *)bs->bs_var;
			if (bc != NULL) {
				l = rules_strlen_scan(bc->bc_condbs);
				if (l > maxlen)
					maxlen = l;
				l = rules_strlen_scan(bc->bc_elsebs);
				if (l > maxlen)
					maxlen = l;
			}
			break;
		case B_AC_FORMAP: {
			struct bt_for *bfor = (struct bt_for *)bs->bs_var;
			if (bfor != NULL) {
				l = rules_strlen_scan(bfor->bfor_body);
				if (l > maxlen)
					maxlen = l;
			}
			break;
		}
		case B_AC_WHILE: {
			struct bt_while *bwh = (struct bt_while *)bs->bs_var;
			if (bwh != NULL) {
				l = rules_strlen_scan(bwh->bwh_body);
				if (l > maxlen)
					maxlen = l;
			}
			break;
		}
		default:
			break;
		}

		bs = SLIST_NEXT(bs, bs_next);
	}

	return maxlen;
}

int
rules_setup(int fd)
{
	struct dtioc_probe_info *dtpi;
	struct dtioc_req *dtrq;
	struct bt_rule *r, *rbegin = NULL, *rend = NULL;
	struct bt_probe *bp;
	struct bt_stmt *bs;
	struct bt_arg *ba;
	int dokstack = 0, halt = 0, on = 1;
	uint64_t evtflags;
	uint16_t strargs;
	uint16_t strlen;

	TAILQ_FOREACH(r, &g_rules, br_next) {
		evtflags = 0;
		strargs = 0;
		strlen = 0;

		if (r->br_filter != NULL &&
		    r->br_filter->bf_condition != NULL)  {

			bs = r->br_filter->bf_condition;
			ba = SLIST_FIRST(&bs->bs_args);

			evtflags |= ba2dtflags(ba);
			strargs |= ba2strargs(ba);
			strlen = MAXIMUM(strlen, ba_strlen(ba));
		}

		evtflags |= rules_action_scan(SLIST_FIRST(&r->br_action));
		strargs |= rules_strargs_scan(SLIST_FIRST(&r->br_action));
		strlen = MAXIMUM(strlen,
		    rules_strlen_scan(SLIST_FIRST(&r->br_action)));

		SLIST_FOREACH(bp, &r->br_probes, bp_next) {
			debug("parsed probe '%s'", probe_name(bp));
			debug_dump_filter(r);

			if (bp->bp_type != B_PT_PROBE) {
				if (bp->bp_type == B_PT_BEGIN) {
					if (rbegin != NULL)
						probe_bail(bp);
					rbegin = r;
				}
				if (bp->bp_type == B_PT_END) {
					if (rend != NULL)
						probe_bail(bp);
					rend = r;
				}
				continue;
			}

			dtpi_cache(fd);

			{
				struct dtioc_probe_info *matches = NULL;
				struct bt_probe *bpnew, *bpprev;
				size_t j, nmatch;

				nmatch = dtpi_get_by_pattern(bp->bp_prov,
				    bp->bp_func, bp->bp_name, &matches, 0);
				if (nmatch == 0)
					errx(1, "no probes matched '%s'",
					    probe_name(bp));

				debug("probe '%s' matched %zu probes\n",
				    probe_name(bp), nmatch);

				/* Reuse the current bp for the first match */
				dtpi = &matches[0];
				dtrq = calloc(1, sizeof(*dtrq));
				if (dtrq == NULL)
					err(1, "dtrq: calloc");
				bp->bp_pbn = dtpi->dtpi_pbn;
				dtrq->dtrq_pbn = dtpi->dtpi_pbn;
				dtrq->dtrq_nsecs = bp->bp_nsecs;
				dtrq->dtrq_evtflags = evtflags;
				dtrq->dtrq_strargs = strargs;
				dtrq->dtrq_strlen = strlen;
				fill_memcap(SLIST_FIRST(&r->br_action),
				    dtpi, dtrq);
				if (r->br_filter &&
				    r->br_filter->bf_condition)
					fill_memcap(
					    r->br_filter->bf_condition,
					    dtpi, dtrq);
				if (dtrq->dtrq_evtflags & DTEVT_KSTACK)
					dokstack = 1;
				bp->bp_cookie = dtrq;

				/* Create additional probes for remaining matches */
				bpprev = bp;
				for (j = 1; j < nmatch; j++) {
					dtpi = &matches[j];
					bpnew = calloc(1, sizeof(*bpnew));
					if (bpnew == NULL)
						err(1, "bt_probe: calloc");
					bpnew->bp_prov = bp->bp_prov;
					bpnew->bp_func = bp->bp_func;
					bpnew->bp_name = bp->bp_name;
					bpnew->bp_type = bp->bp_type;
					bpnew->bp_nsecs = bp->bp_nsecs;
					bpnew->bp_pbn = dtpi->dtpi_pbn;

					dtrq = calloc(1, sizeof(*dtrq));
					if (dtrq == NULL)
						err(1, "dtrq: calloc");
					dtrq->dtrq_pbn = dtpi->dtpi_pbn;
					dtrq->dtrq_nsecs = bp->bp_nsecs;
					dtrq->dtrq_evtflags = evtflags;
					dtrq->dtrq_strargs = strargs;
					dtrq->dtrq_strlen = strlen;
					fill_memcap(SLIST_FIRST(
					    &r->br_action), dtpi, dtrq);
					if (r->br_filter &&
					    r->br_filter->bf_condition)
						fill_memcap(
						    r->br_filter->bf_condition,
						    dtpi, dtrq);
					if (dtrq->dtrq_evtflags & DTEVT_KSTACK)
						dokstack = 1;
					bpnew->bp_cookie = dtrq;

					SLIST_INSERT_AFTER(bpprev, bpnew,
					    bp_next);
					bpprev = bpnew;
					g_nprobes++;
				}
				/* Skip past newly inserted probes */
				bp = bpprev;
				free(matches);
			}
		}
	}

	if (dokstack)
		kelf = kelf_open_kernel(_PATH_KSYMS);

	/* Initialize "fake" event for BEGIN/END */
	bt_devt.dtev_pbn = EVENT_BEGIN;
	strlcpy(bt_devt.dtev_comm, getprogname(), sizeof(bt_devt.dtev_comm));
	bt_devt.dtev_pid = getpid();
	bt_devt.dtev_tid = getthrid();
	clock_gettime(CLOCK_REALTIME, &bt_devt.dtev_tsp);

	if (rbegin)
		halt = rule_eval(rbegin, &bt_devt);

	/* Enable all probes */
	TAILQ_FOREACH(r, &g_rules, br_next) {
		SLIST_FOREACH(bp, &r->br_probes, bp_next) {
			if (bp->bp_type != B_PT_PROBE)
				continue;

			dtrq = bp->bp_cookie;
			if (ioctl(fd, DTIOCPRBENABLE, dtrq)) {
				if (errno == EEXIST)
					probe_bail(bp);
				err(1, "DTIOCPRBENABLE");
			}
		}
	}

	if (g_nprobes > 0) {
		if (ioctl(fd, DTIOCRECORD, &on))
			err(1, "DTIOCRECORD");
	}

	return halt;
}

/*
 * Returns non-zero if the program should halt.
 */
int
rules_apply(int fd, struct dt_evt *dtev)
{
	struct bt_rule *r;
	struct bt_probe *bp;

	TAILQ_FOREACH(r, &g_rules, br_next) {
		SLIST_FOREACH(bp, &r->br_probes, bp_next) {
			if (bp->bp_type != B_PT_PROBE ||
			    bp->bp_pbn != dtev->dtev_pbn)
				continue;

			dtai_cache(fd, &dt_dtpis[dtev->dtev_pbn - 1]);
			if (rule_eval(r, dtev))
				return 1;
		}
	}
	return 0;
}

void
rules_teardown(int fd)
{
	struct dtioc_req *dtrq;
	struct bt_probe *bp;
	struct bt_rule *r, *rend = NULL;
	int dokstack = 0, off = 0;

	if (g_nprobes > 0) {
		if (ioctl(fd, DTIOCRECORD, &off))
			err(1, "DTIOCRECORD");
	}

	TAILQ_FOREACH(r, &g_rules, br_next) {
		SLIST_FOREACH(bp, &r->br_probes, bp_next) {
			if (bp->bp_type != B_PT_PROBE) {
				if (bp->bp_type == B_PT_END)
					rend = r;
				continue;
			}

			dtrq = bp->bp_cookie;
			if (ioctl(fd, DTIOCPRBDISABLE, dtrq))
				err(1, "DTIOCPRBDISABLE");
			if (dtrq->dtrq_evtflags & DTEVT_KSTACK)
				dokstack = 1;
		}
	}

	kelf_close(kelf);

	/* Update "fake" event for BEGIN/END */
	bt_devt.dtev_pbn = EVENT_END;
	clock_gettime(CLOCK_REALTIME, &bt_devt.dtev_tsp);

	if (rend)
		rule_eval(rend, &bt_devt);

	/* Print non-empty map & hist */
	TAILQ_FOREACH(r, &g_rules, br_next)
		rule_printmaps(r);
}

/*
 * Returns non-zero if the program should halt.
 */
int
rule_eval(struct bt_rule *r, struct dt_evt *dtev)
{
	struct bt_stmt *bs;
	struct bt_probe *bp;

	SLIST_FOREACH(bp, &r->br_probes, bp_next) {
		debug("eval rule '%s'", probe_name(bp));
		debug_dump_filter(r);
	}

	if (r->br_filter != NULL && r->br_filter->bf_condition != NULL) {
		if (stmt_test(r->br_filter->bf_condition, dtev) == false) {
			bt_filtered++;
			return 0;
		}
	}

	SLIST_FOREACH(bs, &r->br_action, bs_next) {
		int rc = stmt_eval(bs, dtev);
		if (rc == STMT_EXIT)
			return 1;
		if (rc != STMT_NORMAL)
			break;	/* break/continue outside a loop: stop action */
	}

	return 0;
}

void
rule_printmaps(struct bt_rule *r)
{
	struct bt_stmt *bs;

	SLIST_FOREACH(bs, &r->br_action, bs_next) {
		struct bt_arg *ba;

		SLIST_FOREACH(ba, &bs->bs_args, ba_next) {
			struct bt_var *bv;
			struct map *map;

			if (ba->ba_type != B_AT_MAP && ba->ba_type != B_AT_HIST)
				continue;
			/* B_AT_HIST sentinel used by B_AC_MAPHIST has NULL value */
			if (ba->ba_value == NULL)
				continue;

			bv = ba->ba_value;
			map = (struct map *)bv->bv_value;
			if (map == NULL)
				continue;

			/* Skip maps already printed with print(). */
			if (bv->bv_printed)
				continue;

			if (bv->bv_type == B_VT_MAPHIST)
				map_hist_print(map, bv_name(bv));
			else if (ba->ba_type == B_AT_MAP)
				map_print(map, SIZE_T_MAX, bv_name(bv));
			else
				hist_print((struct hist *)map, bv_name(bv));
			map_clear(map);
			bv->bv_value = NULL;
		}
	}
}

time_t
builtin_gettime(struct dt_evt *dtev)
{
	struct timespec ts;

	if (dtev == NULL) {
		clock_gettime(CLOCK_REALTIME, &ts);
		return ts.tv_sec;
	}

	return dtev->dtev_tsp.tv_sec;
}

static inline uint64_t
TIMESPEC_TO_NSEC(struct timespec *ts)
{
	return (ts->tv_sec * 1000000000L + ts->tv_nsec);
}

uint64_t
builtin_nsecs(struct dt_evt *dtev)
{
	struct timespec ts;

	if (dtev == NULL) {
		clock_gettime(CLOCK_REALTIME, &ts);
		return TIMESPEC_TO_NSEC(&ts);
	}

	return TIMESPEC_TO_NSEC(&dtev->dtev_tsp);
}

uint64_t
builtin_elapsed(struct dt_evt *dtev)
{
	return builtin_nsecs(dtev) - g_start_nsecs;
}

const char *
builtin_stack(struct dt_evt *dtev, int kernel)
{
	struct stacktrace *st = &dtev->dtev_kstack;
	static char buf[4096];
	const char *last = "\nkernel\n";
	char *bp;
	size_t i;
	int sz;

	if (!kernel) {
		st = &dtev->dtev_ustack;
		last = "\nuserland\n";
	} else if (st->st_count == 0) {
		return "\nuserland\n";
	}

	buf[0] = '\0';
	bp = buf;
	sz = sizeof(buf);
	for (i = 0; i < st->st_count; i++) {
		int l;

		if (!kernel)
			l = kelf_snprintsym_proc(dtfd, dtev->dtev_pid, bp, sz - 1,
			    st->st_pc[i]);
		else
			l = kelf_snprintsym_kernel(kelf, bp, sz - 1,
			    st->st_pc[i]);
		if (l < 0)
			break;
		if (l >= sz - 1) {
			bp += sz - 1;
			sz = 1;
			break;
		}
		bp += l;
		sz -= l;
	}
	snprintf(bp, sz, "%s", last);

	return buf;
}

/*
 * Format a register_t value based on its CTF type.  Resolves through
 * typedefs, qualifiers, and displays pointers, enums, and integers
 * with appropriate formatting.
 */
static const char *
ctf_format_arg(ctf_file_t *cf, uint16_t typeid, long val)
{
	static char buf[128];
	const char *name, *modif;
	uint16_t kind, ref;
	uint32_t enc;
	int depth = 0;

	/* Resolve typedefs and qualifiers */
	while (depth++ < 16) {
		kind = ctf_type_kind(cf, typeid);

		switch (kind) {
		case CTF_K_TYPEDEF:
		case CTF_K_VOLATILE:
		case CTF_K_CONST:
		case CTF_K_RESTRICT:
			typeid = ctf_type_reference(cf, typeid);
			if (typeid == 0)
				goto fallback;
			continue;
		default:
			break;
		}
		break;
	}

	switch (kind) {
	case CTF_K_INTEGER:
		enc = ctf_type_encoding(cf, typeid);
		if (CTF_INT_ENCODING(enc) & CTF_INT_SIGNED) {
			if (CTF_INT_ENCODING(enc) & CTF_INT_CHAR) {
				snprintf(buf, sizeof(buf), "'%c'", (char)val);
			} else {
				snprintf(buf, sizeof(buf), "%ld", val);
			}
		} else {
			if ((unsigned long)val > 4096)
				snprintf(buf, sizeof(buf), "0x%lx", val);
			else
				snprintf(buf, sizeof(buf), "%lu",
				    (unsigned long)val);
		}
		return buf;

	case CTF_K_POINTER:
		ref = ctf_type_reference(cf, typeid);
		if (ref != 0) {
			uint16_t refkind;

			modif = "";
			refkind = ctf_type_kind(cf, ref);
			switch (refkind) {
			case CTF_K_STRUCT:
				modif = "struct ";
				break;
			case CTF_K_UNION:
				modif = "union ";
				break;
			case CTF_K_VOLATILE:
				modif = "volatile ";
				ref = ctf_type_reference(cf, ref);
				break;
			case CTF_K_CONST:
				modif = "const ";
				ref = ctf_type_reference(cf, ref);
				break;
			default:
				break;
			}
			name = ctf_type_name(cf, ref);
			if (name != NULL) {
				snprintf(buf, sizeof(buf), "(%s%s *)0x%lx",
				    modif, name, val);
				return buf;
			}
		}
		snprintf(buf, sizeof(buf), "0x%lx", val);
		return buf;

	case CTF_K_ENUM:
		name = ctf_enum_name(cf, typeid, (int)val);
		if (name != NULL) {
			snprintf(buf, sizeof(buf), "%s", name);
			return buf;
		}
		snprintf(buf, sizeof(buf), "%d", (int)val);
		return buf;

	default:
		break;
	}

fallback:
	snprintf(buf, sizeof(buf), "0x%lx", val);
	return buf;
}

const char *
builtin_arg(struct dt_evt *dtev, enum bt_argtype dat)
{
	static char buf[sizeof("18446744073709551615")]; /* UINT64_MAX */
	struct dtioc_probe_info *dtpi;
	struct dtioc_arg_info *dtai;
	const char *argtype;
	unsigned int argn;

	argn = dat - B_AT_BI_ARG0;
	dtpi = &dt_dtpis[dtev->dtev_pbn - 1];
	if (dtpi == NULL || argn >= dtpi->dtpi_nargs)
		return "0";

	/* Try CTF-based type-aware formatting */
	if (ctf_handle != NULL) {
		uint16_t argtypes[DTMAXFUNCARGS];
		uint16_t ret_type;
		int nargs;

		nargs = ctf_func_info(ctf_handle, dtpi->dtpi_func,
		    &ret_type, argtypes, DTMAXFUNCARGS);
		if (nargs > 0 && argn < (unsigned int)nargs)
			return ctf_format_arg(ctf_handle, argtypes[argn],
			    dtev->dtev_args[argn]);
	}

	/* Fallback: use kernel-provided type name string */
	dtai = dt_args[dtev->dtev_pbn - 1];
	argtype = dtai[argn].dtai_argtype;

	if (strncmp(argtype, "int", DTNAMESIZE) == 0)
		snprintf(buf, sizeof(buf), "%d",
		    (int)dtev->dtev_args[argn]);
	else
		snprintf(buf, sizeof(buf), "%lu",
		    (unsigned long)dtev->dtev_args[argn]);

	return buf;
}

/*
 * CTF member iterator callback for ctf_resolve_deref().
 * Stops at the first member whose name matches info->field.
 */
struct deref_info {
	const char	*field;
	uint32_t	 offset;	/* byte offset of member */
	uint16_t	 size;		/* size of member type in bytes */
	uint16_t	 typeid;	/* CTF type ID of member (for chaining) */
	int		 found;
};

static int
deref_member_cb(const char *name, uint16_t typeid, unsigned long offset_bits,
    void *arg)
{
	struct deref_info *info = arg;
	ssize_t sz;

	if (strcmp(name, info->field) != 0)
		return 0;

	info->offset = (uint32_t)(offset_bits / 8);
	sz = ctf_type_size(ctf_handle, typeid);
	if (sz <= 0 || sz > (ssize_t)sizeof(uint64_t))
		sz = sizeof(uint64_t);
	info->size = (uint16_t)sz;
	info->typeid = typeid;
	info->found = 1;
	return 1;	/* stop iteration */
}

/*
 * Resolve the byte offset and size of `field' in the struct pointed to
 * by the pointer type `ptr_typeid'.  Optionally returns the CTF type ID
 * of the field in `*field_typeidp' for use in chained dereferences.
 * Returns 0 on success, -1 if CTF data is unavailable or resolution fails.
 */
static int
ctf_deref_field(uint16_t ptr_typeid, const char *field,
    uint32_t *offsetp, uint16_t *sizep, uint16_t *field_typeidp)
{
	uint16_t typeid = ptr_typeid, ref;
	uint16_t kind;
	struct deref_info info;
	int depth;

	if (ctf_handle == NULL)
		return -1;

	/* Resolve typedefs and qualifiers to get the pointer kind. */
	for (depth = 0; depth < 16; depth++) {
		kind = ctf_type_kind(ctf_handle, typeid);
		switch (kind) {
		case CTF_K_TYPEDEF:
		case CTF_K_VOLATILE:
		case CTF_K_CONST:
		case CTF_K_RESTRICT:
			typeid = ctf_type_reference(ctf_handle, typeid);
			if (typeid == 0)
				return -1;
			continue;
		default:
			break;
		}
		break;
	}

	if (kind != CTF_K_POINTER)
		return -1;

	/* Dereference the pointer to get the pointed-to type. */
	ref = ctf_type_reference(ctf_handle, typeid);
	if (ref == 0)
		return -1;

	/* Resolve typedefs in the pointed-to type. */
	for (depth = 0; depth < 16; depth++) {
		kind = ctf_type_kind(ctf_handle, ref);
		switch (kind) {
		case CTF_K_TYPEDEF:
		case CTF_K_VOLATILE:
		case CTF_K_CONST:
		case CTF_K_RESTRICT:
			ref = ctf_type_reference(ctf_handle, ref);
			if (ref == 0)
				return -1;
			continue;
		default:
			break;
		}
		break;
	}

	if (kind != CTF_K_STRUCT && kind != CTF_K_UNION)
		return -1;

	memset(&info, 0, sizeof(info));
	info.field = field;
	ctf_member_iter(ctf_handle, ref, deref_member_cb, &info);
	if (!info.found)
		return -1;

	*offsetp = info.offset;
	*sizep = info.size;
	if (field_typeidp != NULL)
		*field_typeidp = info.typeid;
	return 0;
}

/*
 * Using CTF, resolve the byte offset and size of `field' in the struct
 * pointed to by argument `argn' of kernel function `funcname'.
 * Optionally returns the CTF type ID of the resolved field in `*field_typeidp'
 * for use in chained dereferences.
 * Returns 0 on success, -1 if CTF is unavailable or resolution fails.
 */
int
ctf_resolve_deref(const char *funcname, int argn, const char *field,
    uint32_t *offsetp, uint16_t *sizep, uint16_t *field_typeidp)
{
	uint16_t argtypes[DTMAXFUNCARGS];
	uint16_t ret_type;
	int nargs;

	if (ctf_handle == NULL)
		return -1;

	nargs = ctf_func_info(ctf_handle, funcname, &ret_type, argtypes,
	    DTMAXFUNCARGS);
	if (nargs <= 0 || argn >= nargs)
		return -1;

	return ctf_deref_field(argtypes[argn], field, offsetp, sizep,
	    field_typeidp);
}

/*
 * Resolve CTF type info for a single B_AT_FN_DEREF node and assign it a
 * capture slot in dtrq.  For chained dereferences (bd_base is itself a
 * B_AT_FN_DEREF), the inner node is processed first so its slot is known.
 * Returns the assigned slot index on success, -1 on failure.
 */
static int
fill_deref_node(struct bt_deref *bd, struct dtioc_probe_info *dtpi,
    struct dtioc_req *dtrq)
{
	uint32_t offset;
	uint16_t size;
	uint8_t slot;

	if (dtrq->dtrq_nmemcap >= DTMAXMEMCAPS) {
		if (verbose)
			warnx("too many struct dereferences for probe %s",
			    dtpi->dtpi_func);
		return -1;
	}

	if (bd->bd_base->ba_type == B_AT_FN_DEREF) {
		/* Chained: resolve the inner node first to get its typeid. */
		struct bt_deref *bd_inner = bd->bd_base->ba_value;
		int inner_slot;

		inner_slot = fill_deref_node(bd_inner, dtpi, dtrq);
		if (inner_slot < 0)
			return -1;
		if (bd_inner->bd_typeid == 0)
			return -1;
		if (ctf_deref_field(bd_inner->bd_typeid, bd->bd_field,
		    &offset, &size, &bd->bd_typeid) != 0) {
			if (verbose)
				warnx("cannot resolve '%s->%s' for probe %s",
				    ba_name(bd->bd_base), bd->bd_field,
				    dtpi->dtpi_func);
			return -1;
		}
		slot = dtrq->dtrq_nmemcap++;
		dtrq->dtrq_memcap[slot].dtrmc_argn = (uint8_t)inner_slot;
		dtrq->dtrq_memcap[slot].dtrmc_flags = DTMC_FL_MEMBASE;
		dtrq->dtrq_memcap[slot].dtrmc_offset = (int32_t)offset;
		dtrq->dtrq_memcap[slot].dtrmc_size = size;
	} else if (bd->bd_base->ba_type == B_AT_FN_SUBSCRIPT) {
		/* Base is a subscript: use its element typeid. */
		struct bt_subscript *bss_inner = bd->bd_base->ba_value;
		int inner_slot;

		inner_slot = fill_subscript_node(bss_inner, dtpi, dtrq);
		if (inner_slot < 0 || bss_inner->bss_typeid == 0)
			return -1;
		if (ctf_deref_field(bss_inner->bss_typeid, bd->bd_field,
		    &offset, &size, &bd->bd_typeid) != 0) {
			if (verbose)
				warnx("cannot resolve '%s->%s' for probe %s",
				    ba_name(bd->bd_base), bd->bd_field,
				    dtpi->dtpi_func);
			return -1;
		}
		slot = dtrq->dtrq_nmemcap++;
		dtrq->dtrq_memcap[slot].dtrmc_argn = (uint8_t)inner_slot;
		dtrq->dtrq_memcap[slot].dtrmc_flags = DTMC_FL_MEMBASE;
		dtrq->dtrq_memcap[slot].dtrmc_offset = (int32_t)offset;
		dtrq->dtrq_memcap[slot].dtrmc_size = size;
	} else {
		/* Direct: base is an argN builtin. */
		int argn = bd->bd_base->ba_type - B_AT_BI_ARG0;

		if (ctf_resolve_deref(dtpi->dtpi_func, argn, bd->bd_field,
		    &offset, &size, &bd->bd_typeid) != 0) {
			if (verbose)
				warnx("cannot resolve '%s->%s' for probe %s",
				    ba_name(bd->bd_base), bd->bd_field,
				    dtpi->dtpi_func);
			return -1;
		}
		slot = dtrq->dtrq_nmemcap++;
		dtrq->dtrq_memcap[slot].dtrmc_argn = (uint8_t)argn;
		dtrq->dtrq_memcap[slot].dtrmc_flags = 0;
		dtrq->dtrq_memcap[slot].dtrmc_offset = (int32_t)offset;
		dtrq->dtrq_memcap[slot].dtrmc_size = size;
	}

	dtrq->dtrq_evtflags |= DTEVT_MEMARGS;
	bd->bd_offset = offset;
	bd->bd_size = size;
	bd->bd_slot = slot;
	return slot;
}

/*
 * Using CTF, resolve the element type and stride of a pointer type.
 * ptr_typeid must resolve to CTF_K_POINTER after qualifier stripping.
 * Sets *elem_typeidp to the pointed-to type ID and *stridep to its size.
 * Returns 0 on success, -1 if CTF is unavailable or type is not a pointer.
 */
static int
ctf_subscript_stride(uint16_t ptr_typeid, uint16_t *elem_typeidp,
    uint32_t *stridep)
{
	uint16_t typeid = ptr_typeid, kind, ref;
	ssize_t sz;
	int depth;

	if (ctf_handle == NULL)
		return -1;

	/* Strip typedefs and qualifiers to reach the pointer kind. */
	for (depth = 0; depth < 16; depth++) {
		kind = ctf_type_kind(ctf_handle, typeid);
		switch (kind) {
		case CTF_K_TYPEDEF:
		case CTF_K_VOLATILE:
		case CTF_K_CONST:
		case CTF_K_RESTRICT:
			typeid = ctf_type_reference(ctf_handle, typeid);
			if (typeid == 0)
				return -1;
			continue;
		default:
			break;
		}
		break;
	}

	if (kind != CTF_K_POINTER)
		return -1;

	ref = ctf_type_reference(ctf_handle, typeid);
	if (ref == 0)
		return -1;

	sz = ctf_type_size(ctf_handle, ref);
	if (sz <= 0)
		sz = (ssize_t)sizeof(uint64_t);

	*elem_typeidp = ref;
	*stridep = (uint32_t)sz;
	return 0;
}

/*
 * Resolve CTF type info for a single B_AT_FN_SUBSCRIPT node and assign it a
 * capture slot in dtrq.  The base may be an argN builtin, a B_AT_FN_DEREF
 * node, or a B_AT_FN_SUBSCRIPT node (for chained subscripts).
 * Returns the assigned slot index on success, -1 on failure.
 */
static int
fill_subscript_node(struct bt_subscript *bss, struct dtioc_probe_info *dtpi,
    struct dtioc_req *dtrq)
{
	uint16_t elem_typeid;
	uint32_t stride;
	uint8_t slot;

	if (dtrq->dtrq_nmemcap >= DTMAXMEMCAPS) {
		if (verbose)
			warnx("too many captures for probe %s",
			    dtpi->dtpi_func);
		return -1;
	}

	if (bss->bss_base->ba_type == B_AT_FN_DEREF) {
		struct bt_deref *bd_inner = bss->bss_base->ba_value;
		int inner_slot = fill_deref_node(bd_inner, dtpi, dtrq);

		if (inner_slot < 0 || bd_inner->bd_typeid == 0)
			return -1;
		if (ctf_subscript_stride(bd_inner->bd_typeid, &elem_typeid,
		    &stride) != 0) {
			if (verbose)
				warnx("cannot subscript '%s' for probe %s",
				    ba_name(bss->bss_base), dtpi->dtpi_func);
			return -1;
		}
		slot = dtrq->dtrq_nmemcap++;
		dtrq->dtrq_memcap[slot].dtrmc_argn = (uint8_t)inner_slot;
		dtrq->dtrq_memcap[slot].dtrmc_flags = DTMC_FL_MEMBASE;
		dtrq->dtrq_memcap[slot].dtrmc_offset =
		    (int32_t)(bss->bss_index * (long)stride);
		dtrq->dtrq_memcap[slot].dtrmc_size =
		    (uint16_t)MINIMUM(stride, sizeof(uint64_t));
	} else if (bss->bss_base->ba_type == B_AT_FN_SUBSCRIPT) {
		struct bt_subscript *bss_inner = bss->bss_base->ba_value;
		int inner_slot = fill_subscript_node(bss_inner, dtpi, dtrq);

		if (inner_slot < 0 || bss_inner->bss_typeid == 0)
			return -1;
		if (ctf_subscript_stride(bss_inner->bss_typeid, &elem_typeid,
		    &stride) != 0) {
			if (verbose)
				warnx("cannot subscript '%s' for probe %s",
				    ba_name(bss->bss_base), dtpi->dtpi_func);
			return -1;
		}
		slot = dtrq->dtrq_nmemcap++;
		dtrq->dtrq_memcap[slot].dtrmc_argn = (uint8_t)inner_slot;
		dtrq->dtrq_memcap[slot].dtrmc_flags = DTMC_FL_MEMBASE;
		dtrq->dtrq_memcap[slot].dtrmc_offset =
		    (int32_t)(bss->bss_index * (long)stride);
		dtrq->dtrq_memcap[slot].dtrmc_size =
		    (uint16_t)MINIMUM(stride, sizeof(uint64_t));
	} else {
		/* Direct: base is an argN builtin. */
		int argn = bss->bss_base->ba_type - B_AT_BI_ARG0;
		uint16_t argtypes[DTMAXFUNCARGS];
		uint16_t ret_type;
		int nargs;

		if (ctf_handle == NULL)
			return -1;
		nargs = ctf_func_info(ctf_handle, dtpi->dtpi_func,
		    &ret_type, argtypes, DTMAXFUNCARGS);
		if (nargs <= 0 || argn >= nargs)
			return -1;
		if (ctf_subscript_stride(argtypes[argn], &elem_typeid,
		    &stride) != 0) {
			if (verbose)
				warnx("cannot subscript arg%d for probe %s",
				    argn, dtpi->dtpi_func);
			return -1;
		}
		slot = dtrq->dtrq_nmemcap++;
		dtrq->dtrq_memcap[slot].dtrmc_argn = (uint8_t)argn;
		dtrq->dtrq_memcap[slot].dtrmc_flags = 0;
		dtrq->dtrq_memcap[slot].dtrmc_offset =
		    (int32_t)(bss->bss_index * (long)stride);
		dtrq->dtrq_memcap[slot].dtrmc_size =
		    (uint16_t)MINIMUM(stride, sizeof(uint64_t));
	}

	dtrq->dtrq_evtflags |= DTEVT_MEMARGS;
	bss->bss_stride = stride;
	bss->bss_typeid = elem_typeid;
	bss->bss_slot = slot;
	return slot;
}

/*
 * Walk a bt_arg tree and for each B_AT_FN_DEREF node, resolve the
 * struct field offset/size via CTF and fill in the probe's dtrq_memcap.
 * Also stores resolved offset/size/slot in bt_deref for use at display time.
 */
void
ba_fill_deref(struct bt_arg *ba, struct dtioc_probe_info *dtpi,
    struct dtioc_req *dtrq)
{
	while (ba != NULL) {
		switch (ba->ba_type) {
		case B_AT_FN_DEREF:
			fill_deref_node(ba->ba_value, dtpi, dtrq);
			break;
		case B_AT_FN_SUBSCRIPT:
			fill_subscript_node(ba->ba_value, dtpi, dtrq);
			break;
		case B_AT_MAP:
			if (ba->ba_key != NULL)
				ba_fill_deref(ba->ba_key, dtpi, dtrq);
			break;
		case B_AT_TUPLE:
			if (ba->ba_value != NULL)
				ba_fill_deref(ba->ba_value, dtpi, dtrq);
			break;
		case B_AT_OP_PLUS ... B_AT_OP_SHR:
			if (ba->ba_value != NULL)
				ba_fill_deref(ba->ba_value, dtpi, dtrq);
			break;
		case B_AT_OP_TERN: {
			struct bt_ternary *btr = ba->ba_value;
			ba_fill_deref(btr->btr_cond, dtpi, dtrq);
			ba_fill_deref(btr->btr_then, dtpi, dtrq);
			ba_fill_deref(btr->btr_else, dtpi, dtrq);
			break;
		}
		default:
			break;
		}
		ba = SLIST_NEXT(ba, ba_next);
	}
}

/*
 * Walk a statement list and call ba_fill_deref() on all argument trees,
 * filling in struct member capture specs for each deref node.
 */
void
fill_memcap(struct bt_stmt *bs, struct dtioc_probe_info *dtpi,
    struct dtioc_req *dtrq)
{
	struct bt_arg *ba;
	struct bt_cond *bc;

	while (bs != NULL) {
		SLIST_FOREACH(ba, &bs->bs_args, ba_next)
			ba_fill_deref(ba, dtpi, dtrq);

		switch (bs->bs_act) {
		case B_AC_BUCKETIZE:
		case B_AC_INSERT:
		case B_AC_MAPHIST:
			ba = (struct bt_arg *)bs->bs_var;
			ba_fill_deref(ba, dtpi, dtrq);
			break;
		case B_AC_TEST:
			bc = (struct bt_cond *)bs->bs_var;
			if (bc != NULL) {
				fill_memcap(bc->bc_condbs, dtpi, dtrq);
				fill_memcap(bc->bc_elsebs, dtpi, dtrq);
			}
			break;
		case B_AC_FORMAP: {
			struct bt_for *bfor = (struct bt_for *)bs->bs_var;
			if (bfor != NULL)
				fill_memcap(bfor->bfor_body, dtpi, dtrq);
			break;
		}
		case B_AC_WHILE: {
			struct bt_while *bwh = (struct bt_while *)bs->bs_var;
			if (bwh != NULL)
				fill_memcap(bwh->bwh_body, dtpi, dtrq);
			break;
		}
		default:
			break;
		}
		bs = SLIST_NEXT(bs, bs_next);
	}
}

/*
 * Returns non-zero if the program should halt.
 */
int
stmt_eval(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_stmt *bbs;
	struct bt_cond *bc;
	int halt = 0;

	switch (bs->bs_act) {
	case B_AC_BREAK:
		return STMT_BREAK;
	case B_AC_BUCKETIZE:
		stmt_bucketize(bs, dtev);
		break;
	case B_AC_CONTINUE:
		return STMT_CONT;
	case B_AC_MAPHIST:
		stmt_map_bucketize(bs, dtev);
		break;
	case B_AC_FORMAP:
		return stmt_map_foreach(bs, dtev);
	case B_AC_CLEAR:
		stmt_clear(bs);
		break;
	case B_AC_DELETE:
		stmt_delete(bs, dtev);
		break;
	case B_AC_EXIT:
		halt = 1;
		break;
	case B_AC_INSERT:
		stmt_insert(bs, dtev);
		break;
	case B_AC_PRINT:
		stmt_print(bs, dtev);
		break;
	case B_AC_PRINTF:
		stmt_printf(bs, dtev);
		break;
	case B_AC_STORE:
		stmt_store(bs, dtev);
		break;
	case B_AC_TEST: {
		int rc;

		bc = (struct bt_cond *)bs->bs_var;
		if (stmt_test(bs, dtev) == true)
			bbs = bc->bc_condbs;
		else
			bbs = bc->bc_elsebs;

		while (bbs != NULL) {
			rc = stmt_eval(bbs, dtev);
			if (rc != STMT_NORMAL)
				return rc;
			bbs = SLIST_NEXT(bbs, bs_next);
		}
		break;
	}
	case B_AC_TIME:
		stmt_time(bs, dtev);
		break;
	case B_AC_WHILE: {
		struct bt_while *bwh = (struct bt_while *)bs->bs_var;
		int iters = 0, rc;

		while (stmt_test(bs, dtev)) {
			bbs = bwh->bwh_body;
			while (bbs != NULL) {
				rc = stmt_eval(bbs, dtev);
				if (rc == STMT_EXIT)
					return STMT_EXIT;
				if (rc == STMT_BREAK)
					goto while_done;
				if (rc == STMT_CONT)
					break;	/* restart condition check */
				bbs = SLIST_NEXT(bbs, bs_next);
			}
			if (++iters >= 1024)
				break;
		}
	while_done:
		break;
	}
	case B_AC_ZERO:
		stmt_zero(bs);
		break;
	default:
		xabort("no handler for action type %d", bs->bs_act);
	}
	return halt;
}

/*
 * Increment a bucket:	{ @h = hist(v); } or { @h = lhist(v, min, max, step); }
 *
 * In this case 'h' is represented by `bv' and '(min, max, step)' by `brange'.
 */
void
stmt_bucketize(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_arg *brange, *bhist = SLIST_FIRST(&bs->bs_args);
	struct bt_arg *bval = (struct bt_arg *)bs->bs_var;
	struct bt_var *bv = bhist->ba_value;
	struct hist *hist;
	const char *bucket;
	long step = 0;

	assert(bhist->ba_type == B_AT_HIST);
	assert(SLIST_NEXT(bval, ba_next) == NULL);

	brange = bhist->ba_key;
	bucket = ba2bucket(bval, brange, dtev, &step);
	if (bucket == NULL) {
		debug("hist=%p '%s' value=%lu out of range\n", bv->bv_value,
		    bv_name(bv), ba2long(bval, dtev));
		return;
	}
	debug("hist=%p '%s' increment bucket '%s'\n", bv->bv_value,
	    bv_name(bv), bucket);

	/* hist is NULL before first insert or after clear() */
	hist = (struct hist *)bv->bv_value;
	if (hist == NULL)
		hist = hist_new(step);

	hist_increment(hist, bucket);

	debug("hist=%p '%s' increment bucket=%p '%s' bval=%p\n", hist,
	    bv_name(bv), brange, bucket, bval);

	bv->bv_value = (struct bt_arg *)hist;
	bv->bv_type = B_VT_HIST;
	bv->bv_printed = 0;
}

/*
 * Keyed histogram insert:	{ @map[key] = hist(val); }
 *				{ @map[key] = lhist(val, min, max, step); }
 */
void
stmt_map_bucketize(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_arg *bmap = SLIST_FIRST(&bs->bs_args);
	struct bt_arg *bhist = SLIST_NEXT(bmap, ba_next);
	struct bt_arg *bval = (struct bt_arg *)bs->bs_var;
	struct bt_var *bv = bmap->ba_value;
	struct bt_arg *brange;
	struct map *map;
	const char *mhash, *bucket;
	long step = 0;

	assert(bmap->ba_type == B_AT_MAP);
	assert(bhist->ba_type == B_AT_HIST);
	assert(SLIST_NEXT(bval, ba_next) == NULL);

	brange = bhist->ba_key;
	mhash = ba2hash(bmap->ba_key, dtev);
	bucket = ba2bucket(bval, brange, dtev, &step);
	if (bucket == NULL) {
		debug("maphist '%s'[%s] value=%lu out of range\n",
		    bv_name(bv), mhash, ba2long(bval, dtev));
		return;
	}

	map = (struct map *)bv->bv_value;
	if (map == NULL) {
		map = map_new();
		bv->bv_value = (struct bt_arg *)map;
		bv->bv_type = B_VT_MAPHIST;
		bv->bv_printed = 0;
	}

	map_hist_bucket(map, mhash, bucket, step);
	debug("maphist '%s'[%s] bucket '%s'\n", bv_name(bv), mhash, bucket);
}

/*
 * Callback state for stmt_map_foreach.
 */
struct foreach_state {
	struct bt_for	*fs_bfor;
	struct dt_evt	*fs_dtev;
	struct bt_arg	 fs_key_ba;	/* B_AT_STR: current entry's key */
	struct bt_arg	 fs_tuple_ba;	/* B_AT_TUPLE: (key, value) pair */
	int		 fs_halt;	/* non-zero if body called exit() */
};

static int
foreach_cb(const char *key, struct bt_arg *val, void *arg)
{
	struct foreach_state *st = arg;
	struct bt_stmt *body;

	st->fs_key_ba.ba_value = (void *)key;
	SLIST_NEXT(&st->fs_key_ba, ba_next) = val;

	body = st->fs_bfor->bfor_body;
	while (body != NULL) {
		int rc = stmt_eval(body, st->fs_dtev);
		if (rc == STMT_EXIT) {
			st->fs_halt = STMT_EXIT;
			return 1;	/* stop iteration */
		}
		if (rc == STMT_BREAK)
			return 1;	/* stop iteration; fs_halt stays 0 */
		if (rc == STMT_CONT)
			return 0;	/* skip remaining body; go to next entry */
		body = SLIST_NEXT(body, bs_next);
	}
	return 0;
}

/*
 * For-loop over a map:	{ for ($kv : @map) { } }
 *
 * Binds the loop variable to a (key, value) tuple for each map entry and
 * executes the body.  $kv.0 is the key string; $kv.1 is the stored value.
 * Returns non-zero if a body statement requested a halt (e.g. exit()).
 */
int
stmt_map_foreach(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_for *bfor = (struct bt_for *)bs->bs_var;
	struct bt_arg *mapref = SLIST_FIRST(&bs->bs_args);
	struct bt_var *mapvar = mapref->ba_value;
	struct map *map;
	struct foreach_state st;

	assert(mapref->ba_type == B_AT_VAR);
	assert(bfor != NULL);

	map = (struct map *)mapvar->bv_value;
	if (map == NULL || mapvar->bv_type != B_VT_MAP)
		return 0;

	/*
	 * Build a reusable (key, value) tuple.
	 * fs_key_ba:   B_AT_STR pointing at each entry's key string in turn.
	 * fs_tuple_ba: B_AT_TUPLE with fs_key_ba as the element list head.
	 * foreach_cb updates fs_key_ba.ba_value and ba_next per iteration.
	 */
	st.fs_bfor  = bfor;
	st.fs_dtev  = dtev;
	st.fs_halt  = 0;
	st.fs_key_ba   = (struct bt_arg)BA_INITIALIZER(NULL, B_AT_STR);
	st.fs_tuple_ba = (struct bt_arg)BA_INITIALIZER(&st.fs_key_ba, B_AT_TUPLE);

	bfor->bfor_var->bv_value = &st.fs_tuple_ba;
	bfor->bfor_var->bv_type  = B_VT_TUPLE;

	map_foreach(map, foreach_cb, &st);

	bfor->bfor_var->bv_value = NULL;
	bfor->bfor_var->bv_type  = B_VT_LONG;
	return st.fs_halt;
}

/*
 * Empty a map:		{ clear(@map); }
 */
void
stmt_clear(struct bt_stmt *bs)
{
	struct bt_arg *ba = SLIST_FIRST(&bs->bs_args);
	struct bt_var *bv = ba->ba_value;
	struct map *map;

	assert(bs->bs_var == NULL);
	assert(ba->ba_type == B_AT_VAR);

	if (bv->bv_type == B_VT_LONG || bv->bv_type == B_VT_STR ||
	    bv->bv_type == B_VT_TUPLE) {
		bv->bv_value = NULL;
		debug("var '%s' clear\n", bv_name(bv));
		return;
	}

	map = (struct map *)bv->bv_value;
	if (map == NULL)
		return;

	if (bv->bv_type != B_VT_MAP && bv->bv_type != B_VT_HIST &&
	    bv->bv_type != B_VT_MAPHIST)
		errx(1, "invalid variable type for clear(%s)", ba_name(ba));

	map_clear(map);
	bv->bv_value = NULL;
	bv->bv_printed = 0;

	debug("map=%p '%s' clear\n", map, bv_name(bv));
}

/*
 * Map delete:	 	{ delete(@map[key]); }
 *
 * In this case 'map' is represented by `bv' and 'key' by `bkey'.
 */
void
stmt_delete(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_arg *bkey, *bmap = SLIST_FIRST(&bs->bs_args);
	struct bt_var *bv = bmap->ba_value;
	struct map *map;
	const char *hash;

	assert(bmap->ba_type == B_AT_MAP);
	assert(bs->bs_var == NULL);

	map = (struct map *)bv->bv_value;
	if (map == NULL)
		return;

	bkey = bmap->ba_key;
	hash = ba2hash(bkey, dtev);
	debug("map=%p '%s' delete key=%p '%s'\n", map, bv_name(bv), bkey, hash);

	map_delete(map, hash);
}

/*
 * Map insert:	 	{ @map[key] = 42; }
 *
 * In this case 'map' is represented by `bv', 'key' by `bkey' and
 * '42' by `bval'.
 */
void
stmt_insert(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_arg *bkey, *bmap = SLIST_FIRST(&bs->bs_args);
	struct bt_arg *bval = (struct bt_arg *)bs->bs_var;
	struct bt_var *bv = bmap->ba_value;
	struct map *map;
	const char *hash;
	long val;

	assert(bmap->ba_type == B_AT_MAP);
	assert(SLIST_NEXT(bval, ba_next) == NULL);

	bkey = bmap->ba_key;
	hash = ba2hash(bkey, dtev);

	/* map is NULL before first insert or after clear() */
	map = (struct map *)bv->bv_value;
	if (map == NULL)
		map = map_new();

	/* Operate on existing value for count(), max(), min() and sum(). */
	switch (bval->ba_type) {
	case B_AT_MF_COUNT:
		val = ba2long(map_get(map, hash), NULL);
		val++;
		bval = ba_new(val, B_AT_LONG);
		break;
	case B_AT_MF_MAX:
		val = ba2long(map_get(map, hash), NULL);
		val = MAXIMUM(val, ba2long(bval->ba_value, dtev));
		bval = ba_new(val, B_AT_LONG);
		break;
	case B_AT_MF_MIN:
		val = ba2long(map_get(map, hash), NULL);
		val = MINIMUM(val, ba2long(bval->ba_value, dtev));
		bval = ba_new(val, B_AT_LONG);
		break;
	case B_AT_MF_SUM:
		val = ba2long(map_get(map, hash), NULL);
		val += ba2long(bval->ba_value, dtev);
		bval = ba_new(val, B_AT_LONG);
		break;
	case B_AT_MF_AVG:
	case B_AT_MF_STATS: {
		struct bt_arg *cur = map_get(map, hash);
		struct avgstate *as;
		long sample = ba2long(bval->ba_value, dtev);
		enum bt_argtype type = bval->ba_type;

		if (cur->ba_type == B_AT_MF_AVG ||
		    cur->ba_type == B_AT_MF_STATS) {
			/* Update state in place; skip map_insert. */
			as = (struct avgstate *)cur->ba_value;
			as->count++;
			as->sum += sample;
			bval = NULL;
		} else {
			/* First insertion for this key. */
			struct bt_avg *bav = calloc(1, sizeof(*bav));
			if (bav == NULL)
				err(1, "avg: calloc");
			bav->ba.ba_type = type;
			bav->ba.ba_value = &bav->state;
			bav->state.count = 1;
			bav->state.sum = sample;
			bval = &bav->ba;
		}
		break;
	}
	default:
		bval = baeval(bval, dtev);
		break;
	}

	if (bval != NULL)
		map_insert(map, hash, bval);

	debug("map=%p '%s' insert key=%p '%s' bval=%p\n", map,
	    bv_name(bv), bkey, hash, bval);

	bv->bv_value = (struct bt_arg *)map;
	bv->bv_type = B_VT_MAP;
	bv->bv_printed = 0;
}

/*
 * Print variables:	{ print(890); print(@map[, 8]); print(comm); }
 *
 * In this case the global variable 'map' is pointed at by `ba'
 * and '8' is represented by `btop'.
 */
void
stmt_print(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_arg *btop, *ba = SLIST_FIRST(&bs->bs_args);
	struct bt_var *bv = ba->ba_value;
	struct map *map;
	size_t top = SIZE_T_MAX;

	assert(bs->bs_var == NULL);

	/* Parse optional `top' argument. */
	btop = SLIST_NEXT(ba, ba_next);
	if (btop != NULL) {
		assert(SLIST_NEXT(btop, ba_next) == NULL);
		top = ba2long(btop, dtev);
	}

	/* Static argument. */
	if (ba->ba_type != B_AT_VAR) {
		assert(btop == NULL);
		printf("%s\n", ba2str(ba, dtev));
		return;
	}

	map = (struct map *)bv->bv_value;
	if (map == NULL)
		return;

	debug("map=%p '%s' print (top=%d)\n", bv->bv_value, bv_name(bv), top);

	if (bv->bv_type == B_VT_MAP) {
		map_print(map, top, bv_name(bv));
		bv->bv_printed = 1;
	} else if (bv->bv_type == B_VT_HIST) {
		hist_print((struct hist *)map, bv_name(bv));
		bv->bv_printed = 1;
	} else if (bv->bv_type == B_VT_MAPHIST) {
		map_hist_print(map, bv_name(bv));
		bv->bv_printed = 1;
	} else
		printf("@%s: %s\n", bv_name(bv), ba2str(ba, dtev));
}

/*
 * Variable store: 	{ @var = 3; }
 *
 * In this case '3' is represented by `ba', the argument of a STORE
 * action.
 *
 * If the argument depends of the value of an event (builtin) or is
 * the result of an operation, its evaluation is stored in a new `ba'.
 */
void
stmt_store(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_arg *ba = SLIST_FIRST(&bs->bs_args);
	struct bt_var *bvar, *bv = bs->bs_var;
	struct map *map;

	assert(SLIST_NEXT(ba, ba_next) == NULL);

	switch (ba->ba_type) {
	case B_AT_STR:
		bv->bv_value = ba;
		bv->bv_type = B_VT_STR;
		break;
	case B_AT_LONG:
		bv->bv_value = ba;
		bv->bv_type = B_VT_LONG;
		break;
	case B_AT_VAR:
		bvar = ba->ba_value;
		bv->bv_type = bvar->bv_type;
		bv->bv_value = bvar->bv_value;
		break;
	case B_AT_MAP:
		bvar = ba->ba_value;
		map = (struct map *)bvar->bv_value;
		/* Uninitialized map */
		if (map == NULL)
			bv->bv_value = 0;
		else
			bv->bv_value = map_get(map, ba2hash(ba->ba_key, dtev));
		bv->bv_type = B_VT_LONG; /* XXX should we type map? */
		break;
	case B_AT_TUPLE:
		bv->bv_value = baeval(ba, dtev);
		bv->bv_type = B_VT_TUPLE;
		break;
	case B_AT_BI_PID:
	case B_AT_BI_TID:
	case B_AT_BI_CPU:
	case B_AT_BI_NSECS:
	case B_AT_BI_ELAPSED:
	case B_AT_BI_UID:
	case B_AT_BI_GID:
	case B_AT_BI_RETVAL:
	case B_AT_BI_ARG0 ... B_AT_BI_ARG9:
	case B_AT_FN_SIZEOF:
	case B_AT_FN_LEN:
	case B_AT_FN_STRNCMP:
	case B_AT_FN_DEREF:
	case B_AT_FN_SUBSCRIPT:
	case B_AT_OP_PLUS ... B_AT_OP_SHR:
		bv->bv_value = baeval(ba, dtev);
		bv->bv_type = B_VT_LONG;
		break;
	case B_AT_OP_TERN: {
		struct bt_arg *result = baeval(ba, dtev);
		bv->bv_value = result;
		bv->bv_type = (result->ba_type == B_AT_STR) ? B_VT_STR :
		    B_VT_LONG;
		break;
	}
	case B_AT_BI_COMM:
	case B_AT_BI_KSTACK:
	case B_AT_BI_USTACK:
	case B_AT_BI_PROBE:
	case B_AT_FN_STR:
	case B_AT_FN_KSYM:
	case B_AT_FN_USYM:
		bv->bv_value = baeval(ba, dtev);
		bv->bv_type = B_VT_STR;
		break;
	default:
		xabort("store not implemented for type %d", ba->ba_type);
	}

	debug("bv=%p var '%s' store (%p)='%s'\n", bv, bv_name(bv), bv->bv_value,
	    ba2str(bv->bv_value, dtev));
}

/*
 * String conversion:	{ str(arg0); str($1, 32); }
 *
 * When the argument is arg0..arg9, returns the string captured by the kernel
 * at probe fire time (via dt_copy_strargs).  For any other expression the
 * value is converted to a string at display time.  An optional second
 * argument limits the result to that many bytes (including the NUL).
 *
 * Since fn_str is only called from ba2str, *buf is the static buffer
 * provided there.
 */
struct bt_arg *
fn_str(struct bt_arg *ba, struct dt_evt *dtev, char *buf)
{
	struct bt_arg *arg, *lenarg;
	ssize_t len = STRLEN;

	assert(ba->ba_type == B_AT_FN_STR);

	arg = (struct bt_arg *)ba->ba_value;
	assert(arg != NULL);

	lenarg = SLIST_NEXT(arg, ba_next);
	if (lenarg != NULL) {
		/* Should have only 1 optional argument. */
		assert(SLIST_NEXT(lenarg, ba_next) == NULL);
		len = MINIMUM(ba2long(lenarg, dtev) + 1, STRLEN);
	}

	/* All negative lengths behave the same as a zero length. */
	if (len < 1)
		return ba_new("", B_AT_STR);

	/*
	 * For probe arguments, return the string captured by the kernel at
	 * probe fire time from the appropriate address space.
	 */
	if (arg->ba_type >= B_AT_BI_ARG0 && arg->ba_type <= B_AT_BI_ARG9) {
		int argn = arg->ba_type - B_AT_BI_ARG0;
		strlcpy(buf, dtev->dtev_str[argn], len);
		return ba_new(buf, B_AT_STR);
	}

	strlcpy(buf, ba2str(arg, dtev), len);
	return ba_new(buf, B_AT_STR);
}

/*
 * Expression test:	{ if (expr) stmt; }
 */
bool
stmt_test(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_arg *ba;

	if (bs == NULL)
		return true;

	ba = SLIST_FIRST(&bs->bs_args);

	if (ba->ba_type >= B_AT_OP_PLUS)
		return baexpr2long(ba, dtev) != 0;
	return ba2long(ba, dtev) != 0;
}

/*
 * Print time: 		{ time("%H:%M:%S"); }
 */
void
stmt_time(struct bt_stmt *bs, struct dt_evt *dtev)
{
	struct bt_arg *ba = SLIST_FIRST(&bs->bs_args);
	time_t time;
	struct tm *tm;
	char buf[64];

	assert(bs->bs_var == NULL);
	assert(ba->ba_type == B_AT_STR);
	assert(strlen(ba2str(ba, dtev)) < (sizeof(buf) - 1));

	time = builtin_gettime(dtev);
	tm = localtime(&time);
	strftime(buf, sizeof(buf), ba2str(ba, dtev), tm);
	printf("%s", buf);
}

/*
 * Set entries to 0:	{ zero(@map); }
 */
void
stmt_zero(struct bt_stmt *bs)
{
	struct bt_arg *ba = SLIST_FIRST(&bs->bs_args);
	struct bt_var *bv = ba->ba_value;
	struct map *map;

	assert(bs->bs_var == NULL);
	assert(ba->ba_type == B_AT_VAR);

	if (bv->bv_type == B_VT_LONG || bv->bv_type == B_VT_STR ||
	    bv->bv_type == B_VT_TUPLE) {
		bv->bv_value = ba_new(0, B_AT_LONG);
		bv->bv_type = B_VT_LONG;
		debug("var '%s' zero\n", bv_name(bv));
		return;
	}

	map = (struct map *)bv->bv_value;
	if (map == NULL)
		return;

	if (bv->bv_type != B_VT_MAP && bv->bv_type != B_VT_HIST &&
	    bv->bv_type != B_VT_MAPHIST)
		errx(1, "invalid variable type for zero(%s)", ba_name(ba));

	map_zero(map);

	debug("map=%p '%s' zero\n", map, bv_name(bv));
}

struct bt_arg *
ba_read(struct bt_arg *ba)
{
	struct bt_var *bv = ba->ba_value;

	assert(ba->ba_type == B_AT_VAR);
	debug("bv=%p read '%s' (%p)\n", bv, bv_name(bv), bv->bv_value);

	/* Handle map/hist access after clear(). */
	if (bv->bv_value == NULL)
		return &g_nullba;

	return bv->bv_value;
}

// XXX
extern struct bt_arg	*ba_append(struct bt_arg *, struct bt_arg *);

/*
 * Return a new argument that doesn't depend on `dtev'.  This is used
 * when storing values in variables, maps, etc.
 */
struct bt_arg *
baeval(struct bt_arg *bval, struct dt_evt *dtev)
{
	struct bt_arg *ba, *bh = NULL;

	switch (bval->ba_type) {
	case B_AT_VAR:
		ba = baeval(ba_read(bval), NULL);
		break;
	case B_AT_LONG:
	case B_AT_BI_PID:
	case B_AT_BI_TID:
	case B_AT_BI_CPU:
	case B_AT_BI_NSECS:
	case B_AT_BI_ELAPSED:
	case B_AT_BI_UID:
	case B_AT_BI_GID:
	case B_AT_BI_ARG0 ... B_AT_BI_ARG9:
	case B_AT_BI_RETVAL:
	case B_AT_FN_SIZEOF:
	case B_AT_FN_LEN:
	case B_AT_FN_STRNCMP:
	case B_AT_FN_DEREF:
	case B_AT_FN_SUBSCRIPT:
	case B_AT_OP_PLUS ... B_AT_OP_SHR:
		ba = ba_new(ba2long(bval, dtev), B_AT_LONG);
		break;
	case B_AT_OP_TERN: {
		struct bt_ternary *btr = bval->ba_value;
		ba = baeval(ba2long(btr->btr_cond, dtev)
		    ? btr->btr_then : btr->btr_else, dtev);
		break;
	}
	case B_AT_STR:
	case B_AT_BI_COMM:
	case B_AT_BI_KSTACK:
	case B_AT_BI_USTACK:
	case B_AT_BI_PROBE:
	case B_AT_FN_STR:
	case B_AT_FN_KSYM:
	case B_AT_FN_USYM:
		ba = ba_new(ba2str(bval, dtev), B_AT_STR);
		break;
	case B_AT_TUPLE:
		ba = bval->ba_value;
		do {
			bh = ba_append(bh, baeval(ba, dtev));
		} while ((ba = SLIST_NEXT(ba, ba_next)) != NULL);
		ba = ba_new(bh, B_AT_TUPLE);
		break;
	default:
		xabort("no eval support for type %d", bval->ba_type);
	}

	return ba;
}

/*
 * Return a string of coma-separated values
 */
const char *
ba2hash(struct bt_arg *ba, struct dt_evt *dtev)
{
	static char buf[KLEN];
	char *hash;
	int l, len;

	buf[0] = '\0';
	l = snprintf(buf, sizeof(buf), "%s", ba2str(ba, dtev));
	if (l < 0 || (size_t)l > sizeof(buf)) {
		warn("string too long %d > %lu", l, sizeof(buf));
		return buf;
	}

	len = 0;
	while ((ba = SLIST_NEXT(ba, ba_next)) != NULL) {
		len += l;
		hash = buf + len;

		l = snprintf(hash, sizeof(buf) - len, ", %s", ba2str(ba, dtev));
		if (l < 0 || (size_t)l > (sizeof(buf) - len)) {
			warn("hash too long %d > %lu", l + len, sizeof(buf));
			break;
		}
	}

	return buf;
}

static unsigned long
next_pow2(unsigned long x)
{
	size_t i;

	x--;
	for (i = 0; i < (sizeof(x)  * 8) - 1; i++)
		x |= (x >> 1);

	return x + 1;
}

/*
 * Return the ceiling value the interval holding `ba' or NULL if it is
 * out of the (min, max) values.
 */
const char *
ba2bucket(struct bt_arg *ba, struct bt_arg *brange, struct dt_evt *dtev,
    long *pstep)
{
	static char buf[KLEN];
	long val, bucket;
	int l;

	val = ba2long(ba, dtev);
	if (brange == NULL)
		bucket = next_pow2(val);
	else {
		long min, max, step;

		assert(brange->ba_type == B_AT_LONG);
		min = ba2long(brange, NULL);

		brange = SLIST_NEXT(brange, ba_next);
		assert(brange->ba_type == B_AT_LONG);
		max = ba2long(brange, NULL);

		if ((val < min) || (val > max))
			return NULL;

		brange = SLIST_NEXT(brange, ba_next);
		assert(brange->ba_type == B_AT_LONG);
		step = ba2long(brange, NULL);

		bucket = ((val / step) + 1) * step;
		*pstep = step;
	}

	buf[0] = '\0';
	l = snprintf(buf, sizeof(buf), "%lu", bucket);
	if (l < 0 || (size_t)l > sizeof(buf)) {
		warn("string too long %d > %lu", l, sizeof(buf));
		return buf;
	}

	return buf;
}

/*
 * Evaluate the operation encoded in `ba' and return its result.
 */
long
baexpr2long(struct bt_arg *ba, struct dt_evt *dtev)
{
	static long recursions;
	struct bt_arg *lhs, *rhs;
	long lval, rval, result;

	if (++recursions >= __MAXOPERANDS)
		errx(1, "too many operands (>%d) in expression", __MAXOPERANDS);

	lhs = ba->ba_value;
	rhs = SLIST_NEXT(lhs, ba_next);

	/*
	 * String comparison also use '==' and '!='.
	 */
	if (lhs->ba_type == B_AT_STR ||
	    (rhs != NULL && rhs->ba_type == B_AT_STR)) {
	    	char lstr[STRLEN], rstr[STRLEN];

		strlcpy(lstr, ba2str(lhs, dtev), sizeof(lstr));
		strlcpy(rstr, ba2str(rhs, dtev), sizeof(rstr));

	    	result = strncmp(lstr, rstr, STRLEN) == 0;

		switch (ba->ba_type) {
		case B_AT_OP_EQ:
			break;
		case B_AT_OP_NE:
	    		result = !result;
			break;
		default:
			warnx("operation '%d' unsupported on strings",
			    ba->ba_type);
			result = 1;
		}

		debug("ba=%p eval '(%s %s %s) = %d'\n", ba, lstr, ba_name(ba),
		   rstr, result);

		goto out;
	}

	lval = ba2long(lhs, dtev);
	if (rhs == NULL) {
		rval = 0;
	} else {
		assert(SLIST_NEXT(rhs, ba_next) == NULL);
		rval = ba2long(rhs, dtev);
	}

	switch (ba->ba_type) {
	case B_AT_OP_PLUS:
		result = lval + rval;
		break;
	case B_AT_OP_MINUS:
		result = lval - rval;
		break;
	case B_AT_OP_MULT:
		result = lval * rval;
		break;
	case B_AT_OP_DIVIDE:
		result = lval / rval;
		break;
	case B_AT_OP_MODULO:
		result = lval % rval;
		break;
	case B_AT_OP_BAND:
		result = lval & rval;
		break;
	case B_AT_OP_XOR:
		result = lval ^ rval;
		break;
	case B_AT_OP_BOR:
		result = lval | rval;
		break;
	case B_AT_OP_EQ:
		result = (lval == rval);
		break;
	case B_AT_OP_NE:
		result = (lval != rval);
		break;
	case B_AT_OP_LE:
		result = (lval <= rval);
		break;
	case B_AT_OP_LT:
		result = (lval < rval);
		break;
	case B_AT_OP_GE:
		result = (lval >= rval);
		break;
	case B_AT_OP_GT:
		result = (lval > rval);
		break;
	case B_AT_OP_LAND:
		result = (lval && rval);
		break;
	case B_AT_OP_LOR:
		result = (lval || rval);
		break;
	case B_AT_OP_LNOT:
		result = !lval;
		break;
	case B_AT_OP_BNOT:
		result = ~lval;
		break;
	case B_AT_OP_NEG:
		result = -lval;
		break;
	case B_AT_OP_SHL:
		result = lval << rval;
		break;
	case B_AT_OP_SHR:
		result = (long)((unsigned long)lval >> rval);
		break;
	default:
		xabort("unsupported operation %d", ba->ba_type);
	}

	debug("ba=%p eval '(%ld %s %ld) = %d'\n", ba, lval, ba_name(ba),
	   rval, result);

out:
	--recursions;

	return result;
}

const char *
ba_name(struct bt_arg *ba)
{
	switch (ba->ba_type) {
	case B_AT_STR:
		return (const char *)ba->ba_value;
	case B_AT_LONG:
		return ba2str(ba, NULL);
	case B_AT_NIL:
		return "0";
	case B_AT_VAR:
	case B_AT_MAP:
	case B_AT_HIST:
		break;
	case B_AT_BI_PID:
		return "pid";
	case B_AT_BI_TID:
		return "tid";
	case B_AT_BI_COMM:
		return "comm";
	case B_AT_BI_CPU:
		return "cpu";
	case B_AT_BI_NSECS:
		return "nsecs";
	case B_AT_BI_ELAPSED:
		return "elapsed";
	case B_AT_BI_UID:
		return "uid";
	case B_AT_BI_GID:
		return "gid";
	case B_AT_BI_KSTACK:
		return "kstack";
	case B_AT_BI_USTACK:
		return "ustack";
	case B_AT_BI_ARG0:
		return "arg0";
	case B_AT_BI_ARG1:
		return "arg1";
	case B_AT_BI_ARG2:
		return "arg2";
	case B_AT_BI_ARG3:
		return "arg3";
	case B_AT_BI_ARG4:
		return "arg4";
	case B_AT_BI_ARG5:
		return "arg5";
	case B_AT_BI_ARG6:
		return "arg6";
	case B_AT_BI_ARG7:
		return "arg7";
	case B_AT_BI_ARG8:
		return "arg8";
	case B_AT_BI_ARG9:
		return "arg9";
	case B_AT_BI_ARGS:
		return "args";
	case B_AT_BI_RETVAL:
		return "retval";
	case B_AT_BI_PROBE:
		return "probe";
	case B_AT_FN_STR:
		return "str";
	case B_AT_FN_SIZEOF:
		return "sizeof";
	case B_AT_FN_KSYM:
		return "ksym";
	case B_AT_FN_USYM:
		return "usym";
	case B_AT_FN_LEN:
		return "len";
	case B_AT_FN_STRNCMP:
		return "strncmp";
	case B_AT_FN_DEREF: {
		static char buf[64];
		struct bt_deref *bd = ba->ba_value;
		snprintf(buf, sizeof(buf), "%s->%s",
		    ba_name(bd->bd_base), bd->bd_field);
		return buf;
	}
	case B_AT_FN_SUBSCRIPT: {
		static char buf[64];
		struct bt_subscript *bss = ba->ba_value;
		snprintf(buf, sizeof(buf), "%s[%ld]",
		    ba_name(bss->bss_base), bss->bss_index);
		return buf;
	}
	case B_AT_OP_PLUS:
		return "+";
	case B_AT_OP_MINUS:
		return "-";
	case B_AT_OP_MULT:
		return "*";
	case B_AT_OP_DIVIDE:
		return "/";
	case B_AT_OP_MODULO:
		return "%";
	case B_AT_OP_BAND:
		return "&";
	case B_AT_OP_XOR:
		return "^";
	case B_AT_OP_BOR:
		return "|";
	case B_AT_OP_EQ:
		return "==";
	case B_AT_OP_NE:
		return "!=";
	case B_AT_OP_LE:
		return "<=";
	case B_AT_OP_LT:
		return "<";
	case B_AT_OP_GE:
		return ">=";
	case B_AT_OP_GT:
		return ">";
	case B_AT_OP_LAND:
		return "&&";
	case B_AT_OP_LOR:
		return "||";
	case B_AT_OP_LNOT:
		return "!";
	case B_AT_OP_BNOT:
		return "~";
	case B_AT_OP_NEG:
		return "-";
	case B_AT_OP_SHL:
		return "<<";
	case B_AT_OP_SHR:
		return ">>";
	case B_AT_OP_TERN:
		return "?:";
	default:
		xabort("unsupported type %d", ba->ba_type);
	}

	assert(ba->ba_type == B_AT_VAR || ba->ba_type == B_AT_MAP ||
	    ba->ba_type == B_AT_HIST);

	static char buf[64];
	size_t sz;
	int l;

	buf[0] = '@';
	buf[1] = '\0';
	sz = sizeof(buf) - 1;
	l = snprintf(buf+1, sz, "%s", bv_name(ba->ba_value));
	if (l < 0 || (size_t)l > sz) {
		warn("string too long %d > %zu", l, sz);
		return buf;
	}

	if (ba->ba_type == B_AT_MAP) {
		sz -= l;
		l = snprintf(buf+1+l, sz, "[%s]", ba_name(ba->ba_key));
		if (l < 0 || (size_t)l > sz) {
			warn("string too long %d > %zu", l, sz);
			return buf;
		}
	}

	return buf;
}

/*
 * Return the representation of `ba' as long.
 */
long
ba2long(struct bt_arg *ba, struct dt_evt *dtev)
{
	struct bt_var *bv;
	long val;

	switch (ba->ba_type) {
	case B_AT_STR:
		val = (*ba2str(ba, dtev) == '\0') ? 0 : 1;
		break;
	case B_AT_LONG:
		val = (long)ba->ba_value;
		break;
	case B_AT_VAR:
		ba = ba_read(ba);
		val = (long)ba->ba_value;
		break;
	case B_AT_MAP:
		bv = ba->ba_value;
		/* Uninitialized map */
		if (bv->bv_value == NULL)
			return 0;
		val = ba2long(map_get((struct map *)bv->bv_value,
		    ba2hash(ba->ba_key, dtev)), dtev);
		break;
	case B_AT_NIL:
		val = 0L;
		break;
	case B_AT_BI_PID:
		val = dtev->dtev_pid;
		break;
	case B_AT_BI_TID:
		val = dtev->dtev_tid;
		break;
	case B_AT_BI_CPU:
		val = dtev->dtev_cpu;
		break;
	case B_AT_BI_NSECS:
		val = builtin_nsecs(dtev);
		break;
	case B_AT_BI_ELAPSED:
		val = builtin_elapsed(dtev);
		break;
	case B_AT_BI_UID:
		val = dtev->dtev_uid;
		break;
	case B_AT_BI_GID:
		val = dtev->dtev_gid;
		break;
	case B_AT_BI_ARG0 ... B_AT_BI_ARG9:
		val = dtev->dtev_args[ba->ba_type - B_AT_BI_ARG0];
		break;
	case B_AT_BI_RETVAL:
		val = dtev->dtev_retval[0];
		break;
	case B_AT_BI_PROBE:
		val = dtev->dtev_pbn;
		break;
	case B_AT_FN_KSYM:
	case B_AT_FN_USYM:
		/* Symbol names are strings; non-empty means true. */
		val = (*ba2str(ba, dtev) != '\0') ? 1 : 0;
		break;
	case B_AT_FN_LEN: {
		struct bt_arg *bvar = ba->ba_value;
		struct bt_var *bv = bvar->ba_value;

		if (bv->bv_type == B_VT_MAP && bv->bv_value != NULL)
			val = (long)map_len((struct map *)bv->bv_value);
		else
			val = 0;
		break;
	}
	case B_AT_FN_STRNCMP: {
		char s1[STRLEN];
		struct bt_arg *a1 = ba->ba_value;
		struct bt_arg *a2 = SLIST_NEXT(a1, ba_next);
		struct bt_arg *a3 = SLIST_NEXT(a2, ba_next);

		strlcpy(s1, ba2str(a1, dtev), sizeof(s1));
		val = strncmp(s1, ba2str(a2, dtev), (size_t)ba2long(a3, dtev));
		break;
	}
	case B_AT_FN_SIZEOF: {
		const char *tname = (const char *)ba->ba_value;
		uint16_t typeid;
		ssize_t sz;

		if (ctf_handle == NULL || tname == NULL) {
			val = 0;
			break;
		}
		typeid = ctf_type_by_name(ctf_handle, tname);
		sz = (typeid != 0) ? ctf_type_size(ctf_handle, typeid) : -1;
		val = (sz > 0) ? sz : 0;
		break;
	}
	case B_AT_FN_DEREF: {
		struct bt_deref *bd = ba->ba_value;
		val = (bd->bd_slot != BD_SLOT_UNSET)
		    ? (long)dtev->dtev_mem[bd->bd_slot] : 0;
		break;
	}
	case B_AT_FN_SUBSCRIPT: {
		struct bt_subscript *bss = ba->ba_value;
		val = (bss->bss_slot != BSS_SLOT_UNSET)
		    ? (long)dtev->dtev_mem[bss->bss_slot] : 0;
		break;
	}
	case B_AT_OP_TERN: {
		struct bt_ternary *btr = ba->ba_value;
		val = ba2long(ba2long(btr->btr_cond, dtev)
		    ? btr->btr_then : btr->btr_else, dtev);
		break;
	}
	case B_AT_OP_PLUS ... B_AT_OP_SHR:
		val = baexpr2long(ba, dtev);
		break;
	case B_AT_MF_AVG:
	case B_AT_MF_STATS: {
		struct avgstate *as = (struct avgstate *)ba->ba_value;
		val = (as->count > 0) ? as->sum / as->count : 0;
		break;
	}
	case B_AT_TMEMBER: {
		unsigned long idx = (unsigned long)ba->ba_key;
		struct bt_arg *elem;

		bv = ba->ba_value;
		if (bv->bv_value == NULL)
			return 0;
		elem = bv->bv_value;
		assert(elem->ba_type == B_AT_TUPLE);
		elem = elem->ba_value;
		while (elem != NULL && idx-- > 0)
			elem = SLIST_NEXT(elem, ba_next);
		val = (elem != NULL) ? ba2long(elem, dtev) : 0;
		break;
	}
	default:
		xabort("no long conversion for type %d", ba->ba_type);
	}

	return  val;
}

/*
 * Return the representation of `ba' as string.
 */
const char *
ba2str(struct bt_arg *ba, struct dt_evt *dtev)
{
	static char buf[STRLEN];
	struct bt_var *bv;
	struct dtioc_probe_info *dtpi;
	unsigned long idx;
	const char *str;

	buf[0] = '\0';
	switch (ba->ba_type) {
	case B_AT_STR:
		str = (const char *)ba->ba_value;
		break;
	case B_AT_LONG:
		snprintf(buf, sizeof(buf), "%ld",(long)ba->ba_value);
		str = buf;
		break;
	case B_AT_TUPLE:
		snprintf(buf, sizeof(buf), "(%s)", ba2hash(ba->ba_value, dtev));
		str = buf;
		break;
	case B_AT_TMEMBER:
		idx = (unsigned long)ba->ba_key;
		bv = ba->ba_value;
		/* Uninitialized tuple */
		if (bv->bv_value == NULL) {
			str = buf;
			break;
		}
		ba = bv->bv_value;
		assert(ba->ba_type == B_AT_TUPLE);
		ba = ba->ba_value;
		while (ba != NULL && idx-- > 0) {
			ba = SLIST_NEXT(ba, ba_next);
		}
		str = ba2str(ba, dtev);
		break;
	case B_AT_NIL:
		str = "";
		break;
	case B_AT_BI_KSTACK:
		str = builtin_stack(dtev, 1);
		break;
	case B_AT_BI_USTACK:
		str = builtin_stack(dtev, 0);
		break;
	case B_AT_BI_COMM:
		str = dtev->dtev_comm;
		break;
	case B_AT_BI_CPU:
		snprintf(buf, sizeof(buf), "%u", dtev->dtev_cpu);
		str = buf;
		break;
	case B_AT_BI_PID:
		snprintf(buf, sizeof(buf), "%d", dtev->dtev_pid);
		str = buf;
		break;
	case B_AT_BI_TID:
		snprintf(buf, sizeof(buf), "%d", dtev->dtev_tid);
		str = buf;
		break;
	case B_AT_BI_NSECS:
		snprintf(buf, sizeof(buf), "%llu", builtin_nsecs(dtev));
		str = buf;
		break;
	case B_AT_BI_ELAPSED:
		snprintf(buf, sizeof(buf), "%llu", builtin_elapsed(dtev));
		str = buf;
		break;
	case B_AT_BI_UID:
		snprintf(buf, sizeof(buf), "%u", dtev->dtev_uid);
		str = buf;
		break;
	case B_AT_BI_GID:
		snprintf(buf, sizeof(buf), "%u", dtev->dtev_gid);
		str = buf;
		break;
	case B_AT_BI_ARG0 ... B_AT_BI_ARG9:
		str = builtin_arg(dtev, ba->ba_type);
		break;
	case B_AT_BI_RETVAL:
		if (ctf_handle != NULL && dtev->dtev_pbn != EVENT_BEGIN &&
		    dtev->dtev_pbn != EVENT_END) {
			struct dtioc_probe_info *rpi;
			uint16_t ret_type;
			int nargs;

			rpi = &dt_dtpis[dtev->dtev_pbn - 1];
			nargs = ctf_func_info(ctf_handle, rpi->dtpi_func,
			    &ret_type, NULL, 0);
			if (nargs >= 0 && ret_type != 0) {
				str = ctf_format_arg(ctf_handle, ret_type,
				    dtev->dtev_retval[0]);
				break;
			}
		}
		snprintf(buf, sizeof(buf), "%ld", (long)dtev->dtev_retval[0]);
		str = buf;
		break;
	case B_AT_BI_PROBE:
		if (dtev->dtev_pbn == EVENT_BEGIN) {
			str = "BEGIN";
			break;
		} else if (dtev->dtev_pbn == EVENT_END) {
			str = "END";
			break;
		}
		dtpi = &dt_dtpis[dtev->dtev_pbn - 1];
		if (dtpi != NULL) {
			if (dtpi->dtpi_name[0] == '\0')
				snprintf(buf, sizeof(buf), "%s:%s",
				    dtpi->dtpi_prov, dtpi_func(dtpi));
			else
				snprintf(buf, sizeof(buf), "%s:%s:%s",
				    dtpi->dtpi_prov, dtpi_func(dtpi),
				    dtpi->dtpi_name);
		} else
			snprintf(buf, sizeof(buf), "%u", dtev->dtev_pbn);
		str = buf;
		break;
	case B_AT_MAP:
		bv = ba->ba_value;
		/* Uninitialized map */
		if (bv->bv_value == NULL) {
			str = buf;
			break;
		}
		str = ba2str(map_get((struct map *)bv->bv_value,
		    ba2hash(ba->ba_key, dtev)), dtev);
		break;
	case B_AT_VAR:
		str = ba2str(ba_read(ba), dtev);
		break;
	case B_AT_FN_STR:
		str = (const char*)(fn_str(ba, dtev, buf))->ba_value;
		break;
	case B_AT_FN_DEREF: {
		struct bt_deref *bd = ba->ba_value;
		uint64_t v = (bd->bd_slot != BD_SLOT_UNSET)
		    ? dtev->dtev_mem[bd->bd_slot] : 0;
		snprintf(buf, sizeof(buf), "%ld", (long)v);
		str = buf;
		break;
	}
	case B_AT_FN_SUBSCRIPT: {
		struct bt_subscript *bss = ba->ba_value;
		uint64_t v = (bss->bss_slot != BSS_SLOT_UNSET)
		    ? dtev->dtev_mem[bss->bss_slot] : 0;
		snprintf(buf, sizeof(buf), "%ld", (long)v);
		str = buf;
		break;
	}
	case B_AT_FN_SIZEOF:
	case B_AT_FN_LEN:
	case B_AT_FN_STRNCMP:
	case B_AT_OP_PLUS ... B_AT_OP_SHR:
		snprintf(buf, sizeof(buf), "%ld", ba2long(ba, dtev));
		str = buf;
		break;
	case B_AT_FN_KSYM: {
		unsigned long addr = (unsigned long)ba2long(ba->ba_value, dtev);
		if (kelf != NULL)
			kelf_snprintsym_kernel(kelf, buf, sizeof(buf), addr);
		else
			snprintf(buf, sizeof(buf), "\n0x%lx", addr);
		str = buf + 1;	/* skip leading '\n' */
		break;
	}
	case B_AT_FN_USYM: {
		unsigned long addr = (unsigned long)ba2long(ba->ba_value, dtev);
		if (dtev != NULL)
			kelf_snprintsym_proc(dtfd, dtev->dtev_pid, buf,
			    sizeof(buf), addr);
		else
			snprintf(buf, sizeof(buf), "\n0x%lx", addr);
		str = buf + 1;	/* skip leading '\n' */
		break;
	}
	case B_AT_OP_TERN: {
		struct bt_ternary *btr = ba->ba_value;
		str = ba2str(ba2long(btr->btr_cond, dtev)
		    ? btr->btr_then : btr->btr_else, dtev);
		break;
	}
	case B_AT_MF_COUNT:
	case B_AT_MF_MAX:
	case B_AT_MF_MIN:
	case B_AT_MF_SUM:
		assert(0);
		break;
	case B_AT_MF_AVG: {
		struct avgstate *as = (struct avgstate *)ba->ba_value;
		long avg = (as->count > 0) ? as->sum / as->count : 0;
		snprintf(buf, sizeof(buf), "%ld", avg);
		str = buf;
		break;
	}
	case B_AT_MF_STATS: {
		struct avgstate *as = (struct avgstate *)ba->ba_value;
		long avg = (as->count > 0) ? as->sum / as->count : 0;
		snprintf(buf, sizeof(buf), "count %ld, avg %ld, total %ld",
		    as->count, avg, as->sum);
		str = buf;
		break;
	}
	default:
		xabort("no string conversion for type %d", ba->ba_type);
	}

	return str;
}

int
ba2flags(struct bt_arg *ba)
{
	int flags = 0;

	assert(ba->ba_type != B_AT_MAP);
	assert(ba->ba_type != B_AT_TUPLE);

	switch (ba->ba_type) {
	case B_AT_STR:
	case B_AT_LONG:
	case B_AT_TMEMBER:
	case B_AT_VAR:
	case B_AT_HIST:
	case B_AT_NIL:
		break;
	case B_AT_BI_KSTACK:
		flags |= DTEVT_KSTACK;
		break;
	case B_AT_BI_USTACK:
		flags |= DTEVT_USTACK;
		break;
	case B_AT_BI_COMM:
		flags |= DTEVT_EXECNAME;
		break;
	case B_AT_BI_CPU:
	case B_AT_BI_PID:
	case B_AT_BI_TID:
	case B_AT_BI_NSECS:
	case B_AT_BI_ELAPSED:
	case B_AT_BI_UID:
	case B_AT_BI_GID:
		break;
	case B_AT_BI_ARG0 ... B_AT_BI_ARG9:
		flags |= DTEVT_FUNCARGS;
		break;
	case B_AT_BI_RETVAL:
	case B_AT_BI_PROBE:
		break;
	case B_AT_MF_COUNT:
		break;
	case B_AT_MF_MAX:
	case B_AT_MF_MIN:
	case B_AT_MF_SUM:
	case B_AT_MF_AVG:
	case B_AT_MF_STATS:
		if (ba->ba_value != NULL)
			flags |= ba2dtflags(ba->ba_value);
		break;
	case B_AT_FN_STR: {
		struct bt_arg *inner = (struct bt_arg *)ba->ba_value;
		if (inner != NULL &&
		    inner->ba_type >= B_AT_BI_ARG0 &&
		    inner->ba_type <= B_AT_BI_ARG9)
			flags |= DTEVT_FUNCARGS | DTEVT_STRARGS;
		break;
	}
	case B_AT_FN_SIZEOF:
		/* sizeof is a compile-time constant; no kernel data needed. */
		break;
	case B_AT_FN_KSYM:
	case B_AT_FN_USYM:
		/* The address argument may require kernel data. */
		if (ba->ba_value != NULL)
			flags |= ba2flags(ba->ba_value);
		break;
	case B_AT_FN_LEN:
		break;
	case B_AT_FN_STRNCMP: {
		struct bt_arg *a1 = ba->ba_value;
		struct bt_arg *a2 = SLIST_NEXT(a1, ba_next);

		flags |= ba2flags(a1);
		flags |= ba2flags(a2);
		break;
	}
	case B_AT_FN_DEREF:
	case B_AT_FN_SUBSCRIPT:
		/* We need the arg's register value (pointer) to dereference. */
		flags |= DTEVT_FUNCARGS;
		break;
	case B_AT_OP_PLUS ... B_AT_OP_SHR:
		flags |= ba2dtflags(ba->ba_value);
		break;
	case B_AT_OP_TERN: {
		struct bt_ternary *btr = ba->ba_value;
		flags |= ba2flags(btr->btr_cond);
		flags |= ba2flags(btr->btr_then);
		flags |= ba2flags(btr->btr_else);
		break;
	}
	default:
		xabort("invalid argument type %d", ba->ba_type);
	}

	return flags;
}

/*
 * Return dt(4) flags indicating which data should be recorded by the
 * kernel, if any, for a given `ba'.
 */
int
ba2dtflags(struct bt_arg *ba)
{
	static long recursions;
	struct bt_arg *bval;
	int flags = 0;

	if (++recursions >= __MAXOPERANDS)
		errx(1, "too many operands (>%d) in expression", __MAXOPERANDS);

	do {
		if (ba->ba_type == B_AT_MAP)
			flags |= ba2dtflags(ba->ba_key);
		else if (ba->ba_type == B_AT_TUPLE) {
			bval = ba->ba_value;
			do {
				flags |= ba2flags(bval);
			} while ((bval = SLIST_NEXT(bval, ba_next)) != NULL);
		} else
			flags |= ba2flags(ba);

	} while ((ba = SLIST_NEXT(ba, ba_next)) != NULL);

	--recursions;

	return flags;
}

long
bacmp(struct bt_arg *a, struct bt_arg *b)
{
	char astr[STRLEN];
	long val;

	if (a->ba_type != b->ba_type)
		return a->ba_type - b->ba_type;

	switch (a->ba_type) {
	case B_AT_LONG:
	case B_AT_MF_AVG:
	case B_AT_MF_STATS:
		return ba2long(a, NULL) - ba2long(b, NULL);
	case B_AT_STR:
		strlcpy(astr, ba2str(a, NULL), sizeof(astr));
		return strcmp(astr, ba2str(b, NULL));
	case B_AT_TUPLE:
		/* Compare two lists of arguments one by one. */
		a = a->ba_value;
		b = b->ba_value;
		do {
			val = bacmp(a, b);
			if (val != 0)
				break;

			a = SLIST_NEXT(a, ba_next);
			b = SLIST_NEXT(b, ba_next);
			if (a == NULL && b != NULL)
				val = -1;
			else if (a != NULL && b == NULL)
				val = 1;
		} while (a != NULL && b != NULL);

		return val;
	default:
		xabort("no compare support for type %d", a->ba_type);
	}
}

__dead void
xabort(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	abort();
}

void
debug(const char *fmt, ...)
{
	va_list ap;

	if (verbose < 2)
		return;

	fprintf(stderr, "debug: ");

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void
debugx(const char *fmt, ...)
{
	va_list ap;

	if (verbose < 2)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void
debug_dump_term(struct bt_arg *ba)
{
	switch (ba->ba_type) {
	case B_AT_LONG:
		debugx("%s", ba2str(ba, NULL));
		break;
	case B_AT_OP_PLUS ... B_AT_OP_SHR:
		debug_dump_expr(ba);
		break;
	default:
		debugx("%s", ba_name(ba));
	}
}

void
debug_dump_expr(struct bt_arg *ba)
{
	struct bt_arg *lhs, *rhs;

	lhs = ba->ba_value;
	rhs = SLIST_NEXT(lhs, ba_next);

	/* Left */
	debug_dump_term(lhs);

	/* Right */
	if (rhs != NULL) {
		debugx(" %s ", ba_name(ba));
		debug_dump_term(rhs);
	} else {
		if (ba->ba_type != B_AT_OP_NE)
			debugx(" %s NULL", ba_name(ba));
	}
}

void
debug_dump_filter(struct bt_rule *r)
{
	struct bt_stmt *bs;

	if (verbose < 2)
		return;

	if (r->br_filter == NULL) {
		debugx("\n");
		return;
	}

	bs = r->br_filter->bf_condition;

	debugx(" /");
	debug_dump_expr(SLIST_FIRST(&bs->bs_args));
	debugx("/\n");
}
