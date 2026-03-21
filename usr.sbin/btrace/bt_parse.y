/*	$OpenBSD: bt_parse.y,v 1.62 2025/01/23 11:17:32 mpi Exp $	*/

/*
 * Copyright (c) 2019-2023 Martin Pieuchot <mpi@openbsd.org>
 * Copyright (c) 2019 Tobias Heider <tobhe@openbsd.org>
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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
 * B tracing language parser.
 *
 * The dialect of the language understood by this parser aims to be
 * compatible with the one understood by bpftrace(8), see:
 *
 * https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md
 *
 */

%{
#include <sys/queue.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include "bt_parser.h"

/* Name for the default map @[], hopefully nobody will use this one ;) */
#define UNNAMED_MAP	"___unnamed_map_doesnt_have_any_name"

/* Number of rules to evaluate. */
struct bt_ruleq		g_rules = TAILQ_HEAD_INITIALIZER(g_rules);

/* Number of probes except BEGIN/END. */
int		 	g_nprobes;

/* List of global variables, including maps. */
SLIST_HEAD(, bt_var)	 g_variables;

/* List of local variables, cleaned for each new rule. */
SLIST_HEAD(, bt_var)	l_variables;

struct bt_arg 		g_nullba = BA_INITIALIZER(0, B_AT_LONG);
struct bt_arg		g_maxba = BA_INITIALIZER(LONG_MAX, B_AT_LONG);

struct bt_rule	*br_new(struct bt_probe *, struct bt_filter *,
		     struct bt_stmt *);
struct bt_probe	*bp_new(const char *, const char *, const char *, long);
struct bt_arg	*ba_append(struct bt_arg *, struct bt_arg *);
struct bt_arg	*ba_op(enum bt_argtype, struct bt_arg *, struct bt_arg *);
struct bt_stmt	*bs_new(enum bt_action, struct bt_arg *, struct bt_var *);
struct bt_stmt	*bs_append(struct bt_stmt *, struct bt_stmt *);

struct bt_var	*bg_lookup(const char *);
struct bt_stmt	*bg_store(const char *, struct bt_arg *);
struct bt_arg	*bg_find(const char *);
struct bt_var	*bg_get(const char *);

struct bt_arg	*bi_find(struct bt_arg *, unsigned long);

struct bt_var	*bl_lookup(const char *);
struct bt_stmt	*bl_store(const char *, struct bt_arg *);
struct bt_arg	*bl_find(const char *);

struct bt_arg	*bm_find(const char *, struct bt_arg *);
struct bt_stmt	*bm_insert(const char *, struct bt_arg *, struct bt_arg *);
struct bt_stmt	*bm_op(enum bt_action, struct bt_arg *, struct bt_arg *);

struct bt_stmt	*bh_inc(const char *, struct bt_arg *, struct bt_arg *);
struct bt_stmt	*bhm_inc(const char *, struct bt_arg *, struct bt_arg *, struct bt_arg *);
struct bt_stmt	*bfor_new(const char *, const char *, struct bt_stmt *);
struct bt_stmt	*bwhile_new(struct bt_arg *, struct bt_stmt *);
struct bt_stmt	*bm_update(struct bt_arg *, struct bt_arg *);
struct bt_arg	*btern_new(struct bt_arg *, struct bt_arg *, struct bt_arg *);

/*
 * Lexer
 */
const char	*pbuf;
size_t		 plen;
size_t		 pindex;
int		 perrors = 0;

typedef struct {
	union {
		long			 number;
		int			 i;
		const char		*string;
		struct bt_probe		*probe;
		struct bt_filter	*filter;
		struct bt_stmt		*stmt;
		struct bt_arg		*arg;
	} v;
	const char			*filename;
	int				 lineno;
	int				 colno;
} yystype;
#define YYSTYPE yystype

static void	 yyerror(const char *, ...);
static int	 yylex(void);

static int 	 pflag = 0;		/* probe parsing context flag */
static int 	 beflag = 0;		/* BEGIN/END parsing context flag */
%}

/*
 * 2 shift/reduce conflicts on GVAR '[': shift wins, choosing
 * mentry : GVAR '[' vargs ']' over variable : GVAR -> factor '[' NUMBER ']'.
 * This is correct: @map[key] is always a map access, not a subscript.
 */
%expect 4

%right '?' ':'		/* ternary operator, lowest expression precedence */

%token	<v.i>		ERROR ENDFILT
%token	<v.i>		OP_EQ OP_NE OP_LE OP_LT OP_GE OP_GT OP_LAND OP_LOR OP_SHL OP_SHR OP_ARROW
%token	<v.i>		OP_PLUSEQ OP_MINUSEQ OP_MULTEQ OP_DIVEQ OP_MODEQ
%token	<v.i>		OP_BANDEQ OP_BOREQ OP_XOREQ OP_SHLEQ OP_SHREQ
%token	<v.i>		OP_INC OP_DEC
/* Builtins */
%token	<v.i>		BUILTIN BEGIN BREAK CONTINUE ELSE END FOR IF KSYM LEN NTOP SIZEOF STR STRNCMP USYM WHILE
/* Functions and Map operators */
%token  <v.i>		F_DELETE F_PRINT
%token	<v.i>		MFUNC FUNC0 FUNC1 FUNCN OP1 OP2 OP4 MOP0 MOP1
%token	<v.string>	STRING CSTRING GVAR LVAR
%token	<v.arg>		PVAR PNUM
%token	<v.number>	NUMBER

%type	<v.i>		beginend
%type	<v.probe>	plist probe pname
%type	<v.filter>	filter
%type	<v.stmt>	action stmt stmtblck stmtlist block
%type	<v.arg>		vargs mentry mpat pargs
%type	<v.arg>		expr term fterm uterm variable factor func
%type	<v.string>	typename
%%

grammar	: /* empty */
	| grammar '\n'
	| grammar rule
	| grammar error
	;

rule	: plist filter action		{ br_new($1, $2, $3); beflag = 0; }
	;

beginend: BEGIN	| END ;

plist	: plist ',' probe		{ $$ = bp_append($1, $3); }
	| probe
	;

probe	: { pflag = 1; } pname		{ $$ = $2; pflag = 0; }
	| { beflag = 1; } beginend	{ $$ = bp_new(NULL, NULL, NULL, $2); }
	;

pname	: STRING ':' STRING ':' STRING	{ $$ = bp_new($1, $3, $5, 0); }
	| STRING ':' STRING ':' NUMBER	{ $$ = bp_new($1, $3, NULL, $5); }
	| STRING ':' STRING		{ $$ = bp_new($1, $3, "", 0); }
	;

mentry	: GVAR '[' vargs ']'		{ $$ = bm_find($1, $3); }
	;

mpat	: MOP0 '(' ')'			{ $$ = ba_new(NULL, $1); }
	| MOP1 '(' expr ')'		{ $$ = ba_new($3, $1); }
	| expr
	;

filter	: /* empty */			{ $$ = NULL; }
	| '/' expr ENDFILT		{ $$ = bc_new(NULL, B_AT_OP_NE, $2); }
	;

/*
 * Operator precedence (lowest to highest):
 *  0. ? : (ternary, lowest)
 *  1. &&, ||
 *  2. ==, !=, <, <=, >=, >
 *  3. +, -, &, ^, |, <<, >>
 *  4. *, /, %
 *  5. unary !, ~, - (highest)
 */
expr	: expr '?' expr ':' expr	{ $$ = btern_new($1, $3, $5); }
	| expr OP_LAND term	{ $$ = ba_op(B_AT_OP_LAND, $1, $3); }
	| expr OP_LOR term	{ $$ = ba_op(B_AT_OP_LOR, $1, $3); }
	| term
	;

term	: term OP_EQ fterm	{ $$ = ba_op(B_AT_OP_EQ, $1, $3); }
	| term OP_NE fterm	{ $$ = ba_op(B_AT_OP_NE, $1, $3); }
	| term OP_LE fterm	{ $$ = ba_op(B_AT_OP_LE, $1, $3); }
	| term OP_LT fterm	{ $$ = ba_op(B_AT_OP_LT, $1, $3); }
	| term OP_GE fterm	{ $$ = ba_op(B_AT_OP_GE, $1, $3); }
	| term OP_GT fterm	{ $$ = ba_op(B_AT_OP_GT, $1, $3); }
	| term '+' fterm	{ $$ = ba_op(B_AT_OP_PLUS, $1, $3); }
	| term '-' fterm	{ $$ = ba_op(B_AT_OP_MINUS, $1, $3); }
	| term '&' fterm	{ $$ = ba_op(B_AT_OP_BAND, $1, $3); }
	| term '^' fterm	{ $$ = ba_op(B_AT_OP_XOR, $1, $3); }
	| term '|' fterm	{ $$ = ba_op(B_AT_OP_BOR, $1, $3); }
	| term OP_SHL fterm	{ $$ = ba_op(B_AT_OP_SHL, $1, $3); }
	| term OP_SHR fterm	{ $$ = ba_op(B_AT_OP_SHR, $1, $3); }
	| fterm
	;

fterm	: fterm '*' uterm	{ $$ = ba_op(B_AT_OP_MULT, $1, $3); }
	| fterm '/' uterm	{ $$ = ba_op(B_AT_OP_DIVIDE, $1, $3); }
	| fterm '%' uterm	{ $$ = ba_op(B_AT_OP_MODULO, $1, $3); }
	| uterm
	;

uterm	: '!' uterm		{ $$ = ba_new($2, B_AT_OP_LNOT); }
	| '~' uterm		{ $$ = ba_new($2, B_AT_OP_BNOT); }
	| '-' uterm		{ $$ = ba_new($2, B_AT_OP_NEG); }
	| factor
	;

variable: LVAR			{ $$ = bl_find($1); }
	| GVAR			{ $$ = bg_find($1); }
	| variable '.' NUMBER	{ $$ = bi_find($1, $3); }
	;

factor : '(' expr ')'		{ $$ = $2; }
	| '(' vargs ',' expr ')'{ $$ = ba_new(ba_append($2, $4), B_AT_TUPLE); }
	| NUMBER		{ $$ = ba_new($1, B_AT_LONG); }
	| BUILTIN		{ $$ = ba_new(NULL, $1); }
	| CSTRING		{ $$ = ba_new($1, B_AT_STR); }
	| PVAR
	| PNUM
	| variable
	| mentry
	| func
	| factor OP_ARROW STRING { $$ = bd_new($1, $3); }
	| factor '[' NUMBER ']'	{ $$ = bsub_new($1, $3); }
	;

func	: STR '(' factor ')'		{ $$ = ba_new($3, B_AT_FN_STR); }
	| STR '(' factor ',' expr ')'	{ $$ = ba_op(B_AT_FN_STR, $3, $5); }
	| SIZEOF '(' typename ')'	{ $$ = ba_new($3, B_AT_FN_SIZEOF); }
	| KSYM '(' expr ')'		{ $$ = ba_new($3, B_AT_FN_KSYM); }
	| USYM '(' expr ')'		{ $$ = ba_new($3, B_AT_FN_USYM); }
	| LEN '(' variable ')'		{ $$ = ba_new($3, B_AT_FN_LEN); }
	| NTOP '(' expr ')'		{ $$ = ba_new($3, B_AT_FN_NTOP); }
	| NTOP '(' expr ',' expr ')'	{ $$ = ba_new(ba_append($3, $5), B_AT_FN_NTOP); }
	| STRNCMP '(' expr ',' expr ',' expr ')'
					{ $$ = ba_new(ba_append(ba_append($3, $5), $7), B_AT_FN_STRNCMP); }
	;

typename : STRING			{ $$ = $1; }
	| STRING STRING			{
		size_t len = strlen($1) + 1 + strlen($2) + 1;
		char *s = calloc(len, 1);
		if (s == NULL)
			err(1, NULL);
		snprintf(s, len, "%s %s", $1, $2);
		$$ = s;
	}
	;

vargs	: expr
	| vargs ',' expr		{ $$ = ba_append($1, $3); }
	;

pargs	: expr
	| GVAR ',' expr			{ $$ = ba_append(bg_find($1), $3); }
	;

NL	: /* empty */
	| '\n'
	;

stmt	: ';' NL			{ $$ = NULL; }
	| GVAR '=' expr			{ $$ = bg_store($1, $3); }
	| LVAR '=' expr			{ $$ = bl_store($1, $3); }
	| GVAR '[' vargs ']' '=' mpat	{ $$ = bm_insert($1, $3, $6); }
	| FUNCN '(' vargs ')'		{ $$ = bs_new($1, $3, NULL); }
	| FUNC1 '(' expr ')'		{ $$ = bs_new($1, $3, NULL); }
	| MFUNC '(' variable ')'	{ $$ = bs_new($1, $3, NULL); }
	| FUNC0 '(' ')'			{ $$ = bs_new($1, NULL, NULL); }
	| F_DELETE '(' mentry ')'	{ $$ = bm_op($1, $3, NULL); }
	| F_PRINT '(' pargs ')'		{ $$ = bs_new($1, $3, NULL); }
	| GVAR '=' OP1 '(' expr ')'	{ $$ = bh_inc($1, $5, NULL); }
	| GVAR '=' OP4 '(' expr ',' vargs ')'	{ $$ = bh_inc($1, $5, $7); }
	| GVAR '[' vargs ']' '=' OP1 '(' expr ')'		{ $$ = bhm_inc($1, $3, $8, NULL); }
	| GVAR '[' vargs ']' '=' OP4 '(' expr ',' vargs ')'	{ $$ = bhm_inc($1, $3, $8, $10); }
	| BREAK			{ $$ = bs_new(B_AC_BREAK, NULL, NULL); }
	| CONTINUE		{ $$ = bs_new(B_AC_CONTINUE, NULL, NULL); }
	/* compound assignment: local variables */
	| LVAR OP_PLUSEQ  expr	{ $$ = bl_store($1, ba_op(B_AT_OP_PLUS,   bl_find($1), $3)); }
	| LVAR OP_MINUSEQ expr	{ $$ = bl_store($1, ba_op(B_AT_OP_MINUS,  bl_find($1), $3)); }
	| LVAR OP_MULTEQ  expr	{ $$ = bl_store($1, ba_op(B_AT_OP_MULT,   bl_find($1), $3)); }
	| LVAR OP_DIVEQ   expr	{ $$ = bl_store($1, ba_op(B_AT_OP_DIVIDE, bl_find($1), $3)); }
	| LVAR OP_MODEQ   expr	{ $$ = bl_store($1, ba_op(B_AT_OP_MODULO, bl_find($1), $3)); }
	| LVAR OP_BANDEQ  expr	{ $$ = bl_store($1, ba_op(B_AT_OP_BAND,   bl_find($1), $3)); }
	| LVAR OP_BOREQ   expr	{ $$ = bl_store($1, ba_op(B_AT_OP_BOR,    bl_find($1), $3)); }
	| LVAR OP_XOREQ   expr	{ $$ = bl_store($1, ba_op(B_AT_OP_XOR,    bl_find($1), $3)); }
	| LVAR OP_SHLEQ   expr	{ $$ = bl_store($1, ba_op(B_AT_OP_SHL,    bl_find($1), $3)); }
	| LVAR OP_SHREQ   expr	{ $$ = bl_store($1, ba_op(B_AT_OP_SHR,    bl_find($1), $3)); }
	| LVAR OP_INC		{ $$ = bl_store($1, ba_op(B_AT_OP_PLUS,   bl_find($1), ba_new(1L, B_AT_LONG))); }
	| LVAR OP_DEC		{ $$ = bl_store($1, ba_op(B_AT_OP_MINUS,  bl_find($1), ba_new(1L, B_AT_LONG))); }
	| OP_INC LVAR		{ $$ = bl_store($2, ba_op(B_AT_OP_PLUS,   bl_find($2), ba_new(1L, B_AT_LONG))); }
	| OP_DEC LVAR		{ $$ = bl_store($2, ba_op(B_AT_OP_MINUS,  bl_find($2), ba_new(1L, B_AT_LONG))); }
	/* compound assignment: global scalar variables */
	| GVAR OP_PLUSEQ  expr	{ $$ = bg_store($1, ba_op(B_AT_OP_PLUS,   bg_find($1), $3)); }
	| GVAR OP_MINUSEQ expr	{ $$ = bg_store($1, ba_op(B_AT_OP_MINUS,  bg_find($1), $3)); }
	| GVAR OP_MULTEQ  expr	{ $$ = bg_store($1, ba_op(B_AT_OP_MULT,   bg_find($1), $3)); }
	| GVAR OP_DIVEQ   expr	{ $$ = bg_store($1, ba_op(B_AT_OP_DIVIDE, bg_find($1), $3)); }
	| GVAR OP_MODEQ   expr	{ $$ = bg_store($1, ba_op(B_AT_OP_MODULO, bg_find($1), $3)); }
	| GVAR OP_BANDEQ  expr	{ $$ = bg_store($1, ba_op(B_AT_OP_BAND,   bg_find($1), $3)); }
	| GVAR OP_BOREQ   expr	{ $$ = bg_store($1, ba_op(B_AT_OP_BOR,    bg_find($1), $3)); }
	| GVAR OP_XOREQ   expr	{ $$ = bg_store($1, ba_op(B_AT_OP_XOR,    bg_find($1), $3)); }
	| GVAR OP_SHLEQ   expr	{ $$ = bg_store($1, ba_op(B_AT_OP_SHL,    bg_find($1), $3)); }
	| GVAR OP_SHREQ   expr	{ $$ = bg_store($1, ba_op(B_AT_OP_SHR,    bg_find($1), $3)); }
	| GVAR OP_INC		{ $$ = bg_store($1, ba_op(B_AT_OP_PLUS,   bg_find($1), ba_new(1L, B_AT_LONG))); }
	| GVAR OP_DEC		{ $$ = bg_store($1, ba_op(B_AT_OP_MINUS,  bg_find($1), ba_new(1L, B_AT_LONG))); }
	| OP_INC GVAR		{ $$ = bg_store($2, ba_op(B_AT_OP_PLUS,   bg_find($2), ba_new(1L, B_AT_LONG))); }
	| OP_DEC GVAR		{ $$ = bg_store($2, ba_op(B_AT_OP_MINUS,  bg_find($2), ba_new(1L, B_AT_LONG))); }
	/* compound assignment: map entries (@map[key] op= expr; @map[key]++) */
	| mentry OP_PLUSEQ  expr { $$ = bm_update($1, ba_op(B_AT_OP_PLUS,   $1, $3)); }
	| mentry OP_MINUSEQ expr { $$ = bm_update($1, ba_op(B_AT_OP_MINUS,  $1, $3)); }
	| mentry OP_MULTEQ  expr { $$ = bm_update($1, ba_op(B_AT_OP_MULT,   $1, $3)); }
	| mentry OP_DIVEQ   expr { $$ = bm_update($1, ba_op(B_AT_OP_DIVIDE, $1, $3)); }
	| mentry OP_MODEQ   expr { $$ = bm_update($1, ba_op(B_AT_OP_MODULO, $1, $3)); }
	| mentry OP_BANDEQ  expr { $$ = bm_update($1, ba_op(B_AT_OP_BAND,   $1, $3)); }
	| mentry OP_BOREQ   expr { $$ = bm_update($1, ba_op(B_AT_OP_BOR,    $1, $3)); }
	| mentry OP_XOREQ   expr { $$ = bm_update($1, ba_op(B_AT_OP_XOR,    $1, $3)); }
	| mentry OP_SHLEQ   expr { $$ = bm_update($1, ba_op(B_AT_OP_SHL,    $1, $3)); }
	| mentry OP_SHREQ   expr { $$ = bm_update($1, ba_op(B_AT_OP_SHR,    $1, $3)); }
	| mentry OP_INC		{ $$ = bm_update($1, ba_op(B_AT_OP_PLUS,   $1, ba_new(1L, B_AT_LONG))); }
	| mentry OP_DEC		{ $$ = bm_update($1, ba_op(B_AT_OP_MINUS,  $1, ba_new(1L, B_AT_LONG))); }
	;

stmtblck: IF '(' expr ')' block			{ $$ = bt_new($3, $5, NULL); }
	| IF '(' expr ')' block ELSE block	{ $$ = bt_new($3, $5, $7); }
	| IF '(' expr ')' block ELSE stmtblck	{ $$ = bt_new($3, $5, $7); }
	| FOR '(' LVAR ':' GVAR ')' block	{ $$ = bfor_new($3, $5, $7); }
	| WHILE '(' expr ')' block		{ $$ = bwhile_new($3, $5); }
	;

stmtlist: stmtlist stmtblck		{ $$ = bs_append($1, $2); }
	| stmtlist stmt			{ $$ = bs_append($1, $2); }
	| stmtblck
	| stmt
	;

block	: action
	| stmt ';'
	;

action	: '{' stmtlist '}'		{ $$ = $2; }
	| '{' '}'			{ $$ = NULL; }
	;

%%

struct bt_arg*
get_varg(int index)
{
	extern int nargs;
	extern char **vargs;
	const char *errstr = NULL;
	long val;

	if (1 <= index && index <= nargs) {
		val = (long)strtonum(vargs[index-1], LONG_MIN, LONG_MAX,
		    &errstr);
		if (errstr == NULL)
			return ba_new(val, B_AT_LONG);
		return ba_new(vargs[index-1], B_AT_STR);
	}

	return ba_new(0L, B_AT_NIL);
}

struct bt_arg*
get_nargs(void)
{
	extern int nargs;

	return ba_new((long) nargs, B_AT_LONG);
}

/* Create a new rule, representing  "probe / filter / { action }" */
struct bt_rule *
br_new(struct bt_probe *probe, struct bt_filter *filter, struct bt_stmt *head)
{
	struct bt_rule *br;

	br = calloc(1, sizeof(*br));
	if (br == NULL)
		err(1, "bt_rule: calloc");
	/* SLIST_INSERT_HEAD() nullify the next pointer. */
	SLIST_FIRST(&br->br_probes) = probe;
	br->br_filter = filter;
	/* SLIST_INSERT_HEAD() nullify the next pointer. */
	SLIST_FIRST(&br->br_action) = head;

	SLIST_FIRST(&br->br_variables) = SLIST_FIRST(&l_variables);
	SLIST_INIT(&l_variables);

	do {
		if (probe->bp_type != B_PT_PROBE)
			continue;
		g_nprobes++;
	} while ((probe = SLIST_NEXT(probe, bp_next)) != NULL);

	TAILQ_INSERT_TAIL(&g_rules, br, br_next);

	return br;
}

/* Create a new condition */
struct bt_filter *
bc_new(struct bt_arg *term, enum bt_argtype op, struct bt_arg *ba)
{
	struct bt_filter *bf;

	bf = calloc(1, sizeof(*bf));
	if (bf == NULL)
		err(1, "bt_filter: calloc");

	bf->bf_condition = bs_new(B_AC_TEST, ba_op(op, term, ba), NULL);

	return bf;
}

/* Create a new if/else test */
struct bt_stmt *
bt_new(struct bt_arg *ba, struct bt_stmt *condbs, struct bt_stmt *elsebs)
{
	struct bt_arg *bop;
	struct bt_cond *bc;

	bop = ba_op(B_AT_OP_NE, NULL, ba);

	bc = calloc(1, sizeof(*bc));
	if (bc == NULL)
		err(1, "bt_cond: calloc");
	bc->bc_condbs = condbs;
	bc->bc_elsebs = elsebs;

	return bs_new(B_AC_TEST, bop, (struct bt_var *)bc);
}

/*
 * interval and profile support the same units.
 */
static uint64_t
bp_unit_to_nsec(const char *unit, long value)
{
	static const struct {
		const char *name;
		enum { UNIT_HZ, UNIT_US, UNIT_MS, UNIT_S } id;
		long long max;
	} units[] = {
		{ .name = "hz", .id = UNIT_HZ, .max = 1000000LL },
		{ .name = "us", .id = UNIT_US, .max = LLONG_MAX / 1000 },
		{ .name = "ms", .id = UNIT_MS, .max = LLONG_MAX / 1000000 },
		{ .name = "s", .id = UNIT_S, .max = LLONG_MAX / 1000000000 },
	};
	size_t i;

	for (i = 0; i < nitems(units); i++) {
		if (strcmp(units[i].name, unit) == 0) {
			if (value < 1)
				yyerror("Number is invalid: %ld", value);
			if (value > units[i].max)
				yyerror("Number is too large: %ld", value);
			switch (units[i].id) {
			case UNIT_HZ:
				return (1000000000LLU / value);
			case UNIT_US:
				return (value * 1000LLU);
			case UNIT_MS:
				return (value * 1000000LLU);
			case UNIT_S:
				return (value * 1000000000LLU);
			}
		}
	}
	yyerror("Invalid unit: %s", unit);
	return 0;
}

/* Create a new probe */
struct bt_probe *
bp_new(const char *prov, const char *func, const char *name, long number)
{
	struct bt_probe *bp;
	enum bt_ptype ptype;

	if (prov == NULL && func == NULL && name == NULL)
		ptype = number; /* BEGIN or END */
	else
		ptype = B_PT_PROBE;

	bp = calloc(1, sizeof(*bp));
	if (bp == NULL)
		err(1, "bt_probe: calloc");
	bp->bp_prov = prov;
	bp->bp_func = func;
	bp->bp_name = name;
	if (ptype == B_PT_PROBE && name == NULL)
		bp->bp_nsecs = bp_unit_to_nsec(func, number);
	bp->bp_type = ptype;

	return bp;
}

/*
 * Link two probes together, to build a probe list attached to
 * a single action.
 */
struct bt_probe *
bp_append(struct bt_probe *bp0, struct bt_probe *bp1)
{
	struct bt_probe *bp = bp0;

	assert(bp1 != NULL);

	if (bp0 == NULL)
		return bp1;

	while (SLIST_NEXT(bp, bp_next) != NULL)
		bp = SLIST_NEXT(bp, bp_next);

	SLIST_INSERT_AFTER(bp, bp1, bp_next);

	return bp0;
}

/* Create a new argument */
struct bt_arg *
ba_new0(void *val, enum bt_argtype type)
{
	struct bt_arg *ba;

	ba = calloc(1, sizeof(*ba));
	if (ba == NULL)
		err(1, "bt_arg: calloc");
	ba->ba_value = val;
	ba->ba_type = type;

	return ba;
}

/*
 * Create a struct member dereference node: base->field.
 * base must be an argN builtin or a B_AT_FN_DEREF node (for chains like
 * arg0->ptr->field).  The offset, size, typeid, and slot fields are filled
 * at setup time in btrace.c when CTF type information is resolved per-probe.
 */
struct bt_arg *
bd_new(struct bt_arg *base, const char *field)
{
	struct bt_deref *bd;

	if (base->ba_type != B_AT_FN_DEREF &&
	    base->ba_type != B_AT_FN_SUBSCRIPT &&
	    (base->ba_type < B_AT_BI_ARG0 || base->ba_type > B_AT_BI_ARG9))
		yyerror("'->' can only be applied to argN, argN[N], or "
		    "argN->field");

	bd = calloc(1, sizeof(*bd));
	if (bd == NULL)
		err(1, "bt_deref: calloc");
	bd->bd_base = base;
	bd->bd_field = field;
	bd->bd_slot = BD_SLOT_UNSET;	/* not yet assigned */

	return ba_new(bd, B_AT_FN_DEREF);
}

/*
 * Link two arguments together, to build an argument list used in
 * operators, tuples and function calls.
 */
struct bt_arg *
ba_append(struct bt_arg *da0, struct bt_arg *da1)
{
	struct bt_arg *ba = da0;

	assert(da1 != NULL);

	if (da0 == NULL)
		return da1;

	while (SLIST_NEXT(ba, ba_next) != NULL)
		ba = SLIST_NEXT(ba, ba_next);

	SLIST_INSERT_AFTER(ba, da1, ba_next);

	return da0;
}

/* Create an operator argument */
struct bt_arg *
ba_op(enum bt_argtype op, struct bt_arg *da0, struct bt_arg *da1)
{
	return ba_new(ba_append(da0, da1), op);
}

/* Create a new statement: function call or assignment. */
struct bt_stmt *
bs_new(enum bt_action act, struct bt_arg *head, struct bt_var *var)
{
	struct bt_stmt *bs;

	bs = calloc(1, sizeof(*bs));
	if (bs == NULL)
		err(1, "bt_stmt: calloc");
	bs->bs_act = act;
	bs->bs_var = var;
	/* SLIST_INSERT_HEAD() nullify the next pointer. */
	SLIST_FIRST(&bs->bs_args) = head;

	return bs;
}

/* Link two statements together, to build an 'action'. */
struct bt_stmt *
bs_append(struct bt_stmt *ds0, struct bt_stmt *ds1)
{
	struct bt_stmt *bs = ds0;

	if (ds0 == NULL)
		return ds1;

	if (ds1 == NULL)
		return ds0;

	while (SLIST_NEXT(bs, bs_next) != NULL)
		bs = SLIST_NEXT(bs, bs_next);

	SLIST_INSERT_AFTER(bs, ds1, bs_next);

	return ds0;
}

const char *
bv_name(struct bt_var *bv)
{
	if (strncmp(bv->bv_name, UNNAMED_MAP, strlen(UNNAMED_MAP)) == 0)
		return "";
	return bv->bv_name;
}

/* Allocate a variable. */
struct bt_var *
bv_new(const char *vname)
{
	struct bt_var *bv;

	bv = calloc(1, sizeof(*bv));
	if (bv == NULL)
		err(1, "bt_var: calloc");
	bv->bv_name = vname;

	return bv;
}

/* Return the global variable corresponding to `vname'. */
struct bt_var *
bg_lookup(const char *vname)
{
	struct bt_var *bv;

	SLIST_FOREACH(bv, &g_variables, bv_next) {
		if (strcmp(vname, bv->bv_name) == 0)
			break;
	}

	return bv;
}

/* Find or allocate a global variable corresponding to `vname' */
struct bt_var *
bg_get(const char *vname)
{
	struct bt_var *bv;

	bv = bg_lookup(vname);
	if (bv == NULL) {
		bv = bv_new(vname);
		SLIST_INSERT_HEAD(&g_variables, bv, bv_next);
	}

	return bv;
}

/* Create an "argument" that points to an existing untyped variable. */
struct bt_arg *
bg_find(const char *vname)
{
	return ba_new(bg_get(vname), B_AT_VAR);
}

/* Create a 'store' statement to assign a value to a global variable. */
struct bt_stmt *
bg_store(const char *vname, struct bt_arg *vval)
{
	return bs_new(B_AC_STORE, vval, bg_get(vname));
}

/* Return the local variable corresponding to `vname'. */
struct bt_var *
bl_lookup(const char *vname)
{
	struct bt_var *bv;

	SLIST_FOREACH(bv, &l_variables, bv_next) {
		if (strcmp(vname, bv->bv_name) == 0)
			break;
	}

	return bv;
}

/* Find or create a local variable corresponding to `vname' */
struct bt_arg *
bl_find(const char *vname)
{
	struct bt_var *bv;

	bv = bl_lookup(vname);
	if (bv == NULL) {
		bv = bv_new(vname);
		SLIST_INSERT_HEAD(&l_variables, bv, bv_next);
	}

	return ba_new(bv, B_AT_VAR);
}

/* Create a 'store' statement to assign a value to a local variable. */
struct bt_stmt *
bl_store(const char *vname, struct bt_arg *vval)
{
	struct bt_var *bv;

	bv = bl_lookup(vname);
	if (bv == NULL) {
		bv = bv_new(vname);
		SLIST_INSERT_HEAD(&l_variables, bv, bv_next);
	}

	return bs_new(B_AC_STORE, vval, bv);
}

/* Create an argument that points to a tuple variable and a given index */
struct bt_arg *
bi_find(struct bt_arg *ba, unsigned long index)
{
	struct bt_var *bv = ba->ba_value;

	ba = ba_new(bv, B_AT_TMEMBER);
	ba->ba_key = (void *)index;
	return ba;
}

struct bt_stmt *
bm_op(enum bt_action mact, struct bt_arg *ba, struct bt_arg *mval)
{
	return bs_new(mact, ba, (struct bt_var *)mval);
}

/* Create a 'map store' statement to assign a value to a map entry. */
struct bt_stmt *
bm_insert(const char *mname, struct bt_arg *mkey, struct bt_arg *mval)
{
	struct bt_arg *ba;

	if (mkey->ba_type == B_AT_TUPLE)
		yyerror("tuple cannot be used as map key");

	ba = ba_new(bg_get(mname), B_AT_MAP);
	ba->ba_key = mkey;

	return bs_new(B_AC_INSERT, ba, (struct bt_var *)mval);
}

/* Create an argument that points to a map variable and attach a key to it. */
struct bt_arg *
bm_find(const char *vname, struct bt_arg *mkey)
{
	struct bt_arg *ba;

	ba = ba_new(bg_get(vname), B_AT_MAP);
	ba->ba_key = mkey;
	return ba;
}

/*
 * Create a map compound-assignment statement: @map[key] op= val.
 * 'mentry' is a B_AT_MAP arg from bm_find(); 'mval' is the new computed value.
 * A fresh B_AT_MAP arg is allocated for the write target so that the read
 * reference inside 'mval' and the write target share var+key without aliasing
 * the ba_next pointer (which ba_op modifies on the read side).
 */
struct bt_stmt *
bm_update(struct bt_arg *mentry, struct bt_arg *mval)
{
	struct bt_arg *ba;

	ba = ba_new(mentry->ba_value, B_AT_MAP);
	ba->ba_key = mentry->ba_key;
	return bs_new(B_AC_INSERT, ba, (struct bt_var *)mval);
}

/*
 * Histograms implemented using associative arrays (maps).  In the case
 * of linear histograms `ba_key' points to a list of (min, max, step)
 * necessary to "bucketize" any value.
 */
struct bt_stmt *
bh_inc(const char *hname, struct bt_arg *hval, struct bt_arg *hrange)
{
	struct bt_arg *ba;

	if (hrange == NULL) {
		/* Power-of-2 histogram */
	} else {
		long min = 0, max;
		int count = 0;

		/* Linear histogram */
		for (ba = hrange; ba != NULL; ba = SLIST_NEXT(ba, ba_next)) {
			if (++count > 3)
				yyerror("too many arguments");
			if (ba->ba_type != B_AT_LONG)
				yyerror("type invalid");

			switch (count) {
			case 1:
				min = (long)ba->ba_value;
				if (min >= 0)
					break;
				yyerror("negative minimum");
			case 2:
				max = (long)ba->ba_value;
				if (max > min)
					break;
				yyerror("maximum smaller than minimum (%d < %d)",
				    max,  min);
			case 3:
				break;
			default:
				assert(0);
			}
		}
		if (count < 3)
			yyerror("%d missing arguments", 3 - count);
	}

	ba = ba_new(bg_get(hname), B_AT_HIST);
	ba->ba_key = hrange;
	return bs_new(B_AC_BUCKETIZE, ba, (struct bt_var *)hval);
}

/*
 * Keyed histogram: @map[key] = hist(val) or @map[key] = lhist(val, min, max, step)
 */
struct bt_stmt *
bhm_inc(const char *mname, struct bt_arg *mkey, struct bt_arg *hval,
    struct bt_arg *hrange)
{
	struct bt_arg *bmap, *bhist;
	struct bt_stmt *bs;

	if (hrange != NULL) {
		struct bt_arg *ba;
		long min = 0, max;
		int count = 0;

		for (ba = hrange; ba != NULL; ba = SLIST_NEXT(ba, ba_next)) {
			if (++count > 3)
				yyerror("too many arguments");
			if (ba->ba_type != B_AT_LONG)
				yyerror("type invalid");
			switch (count) {
			case 1:
				min = (long)ba->ba_value;
				if (min >= 0)
					break;
				yyerror("negative minimum");
			case 2:
				max = (long)ba->ba_value;
				if (max > min)
					break;
				yyerror("maximum smaller than minimum (%d < %d)",
				    max, min);
			case 3:
				break;
			default:
				assert(0);
			}
		}
		if (count < 3)
			yyerror("%d missing arguments", 3 - count);
	}

	bmap = bm_find(mname, mkey);
	bhist = ba_new(NULL, B_AT_HIST);	/* sentinel: ba_value=NULL, ba_key=range */
	bhist->ba_key = hrange;
	bs = bs_new(B_AC_MAPHIST, bmap, (struct bt_var *)hval);
	ba_append(bmap, bhist);
	return bs;
}

/*
 * For-loop over a map:	for ($kv : @map) { }
 *
 * Each iteration binds $kv to a (key, value) tuple for one map entry.
 * $kv.0 is the key string; $kv.1 is the aggregated value.
 */
struct bt_stmt *
bfor_new(const char *varname, const char *mapname, struct bt_stmt *body)
{
	struct bt_var *lvar;
	struct bt_for *bfor;
	struct bt_arg *mapref;

	lvar = bl_lookup(varname);
	if (lvar == NULL) {
		lvar = bv_new(varname);
		SLIST_INSERT_HEAD(&l_variables, lvar, bv_next);
	}

	bfor = calloc(1, sizeof(*bfor));
	if (bfor == NULL)
		err(1, "bfor: calloc");
	bfor->bfor_var = lvar;
	bfor->bfor_body = body;

	mapref = ba_new(bg_get(mapname), B_AT_VAR);
	return bs_new(B_AC_FORMAP, mapref, (struct bt_var *)bfor);
}

/*
 * Array subscript node: base[index]
 * base must be an argN builtin, a B_AT_FN_DEREF, or a B_AT_FN_SUBSCRIPT.
 * index must be a non-negative constant integer.
 * The element stride and capture slot are filled at setup time in btrace.c.
 */
struct bt_arg *
bsub_new(struct bt_arg *base, long index)
{
	struct bt_subscript *bss;

	if (base->ba_type != B_AT_FN_DEREF &&
	    base->ba_type != B_AT_FN_SUBSCRIPT &&
	    (base->ba_type < B_AT_BI_ARG0 || base->ba_type > B_AT_BI_ARG9))
		yyerror("'[]' can only be applied to argN, argN[N], or "
		    "argN->field");
	if (index < 0)
		yyerror("subscript index must be non-negative");

	bss = calloc(1, sizeof(*bss));
	if (bss == NULL)
		err(1, "bt_subscript: calloc");
	bss->bss_base = base;
	bss->bss_index = index;
	bss->bss_slot = BSS_SLOT_UNSET;

	return ba_new(bss, B_AT_FN_SUBSCRIPT);
}

/*
 * Ternary expression: cond ? then : else
 */
struct bt_arg *
btern_new(struct bt_arg *cond, struct bt_arg *then_ba, struct bt_arg *else_ba)
{
	struct bt_ternary *btr;

	btr = calloc(1, sizeof(*btr));
	if (btr == NULL)
		err(1, "bt_ternary: calloc");
	btr->btr_cond = cond;
	btr->btr_then = then_ba;
	btr->btr_else = else_ba;

	return ba_new(btr, B_AT_OP_TERN);
}

/*
 * While-loop: while (expr) { body }
 */
struct bt_stmt *
bwhile_new(struct bt_arg *cond, struct bt_stmt *body)
{
	struct bt_arg *bop;
	struct bt_while *bwh;

	bop = ba_op(B_AT_OP_NE, NULL, cond);

	bwh = calloc(1, sizeof(*bwh));
	if (bwh == NULL)
		err(1, "bwhile: calloc");
	bwh->bwh_body = body;

	return bs_new(B_AC_WHILE, bop, (struct bt_var *)bwh);
}

struct keyword {
	const char	*word;
	int		 token;
	int		 type;
};

int
kw_cmp(const void *str, const void *xkw)
{
	return (strcmp(str, ((const struct keyword *)xkw)->word));
}

struct keyword *
lookup(char *s)
{
	static const struct keyword kws[] = {
		{ "AF_INET",	BUILTIN,	B_AT_BI_AF_INET },
		{ "AF_INET6",	BUILTIN,	B_AT_BI_AF_INET6 },
		{ "BEGIN",	BEGIN,		B_PT_BEGIN },
		{ "END",	END,		B_PT_END },
		{ "arg0",	BUILTIN,	B_AT_BI_ARG0 },
		{ "arg1",	BUILTIN,	B_AT_BI_ARG1 },
		{ "arg2",	BUILTIN,	B_AT_BI_ARG2 },
		{ "arg3",	BUILTIN,	B_AT_BI_ARG3 },
		{ "arg4",	BUILTIN,	B_AT_BI_ARG4 },
		{ "arg5",	BUILTIN,	B_AT_BI_ARG5 },
		{ "arg6",	BUILTIN,	B_AT_BI_ARG6 },
		{ "arg7",	BUILTIN,	B_AT_BI_ARG7 },
		{ "arg8",	BUILTIN,	B_AT_BI_ARG8 },
		{ "arg9",	BUILTIN,	B_AT_BI_ARG9 },
		{ "avg",	MOP1,		B_AT_MF_AVG },
		{ "break",	BREAK,		0 },
		{ "clear",	MFUNC,		B_AC_CLEAR },
		{ "comm",	BUILTIN,	B_AT_BI_COMM },
		{ "continue",	CONTINUE,	0 },
		{ "count",	MOP0, 		B_AT_MF_COUNT },
		{ "cpu",	BUILTIN,	B_AT_BI_CPU },
		{ "delete",	F_DELETE,	B_AC_DELETE },
		{ "elapsed",	BUILTIN,	B_AT_BI_ELAPSED },
		{ "else",	ELSE,		0 },
		{ "exit",	FUNC0,		B_AC_EXIT },
		{ "for",	FOR,		0 },
		{ "gid",	BUILTIN,	B_AT_BI_GID },
		{ "hist",	OP1,		0 },
		{ "if",		IF,		0 },
		{ "kstack",	BUILTIN,	B_AT_BI_KSTACK },
		{ "ksym",	KSYM,		B_AT_FN_KSYM },
		{ "len",	LEN,		B_AT_FN_LEN },
		{ "lhist",	OP4,		0 },
		{ "max",	MOP1,		B_AT_MF_MAX },
		{ "min",	MOP1,		B_AT_MF_MIN },
		{ "nsecs",	BUILTIN,	B_AT_BI_NSECS },
		{ "ntop",	NTOP,		B_AT_FN_NTOP },
		{ "pid",	BUILTIN,	B_AT_BI_PID },
		{ "print",	F_PRINT,	B_AC_PRINT },
		{ "printf",	FUNCN,		B_AC_PRINTF },
		{ "probe",	BUILTIN,	B_AT_BI_PROBE },
		{ "retval",	BUILTIN,	B_AT_BI_RETVAL },
		{ "sizeof",	SIZEOF,		B_AT_FN_SIZEOF },
		{ "stats",	MOP1,		B_AT_MF_STATS },
		{ "str",	STR,		B_AT_FN_STR },
		{ "strncmp",	STRNCMP,	B_AT_FN_STRNCMP },
		{ "sum",	MOP1,		B_AT_MF_SUM },
		{ "tid",	BUILTIN,	B_AT_BI_TID },
		{ "time",	FUNC1,		B_AC_TIME },
		{ "uid",	BUILTIN,	B_AT_BI_UID },
		{ "ustack",	BUILTIN,	B_AT_BI_USTACK },
		{ "usym",	USYM,		B_AT_FN_USYM },
		{ "while",	WHILE,		0 },
		{ "zero",	MFUNC,		B_AC_ZERO },
	};

	return bsearch(s, kws, nitems(kws), sizeof(kws[0]), kw_cmp);
}

int
peek(void)
{
	if (pbuf != NULL) {
		if (pindex < plen)
			return pbuf[pindex];
	}
	return EOF;
}

int
lgetc(void)
{
	if (pbuf != NULL) {
		if (pindex < plen) {
			yylval.colno++;
			return pbuf[pindex++];
		}
	}
	return EOF;
}

void
lungetc(void)
{
	if (pbuf != NULL && pindex > 0) {
		yylval.colno--;
		pindex--;
	}
}

static inline int
allowed_to_end_number(int x)
{
	return (isspace(x) || x == ')' || x == '/' || x == '{' || x == ';' ||
	    x == ']' || x == ',' || x == '=');
}

static inline int
allowed_in_string(int x)
{
	return (isalnum(x) || x == '_');
}

static inline int
allowed_in_probe_string(int x)
{
	return (isalnum(x) || x == '_' || x == '*' || x == '?');
}

static int
skip(void)
{
	int c;

again:
	/* skip whitespaces */
	for (c = lgetc(); isspace(c); c = lgetc()) {
		if (c == '\n') {
			yylval.lineno++;
			yylval.colno = 0;
		}
	}

	/* skip single line comments and shell magic */
	if ((c == '/' && peek() == '/') ||
	    (yylval.lineno == 1 && yylval.colno == 1 && c == '#' &&
	     peek() == '!')) {
		for (c = lgetc(); c != EOF; c = lgetc()) {
			if (c == '\n') {
				yylval.lineno++;
				yylval.colno = 0;
				goto again;
			}
		}
	}

	/* skip multi line comments */
	if (c == '/' && peek() == '*') {
		int pc;

		for (pc = 0, c = lgetc(); c != EOF; c = lgetc()) {
			if (pc == '*' && c == '/')
				goto again;
			else if (c == '\n')
				yylval.lineno++;
			pc = c;
		}
	}

	return c;
}

int
yylex(void)
{
	unsigned char	 buf[1024];
	unsigned char	*ebuf, *p, *str;
	int		 c;

	ebuf = buf + sizeof(buf);
	p = buf;

again:
	c = skip();

	switch (c) {
	case '!':
	case '=':
		if (peek() == '=') {
			lgetc();
			return (c == '=') ? OP_EQ : OP_NE;
		}
		return c;
	case '<':
		if (peek() == '<') {
			lgetc();
			if (peek() == '=') {
				lgetc();
				return OP_SHLEQ;
			}
			return OP_SHL;
		}
		if (peek() == '=') {
			lgetc();
			return OP_LE;
		}
		return OP_LT;
	case '>':
		if (peek() == '>') {
			lgetc();
			if (peek() == '=') {
				lgetc();
				return OP_SHREQ;
			}
			return OP_SHR;
		}
		if (peek() == '=') {
			lgetc();
			return OP_GE;
		}
		return OP_GT;
	case '+':
		if (peek() == '+') {
			lgetc();
			return OP_INC;
		}
		if (peek() == '=') {
			lgetc();
			return OP_PLUSEQ;
		}
		return c;
	case '*':
		if (!pflag && peek() == '=') {
			lgetc();
			return OP_MULTEQ;
		}
		if (!pflag)
			return c;
		break;	/* pflag: let word-parser consume '*' as probe wildcard */
	case '%':
		if (peek() == '=') {
			lgetc();
			return OP_MODEQ;
		}
		return c;
	case '^':
		if (peek() == '=') {
			lgetc();
			return OP_XOREQ;
		}
		return c;
	case '~':
		return c;
	case '?':
		if (!pflag)
			return c;
		break;	/* pflag: let word-parser consume '?' as probe wildcard */
	case '&':
		if (peek() == '&') {
			lgetc();
			return OP_LAND;
		}
		if (peek() == '=') {
			lgetc();
			return OP_BANDEQ;
		}
		return c;
	case '|':
		if (peek() == '|') {
			lgetc();
			return OP_LOR;
		}
		if (peek() == '=') {
			lgetc();
			return OP_BOREQ;
		}
		return c;
	case '-':
		if (peek() == '-') {
			lgetc();
			return OP_DEC;
		}
		if (peek() == '>') {
			lgetc();
			return OP_ARROW;
		}
		if (peek() == '=') {
			lgetc();
			return OP_MINUSEQ;
		}
		return c;
	case '/':
		if (peek() == '=') {
			lgetc();
			return OP_DIVEQ;
		}
		while (isspace(peek())) {
			if (lgetc() == '\n') {
				yylval.lineno++;
				yylval.colno = 0;
			}
		}
		if (peek() == '{' || peek() == '/' || peek() == '\n')
			return ENDFILT;
		/* FALLTHROUGH */
	case ',':
	case '(':
	case ')':
	case '{':
	case '}':
	case ':':
	case ';':
		return c;
	case '$':
		c = lgetc();
		if (c == '#') {
			yylval.v.arg = get_nargs();
			return PNUM;
		} else if (isdigit(c)) {
			do {
				*p++ = c;
				if (p == ebuf) {
					yyerror("line too long");
					return ERROR;
				}
			} while ((c = lgetc()) != EOF && isdigit(c));
			lungetc();
			*p = '\0';
			if (c == EOF || allowed_to_end_number(c)) {
				const char *errstr = NULL;
				int num;

				num = strtonum(buf, 1, INT_MAX, &errstr);
				if (errstr) {
					yyerror("'$%s' is %s", buf, errstr);
					return ERROR;
				}

				yylval.v.arg = get_varg(num);
				return PVAR;
			}
		} else if (isalpha(c)) {
			do {
				*p++ = c;
				if (p == ebuf) {
					yyerror("line too long");
					return ERROR;
				}
			} while ((c = lgetc()) != EOF && allowed_in_string(c));
			lungetc();
			*p = '\0';
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "%s", __func__);
			return LVAR;
		}
		yyerror("'$%s%c' is an invalid variable name", buf, c);
		return ERROR;
		break;
	case '@':
		c = lgetc();
		/* check for unnamed map '@' */
		if (isalpha(c)) {
			do {
				*p++ = c;
				if (p == ebuf) {
					yyerror("line too long");
					return ERROR;
				}
			} while ((c = lgetc()) != EOF && allowed_in_string(c));
			lungetc();
			*p = '\0';
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "%s", __func__);
			return GVAR;
		} else if (allowed_to_end_number(c) || c == '[') {
			lungetc();
			*p = '\0';
			yylval.v.string = UNNAMED_MAP;
			return GVAR;
		}
		yyerror("'@%s%c' is an invalid variable name", buf, c);
		return ERROR;
		break;
	case EOF:
		return 0;
	case '"':
		/* parse C-like string */
		while ((c = lgetc()) != EOF) {
			if (c == '"') {
				/* handle multi-line strings */
				c = skip();
				if (c == '"')
					continue;
				else
					lungetc();
				break;
			}
			if (c == '\\') {
				c = lgetc();
				switch (c) {
				case '\\':	c = '\\';	break;
				case '\'':	c = '\'';	break;
				case '"':	c = '"';	break;
				case 'a':	c = '\a';	break;
				case 'b':	c = '\b';	break;
				case 'e':	c = 033;	break;
				case 'f':	c = '\f';	break;
				case 'n':	c = '\n';	break;
				case 'r':	c = '\r';	break;
				case 't':	c = '\t';	break;
				case 'v':	c = '\v';	break;
				default:
					yyerror("'%c' unsupported escape", c);
					return ERROR;
				}
			}
			*p++ = c;
			if (p == ebuf) {
				yyerror("line too long");
				return ERROR;
			}
		}
		if (c == EOF) {
			yyerror("\"%s\" invalid EOF", buf);
			return ERROR;
		}
		*p++ = '\0';
		if ((str = strdup(buf)) == NULL)
			err(1, "%s", __func__);
		yylval.v.string = str;
		return CSTRING;
	default:
		break;
	}

	/* parsing number */
	if (isdigit(c)) {
		do {
			*p++ = c;
			if (p == ebuf) {
				yyerror("line too long");
				return ERROR;
			}
		} while ((c = lgetc()) != EOF &&
		    (isxdigit(c) || c == 'x' || c == 'X'));
		lungetc();
		if (c == EOF || allowed_to_end_number(c)) {
			*p = '\0';
			errno = 0;
			yylval.v.number = strtol(buf, NULL, 0);
			if (errno == ERANGE) {
				/*
				 * Characters are already validated, so only
				 * check ERANGE.
				 */
				yyerror("%sflow", (yylval.v.number == LONG_MIN)
				    ? "under" : "over");
				return ERROR;
			}
			return NUMBER;
		} else {
			while (p > buf + 1) {
				--p;
				lungetc();
			}
			c = *--p;
		}
	}

	/* parsing next word */
	if (allowed_in_string(c) || (pflag && (c == '*' || c == '?'))) {
		struct keyword *kwp;
		do {
			*p++ = c;
			if (p == ebuf) {
				yyerror("line too long");
				return ERROR;
			}
		} while ((c = lgetc()) != EOF &&
		    (pflag ? allowed_in_probe_string(c)
			   : allowed_in_string(c)));
		lungetc();
		*p = '\0';
		kwp = lookup(buf);
		if (kwp == NULL || pflag) {
			if (kwp == NULL) {
				if ((yylval.v.string = strdup(buf)) == NULL)
					err(1, "%s", __func__);
			} else {
				yylval.v.string = kwp->word;
			}
			return STRING;
		}
		if (beflag) {
			/* Interpret tokens in a BEGIN/END context. */
			if (kwp->type >= B_AT_BI_ARG0 &&
			    kwp->type <= B_AT_BI_ARG9)
				yyerror("the %s builtin cannot be used with "
				    "BEGIN or END probes", kwp->word);
		}
		yylval.v.i = kwp->type;
		return kwp->token;
	}

	if (c == '\n') {
		yylval.lineno++;
		yylval.colno = 0;
	}
	if (c == EOF)
		return 0;
	return c;
}

void
pprint_syntax_error(void)
{
	char line[BUFSIZ];
	int c, indent = yylval.colno;
	size_t i;

	strlcpy(line, &pbuf[pindex - yylval.colno], sizeof(line));

	for (i = 0; line[i] != '\0' && (c = line[i]) != '\n'; i++) {
		if (c == '\t')
			indent += (8 - 1);
		fputc(c, stderr);
	}

	fprintf(stderr, "\n%*c\n", indent, '^');
}

void
yyerror(const char *fmt, ...)
{
	const char *prefix;
	va_list	va;

	prefix = (yylval.filename != NULL) ? yylval.filename : getprogname();

	fprintf(stderr, "%s:%d:%d: ", prefix, yylval.lineno, yylval.colno);
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	fprintf(stderr, ":\n");

	pprint_syntax_error();

	perrors++;
}

int
btparse(const char *str, size_t len, const char *filename, int debug)
{
	if (debug > 0)
		yydebug = 1;
	pbuf = str;
	plen = len;
	pindex = 0;
	yylval.filename = filename;
	yylval.lineno = 1;

	yyparse();
	if (perrors)
		return perrors;

	assert(SLIST_EMPTY(&l_variables));

	return 0;
}
