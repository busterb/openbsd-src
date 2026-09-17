/*	$OpenBSD: constraint.c,v 1.65 2026/09/10 15:06:22 deraadt Exp $	*/

/*
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <imsg.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <tls.h>
#include <pwd.h>
#include <math.h>

#include "ntpd.h"

#define	IMF_FIXDATE	"%a, %d %h %Y %T GMT"
#define	X509_DATE	"%Y-%m-%d %T UTC"

int	 constraint_addr_init(struct constraint *);
void	 constraint_addr_head_clear(struct constraint *);
struct constraint *
	 constraint_byid(u_int32_t);
int	 constraint_close(u_int32_t);
void	 constraint_update(void);
int	 constraint_cmp(const void *, const void *);

struct httpsdate *
	 httpsdate_init(const char *, const char *, const char *,
	    const char *, const u_int8_t *, size_t, int);
void	 httpsdate_free(void *);
int	 httpsdate_request(struct httpsdate *, struct timeval *, int);
void	*httpsdate_query(const char *, const char *, const char *,
	    const char *, const u_int8_t *, size_t,
	    struct timeval *, struct timeval *, int);

char	*tls_readline(struct tls *, size_t *, size_t *, struct timeval *);

u_int constraint_cnt;
extern u_int peer_cnt;
extern struct imsgbuf *ibuf;		/* priv */
extern struct imsgbuf *ibuf_main;	/* chld */

struct httpsdate {
	char			*tls_addr;
	char			*tls_port;
	char			*tls_hostname;
	char			*tls_path;
	char			*tls_request;
	struct tls_config	*tls_config;
	struct tls		*tls_ctx;
	struct tm		 tls_tm;
};

int
constraint_init(struct constraint *cstr)
{
	cstr->state = STATE_NONE;
	cstr->last = getmonotime();
	cstr->constraint = 0;
	cstr->senderrors = 0;

	return (constraint_addr_init(cstr));
}

int
constraint_addr_init(struct constraint *cstr)
{
	struct sockaddr_in	*sa_in;
	struct sockaddr_in6	*sa_in6;
	struct ntp_addr		*h;

	if (cstr->state == STATE_DNS_INPROGRESS)
		return (0);

	if (cstr->addr_head.a == NULL) {
		priv_dns(IMSG_CONSTRAINT_DNS, cstr->addr_head.name, cstr->id);
		cstr->state = STATE_DNS_INPROGRESS;
		return (0);
	}

	h = cstr->addr;
	switch (h->ss.ss_family) {
	case AF_INET:
		sa_in = (struct sockaddr_in *)&h->ss;
		if (ntohs(sa_in->sin_port) == 0)
			sa_in->sin_port = htons(443);
		cstr->state = STATE_DNS_DONE;
		break;
	case AF_INET6:
		sa_in6 = (struct sockaddr_in6 *)&h->ss;
		if (ntohs(sa_in6->sin6_port) == 0)
			sa_in6->sin6_port = htons(443);
		cstr->state = STATE_DNS_DONE;
		break;
	default:
		/* XXX king bula sez it? */
		fatalx("wrong AF in constraint_addr_init");
		/* NOTREACHED */
	}

	return (1);
}

void
constraint_addr_head_clear(struct constraint *cstr)
{
	host_dns_free(cstr->addr_head.a);
	cstr->addr_head.a = NULL;
	cstr->addr = NULL;
}

int
constraint_query(struct constraint *cstr, int synced)
{
	time_t			 now;
	struct ntp_addr_msg	 am;
	struct iovec		 iov[3];
	int			 iov_cnt = 0;

	now = getmonotime();

	switch (cstr->state) {
	case STATE_DNS_DONE:
		/* Proceed and query the time */
		break;
	case STATE_DNS_TEMPFAIL:
		if (now > cstr->last + (cstr->dnstries >= TRIES_AUTO_DNSFAIL ?
		    CONSTRAINT_RETRY_INTERVAL : INTERVAL_AUIO_DNSFAIL)) {
			cstr->dnstries++;
			/* Retry resolving the address */
			constraint_init(cstr);
			return 0;
		}
		return (-1);
	case STATE_QUERY_SENT:
		/*
		 * The caller should expect a reply.  The constraint engine
		 * enforces CONSTRAINT_SCAN_TIMEOUT itself and reports failure
		 * via IMSG_CONSTRAINT_CLOSE, so there is nothing to do here.
		 */
		return (0);
	case STATE_INVALID:
		if (cstr->last + CONSTRAINT_SCAN_INTERVAL > now) {
			/* Nothing to do */
			return (-1);
		}

		/* Reset and retry */
		cstr->senderrors = 0;
		constraint_close(cstr->id);
		break;
	case STATE_REPLY_RECEIVED:
	default:
		/* Nothing to do */
		return (-1);
	}

	cstr->last = now;
	cstr->state = STATE_QUERY_SENT;

	memset(&am, 0, sizeof(am));
	memcpy(&am.a, cstr->addr, sizeof(am.a));
	am.synced = synced;

	iov[iov_cnt].iov_base = &am;
	iov[iov_cnt++].iov_len = sizeof(am);
	if (cstr->addr_head.name) {
		am.namelen = strlen(cstr->addr_head.name) + 1;
		iov[iov_cnt].iov_base = cstr->addr_head.name;
		iov[iov_cnt++].iov_len = am.namelen;
	}
	if (cstr->addr_head.path) {
		am.pathlen = strlen(cstr->addr_head.path) + 1;
		iov[iov_cnt].iov_base = cstr->addr_head.path;
		iov[iov_cnt++].iov_len = am.pathlen;
	}

	imsg_composev(ibuf_main, IMSG_CONSTRAINT_QUERY,
	    cstr->id, 0, -1, iov, iov_cnt);

	return (0);
}

/*
 * priv parent's pipe to the persistent constraint engine.  Set up once in
 * ntpd.c right after the engine is forked, alongside `ibuf' (the pipe to
 * the ntp engine).
 */
extern struct imsgbuf	*ibuf_cstr;	/* priv -> constraint engine */

/*
 * The priv parent no longer parses constraint queries or results: it just
 * relays IMSG_CONSTRAINT_QUERY from the ntp engine to the (single,
 * persistent) constraint engine, and IMSG_CONSTRAINT_RESULT / _CLOSE back.
 * There is nothing left to track per constraint on this side, so unlike the
 * old per-query fork+exec design, this never touches conf->constraints.
 */
int
priv_constraint_dispatch(void)
{
	struct imsg	 imsg;
	int		 n;

	if (imsgbuf_read(ibuf_cstr) != 1)
		return (-1);

	for (;;) {
		if ((n = imsgbuf_get(ibuf_cstr, &imsg)) == -1)
			return (-1);
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_CONSTRAINT_RESULT:
		case IMSG_CONSTRAINT_CLOSE:
			/* forward verbatim; don't parse it here */
			if (imsg_compose(ibuf, imsg.hdr.type, imsg.hdr.peerid,
			    0, -1, imsg.data, imsg.hdr.len - IMSG_HEADER_SIZE)
			    == -1)
				fatal("%s: imsg_compose", __func__);
			break;
		default:
			break;
		}
		imsg_free(&imsg);
	}
	return (0);
}

static int
imsgbuf_read_one(struct imsgbuf *imsgbuf, struct imsg *imsg)
{
	while (1) {
		switch (imsgbuf_get(imsgbuf, imsg)) {
		case -1:
			return (-1);
		case 0:
			break;
		default:
			return (1);
		}

		switch (imsgbuf_read(imsgbuf)) {
		case -1:
			return (-1);
		case 0:
			return (0);
		}
	}
}

/*
 * A single query read off the pipe from the priv parent, fully parsed and
 * owned by the caller.  Used by the (now persistent) constraint engine.
 */
struct cstr_query {
	uint32_t	 id;
	struct ntp_addr	*addr;
	char		*name;
	char		*path;
	int		 synced;
};

static void
cstr_query_free(struct cstr_query *q)
{
	free(q->addr);
	free(q->name);
	free(q->path);
}

/*
 * Block for the next IMSG_CONSTRAINT_QUERY and parse it into *q.
 * Returns 1 on success (caller must cstr_query_free(q) when done),
 * 0 on a malformed message (q->id is still valid, nothing to free),
 * -1 if the pipe to the parent is gone (caller should shut down).
 */
static int
cstr_read_query(struct imsgbuf *ib, struct cstr_query *q)
{
	struct imsg		 imsg;
	struct ntp_addr_msg	 am;
	uint8_t			*data;
	size_t			 mlen;

	switch (imsgbuf_read_one(ib, &imsg)) {
	case -1:
	case 0:
		return (-1);
	}

	memset(q, 0, sizeof(*q));

	if (imsg.hdr.type != IMSG_CONSTRAINT_QUERY) {
		log_warnx("%s: unexpected imsg type", __func__);
		imsg_free(&imsg);
		return (0);
	}
	q->id = imsg.hdr.peerid;

	mlen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (mlen < sizeof(am)) {
		log_warnx("%s: short IMSG_CONSTRAINT_QUERY", __func__);
		imsg_free(&imsg);
		return (0);
	}
	memcpy(&am, imsg.data, sizeof(am));
	if (mlen != sizeof(am) + am.namelen + am.pathlen) {
		log_warnx("%s: malformed IMSG_CONSTRAINT_QUERY", __func__);
		imsg_free(&imsg);
		return (0);
	}
	q->synced = am.synced;

	if ((q->addr = calloc(1, sizeof(*q->addr))) == NULL)
		fatal("calloc");
	memcpy(q->addr, &am.a, sizeof(*q->addr));
	q->addr->next = NULL;

	data = (uint8_t *)imsg.data + sizeof(am);
	if (am.namelen) {
		if ((q->name = get_string(data, am.namelen)) == NULL) {
			log_warnx("invalid IMSG_CONSTRAINT_QUERY name");
			cstr_query_free(q);
			imsg_free(&imsg);
			return (0);
		}
		data += am.namelen;
	}
	if (am.pathlen) {
		if ((q->path = get_string(data, am.pathlen)) == NULL) {
			log_warnx("invalid IMSG_CONSTRAINT_QUERY path");
			cstr_query_free(q);
			imsg_free(&imsg);
			return (0);
		}
	}

	imsg_free(&imsg);
	return (1);
}

static void
cstr_send_close(struct imsgbuf *ib, uint32_t id)
{
	int fail = 1;

	if (imsg_compose(ib, IMSG_CONSTRAINT_CLOSE, id, 0, -1, &fail,
	    sizeof(fail)) == -1)
		fatal("%s: imsg_compose", __func__);
	if (imsgbuf_flush(ib) == -1)
		fatal("imsgbuf_flush");
}

/*
 * The constraint engine: forked once at startup (like the dns engine) and
 * long-lived, rather than fork+exec'd anew for every query.  It receives
 * one IMSG_CONSTRAINT_QUERY at a time on its pipe from the priv parent,
 * runs the HTTPS "Date:" fetch, and reports IMSG_CONSTRAINT_RESULT or
 * IMSG_CONSTRAINT_CLOSE{fail} back.
 */
void
priv_constraint_child(struct ntpd_conf *nconf, struct passwd *pw)
{
	struct imsgbuf		 ibufst;
	struct sigaction	 sa;
	uint8_t			*ca;
	size_t			 ca_len;
	int			 i;

	log_init(nconf->debug ? LOG_TO_STDERR : LOG_TO_SYSLOG, nconf->verbose,
	    LOG_DAEMON);
	log_procinit("constraint");

	if (setpriority(PRIO_PROCESS, 0, 0) == -1)
		log_warn("could not set priority");

	/* load CA certs before chroot() */
	if ((ca = tls_load_file(tls_default_ca_cert_file(), &ca_len, NULL))
	    == NULL)
		fatalx("failed to load constraint ca");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (!nconf->debug && setsid() == -1)
		fatal("setsid");

	/* Reset all signal handlers except the ones we still want. */
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;
	for (i = 1; i < _NSIG; i++)
		sigaction(i, &sa, NULL);
	/*
	 * Unlike the old one-query-per-process design, this process now
	 * outlives many TLS connections: ignore SIGPIPE so a peer resetting
	 * a connection mid-write fails that query instead of the whole
	 * engine.
	 */
	signal(SIGPIPE, SIG_IGN);

	if (pledge("stdio inet", NULL) == -1)
		fatal("pledge");

	if (imsgbuf_init(&ibufst, PARENT_SOCK_FILENO) == -1)
		fatal("imsgbuf_init");

	/*
	 * Close any other fds we may have inherited, and make sure our pipe
	 * to the parent isn't handed to an exec'ed child.  Neither can
	 * happen -- pledge(2) above forbids exec -- but keep the safety
	 * belt, especially for portability.
	 */
	(void)closefrom(PARENT_SOCK_FILENO + 1);
	if (fcntl(PARENT_SOCK_FILENO, F_SETFD, FD_CLOEXEC) == -1)
		fatal("%s: fcntl F_SETFD", __func__);

	setproctitle("constraint engine");

	for (;;) {
		struct cstr_query	 q;
		static char		 addr[NI_MAXHOST];
		struct timeval		 rectv, xmttv;
		struct iovec		 iov[2];
		void			*ctx;
		int			 r;

		if ((r = cstr_read_query(&ibufst, &q)) == -1)
			break;
		if (r == 0)
			continue;	/* malformed; nothing to report */

		if (getnameinfo((struct sockaddr *)&q.addr->ss,
		    SA_LEN((struct sockaddr *)&q.addr->ss),
		    addr, sizeof(addr), NULL, 0, NI_NUMERICHOST) != 0) {
			log_warnx("%s: getnameinfo", __func__);
			cstr_send_close(&ibufst, q.id);
			cstr_query_free(&q);
			continue;
		}
		log_debug("constraint request to %s", addr);

		ctx = httpsdate_query(addr, CONSTRAINT_PORT, q.name, q.path,
		    ca, ca_len, &rectv, &xmttv, q.synced);
		cstr_query_free(&q);

		if (ctx == NULL) {
			/* Abort with failure but without warning */
			cstr_send_close(&ibufst, q.id);
			continue;
		}

		iov[0].iov_base = &rectv;
		iov[0].iov_len = sizeof(rectv);
		iov[1].iov_base = &xmttv;
		iov[1].iov_len = sizeof(xmttv);
		if (imsg_composev(&ibufst, IMSG_CONSTRAINT_RESULT, q.id, 0,
		    -1, iov, 2) == -1)
			fatal("%s: imsg_composev", __func__);
		if (imsgbuf_flush(&ibufst) == -1)
			fatal("imsgbuf_flush");

		httpsdate_free(ctx);
	}

	imsgbuf_clear(&ibufst);
	exit(0);
}

struct constraint *
constraint_byid(u_int32_t id)
{
	struct constraint	*cstr;

	TAILQ_FOREACH(cstr, &conf->constraints, entry) {
		if (cstr->id == id)
			return (cstr);
	}

	return (NULL);
}

int
constraint_close(u_int32_t id)
{
	struct constraint	*cstr;

	if ((cstr = constraint_byid(id)) == NULL) {
		log_warn("%s: id %d: not found", __func__, id);
		return (0);
	}

	cstr->last = getmonotime();

	if (cstr->addr == NULL || (cstr->addr = cstr->addr->next) == NULL) {
		/* Either a pool or all addresses have been tried */
		cstr->addr = cstr->addr_head.a;
		if (cstr->senderrors)
			cstr->state = STATE_INVALID;
		else if (cstr->state >= STATE_QUERY_SENT)
			cstr->state = STATE_DNS_DONE;

		return (1);
	}

	return (constraint_init(cstr));
}

void
constraint_add(struct constraint *cstr)
{
	TAILQ_INSERT_TAIL(&conf->constraints, cstr, entry);
}

void
constraint_remove(struct constraint *cstr)
{
	TAILQ_REMOVE(&conf->constraints, cstr, entry);

	free(cstr->addr_head.name);
	free(cstr->addr_head.path);
	free(cstr->addr);
	free(cstr);
}

void
constraint_purge(void)
{
	struct constraint	*cstr, *ncstr;

	TAILQ_FOREACH_SAFE(cstr, &conf->constraints, entry, ncstr)
		constraint_remove(cstr);
}

void
constraint_msg_result(u_int32_t id, u_int8_t *data, size_t len)
{
	struct constraint	*cstr;
	struct timeval		 tv[2];
	double			 offset;

	if ((cstr = constraint_byid(id)) == NULL) {
		log_warnx("IMSG_CONSTRAINT_CLOSE with invalid constraint id");
		return;
	}

	if (len != sizeof(tv)) {
		log_warnx("invalid IMSG_CONSTRAINT received");
		return;
	}

	memcpy(tv, data, len);

	offset = gettime_from_timeval(&tv[0]) -
	    gettime_from_timeval(&tv[1]);

	log_info("constraint reply from %s: offset %f",
	    log_ntp_addr(cstr->addr),
	    offset);

	cstr->state = STATE_REPLY_RECEIVED;
	cstr->last = getmonotime();
	cstr->constraint = tv[0].tv_sec;

	constraint_update();
}

void
constraint_msg_close(u_int32_t id, u_int8_t *data, size_t len)
{
	struct constraint	*cstr, *tmp;
	int			 fail, cnt;
	static int		 total_fails;

	if ((cstr = constraint_byid(id)) == NULL) {
		log_warnx("IMSG_CONSTRAINT_CLOSE with invalid constraint id");
		return;
	}

	if (len != sizeof(int)) {
		log_warnx("invalid IMSG_CONSTRAINT_CLOSE received");
		return;
	}

	memcpy(&fail, data, len);

	if (fail) {
		log_debug("no constraint reply from %s"
		    " received in time, next query %ds",
		    log_ntp_addr(cstr->addr),
		    CONSTRAINT_SCAN_INTERVAL);
		
		cnt = 0;
		TAILQ_FOREACH(tmp, &conf->constraints, entry)
			cnt++;
		if (cnt > 0 && ++total_fails >= cnt &&
		    conf->constraint_median == 0) {
			log_warnx("constraints configured but none available");
			total_fails = 0;
		}
	}

	if (fail || cstr->state < STATE_QUERY_SENT) {
		cstr->senderrors++;
		constraint_close(cstr->id);
	}
}

void
constraint_msg_dns(u_int32_t id, u_int8_t *data, size_t len)
{
	struct constraint	*cstr, *ncstr = NULL;
	u_int8_t		*p;
	struct ntp_addr		*h;

	if ((cstr = constraint_byid(id)) == NULL) {
		log_debug("IMSG_CONSTRAINT_DNS with invalid constraint id");
		return;
	}
	if (cstr->addr != NULL) {
		log_warnx("IMSG_CONSTRAINT_DNS but addr != NULL!");
		return;
	}
	if (len == 0) {
		log_debug("%s FAILED", __func__);
		cstr->state = STATE_DNS_TEMPFAIL;
		return;
	}

	if (len % (sizeof(struct sockaddr_storage) + sizeof(int)) != 0)
		fatalx("IMSG_CONSTRAINT_DNS len");

	if (cstr->addr_head.pool) {
		struct constraint *n, *tmp;
		TAILQ_FOREACH_SAFE(n, &conf->constraints, entry, tmp) {
			if (cstr->id == n->id)
				continue;
			if (cstr->addr_head.pool == n->addr_head.pool)
				constraint_remove(n);
		}
	}

	p = data;
	do {
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal("calloc ntp_addr");
		memcpy(&h->ss, p, sizeof(h->ss));
		p += sizeof(h->ss);
		len -= sizeof(h->ss);
		memcpy(&h->notauth, p, sizeof(int));
		p += sizeof(int);
		len -= sizeof(int);

		if (ncstr == NULL || cstr->addr_head.pool) {
			ncstr = new_constraint();
			ncstr->addr = h;
			ncstr->addr_head.a = h;
			ncstr->addr_head.name = strdup(cstr->addr_head.name);
			ncstr->addr_head.path = strdup(cstr->addr_head.path);
			if (ncstr->addr_head.name == NULL ||
			    ncstr->addr_head.path == NULL)
				fatal("calloc name");
			ncstr->addr_head.pool = cstr->addr_head.pool;
			ncstr->state = STATE_DNS_DONE;
			constraint_add(ncstr);
			constraint_cnt += constraint_init(ncstr);
		} else {
			h->next = ncstr->addr;
			ncstr->addr = h;
			ncstr->addr_head.a = h;
		}
	} while (len);

	constraint_remove(cstr);
}

int
constraint_cmp(const void *a, const void *b)
{
	time_t at = *(const time_t *)a;
	time_t bt = *(const time_t *)b;
	return at < bt ? -1 : (at > bt ? 1 : 0);
}

void
constraint_update(void)
{
	struct constraint *cstr;
	int	 cnt, i;
	time_t	*values;
	time_t	 now;

	now = getmonotime();

	cnt = 0;
	TAILQ_FOREACH(cstr, &conf->constraints, entry) {
		if (cstr->state != STATE_REPLY_RECEIVED)
			continue;
		cnt++;
	}
	if (cnt == 0)
		return;

	if ((values = calloc(cnt, sizeof(time_t))) == NULL)
		fatal("calloc");

	i = 0;
	TAILQ_FOREACH(cstr, &conf->constraints, entry) {
		if (cstr->state != STATE_REPLY_RECEIVED)
			continue;
		values[i++] = cstr->constraint + (now - cstr->last);
	}

	qsort(values, cnt, sizeof(time_t), constraint_cmp);

	/* calculate median */
	i = cnt / 2;
	if (cnt % 2 == 0)
		conf->constraint_median = (values[i - 1] + values[i]) / 2;
	else
		conf->constraint_median = values[i];

	conf->constraint_last = now;

	free(values);
}

void
constraint_reset(void)
{
	struct constraint *cstr;

	TAILQ_FOREACH(cstr, &conf->constraints, entry) {
		if (cstr->state == STATE_QUERY_SENT)
			continue;
		constraint_close(cstr->id);
		constraint_addr_head_clear(cstr);
		constraint_init(cstr);
	}
	conf->constraint_errors = 0;
}

int
constraint_check(double val)
{
	struct timeval	tv;
	double		diff;
	time_t		now;

	if (conf->constraint_median == 0)
		return (0);

	/* Calculate the constraint with the current offset */
	now = getmonotime();
	tv.tv_sec = conf->constraint_median + (now - conf->constraint_last);
	tv.tv_usec = 0;
	diff = fabs(val - gettime_from_timeval(&tv));

	if (diff > CONSTRAINT_MARGIN) {
		if (conf->constraint_errors++ >
		    (CONSTRAINT_ERROR_MARGIN * peer_cnt)) {
			constraint_reset();
		}

		return (-1);
	}

	return (0);
}

struct httpsdate *
httpsdate_init(const char *addr, const char *port, const char *hostname,
    const char *path, const u_int8_t *ca, size_t ca_len, int synced)
{
	struct httpsdate	*httpsdate = NULL;

	if ((httpsdate = calloc(1, sizeof(*httpsdate))) == NULL)
		goto fail;

	if (hostname == NULL)
		hostname = addr;

	if ((httpsdate->tls_addr = strdup(addr)) == NULL ||
	    (httpsdate->tls_port = strdup(port)) == NULL ||
	    (httpsdate->tls_hostname = strdup(hostname)) == NULL ||
	    (httpsdate->tls_path = strdup(path)) == NULL)
		goto fail;

	if (asprintf(&httpsdate->tls_request,
	    "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
	    httpsdate->tls_path, httpsdate->tls_hostname) == -1)
		goto fail;

	if ((httpsdate->tls_config = tls_config_new()) == NULL)
		goto fail;
	if (tls_config_set_ca_mem(httpsdate->tls_config, ca, ca_len) == -1)
		goto fail;

	/*
	 * Due to the fact that we're trying to determine a constraint for time
	 * we do our own certificate validity checking, since the automatic
	 * version is based on our wallclock, which may well be inaccurate...
	 */
	if (!synced) {
		log_debug("constraints: using received time in certificate validation");
		tls_config_insecure_noverifytime(httpsdate->tls_config);
	}

	return (httpsdate);

 fail:
	httpsdate_free(httpsdate);
	return (NULL);
}

void
httpsdate_free(void *arg)
{
	struct httpsdate *httpsdate = arg;
	if (httpsdate == NULL)
		return;
	if (httpsdate->tls_ctx)
		tls_close(httpsdate->tls_ctx);
	tls_free(httpsdate->tls_ctx);
	tls_config_free(httpsdate->tls_config);
	free(httpsdate->tls_addr);
	free(httpsdate->tls_port);
	free(httpsdate->tls_hostname);
	free(httpsdate->tls_path);
	free(httpsdate->tls_request);
	free(httpsdate);
}

int
httpsdate_request(struct httpsdate *httpsdate, struct timeval *when, int synced)
{
	char	 timebuf1[32], timebuf2[32];
	size_t	 outlen = 0, maxlength = CONSTRAINT_MAXHEADERLENGTH, len;
	char	*line, *p, *buf;
	time_t	 httptime, notbefore, notafter;
	struct tm *tm;
	ssize_t	 ret;

	if ((httpsdate->tls_ctx = tls_client()) == NULL)
		goto fail;

	if (tls_configure(httpsdate->tls_ctx, httpsdate->tls_config) == -1)
		goto fail;

	/*
	 * libtls expects an address string, which can also be a DNS name,
	 * but we pass a pre-resolved IP address string in tls_addr so it
	 * does not trigger any DNS operation and is safe to be called
	 * without the dns pledge.
	 */
	if (tls_connect_servername(httpsdate->tls_ctx, httpsdate->tls_addr,
	    httpsdate->tls_port, httpsdate->tls_hostname) == -1) {
		log_debug("tls connect failed: %s (%s): %s",
		    httpsdate->tls_addr, httpsdate->tls_hostname,
		    tls_error(httpsdate->tls_ctx));
		goto fail;
	}

	buf = httpsdate->tls_request;
	len = strlen(httpsdate->tls_request);
	while (len > 0) {
		ret = tls_write(httpsdate->tls_ctx, buf, len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
			continue;
		if (ret == -1) {
			log_warnx("tls write failed: %s (%s): %s",
			    httpsdate->tls_addr, httpsdate->tls_hostname,
			    tls_error(httpsdate->tls_ctx));
			goto fail;
		}
		buf += ret;
		len -= ret;
	}

	while ((line = tls_readline(httpsdate->tls_ctx, &outlen,
	    &maxlength, when)) != NULL) {
		line[strcspn(line, "\r\n")] = '\0';

		if ((p = strchr(line, ' ')) == NULL || *p == '\0')
			goto next;
		*p++ = '\0';
		if (strcasecmp("Date:", line) != 0)
			goto next;

		/*
		 * Expect the date/time format as IMF-fixdate which is
		 * mandated by HTTP/1.1 in the new RFC 7231 and was
		 * preferred by RFC 2616.  Other formats would be RFC 850
		 * or ANSI C's asctime() - the latter doesn't include
		 * the timezone which is required here.
		 */
		if (strptime(p, IMF_FIXDATE,
		    &httpsdate->tls_tm) == NULL) {
			log_warnx("unsupported date format");
			free(line);
			goto fail;
		}

		free(line);
		break;
 next:
		free(line);
	}
	if (httpsdate->tls_tm.tm_year == 0)
		goto fail;

	/* If we are synced, we already checked the certificate validity */
	if (synced)
		return 0;

	/*
	 * Now manually check the validity of the certificate presented in the
	 * TLS handshake, based on the time specified by the server's HTTP Date:
	 * header.
	 */
	notbefore = tls_peer_cert_notbefore(httpsdate->tls_ctx);
	notafter = tls_peer_cert_notafter(httpsdate->tls_ctx);
	httpsdate->tls_tm.tm_wday = -1;		/* sentinel for error */
	if ((httptime = timegm(&httpsdate->tls_tm)) == -1 &&
	    httpsdate->tls_tm.tm_wday == -1)
		goto fail;
	if (httptime <= notbefore) {
		if ((tm = gmtime(&notbefore)) == NULL)
			goto fail;
		if (strftime(timebuf1, sizeof(timebuf1), X509_DATE, tm) == 0)
			goto fail;
		if (strftime(timebuf2, sizeof(timebuf2), X509_DATE,
		    &httpsdate->tls_tm) == 0)
			goto fail;
		log_warnx("tls certificate not yet valid: %s (%s): "
		    "not before %s, now %s", httpsdate->tls_addr,
		    httpsdate->tls_hostname, timebuf1, timebuf2);
		goto fail;
	}
	if (httptime >= notafter) {
		if ((tm = gmtime(&notafter)) == NULL)
			goto fail;
		if (strftime(timebuf1, sizeof(timebuf1), X509_DATE, tm) == 0)
			goto fail;
		if (strftime(timebuf2, sizeof(timebuf2), X509_DATE,
		    &httpsdate->tls_tm) == 0)
			goto fail;
		log_warnx("tls certificate expired: %s (%s): "
		    "not after %s, now %s", httpsdate->tls_addr,
		    httpsdate->tls_hostname, timebuf1, timebuf2);
		goto fail;
	}

	return (0);

 fail:
	httpsdate_free(httpsdate);
	return (-1);
}

void *
httpsdate_query(const char *addr, const char *port, const char *hostname,
    const char *path, const u_int8_t *ca, size_t ca_len,
    struct timeval *rectv, struct timeval *xmttv, int synced)
{
	struct httpsdate	*httpsdate;
	struct timeval		 when;
	time_t			 t;

	if ((httpsdate = httpsdate_init(addr, port, hostname, path,
	    ca, ca_len, synced)) == NULL)
		return (NULL);

	if (httpsdate_request(httpsdate, &when, synced) == -1)
		return (NULL);

	httpsdate->tls_tm.tm_wday = -1;		/* sentinel for error */
	t = timegm(&httpsdate->tls_tm);
	if (t == -1 && httpsdate->tls_tm.tm_wday == -1) {
		httpsdate_free(httpsdate);
		return (NULL);
	}

	/* Report parsed Date: as "received time" */
	rectv->tv_sec = t;
	rectv->tv_usec = 0;

	/* And add delay as "transmit time" */
	xmttv->tv_sec = when.tv_sec;
	xmttv->tv_usec = when.tv_usec;

	return (httpsdate);
}

/* Based on SSL_readline in ftp/fetch.c */
char *
tls_readline(struct tls *tls, size_t *lenp, size_t *maxlength,
    struct timeval *when)
{
	size_t i, len;
	char *buf, *q, c;
	ssize_t ret;

	len = 128;
	if ((buf = malloc(len)) == NULL)
		fatal("Can't allocate memory for transfer buffer");
	for (i = 0; ; i++) {
		if (i >= len - 1) {
			if ((q = reallocarray(buf, len, 2)) == NULL)
				fatal("Can't expand transfer buffer");
			buf = q;
			len *= 2;
		}
 again:
		ret = tls_read(tls, &c, 1);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
			goto again;
		if (ret == -1) {
			/* SSL read error, ignore */
			free(buf);
			return (NULL);
		}

		if (maxlength != NULL && (*maxlength)-- == 0) {
			log_warnx("maximum length exceeded");
			free(buf);
			return (NULL);
		}

		buf[i] = c;
		if (c == '\n')
			break;
	}
	*lenp = i;
	if (gettimeofday(when, NULL) == -1)
		fatal("gettimeofday");
	return (buf);
}

char *
get_string(u_int8_t *ptr, size_t len)
{
	size_t	 i;

	for (i = 0; i < len; i++)
		if (!(isprint(ptr[i]) || isspace(ptr[i])))
			break;

	return strndup(ptr, i);
}
