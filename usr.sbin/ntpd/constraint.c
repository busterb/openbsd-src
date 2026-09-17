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

u_int constraint_cnt;
extern u_int peer_cnt;
extern struct imsgbuf *ibuf;		/* priv */
extern struct imsgbuf *ibuf_main;	/* chld */

/*
 * A single in-flight constraint query: an asynchronous, non-blocking HTTPS
 * "Date:" fetch driven by cstr_conn_progress() from the engine's poll(2)
 * loop.
 */
struct cstr_conn {
	TAILQ_ENTRY(cstr_conn)	 entry;
	uint32_t		 id;
	int			 fd;		/* non-blocking socket */
	struct tls		*ctx;
	struct tls_config	*tls_config;
	enum {
		CSTR_CONNECTING,
		CSTR_HANDSHAKE,
		CSTR_WRITE,
		CSTR_READ
	}			 state;
	short			 want;		/* POLLIN or POLLOUT */
	time_t			 deadline;	/* getmonotime() + timeout */
	char			*hostname;	/* SNI / cert name */
	char			*request;	/* HTTP HEAD request */
	size_t			 reqlen, reqoff;
	char			 rbuf[CONSTRAINT_MAXHEADERLENGTH];
	size_t			 rlen;
	struct timeval		 when;		/* Date: rx timestamp */
	struct tm		 tm;		/* parsed Date: */
	int			 synced;
	char			 addr[NI_MAXHOST];	/* numeric, for logs */
};
TAILQ_HEAD(cstr_conns, cstr_conn);

static struct cstr_conns cstr_conns = TAILQ_HEAD_INITIALIZER(cstr_conns);
static uint8_t		 *cstr_ca;
static size_t		  cstr_ca_len;

static void	cstr_conn_free(struct cstr_conn *);
static void	cstr_conn_fail(struct imsgbuf *, struct cstr_conn *);
static void	cstr_conn_finish(struct imsgbuf *, struct cstr_conn *);
static int	cstr_conn_scan_date(struct cstr_conn *);
static void	cstr_conn_progress(struct imsgbuf *, struct cstr_conn *);
static void	cstr_conn_start(struct imsgbuf *, uint32_t, struct ntp_addr *,
		    const char *, const char *, int);
static int	cstr_dispatch_imsg(struct imsgbuf *);

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

/* priv parent's pipe to the constraint engine; set up in ntpd.c */
extern struct imsgbuf	*ibuf_cstr;

/*
 * Relay IMSG_CONSTRAINT_QUERY from the ntp engine to the constraint engine,
 * and IMSG_CONSTRAINT_RESULT / _CLOSE back, verbatim and unparsed.
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

static void
cstr_send_close(struct imsgbuf *ib, uint32_t id)
{
	int fail = 1;

	/* Queue only; the engine's poll loop writes it out. */
	if (imsg_compose(ib, IMSG_CONSTRAINT_CLOSE, id, 0, -1, &fail,
	    sizeof(fail)) == -1)
		fatal("%s: imsg_compose", __func__);
}

static void
cstr_conn_free(struct cstr_conn *cc)
{
	if (cc->ctx != NULL)
		tls_close(cc->ctx);	/* best effort; not retried on WANT_POLL */
	tls_free(cc->ctx);
	tls_config_free(cc->tls_config);
	if (cc->fd != -1)
		close(cc->fd);
	free(cc->hostname);
	free(cc->request);
	TAILQ_REMOVE(&cstr_conns, cc, entry);
	free(cc);
}

static void
cstr_conn_fail(struct imsgbuf *ib, struct cstr_conn *cc)
{
	cstr_send_close(ib, cc->id);
	cstr_conn_free(cc);
}

/*
 * Start an asynchronous HTTPS "Date:" fetch for one constraint query.
 * Always inserts cc into cstr_conns (even on immediate failure) so that
 * cstr_conn_fail()'s TAILQ_REMOVE is always valid.
 */
static void
cstr_conn_start(struct imsgbuf *ib, uint32_t id, struct ntp_addr *a,
    const char *name, const char *path, int synced)
{
	struct cstr_conn	*cc;
	struct sockaddr		*sa = (struct sockaddr *)&a->ss;

	if ((cc = calloc(1, sizeof(*cc))) == NULL)
		fatal("calloc");
	cc->id = id;
	cc->fd = -1;
	cc->synced = synced;
	cc->deadline = getmonotime() + CONSTRAINT_SCAN_TIMEOUT;
	TAILQ_INSERT_TAIL(&cstr_conns, cc, entry);

	/*
	 * Get the IP address as a string for SNI/logging.  This only
	 * converts an address into a string and does not trigger any DNS
	 * operation, so it is safe to be called without the dns pledge.
	 */
	if (getnameinfo(sa, SA_LEN(sa), cc->addr, sizeof(cc->addr), NULL, 0,
	    NI_NUMERICHOST) != 0) {
		log_warnx("%s: getnameinfo", __func__);
		cstr_conn_fail(ib, cc);
		return;
	}
	log_debug("constraint request to %s", cc->addr);

	if ((cc->hostname = strdup(name ? name : cc->addr)) == NULL)
		fatal("strdup");
	if (asprintf(&cc->request,
	    "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
	    path ? path : "/", cc->hostname) == -1)
		fatal("asprintf");
	cc->reqlen = strlen(cc->request);

	if ((cc->tls_config = tls_config_new()) == NULL ||
	    tls_config_set_ca_mem(cc->tls_config, cstr_ca, cstr_ca_len) == -1) {
		log_warnx("%s: tls_config", __func__);
		cstr_conn_fail(ib, cc);
		return;
	}
	/*
	 * We are trying to determine a constraint for time, so we do our
	 * own certificate validity checking in cstr_conn_finish() against
	 * the received Date:, since the automatic check is based on our
	 * own (possibly inaccurate) wall clock.
	 */
	if (!synced) {
		log_debug("constraints: using received time in certificate "
		    "validation");
		tls_config_insecure_noverifytime(cc->tls_config);
	}
	if ((cc->ctx = tls_client()) == NULL ||
	    tls_configure(cc->ctx, cc->tls_config) == -1) {
		log_warnx("%s: tls_configure: %s", __func__,
		    cc->ctx ? tls_error(cc->ctx) : "tls_client");
		cstr_conn_fail(ib, cc);
		return;
	}

	if ((cc->fd = socket(sa->sa_family,
	    SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) == -1) {
		log_warn("%s: socket", __func__);
		cstr_conn_fail(ib, cc);
		return;
	}
	if (connect(cc->fd, sa, SA_LEN(sa)) == -1 && errno != EINPROGRESS) {
		log_debug("constraint: connect to %s: %s", cc->addr,
		    strerror(errno));
		cstr_conn_fail(ib, cc);
		return;
	}

	cc->state = CSTR_CONNECTING;
	cc->want = POLLOUT;
}

/*
 * Scan cc->rbuf for a complete header line and check whether it is the
 * Date: header we're after, consuming lines as we go.
 * Returns 1 if cc->tm now holds a parsed Date:, 0 if more data is needed,
 * -1 if the Date: header was malformed.
 */
static int
cstr_conn_scan_date(struct cstr_conn *cc)
{
	char	*nl, *line, *p;
	size_t	 linelen;

	for (;;) {
		if ((nl = memchr(cc->rbuf, '\n', cc->rlen)) == NULL)
			return (0);	/* need more data */

		line = cc->rbuf;
		linelen = nl - cc->rbuf;
		if (linelen > 0 && line[linelen - 1] == '\r')
			linelen--;
		line[linelen] = '\0';

		if ((p = strchr(line, ' ')) != NULL && *p != '\0') {
			*p++ = '\0';
			if (strcasecmp("Date:", line) == 0) {
				if (strptime(p, IMF_FIXDATE, &cc->tm) == NULL) {
					log_warnx("constraint: %s: unsupported"
					    " date format", cc->addr);
					return (-1);
				}
				return (1);
			}
		}

		/* not the line we want; drop it and keep scanning */
		memmove(cc->rbuf, nl + 1, cc->rlen - (nl + 1 - cc->rbuf));
		cc->rlen -= (nl + 1 - cc->rbuf);
	}
}

/*
 * cc->tm holds a Date: parsed from the response.  Validate the certificate
 * against it (unless we're already synced and libtls checked it against
 * our own clock), then report the result and free cc.
 */
static void
cstr_conn_finish(struct imsgbuf *ib, struct cstr_conn *cc)
{
	time_t		 t, notbefore, notafter;
	struct tm	*tmp;
	char		 timebuf1[32], timebuf2[32];
	struct timeval	 rectv, xmttv;
	struct iovec	 iov[2];

	cc->tm.tm_wday = -1;		/* sentinel for error, per timegm(3) */
	t = timegm(&cc->tm);
	if (t == -1 && cc->tm.tm_wday == -1) {
		cstr_conn_fail(ib, cc);
		return;
	}

	if (!cc->synced) {
		notbefore = tls_peer_cert_notbefore(cc->ctx);
		notafter = tls_peer_cert_notafter(cc->ctx);
		if (t <= notbefore) {
			if ((tmp = gmtime(&notbefore)) != NULL &&
			    strftime(timebuf1, sizeof(timebuf1), X509_DATE,
			    tmp) &&
			    strftime(timebuf2, sizeof(timebuf2), X509_DATE,
			    &cc->tm))
				log_warnx("constraint: tls certificate not "
				    "yet valid: %s: not before %s, now %s",
				    cc->addr, timebuf1, timebuf2);
			cstr_conn_fail(ib, cc);
			return;
		}
		if (t >= notafter) {
			if ((tmp = gmtime(&notafter)) != NULL &&
			    strftime(timebuf1, sizeof(timebuf1), X509_DATE,
			    tmp) &&
			    strftime(timebuf2, sizeof(timebuf2), X509_DATE,
			    &cc->tm))
				log_warnx("constraint: tls certificate "
				    "expired: %s: not after %s, now %s",
				    cc->addr, timebuf1, timebuf2);
			cstr_conn_fail(ib, cc);
			return;
		}
	}

	rectv.tv_sec = t;
	rectv.tv_usec = 0;
	xmttv = cc->when;

	iov[0].iov_base = &rectv;
	iov[0].iov_len = sizeof(rectv);
	iov[1].iov_base = &xmttv;
	iov[1].iov_len = sizeof(xmttv);
	if (imsg_composev(ib, IMSG_CONSTRAINT_RESULT, cc->id, 0, -1, iov, 2)
	    == -1)
		fatal("%s: imsg_composev", __func__);

	log_debug("constraint reply from %s", cc->addr);
	cstr_conn_free(cc);
}

/*
 * Drive one connection forward as far as it can go without blocking.
 * Falls through the states in order on each call; returns (via cc->want)
 * the event the caller's poll(2) should wait for next.
 */
static void
cstr_conn_progress(struct imsgbuf *ib, struct cstr_conn *cc)
{
	int		error, ret;
	socklen_t	len;

	switch (cc->state) {
	case CSTR_CONNECTING:
		len = sizeof(error);
		if (getsockopt(cc->fd, SOL_SOCKET, SO_ERROR, &error, &len)
		    == -1)
			error = errno;
		if (error != 0) {
			log_debug("constraint: connect to %s: %s", cc->addr,
			    strerror(error));
			cstr_conn_fail(ib, cc);
			return;
		}
		if (tls_connect_socket(cc->ctx, cc->fd, cc->hostname) == -1) {
			log_debug("constraint: tls_connect_socket %s: %s",
			    cc->addr, tls_error(cc->ctx));
			cstr_conn_fail(ib, cc);
			return;
		}
		cc->state = CSTR_HANDSHAKE;
		/* FALLTHROUGH */
	case CSTR_HANDSHAKE:
		ret = tls_handshake(cc->ctx);
		if (ret == TLS_WANT_POLLIN) {
			cc->want = POLLIN;
			return;
		}
		if (ret == TLS_WANT_POLLOUT) {
			cc->want = POLLOUT;
			return;
		}
		if (ret == -1) {
			log_debug("constraint: tls handshake %s: %s",
			    cc->addr, tls_error(cc->ctx));
			cstr_conn_fail(ib, cc);
			return;
		}
		cc->state = CSTR_WRITE;
		/* FALLTHROUGH */
	case CSTR_WRITE:
		while (cc->reqoff < cc->reqlen) {
			ret = tls_write(cc->ctx, cc->request + cc->reqoff,
			    cc->reqlen - cc->reqoff);
			if (ret == TLS_WANT_POLLIN) {
				cc->want = POLLIN;
				return;
			}
			if (ret == TLS_WANT_POLLOUT) {
				cc->want = POLLOUT;
				return;
			}
			if (ret == -1) {
				log_debug("constraint: tls write %s: %s",
				    cc->addr, tls_error(cc->ctx));
				cstr_conn_fail(ib, cc);
				return;
			}
			cc->reqoff += ret;
		}
		cc->state = CSTR_READ;
		cc->want = POLLIN;
		/* FALLTHROUGH */
	case CSTR_READ:
		for (;;) {
			if (cc->rlen >= sizeof(cc->rbuf) - 1) {
				log_warnx("constraint: %s: response header "
				    "too long", cc->addr);
				cstr_conn_fail(ib, cc);
				return;
			}
			ret = tls_read(cc->ctx, cc->rbuf + cc->rlen,
			    sizeof(cc->rbuf) - 1 - cc->rlen);
			if (ret == TLS_WANT_POLLIN) {
				cc->want = POLLIN;
				return;
			}
			if (ret == TLS_WANT_POLLOUT) {
				cc->want = POLLOUT;
				return;
			}
			if (ret == -1) {
				log_debug("constraint: tls read %s: %s",
				    cc->addr, tls_error(cc->ctx));
				cstr_conn_fail(ib, cc);
				return;
			}
			if (gettimeofday(&cc->when, NULL) == -1)
				fatal("gettimeofday");
			if (ret == 0) {
				/* connection closed without a Date: header */
				log_debug("constraint: %s: connection closed",
				    cc->addr);
				cstr_conn_fail(ib, cc);
				return;
			}
			cc->rlen += ret;
			cc->rbuf[cc->rlen] = '\0';

			switch (cstr_conn_scan_date(cc)) {
			case 1:
				cstr_conn_finish(ib, cc);
				return;
			case -1:
				cstr_conn_fail(ib, cc);
				return;
			}
			/* 0: keep reading */
		}
	}
}

/* Handle one IMSG_CONSTRAINT_QUERY (or more) from the priv parent. */
static int
cstr_dispatch_imsg(struct imsgbuf *ib)
{
	struct imsg		 imsg;
	struct ntp_addr_msg	 am;
	uint8_t			*data;
	char			*name, *path;
	size_t			 mlen;
	int			 n;

	if (imsgbuf_read(ib) != 1)
		return (-1);

	for (;;) {
		if ((n = imsgbuf_get(ib, &imsg)) == -1)
			return (-1);
		if (n == 0)
			break;

		if (imsg.hdr.type != IMSG_CONSTRAINT_QUERY) {
			imsg_free(&imsg);
			continue;
		}

		name = path = NULL;
		mlen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (mlen < sizeof(am)) {
			log_warnx("%s: short IMSG_CONSTRAINT_QUERY", __func__);
			cstr_send_close(ib, imsg.hdr.peerid);
			imsg_free(&imsg);
			continue;
		}
		memcpy(&am, imsg.data, sizeof(am));
		if (mlen != sizeof(am) + am.namelen + am.pathlen) {
			log_warnx("%s: malformed IMSG_CONSTRAINT_QUERY",
			    __func__);
			cstr_send_close(ib, imsg.hdr.peerid);
			imsg_free(&imsg);
			continue;
		}

		data = (uint8_t *)imsg.data + sizeof(am);
		if (am.namelen) {
			if ((name = get_string(data, am.namelen)) == NULL) {
				log_warnx("invalid IMSG_CONSTRAINT_QUERY name");
				cstr_send_close(ib, imsg.hdr.peerid);
				imsg_free(&imsg);
				continue;
			}
			data += am.namelen;
		}
		if (am.pathlen) {
			if ((path = get_string(data, am.pathlen)) == NULL) {
				log_warnx("invalid IMSG_CONSTRAINT_QUERY path");
				free(name);
				cstr_send_close(ib, imsg.hdr.peerid);
				imsg_free(&imsg);
				continue;
			}
		}

		cstr_conn_start(ib, imsg.hdr.peerid, &am.a, name, path,
		    am.synced);
		free(name);
		free(path);
		imsg_free(&imsg);
	}
	return (0);
}

static volatile sig_atomic_t quit_cstr = 0;

static void
cstr_sighdlr(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		quit_cstr = 1;
		break;
	}
}

/*
 * The constraint engine, forked once at startup like the dns engine: runs
 * any number of concurrent, non-blocking HTTPS "Date:" fetches, one per
 * IMSG_CONSTRAINT_QUERY from the priv parent, reporting back
 * IMSG_CONSTRAINT_RESULT or IMSG_CONSTRAINT_CLOSE{fail} per query.
 */
void
priv_constraint_child(struct ntpd_conf *nconf, struct passwd *pw)
{
	struct imsgbuf		 ibufst;
	struct sigaction	 sa;
	struct cstr_conn	*cc, *tcc;
	struct pollfd		*pfd = NULL;
	struct cstr_conn	**pfdconn = NULL;
	void			*newp, *newp2;
	u_int			 pfd_elms = 0, want_elms;
	time_t			 now, deadline;
	int			 nfds, ptimeout, i, j;

	log_init(nconf->debug ? LOG_TO_STDERR : LOG_TO_SYSLOG, nconf->verbose,
	    LOG_DAEMON);
	log_procinit("constraint");

	if (setpriority(PRIO_PROCESS, 0, 0) == -1)
		log_warn("could not set priority");

	/* load CA certs before chroot() */
	if ((cstr_ca = tls_load_file(tls_default_ca_cert_file(), &cstr_ca_len,
	    NULL)) == NULL)
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

	/* Reset all signal handlers, then install the ones we want. */
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;
	for (i = 1; i < _NSIG; i++)
		sigaction(i, &sa, NULL);
	signal(SIGTERM, cstr_sighdlr);
	signal(SIGINT, cstr_sighdlr);
	signal(SIGHUP, SIG_IGN);
	/* a peer resetting a connection mid-write should fail that query,
	 * not this process */
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

	while (quit_cstr == 0) {
		now = getmonotime();

		/* Time out any connection that hasn't finished in time. */
		TAILQ_FOREACH_SAFE(cc, &cstr_conns, entry, tcc) {
			if (cc->deadline <= now) {
				log_debug("constraint: %s: timed out",
				    cc->addr);
				cstr_conn_fail(&ibufst, cc);
			}
		}

		want_elms = 1;
		deadline = 0;
		TAILQ_FOREACH(cc, &cstr_conns, entry) {
			want_elms++;
			if (deadline == 0 || cc->deadline < deadline)
				deadline = cc->deadline;
		}

		if (want_elms > pfd_elms) {
			if ((newp = reallocarray(pfd, want_elms,
			    sizeof(*pfd))) == NULL)
				fatal("reallocarray");
			pfd = newp;
			if ((newp2 = reallocarray(pfdconn, want_elms,
			    sizeof(*pfdconn))) == NULL)
				fatal("reallocarray");
			pfdconn = newp2;
			pfd_elms = want_elms;
		}

		memset(pfd, 0, sizeof(*pfd) * pfd_elms);
		pfd[0].fd = ibufst.fd;
		pfd[0].events = POLLIN;
		if (imsgbuf_queuelen(&ibufst) > 0)
			pfd[0].events |= POLLOUT;
		pfdconn[0] = NULL;

		i = 1;
		TAILQ_FOREACH(cc, &cstr_conns, entry) {
			pfd[i].fd = cc->fd;
			pfd[i].events = cc->want;
			pfdconn[i] = cc;
			i++;
		}

		ptimeout = deadline ?
		    (int)MAXIMUM(1, deadline - now) * 1000 : INFTIM;

		if ((nfds = poll(pfd, i, ptimeout)) == -1) {
			if (errno != EINTR) {
				log_warn("poll error");
				quit_cstr = 1;
			}
			continue;
		}

		if (nfds > 0 && (pfd[0].revents & POLLOUT))
			if (imsgbuf_write(&ibufst) == -1) {
				log_warn("pipe write error (to parent)");
				quit_cstr = 1;
			}

		if (nfds > 0 && (pfd[0].revents & POLLIN)) {
			nfds--;
			if (cstr_dispatch_imsg(&ibufst) == -1)
				quit_cstr = 1;
		}

		for (j = 1; nfds > 0 && j < i; j++) {
			if (pfd[j].revents == 0)
				continue;
			nfds--;
			cstr_conn_progress(&ibufst, pfdconn[j]);
		}
	}

	TAILQ_FOREACH_SAFE(cc, &cstr_conns, entry, tcc)
		cstr_conn_free(cc);
	free(pfd);
	free(pfdconn);
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

char *
get_string(u_int8_t *ptr, size_t len)
{
	size_t	 i;

	for (i = 0; i < len; i++)
		if (!(isprint(ptr[i]) || isspace(ptr[i])))
			break;

	return strndup(ptr, i);
}
