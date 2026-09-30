/*
 * lws-api-test-dnssec-monitor-whois
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Exercises the dnssec-monitor plugin's registry whois refresh, which runs
 * in the unprivileged proxy process, see monitor-whois.c.  A throwaway
 * <base-dir>/domains corpus holds a domain with a fresh whois.json, one
 * with a stale one, and one with none.  The proxy side's whois goes to a
 * local fake registry, and its IPC to a local fake root process on a UDS.
 *
 * Covered behaviours:
 *
 *  - only the domains with a stale or missing whois.json are queried, one
 *    at a time
 *  - each result reaches the root process as an "update_whois" request
 *    carrying a valid IPC JWT, and a payload that is canonical whois JSON
 *    the root side's purifier accepts without complaint
 *  - a domain that has been asked about is not asked about again straight
 *    away, even though its whois.json has not been rewritten
 *  - lines the root process sends every client, like cert_status, are not
 *    taken for the answer, and an answer split across reads is reassembled
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>

#include "private.h"

#define MWT_BASE	"mwt-base"
#define MWT_UDS		"mwt-root.sock"

/* a 64-byte IPC key, as the proxy generates at spawn, as a JWK */
static const char *mwt_jwk =
	"{\"kty\":\"oct\",\"k\":\"5ieyQLLZ7VbF4YoWYNxxQJ-XrUnSI3CMKPylG_tWZfzLsQ9n"
	"Fqlc7zew5WB66xS6AfCoPbWV5741OCFhIW7xKQ\"}";

static const char *mwt_answer =
	"Domain name: %s\r\n"
	"Registration date: 30.09.2026 14:04:37\r\n"
	"Expiration date: 30.09.2029 14:04:37\r\n"
	"DNS: ns1.example.com - \r\n"
	"DNSSEC signed: yes\r\n";

static const char *mwt_expect =
	"{\"creation_date\":1790777077,\"expiry_date\":1885471477,"
	"\"nameservers\":[\"ns1.example.com\"],\"dnssec\":\"yes\"}";

static struct lws_context *cx;
static struct vhd vhd;
static lws_sorted_usec_list_t sul_timeout, sul_settle;
static int port = 7044, fails, interrupted, queries, updates;
static int got_stale, got_new;

static void
mwt_finish(void)
{
	interrupted = 1;
	lws_cancel_service(cx);
}

/* --- the fake registry ------------------------------------------------ */

struct mwt_reg {
	char		query[128];
	size_t		query_len;
	char		answer[512];
	size_t		answer_len;
	size_t		sent;
};

static int
callback_fake_registry(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	struct mwt_reg *r = (struct mwt_reg *)user;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		for (n = 0; n < len && !r->answer_len; n++) {
			char c = ((const char *)in)[n];

			if (c == '\r')
				continue;
			if (c != '\n') {
				if (r->query_len == sizeof(r->query) - 1)
					return -1;
				r->query[r->query_len++] = c;
				continue;
			}
			r->query[r->query_len] = '\0';
			queries++;
			lwsl_user("%s: query for %s\n", __func__, r->query);

			if (strcmp(r->query, "stale.test") &&
			    strcmp(r->query, "new.test")) {
				lwsl_err("%s: unexpected query for %s\n",
					 __func__, r->query);
				fails++;
			}

			r->answer_len = (size_t)lws_snprintf(r->answer,
					sizeof(r->answer), mwt_answer, r->query);
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!r->answer_len)
			break;
		if (r->sent == r->answer_len)
			return -1;
		if (lws_write(wsi, (unsigned char *)r->answer, r->answer_len,
			      LWS_WRITE_RAW) != (int)r->answer_len)
			return -1;
		r->sent = r->answer_len;
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

/* --- the fake root process -------------------------------------------- */

static const char * const mwt_req_paths[] = {
	"req", "jwt", "domain", "zone",
};

struct mwt_field {
	char		*buf;
	size_t		size;
	size_t		len;
};

struct mwt_req {
	char		req[32];
	char		jwt[1024];
	char		domain[128];
	char		zone[8192];
	struct mwt_field f[4];
};

static signed char
mwt_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct mwt_req *a = (struct mwt_req *)ctx->user;
	struct mwt_field *f;

	if (!ctx->path_match ||
	    (reason != LEJPCB_VAL_STR_CHUNK && reason != LEJPCB_VAL_STR_END))
		return 0;

	/* any of them may come in several chunks */
	f = &a->f[ctx->path_match - 1];
	if (f->len + ctx->npos >= f->size)
		return -1;
	memcpy(f->buf + f->len, ctx->buf, ctx->npos);
	f->len += ctx->npos;
	f->buf[f->len] = '\0';

	return 0;
}

static int
mwt_check_update(const char *line, size_t len)
{
	char temp[2048], out[2048], decoded[8192],
	     canon[LWS_WHOIS_CANON_MAX + 1];
	size_t out_len = sizeof(out);
	unsigned long exp_time;
	struct lejp_ctx jctx;
	struct mwt_req a;
	int n, problems;

	memset(&a, 0, sizeof(a));
	a.f[0].buf = a.req;	a.f[0].size = sizeof(a.req);
	a.f[1].buf = a.jwt;	a.f[1].size = sizeof(a.jwt);
	a.f[2].buf = a.domain;	a.f[2].size = sizeof(a.domain);
	a.f[3].buf = a.zone;	a.f[3].size = sizeof(a.zone);

	lejp_construct(&jctx, mwt_req_cb, &a, mwt_req_paths,
		       LWS_ARRAY_SIZE(mwt_req_paths));
	n = lejp_parse(&jctx, (const uint8_t *)line, (int)len);
	lejp_destruct(&jctx);
	if (n < 0 && n != LEJP_CONTINUE) {
		lwsl_err("%s: request is not JSON\n", __func__);
		return 1;
	}

	if (strcmp(a.req, "update_whois")) {
		lwsl_err("%s: unexpected req '%s'\n", __func__, a.req);
		return 1;
	}

	if (lws_jwt_signed_validate(cx, &vhd.auth_jwk, "HS256", a.jwt,
				    strlen(a.jwt), temp, sizeof(temp), out,
				    &out_len) ||
	    lws_jwt_token_sanity(out, out_len, "acme-ipc", "dnssec-monitor",
				 NULL, NULL, 0, &exp_time)) {
		lwsl_err("%s: %s: bad IPC JWT\n", __func__, a.domain);
		return 1;
	}

	n = lws_b64_decode_string(a.zone, decoded, sizeof(decoded));
	if (n <= 0 ||
	    lws_whois_json_purify(canon, sizeof(canon), decoded, (size_t)n,
				  &problems) < 0 || problems) {
		lwsl_err("%s: %s: payload the root side would refuse\n",
			 __func__, a.domain);
		return 1;
	}

	if (strcmp(canon, mwt_expect)) {
		lwsl_err("%s: %s: payload '%s', expected '%s'\n", __func__,
			 a.domain, canon, mwt_expect);
		return 1;
	}

	if (!strcmp(a.domain, "stale.test"))
		got_stale++;
	else if (!strcmp(a.domain, "new.test"))
		got_new++;
	else {
		lwsl_err("%s: update for unexpected %s\n", __func__, a.domain);
		return 1;
	}

	lwsl_user("%s: good update for %s\n", __func__, a.domain);

	return 0;
}

static void
mwt_settled_cb(lws_sorted_usec_list_t *sul)
{
	/* the proxy has had its chance to scan again: nothing new expected */
	if (queries != 2) {
		lwsl_err("%s: %d registry queries, expected 2\n", __func__,
			 queries);
		fails++;
	}
	mwt_finish();
}

struct mwt_root {
	char		line[12288];
	size_t		len;
	int		answer;
	int		half;
};

static int
callback_fake_root(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	/*
	 * Each answer goes after an unrelated line the root process sends to
	 * all its clients, and is itself split between two writes
	 */
	static const char ok[] =
		"{\"req\":\"cert_status\",\"subdomain\":\"new.test\","
		"\"status\":\"error\",\"msg\":\"Error: dns lookup failed\"}\n"
		"{\"req\":\"update_whois\",\"status\":\"ok\"}\n";
	static const size_t split = sizeof(ok) - 1 - 20;
	struct mwt_root *r = (struct mwt_root *)user;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		for (n = 0; n < len; n++) {
			char c = ((const char *)in)[n];

			if (c != '\n') {
				if (r->len == sizeof(r->line) - 1)
					return -1;
				r->line[r->len++] = c;
				continue;
			}

			r->line[r->len] = '\0';
			updates++;
			if (mwt_check_update(r->line, r->len))
				fails++;
			r->len = 0;
			r->answer++;
			lws_callback_on_writable(wsi);

			if (got_stale && got_new)
				/*
				 * Give the proxy long enough to complete, wait,
				 * and scan again, which should find nothing
				 */
				lws_sul_schedule(cx, 0, &sul_settle,
						 mwt_settled_cb,
						 4 * LWS_US_PER_SEC);
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!r->answer)
			break;
		if (!r->half) {
			if (lws_write(wsi, (unsigned char *)ok, split,
				      LWS_WRITE_RAW) != (int)split)
				return -1;
			r->half = 1;
		} else {
			if (lws_write(wsi, (unsigned char *)ok + split,
				      sizeof(ok) - 1 - split, LWS_WRITE_RAW) !=
						(int)(sizeof(ok) - 1 - split))
				return -1;
			r->half = 0;
			r->answer--;
		}
		if (r->answer)
			lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_registry[] = {
	{ "fake-registry", callback_fake_registry, sizeof(struct mwt_reg),
	  0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_root[] = {
	{ "fake-root", callback_fake_root, sizeof(struct mwt_root),
	  0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* --- the corpus -------------------------------------------------------- */

static int
mwt_mkdir(const char *path)
{
	if (mkdir(path, 0700) && errno != EEXIST) {
		lwsl_err("%s: mkdir %s failed: %d\n", __func__, path, errno);
		return 1;
	}

	return 0;
}

static int
mwt_whois_json(const char *domain, time_t age)
{
	struct timeval tv[2];
	char path[256];
	int fd;

	lws_snprintf(path, sizeof(path), MWT_BASE "/domains/%s/whois.json",
		     domain);
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0)
		return 1;
	if (write(fd, "{}", 2) != 2) {
		close(fd);
		return 1;
	}
	close(fd);

	gettimeofday(&tv[0], NULL);
	tv[0].tv_sec -= age;
	tv[1] = tv[0];

	return utimes(path, tv);
}

static int
mwt_corpus(void)
{
	static const char * const domains[] = {
		"fresh.test", "stale.test", "new.test"
	};
	char path[256];
	size_t n;

	if (mwt_mkdir(MWT_BASE) || mwt_mkdir(MWT_BASE "/domains"))
		return 1;

	for (n = 0; n < LWS_ARRAY_SIZE(domains); n++) {
		lws_snprintf(path, sizeof(path), MWT_BASE "/domains/%s",
			     domains[n]);
		if (mwt_mkdir(path))
			return 1;
		lws_snprintf(path, sizeof(path),
			     MWT_BASE "/domains/%s/whois.json", domains[n]);
		unlink(path);
	}

	/* an hour old is fresh, two days old is stale, new.test has none */

	return mwt_whois_json("fresh.test", 3600) ||
	       mwt_whois_json("stale.test", 2 * 24 * 3600);
}

static void
mwt_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out, stale %d, new %d\n", __func__, got_stale,
		 got_new);
	fails++;
	mwt_finish();
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* two listeners, and both ends of the whois and IPC connections */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	lwsl_user("LWS API selftest: dnssec-monitor whois refresh\n");

	if (mwt_corpus()) {
		lwsl_err("unable to create the domains corpus\n");
		return 1;
	}

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port = port;
	info.vhost_name = "fake-registry";
	info.protocols = protocols_registry;
	info.options |= LWS_SERVER_OPTION_ONLY_RAW;
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("Failed to create fake registry vhost\n");
		fails++;
		goto bail;
	}

	unlink(MWT_UDS);
	info.port = 0;
	info.iface = MWT_UDS;
	info.vhost_name = "fake-root";
	info.protocols = protocols_root;
	info.options |= LWS_SERVER_OPTION_UNIX_SOCK;
	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("Failed to create fake root vhost\n");
		fails++;
		goto bail;
	}

	/* the proxy side of the plugin, as far as the whois refresh cares */

	vhd.context		= cx;
	vhd.vhost		= vh;
	vhd.base_dir		= (char *)MWT_BASE;
	vhd.uds_path		= MWT_UDS;
	vhd.whois_server	= "127.0.0.1";
	vhd.whois_port		= (uint16_t)port;

	if (lws_jwk_import(&vhd.auth_jwk, NULL, NULL, mwt_jwk,
			   strlen(mwt_jwk)) ||
	    monitor_whois_start(&vhd)) {
		lwsl_err("unable to start the whois refresh\n");
		fails++;
		goto bail;
	}

	/* don't wait for the usual startup delay */
	lws_sul_schedule(cx, 0, &vhd.sul_whois, monitor_whois_timer_cb, 1);
	lws_sul_schedule(cx, 0, &sul_timeout, mwt_timeout_cb,
			 20 * LWS_US_PER_SEC);

	while (!interrupted)
		if (lws_service(cx, 0) < 0)
			break;

	if (vhd.whois_refusals) {
		lwsl_err("%u answers taken as refusals\n", vhd.whois_refusals);
		fails++;
	}

	if (got_stale != 1 || got_new != 1 || updates != 2) {
		lwsl_err("updates: stale %d, new %d, total %d\n", got_stale,
			 got_new, updates);
		fails++;
	}

bail:
	lws_sul_cancel(&sul_timeout);
	lws_sul_cancel(&sul_settle);
	monitor_whois_stop(&vhd);
	lws_jwk_destroy(&vhd.auth_jwk);
	lws_context_destroy(cx);
	unlink(MWT_UDS);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
