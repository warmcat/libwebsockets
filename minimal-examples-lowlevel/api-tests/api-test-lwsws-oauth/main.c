/*
 * lws api test: the delegated oauth login, against a real lwsws
 *
 * Written in 2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * The fixture (see CMakeLists.txt) is a real lwsws carrying both halves of the
 * delegated login: an auth vhost running lws-auth-server, and an app vhost
 * running lws-oauth2-client + lws-login + lws_login_client, with the app's
 * protected mount reached through an lws-login interceptor-path.  Both vhosts
 * offer h1, h2 and h3 on the same port numbers.
 *
 * Every scenario here can be told which transport to use, because the failure
 * this test exists for did not care what any request said, only how it was
 * framed: the identical exchange completed on h1 and lost its headers on h2 and
 * h3, and nothing in the stack logged anything about it.  A test that only ever
 * spoke h1 could not see it.
 *
 * Scenarios
 *
 *  bounce: fetch the protected mount with an empty jar and walk the handover.
 *          lws-login must bounce to the local BFF, and the BFF must answer with
 *          a PKCE redirect to the auth server carrying client_id, redirect_uri,
 *          state, code_challenge + S256 and service_name, plus the
 *          auth_oauth_state binding cookie that RFC 6749 s10.12 wants.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sqlite3.h>
#include <time.h>

static int	interrupted, bad = 1, port_auth, port_app;
/*
 * An earlier keepalive connection closing ("peer closed while idle") delivers
 * CLOSED_CLIENT_HTTP while a later request is still waiting for its response.
 * Treating that as our own completion abandoned the request with nothing
 * parsed, which looked exactly like a transport fault on h1 and h2 while h3,
 * having no such idle close, passed.
 *
 * Filtering on the wsi is not the answer: on h2 and h3 the transaction arrives
 * on a mux child, not the wsi the connect handed back.  What separates them is
 * simpler -- a close belonging to a transaction of ours has a status by then,
 * and a stale idle close never does.
 */
static const char *server = "127.0.0.1", *alpn = "http/1.1",
		  *test = "bounce", *client_id = "", *service_name = "",
		  *db_path = NULL, *redirect_uris = "";

/*
 * The seeded accounts.  Both are *verified*: a row in "users" is a verified
 * account, "registrations" being the table that holds ones still waiting on an
 * emailed link, so seeding straight into users is what skips the mail round
 * trip a test cannot do.
 *
 * One has no TOTP secret and one has, because the auth server skips the whole
 * second factor when the column is empty -- so the pair covers both the plain
 * password login and the authenticator path with one set of fixtures.
 */
#define SEED_USER		"apitest-user"
#define SEED_USER_TOTP		"apitest-totp-user"
#define SEED_PASSWORD		"apitest-password"
#define SEED_SALT		"0123456789abcdef0123456789abcdef"
/* base32, as the column holds it and as lws_b32_decode_string_len() wants */
#define SEED_TOTP_SECRET	"JBSWY3DPEHPK3PXP"

/* what the exchange under way is collecting */
static char	loc[1024];		/* Location: of the last response */
static char	set_cookie[4096];	/* Set-Cookie(s) of the last response */
static char	body[8192];		/* body of the last response */
static size_t	body_len;
static unsigned int status;

struct lws_context *context;

/* ------------------------------------------------------------------ helpers */

/*
 * Report a failed expectation the way a ctest reader needs it: the scenario and
 * transport are in the test name, so the line only has to say which step and
 * what was wrong with it.
 */
static int
fail(const char *step, const char *fmt, ...)
{
	char s[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(s, sizeof(s), fmt, ap);
	va_end(ap);

	lwsl_err("FAIL: %s: %s\n", step, s);

	return 1;
}

/*
 * Is \p name present in the collected Set-Cookie headers?  Matched as a whole
 * cookie name so auth_session does not also answer for auth_session_x.
 */
static int
has_cookie(const char *name)
{
	size_t nl = strlen(name);
	const char *p = set_cookie;

	while ((p = strstr(p, name))) {
		if ((p == set_cookie || p[-1] == ' ' || p[-1] == ';') &&
		    p[nl] == '=')
			return 1;
		p += nl;
	}

	return 0;
}

/* does the query of the last Location: carry \p key ? */
static int
loc_has(const char *key)
{
	char nb[64];
	const char *q = strchr(loc, '?');

	if (!q)
		return 0;

	lws_snprintf(nb, sizeof(nb), "%s=", key);

	if (!strncmp(q + 1, nb, strlen(nb)))
		return 1;

	lws_snprintf(nb, sizeof(nb), "&%s=", key);

	return !!strstr(q, nb);
}

/* ---------------------------------------------------------------- cookie jar */

/*
 * One jar per vhost, not one jar.
 *
 * In the deployment the app and the auth server are on two registrable
 * domains, so neither ever sees the other's cookies; the BFF forwards the app
 * jar to the auth server explicitly and that is the only path between them.
 * Here both vhosts answer on one name at two ports, and cookies are keyed by
 * host and not by port, so a single jar would let the two servers' same-named
 * cookies overwrite each other -- modelling something that cannot happen and
 * hiding the thing that can.
 */

enum { JAR_AUTH, JAR_APP, JAR_COUNT };

struct cookie {
	char		name[64];
	char		value[3072];
	char		domain[128];	/* "" when the cookie is host-only */
	char		dead;
};

#define COOKIES_MAX 12

static struct cookie	jar[JAR_COUNT][COOKIES_MAX];

static const char *jar_name[JAR_COUNT] = { "auth", "app" };

static struct cookie *
jar_find(int j, const char *name, const char *domain)
{
	int n;

	for (n = 0; n < COOKIES_MAX; n++)
		if (jar[j][n].name[0] && !strcmp(jar[j][n].name, name) &&
		    !strcmp(jar[j][n].domain, domain ? domain : ""))
			return &jar[j][n];

	return NULL;
}

static struct cookie *
jar_slot(int j)
{
	int n;

	for (n = 0; n < COOKIES_MAX; n++)
		if (!jar[j][n].name[0])
			return &jar[j][n];

	return NULL;
}

/*
 * Take in one Set-Cookie value.  A cookie is identified by name *and* scope: a
 * Domain=-scoped one and a host-only one of the same name are two different
 * cookies that a browser stores side by side and sends both of, which is the
 * state that had the field picking a stale csrf over a live one.
 */
static void
jar_set(int j, const char *sc)
{
	char name[64], value[3072], domain[128] = "";
	const char *eq, *semi, *p;
	struct cookie *c;
	size_t n;
	long ma = -1;

	eq = strchr(sc, '=');
	if (!eq || (size_t)(eq - sc) >= sizeof(name))
		return;

	n = (size_t)(eq - sc);
	memcpy(name, sc, n);
	name[n] = '\0';

	semi = strchr(eq + 1, ';');
	n = semi ? (size_t)(semi - eq - 1) : strlen(eq + 1);
	if (n >= sizeof(value))
		n = sizeof(value) - 1;
	memcpy(value, eq + 1, n);
	value[n] = '\0';

	/* attributes we have to understand to model the jar honestly */

	p = semi;
	while (p) {
		while (*p == ';' || *p == ' ')
			p++;
		if (!strncasecmp(p, "Domain=", 7)) {
			const char *e = strchr(p, ';');
			size_t dl = e ? (size_t)(e - p - 7) : strlen(p + 7);

			if (dl >= sizeof(domain))
				dl = sizeof(domain) - 1;
			/* a leading dot is how it may be written; same scope */
			if (p[7] == '.') {
				memcpy(domain, p + 8, dl - 1);
				domain[dl - 1] = '\0';
			} else {
				memcpy(domain, p + 7, dl);
				domain[dl] = '\0';
			}
		}
		if (!strncasecmp(p, "Max-Age=", 8))
			ma = atol(p + 8);
		p = strchr(p, ';');
	}

	c = jar_find(j, name, domain);
	if (!c) {
		c = jar_slot(j);
		if (!c)
			return;
	}

	lws_strncpy(c->name, name, sizeof(c->name));
	lws_strncpy(c->value, value, sizeof(c->value));
	lws_strncpy(c->domain, domain, sizeof(c->domain));
	/* Max-Age=0 (or an empty value) is a deletion */
	c->dead = (char)(!ma || !value[0]);

	lwsl_info("jar[%s]: %s %s=%.16s...\n", jar_name[j],
		  c->dead ? "cleared" : (domain[0] ? "set (Domain)" :
					 "set (host-only)"), name, value);
}

/* absorb every Set-Cookie of the last response */
static void
jar_absorb(int j, const char *set_cookies)
{
	char one[3300];
	const char *p = set_cookies;

	/*
	 * lws_hdr_copy() joins several Set-Cookie headers (or the h2 / h3
	 * crumbs of them) with ';', which is also the attribute separator, so
	 * split on the boundary that actually distinguishes them: a ';'
	 * followed by something that looks like "name=" and is not one of the
	 * attributes.
	 */

	while (p && *p) {
		const char *q = p;
		size_t n;

		for (;;) {
			q = strchr(q, ';');
			if (!q)
				break;
			{
				const char *r = q + 1;

				while (*r == ' ')
					r++;
				if (strncasecmp(r, "Domain=", 7) &&
				    strncasecmp(r, "Path=", 5) &&
				    strncasecmp(r, "Max-Age=", 8) &&
				    strncasecmp(r, "Expires=", 8) &&
				    strncasecmp(r, "HttpOnly", 8) &&
				    strncasecmp(r, "Secure", 6) &&
				    strncasecmp(r, "SameSite=", 9) &&
				    strchr(r, '='))
					break;
			}
			q++;
		}

		n = q ? (size_t)(q - p) : strlen(p);
		if (n >= sizeof(one))
			n = sizeof(one) - 1;
		memcpy(one, p, n);
		one[n] = '\0';

		jar_set(j, one);

		p = q ? q + 1 : NULL;
		while (p && *p == ' ')
			p++;
	}
}

/* compose the Cookie header this jar would send */
static int
jar_header(int j, char *out, size_t out_len)
{
	int n, first = 1, m = 0;

	out[0] = '\0';

	for (n = 0; n < COOKIES_MAX; n++) {
		if (!jar[j][n].name[0] || jar[j][n].dead)
			continue;

		m += lws_snprintf(out + m, out_len - (size_t)m, "%s%s=%s",
				  first ? "" : "; ", jar[j][n].name,
				  jar[j][n].value);
		first = 0;
	}

	return m;
}

static const char *
jar_value(int j, const char *name)
{
	int n;

	for (n = 0; n < COOKIES_MAX; n++)
		if (jar[j][n].name[0] && !jar[j][n].dead &&
		    !strcmp(jar[j][n].name, name))
			return jar[j][n].value;

	return NULL;
}

/* how many live copies of \p name the jar holds, across scopes */
static int
jar_count(int j, const char *name)
{
	int n, c = 0;

	for (n = 0; n < COOKIES_MAX; n++)
		if (jar[j][n].name[0] && !jar[j][n].dead &&
		    !strcmp(jar[j][n].name, name))
			c++;

	return c;
}

/* ------------------------------------------------------------------ callback */

struct req_args {
	const char	*body;		/* NULL for a GET */
	size_t		body_len;
	size_t		body_pos;
	int		jar;
};

static struct req_args cur;

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 4096], *start = &buf[LWS_PRE], *p = start;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (char *)in : "(none)");
		interrupted = 1;
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		{
			unsigned char **pp = (unsigned char **)in,
				      *pend = (*pp) + len;
			char ck[4096];

			if (jar_header(cur.jar, ck, sizeof(ck)) &&
			    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_COOKIE,
					(unsigned char *)ck, (int)strlen(ck),
					pp, pend))
				return -1;

			if (cur.body) {
				char cl[24];

				if (lws_add_http_header_by_token(wsi,
						WSI_TOKEN_HTTP_CONTENT_TYPE,
						(unsigned char *)
						"application/x-www-form-urlencoded",
						33, pp, pend))
					return -1;

				lws_snprintf(cl, sizeof(cl), "%u",
					     (unsigned int)cur.body_len);

				if (lws_add_http_header_by_token(wsi,
						WSI_TOKEN_HTTP_CONTENT_LENGTH,
						(unsigned char *)cl,
						(int)strlen(cl), pp, pend))
					return -1;

				/*
				 * Without these the request goes out with no
				 * body at all and the peer closes on us: the
				 * canonical pattern is to declare the body
				 * pending here and ask for the writeable
				 */
				lws_client_http_body_pending(wsi, 1);
				lws_callback_on_writable(wsi);
			}
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!cur.body || cur.body_pos >= cur.body_len)
			break;
		{
			size_t n = cur.body_len - cur.body_pos;

			if (n > 1024)
				n = 1024;
			memcpy(p, cur.body + cur.body_pos, n);
			cur.body_pos += n;
			if (lws_write(wsi, start, n,
				      cur.body_pos == cur.body_len ?
					LWS_WRITE_HTTP_FINAL :
					LWS_WRITE_HTTP) != (int)n)
				return -1;

			if (cur.body_pos < cur.body_len)
				lws_callback_on_writable(wsi);
			else
				lws_client_http_body_pending(wsi, 0);
		}
		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (unsigned int)lws_http_client_http_response(wsi);

		loc[0] = set_cookie[0] = body[0] = '\0';
		body_len = 0;
		lws_hdr_copy(wsi, loc, sizeof(loc), WSI_TOKEN_HTTP_LOCATION);
		lws_hdr_copy(wsi, set_cookie, sizeof(set_cookie),
			     WSI_TOKEN_HTTP_SET_COOKIE);

		if (set_cookie[0])
			jar_absorb(cur.jar, set_cookie);

		lwsl_info("%s: %u, Location '%s'\n", __func__, status, loc);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (body_len + len < sizeof(body) - 1) {
			memcpy(body + body_len, in, len);
			body_len += len;
			body[body_len] = '\0';
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char rb[1024 + LWS_PRE];
			char *px = rb + LWS_PRE;
			int lenx = sizeof(rb) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		interrupted = 1;
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* ours if this transaction got as far as a status */
		if (status)
			interrupted = 1;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "http", callback_http, 0, 0, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

/*
 * One request, no redirect following: each hop of the flow is an assertion of
 * its own, so the test has to see every status and header itself.
 */
static int
req_full(int which_jar, int port, const char *path, const char *body)
{
	struct lws_client_connect_info i;
	char hostport[128];

	memset(&i, 0, sizeof(i));
	memset(&cur, 0, sizeof(cur));

	/*
	 * The Host header has to carry the port, as a browser's would on a
	 * non-default one: both plugins compose absolute URLs of their own from
	 * it -- the BFF its redirect_uri, the auth server the RFC 9207 iss --
	 * and those have to name somewhere reachable.
	 */
	if (port == 443)
		lws_strncpy(hostport, server, sizeof(hostport));
	else
		lws_snprintf(hostport, sizeof(hostport), "%s:%d", server, port);

	cur.jar		= which_jar;
	cur.body	= body;
	cur.body_len	= body ? strlen(body) : 0;

	i.context		= context;
	i.port			= port;
	i.address		= server;
	i.path			= path;
	i.host			= hostport;
	i.origin		= hostport;
	i.method		= body ? "POST" : "GET";
	i.protocol		= protocols[0].name;
	i.alpn			= alpn;
	/*
	 * The fixture serves the build tree's test cert, which is not for this
	 * name and not signed by anything we trust: this test is about the
	 * login exchange, not about TLS.
	 */
	i.ssl_connection	= LCCSCF_USE_SSL |
				  LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				  LCCSCF_ALLOW_INSECURE |
				  LCCSCF_HTTP_NO_FOLLOW_REDIRECT;

	status = 0;
	interrupted = 0;
	body_len = 0;

	if (!lws_client_connect_via_info(&i))
		return 1;

	{
		lws_usec_t deadline = lws_now_usecs() + (20 * LWS_US_PER_SEC);

		while (!interrupted && lws_service(context, 0) >= 0)
			if (lws_now_usecs() > deadline) {
				lwsl_err("%s: %s timed out with no completed "
					 "transaction\n", __func__, path);

				return 1;
			}
	}

	return 0;
}

/* the app vhost, which is what the old scenario only ever talked to */
static int
req(int port, const char *path)
{
	return req_full(port == port_auth ? JAR_AUTH : JAR_APP, port, path,
			NULL);
}

/* ------------------------------------------------------- credential helpers */

/*
 * PBKDF2-SHA-512, one block, exactly as the auth server computes it for
 * users.password_hash (plugins/protocol_lws_auth_server: pbkdf2_sha512()).
 * Seeding means reproducing it, so if the server's scheme ever changes this
 * test fails loudly rather than quietly seeding an account nothing can log
 * into.
 */
static int
seed_pbkdf2_sha512(const char *password, const char *salt, int iterations,
		   uint8_t *out_hash)
{
	uint8_t salt_block[256], u[64];
	struct lws_genhmac_ctx ctx;
	size_t salt_len = strlen(salt);
	int i, j;

	if (salt_len > sizeof(salt_block) - 4)
		return -1;

	memcpy(salt_block, salt, salt_len);
	salt_block[salt_len] = 0;
	salt_block[salt_len + 1] = 0;
	salt_block[salt_len + 2] = 0;
	salt_block[salt_len + 3] = 1;

	if (lws_genhmac_init(&ctx, LWS_GENHMAC_TYPE_SHA512,
			     (const uint8_t *)password, strlen(password)))
		return -1;
	if (lws_genhmac_update(&ctx, salt_block, salt_len + 4))
		return -1;
	if (lws_genhmac_destroy(&ctx, u))
		return -1;

	memcpy(out_hash, u, 64);

	for (i = 1; i < iterations; i++) {
		if (lws_genhmac_init(&ctx, LWS_GENHMAC_TYPE_SHA512,
				     (const uint8_t *)password,
				     strlen(password)))
			return -1;
		if (lws_genhmac_update(&ctx, u, 64))
			return -1;
		if (lws_genhmac_destroy(&ctx, u))
			return -1;
		for (j = 0; j < 64; j++)
			out_hash[j] ^= u[j];
	}

	return 0;
}

/* the hex form that goes in the column */
static int
seed_password_hash(const char *password, const char *salt, char *hex,
		   size_t hex_len)
{
	uint8_t hash[64];

	if (seed_pbkdf2_sha512(password, salt, 100000, hash))
		return -1;

	return lws_genhash_render(LWS_GENHASH_TYPE_SHA512, hash, hex, hex_len);
}

/*
 * RFC 6238 TOTP for \p secret_b32 at the current time, the same computation
 * the auth server verifies with.
 */
static int
totp_now(const char *secret_b32, uint32_t *code)
{
	uint8_t secret[64], t_bytes[8], hmac_result[LWS_GENHASH_LARGEST];
	struct lws_genhmac_ctx ctx;
	int secret_len, offset;

	secret_len = lws_b32_decode_string_len(secret_b32, -1, (char *)secret,
					       sizeof(secret));
	if (secret_len <= 0)
		return -1;

	lws_ser_wu64be(t_bytes, (uint64_t)time(NULL) / 30);

	if (lws_genhmac_init(&ctx, LWS_GENHMAC_TYPE_SHA1, secret,
			     (size_t)secret_len))
		return -1;
	if (lws_genhmac_update(&ctx, t_bytes, 8)) {
		lws_genhmac_destroy(&ctx, NULL);

		return -1;
	}
	if (lws_genhmac_destroy(&ctx, hmac_result))
		return -1;

	offset = hmac_result[19] & 0x0f;
	*code = (lws_ser_ru32be(&hmac_result[offset]) & 0x7fffffff) % 1000000;

	return 0;
}

/* ------------------------------------------------------------- the seeding */

static int
seed_exec(sqlite3 *db, const char *sql)
{
	char *err = NULL;

	if (sqlite3_exec(db, sql, NULL, NULL, &err) == SQLITE_OK)
		return 0;

	lwsl_err("%s: %s: %s\n", __func__, sql, err ? err : "?");
	if (err)
		sqlite3_free(err);

	return 1;
}

/*
 * Put verified accounts, their service grant, and the oauth client straight
 * into the auth server's db.
 *
 * The schema is created by the plugin at vhost init, so this runs as a second
 * ctest fixture step once lwsws is listening: it only ever inserts, it never
 * defines, so a schema change shows up here as a failing insert rather than as
 * a test quietly running against a table of its own invention.
 */
static int
scenario_seed(void)
{
	char sql[1024], hex[LWS_GENHASH_LARGEST * 2 + 1];
	sqlite3 *db = NULL;
	int r = 1;

	if (!db_path)
		return fail("seed", "--db is required for the seed step");

	if (seed_password_hash(SEED_PASSWORD, SEED_SALT, hex, sizeof(hex)) < 0)
		return fail("seed", "unable to compute the password hash");

	if (sqlite3_open(db_path, &db) != SQLITE_OK)
		return fail("seed", "unable to open %s: %s", db_path,
			    sqlite3_errmsg(db));

	/*
	 * The tables must already exist: if they do not, lwsws has not got as
	 * far as initialising the auth server vhost and seeding into a db we
	 * created ourselves would test nothing.
	 */
	lws_snprintf(sql, sizeof(sql),
		     "SELECT uid FROM users LIMIT 1");
	if (seed_exec(db, sql)) {
		fail("seed", "the auth server's schema is not in %s yet: "
			     "lwsws has not initialised its vhost", db_path);
		goto bail;
	}

	if (seed_exec(db, "BEGIN"))
		goto bail;

	/* the service the interceptor's pmo asks for a grant on */

	lws_snprintf(sql, sizeof(sql),
		     "INSERT OR IGNORE INTO services(service_id, name) "
		     "VALUES (1, '%s')", service_name);
	if (seed_exec(db, sql))
		goto bail;

	/* a password-only account, and one with a second factor */

	lws_snprintf(sql, sizeof(sql),
		     "INSERT OR REPLACE INTO users(uid, username, "
		     "password_hash, salt, totp_secret, session_epoch, "
		     "totp_last) VALUES (1, '%s', '%s', '%s', '', 0, 0)",
		     SEED_USER, hex, SEED_SALT);
	if (seed_exec(db, sql))
		goto bail;

	lws_snprintf(sql, sizeof(sql),
		     "INSERT OR REPLACE INTO users(uid, username, "
		     "password_hash, salt, totp_secret, session_epoch, "
		     "totp_last) VALUES (2, '%s', '%s', '%s', '%s', 0, 0)",
		     SEED_USER_TOTP, hex, SEED_SALT, SEED_TOTP_SECRET);
	if (seed_exec(db, sql))
		goto bail;

	/* both hold the service grant above min-grant-level */

	if (seed_exec(db, "INSERT OR REPLACE INTO "
			  "grants(uid, service_id, grant_level) "
			  "VALUES (1, 1, 2)") ||
	    seed_exec(db, "INSERT OR REPLACE INTO "
			  "grants(uid, service_id, grant_level) "
			  "VALUES (2, 1, 2)"))
		goto bail;

	/*
	 * The oauth client.  client_secret_hash is empty: this is a public
	 * PKCE client, which is what the BFF is.  redirect_uris is the
	 * comma-separated set auth_verify_redirect_uri() matches whole
	 * entries of.
	 */

	lws_snprintf(sql, sizeof(sql),
		     "INSERT OR REPLACE INTO oauth_clients(client_id, "
		     "client_secret_hash, redirect_uris, name) "
		     "VALUES ('%s', '', '%s', 'apitest')",
		     client_id, redirect_uris);
	if (seed_exec(db, sql))
		goto bail;

	if (seed_exec(db, "COMMIT"))
		goto bail;

	/*
	 * Prove the seeded secret is something the verifier's own algorithm can
	 * turn into a code, here rather than as a mystified 401 in a later
	 * login: a secret that is not valid base32 decodes to nothing and every
	 * code computed from it is simply wrong.
	 */
	{
		uint32_t code;

		if (totp_now(SEED_TOTP_SECRET, &code)) {
			fail("seed", "the seeded TOTP secret '%s' is not usable "
				     "base32", SEED_TOTP_SECRET);
			goto bail;
		}

		lwsl_info("seeded TOTP secret is live (code right now %06u)\n",
			  code);
	}

	lwsl_user("PASS: seed: %s (no totp) and %s (totp), grant on '%s', "
		  "client '%s'\n", SEED_USER, SEED_USER_TOTP, service_name,
		  client_id);

	r = 0;

bail:
	sqlite3_close(db);

	return r;
}

/* --------------------------------------------------------- little extractors */

/*
 * The value of \p key from a URL query, left exactly as it appeared.  Taking it
 * verbatim is deliberate: it goes straight back out in a urlencoded form body,
 * so re-coding it could only introduce a difference between what the BFF minted
 * and what the auth server is asked to match.
 */
static int
url_arg(const char *url, const char *key, char *out, size_t out_len)
{
	char nb[64];
	const char *q = strchr(url, '?'), *v, *e;

	out[0] = '\0';
	if (!q)
		return 1;

	lws_snprintf(nb, sizeof(nb), "%s=", key);

	if (!strncmp(q + 1, nb, strlen(nb)))
		v = q + 1 + strlen(nb);
	else {
		lws_snprintf(nb, sizeof(nb), "&%s=", key);
		v = strstr(q, nb);
		if (!v)
			return 1;
		v += strlen(nb);
	}

	e = strchr(v, '&');
	lws_strnncpy(out, v, e ? (size_t)(e - v) : strlen(v), out_len);

	return 0;
}

/* the string value of \p key from a flat JSON object, unescaping only "\/" */
static int
json_str(const char *json, const char *key, char *out, size_t out_len)
{
	char nb[64];
	const char *v;
	size_t m = 0;

	out[0] = '\0';

	lws_snprintf(nb, sizeof(nb), "\"%s\"", key);
	v = strstr(json, nb);
	if (!v)
		return 1;

	v = strchr(v + strlen(nb), ':');
	if (!v)
		return 1;
	v++;
	while (*v == ' ')
		v++;
	if (*v != '"')
		return 1;
	v++;

	while (*v && *v != '"' && m < out_len - 1) {
		if (v[0] == '\\' && v[1] == '/') {
			out[m++] = '/';
			v += 2;
			continue;
		}
		out[m++] = *v++;
	}
	out[m] = '\0';

	return 0;
}

/*
 * The registered redirect_uri has no port in it (the BFF composes it without
 * one), so the callback has to be issued against the app port by path.  Reduce
 * an absolute URL to its path + query.
 */
static const char *
url_path(const char *url)
{
	const char *p = strstr(url, "://");

	if (!p)
		return url;

	p = strchr(p + 3, '/');

	return p ? p : "/";
}

/*
 * The front half of the delegated login: the interceptor-guarded mount, the
 * widget's own view of whether anyone is logged in, and the BFF's PKCE handover
 * to the auth server.
 *
 * Note this deployment shape sets unauth-allow on the interceptor, so an
 * anonymous request is *not* bounced -- it is let through to the public view and
 * the page's widget decides what to render from /.lws-login-status.  Asserting a
 * 302 here would be asserting a different configuration than the one that runs.
 */
static int
scenario_bounce(void)
{
	char p[1024];

	/* (1) the guarded mount is reachable and, unauthenticated, public */

	if (req(port_app, "/sai/"))
		return fail("bounce", "unable to fetch the guarded mount");

	if (!status)
		return fail("bounce", "no parseable response to GET /sai/ "
				      "(the transport framed something the "
				      "client could not read)");

	if (status != 200)
		return fail("bounce", "GET /sai/ answered %u, wanted 200: "
				      "unauth-allow is set, so an anonymous "
				      "request is let through", status);

	if (!strstr(body, "APITEST-OAUTH-GATED-ORIGIN-REACHED"))
		return fail("bounce", "GET /sai/ did not return the origin "
				      "behind the interceptor (%zu bytes of "
				      "body)", body_len);

	/*
	 * (2) the widget's own probe.  This is the request a not-logged-in
	 * widget always makes, and the one that decides whether a user sees
	 * content or a Login button -- so "it says not logged in" has to be a
	 * thing the test can tell apart from "it did not answer".
	 */

	if (req(port_app, "/sai/.lws-login-status"))
		return fail("bounce", "unable to fetch the login status probe");

	if (!status)
		return fail("bounce", "no parseable response to the "
				      "/sai/.lws-login-status probe");

	if (status != 200)
		return fail("bounce", "/sai/.lws-login-status answered %u, "
				      "wanted 200", status);

	if (!body_len)
		return fail("bounce", "/sai/.lws-login-status returned an "
				      "empty body");

	lwsl_info("status probe said: %s\n", body);

	/*
	 * (3) pressing Login: the local BFF must answer with a PKCE redirect
	 * to the auth server, carrying the parameters that let the auth server
	 * enforce the grant before it renders a form, and binding the state to
	 * this user agent.
	 */

	if (req(port_app, "/oauth/login"))
		return fail("bounce", "unable to fetch the BFF login entry");

	if (!status)
		return fail("bounce", "no parseable response to /oauth/login");

	if (status != 302)
		return fail("bounce", "/oauth/login answered %u, wanted a 302 "
				      "to the auth server", status);

	if (!strstr(loc, "/api/authorize"))
		return fail("bounce", "/oauth/login redirected to '%s', wanted "
				      "the auth server's /api/authorize", loc);

	if (!loc_has("client_id"))
		return fail("bounce", "no client_id in '%s'", loc);
	if (!loc_has("redirect_uri"))
		return fail("bounce", "no redirect_uri in '%s'", loc);
	if (!loc_has("state"))
		return fail("bounce", "no state in '%s'", loc);
	if (!loc_has("code_challenge"))
		return fail("bounce", "no code_challenge in '%s'", loc);
	if (!strstr(loc, "code_challenge_method=S256"))
		return fail("bounce", "code_challenge_method is not S256 in "
				      "'%s'", loc);
	if (client_id[0] && !strstr(loc, client_id))
		return fail("bounce", "client_id in '%s' is not the configured "
				      "'%s'", loc, client_id);

	/*
	 * RFC 6749 s10.12: the state must be bound to the user agent, or a
	 * callback URL captured from an attacker's own authorize round trip
	 * can be handed to a victim.  That binding is this cookie -- and a
	 * Set-Cookie is exactly the kind of header that went missing on h2 and
	 * h3 while the body of the same response arrived intact.
	 */

	if (!has_cookie("auth_oauth_state"))
		return fail("bounce", "/oauth/login set no auth_oauth_state "
				      "binding cookie (Set-Cookie seen: '%s')",
				      set_cookie);

	(void)p;

	lwsl_user("PASS: bounce: guarded mount, status probe, and PKCE "
		  "handover to %s\n", loc);

	return 0;
}


/*
 * The credential half, end to end, and the point of the whole fixture: it is
 * the only path that makes the auth server mint a session, which is the
 * response carrying the large Set-Cookies, and the only one that makes the BFF
 * talk to the auth server server-to-server.
 */
static int
scenario_login(void)
{
	char p[1024], body_buf[2048], authorize[1024];
	char csrf[128], state[256], chal[256], ruri[512], redirect[768];

	/* (1) the BFF mints the state, the PKCE verifier, and its binding cookie */

	lws_snprintf(p, sizeof(p), "/oauth/login?service_name=%s", service_name);

	if (req_full(JAR_APP, port_app, p, NULL) || status != 302)
		return fail("login", "/oauth/login answered %u, wanted a 302 "
				     "to the auth server", status);

	lws_strncpy(authorize, loc, sizeof(authorize));

	if (url_arg(authorize, "state", state, sizeof(state)) ||
	    url_arg(authorize, "code_challenge", chal, sizeof(chal)) ||
	    url_arg(authorize, "redirect_uri", ruri, sizeof(ruri)))
		return fail("login", "the authorize redirect is missing a PKCE "
				     "parameter: '%s'", authorize);

	if (!jar_value(JAR_APP, "auth_oauth_state"))
		return fail("login", "no auth_oauth_state binding cookie in "
				     "the app jar after /oauth/login");

	/*
	 * (2) the auth server's own page state.  This is where the browser gets
	 * the auth_csrf cookie, and the csrf_token to submit with it: /api/login
	 * enforces the double-submit, so a test that skips this gets a 403 and
	 * learns nothing about the credentials.
	 */

	if (req_full(JAR_AUTH, port_auth, "/api/status", NULL) || status != 200)
		return fail("login", "/api/status answered %u, wanted 200",
			    status);

	if (json_str(body, "csrf_token", csrf, sizeof(csrf)) || !csrf[0])
		return fail("login", "no csrf_token in the /api/status body "
				     "'%s'", body);

	if (!jar_value(JAR_AUTH, "auth_csrf"))
		return fail("login", "/api/status set no auth_csrf cookie, so "
				     "the double-submit cannot be satisfied");

	/* (3) the credentials, with the BFF's PKCE parameters carried through */

	lws_snprintf(body_buf, sizeof(body_buf),
		     "username=%s&password=%s&csrf_token=%s"
		     "&client_id=%s&redirect_uri=%s&state=%s"
		     "&code_challenge=%s&code_challenge_method=S256"
		     "&service_name=%s",
		     SEED_USER, SEED_PASSWORD, csrf, client_id, ruri, state,
		     chal, service_name);

	if (req_full(JAR_AUTH, port_auth, "/api/login", body_buf))
		return fail("login", "unable to POST /api/login");

	if (status != 200)
		return fail("login", "/api/login answered %u for a seeded "
				     "verified account, body '%s'", status,
			    body);

	if (json_str(body, "redirect", redirect, sizeof(redirect)) ||
	    !strstr(redirect, "code="))
		return fail("login", "/api/login returned no authorization "
				     "code to redirect with: '%s'", body);

	/*
	 * (4) the callback.  This is the hop that matters most: the BFF
	 * exchanges the code at the auth server's /api/token over its own
	 * server-to-server connection, and then plants the session cookies.
	 */

	if (req_full(JAR_APP, port_app, url_path(redirect), NULL))
		return fail("login", "unable to fetch the callback %s",
			    url_path(redirect));

	if (status != 302 && status != 303)
		return fail("login", "/oauth/callback answered %u, wanted a "
				     "redirect back to the app: body '%s'",
			    status, body);

	if (!jar_value(JAR_APP, "auth_session"))
		return fail("login", "/oauth/callback planted no auth_session "
				     "cookie (Set-Cookie seen: '%s')",
			    set_cookie);

	if (!jar_value(JAR_APP, "auth_refresh_session"))
		return fail("login", "/oauth/callback planted no "
				     "auth_refresh_session, so nothing can renew "
				     "the session later (Set-Cookie seen: '%s')",
			    set_cookie);

	if (!jar_value(JAR_APP, "auth_csrf"))
		return fail("login", "/oauth/callback planted no auth_csrf "
				     "sidecar for the refresh session");

	/*
	 * Each of those should exist once.  Two live copies of one name is the
	 * state that had the field submitting a stale csrf while forwarding a
	 * jar that held both.
	 */

	if (jar_count(JAR_APP, "auth_session") != 1 ||
	    jar_count(JAR_APP, "auth_csrf") != 1 ||
	    jar_count(JAR_APP, "auth_refresh_session") != 1)
		return fail("login", "the app jar holds duplicate scopes of a "
				     "session cookie: auth_session %d, "
				     "auth_csrf %d, auth_refresh_session %d",
			    jar_count(JAR_APP, "auth_session"),
			    jar_count(JAR_APP, "auth_csrf"),
			    jar_count(JAR_APP, "auth_refresh_session"));

	/* (5) and the widget now sees a session */

	if (req_full(JAR_APP, port_app, "/sai/.lws-login-status", NULL) ||
	    status != 200)
		return fail("login", "the status probe answered %u after a "
				     "successful login", status);

	if (!strstr(body, "\"logged_in\": 1") &&
	    !strstr(body, "\"logged_in\":1"))
		return fail("login", "the status probe still reports no "
				     "session after a successful login: '%s'",
			    body);

	lwsl_user("PASS: login: %s authenticated, session planted, widget "
		  "agrees\n", SEED_USER);

	return 0;
}

/* ---------------------------------------------------------------------- main */

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;
	if ((p = lws_cmdline_option(argc, argv, "--auth-port")))
		port_auth = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--app-port")))
		port_app = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--client-id")))
		client_id = p;
	if ((p = lws_cmdline_option(argc, argv, "--service-name")))
		service_name = p;
	if ((p = lws_cmdline_option(argc, argv, "-t")))
		test = p;
	if ((p = lws_cmdline_option(argc, argv, "--db")))
		db_path = p;
	if ((p = lws_cmdline_option(argc, argv, "--redirect-uris")))
		redirect_uris = p;

	if (lws_cmdline_option(argc, argv, "--h1"))
		alpn = "http/1.1";
	if (lws_cmdline_option(argc, argv, "--h2"))
		alpn = "h2";
	if (lws_cmdline_option(argc, argv, "--h3"))
		alpn = "h3";

	if (!strcmp(test, "seed")) {
		/* no context needed: this one only touches the db */
		bad = scenario_seed();
		lwsl_user("Completed: %s\n", bad ? "FAIL" : "PASS");

		return bad;
	}

	if (!port_auth || !port_app) {
		lwsl_err("%s: --auth-port and --app-port are required\n",
			 __func__);

		return 1;
	}

	lwsl_user("LWS api test: lwsws oauth: %s over %s\n", test, alpn);

	memset(&info, 0, sizeof info);
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: lws init failed\n", __func__);

		return 1;
	}

	if (!strcmp(test, "bounce"))
		bad = scenario_bounce();
	else if (!strcmp(test, "login"))
		bad = scenario_login();
	else {
		lwsl_err("%s: unknown scenario '%s'\n", __func__, test);
		bad = 1;
	}

	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", bad ? "FAIL" : "PASS");

	return bad;
}
