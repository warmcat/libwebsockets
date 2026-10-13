/*
 * lws-api-test-auth-feed
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * End to end test of the auth feed: the real lws-auth-server on one vhost
 * tells the real lws-login on another what its records say, over the
 * lws-auth-feed ws protocol, so lws-login needs neither the auth server's
 * database nor its key.  lws-login here has no jwt-jwk at all: it must learn
 * the key tokens are signed with from the feed too.
 *
 * The test changes the auth server's records directly in its sqlite db, the
 * way an admin with the sqlite3 shell would, and watches what comes out, both
 * through a feed subscription of its own and through what lws-login does with
 * a session token at the gated mount.  In order, it checks:
 *
 *  - a subscriber with the feed secret is sent a snapshot holding the records
 *    the test seeded;
 *
 *  - a subscriber with no secret, or the wrong one, is refused;
 *
 *  - lws-login lets a token the records back through to the gated mount, so
 *    it got the key and the records from the feed;
 *
 *  - a write to the db that changes nothing in the snapshot (an audit log
 *    row) sends subscribers nothing;
 *
 *  - bumping the user's session epoch, as a password reset does, reaches the
 *    subscriber, and then lws-login refuses the same token.
 */

#include <libwebsockets.h>
#include <lws-auth-feed.h>

#include <sqlite3.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define FEED_SECRET	"apitest-auth-feed-secret-0123456789abcdef"
#define PRIV_PROTOCOL	"lws-api-test-auth-feed-priv"

/* how long anything is given to propagate */
#define PHASE_TIMEOUT_US	(15 * LWS_US_PER_SEC)
/* how long nothing is watched for being sent */
#define QUIET_US		(3 * LWS_US_PER_SEC)

enum {
	PH_SEED,		/* the auth server is up: seed its records */
	PH_SUBSCRIBE,		/* our subscriber gets the seeded records */
	PH_NO_SECRET,		/* a subscriber with no secret is refused */
	PH_BAD_SECRET,		/* ... and one with the wrong secret */
	PH_LIVE,		/* lws-login lets the token through */
	PH_QUIET,		/* an unrelated write sends nothing */
	PH_REVOKE_FEED,		/* an epoch bump reaches the subscriber */
	PH_REVOKE_LOGIN,	/* ... and lws-login refuses the token */
	PH_DONE
};

static const char * const phase_names[] = {
	"auth server came up and was seeded",
	"subscriber is sent the seeded records",
	"subscriber without the secret refused",
	"subscriber with the wrong secret refused",
	"lws-login passes a token the records back, key from the feed",
	"a write changing nothing in the snapshot sends nothing",
	"session epoch bump reaches the subscriber",
	"lws-login refuses the revoked token",
};

/* what each client connection of ours is for */
enum role {
	ROLE_FEED,		/* our feed subscriber */
	ROLE_FEED_NO_SECRET,
	ROLE_FEED_BAD_SECRET,
	ROLE_GATED,		/* a ws upgrade at lws-login's gated mount */
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_check;
static int port_auth, port_app, phase, tests, fail, done;
static lws_usec_t phase_deadline, quiet_until;
static char work[64], db_path[128], jwk_path[128], cookie[2048];

/* what our feed subscriber has seen */
static int snapshots, seen_uid1_sec = -1, seen_uid1_grant = -1;
static char *feed_rx;
static size_t feed_rx_len;

/* how the latest connection for a role went: 1 up, -1 refused, 0 pending */
static int outcome[ROLE_GATED + 1];
static int snapshots_at_quiet;

static void
expect(const char *what, int ok)
{
	tests++;
	if (!ok)
		fail++;
	lwsl_user("  %s: %s\n", ok ? "PASS" : "FAIL", what);
}

static int
db_exec(const char *sql)
{
	char *err = NULL;
	sqlite3 *db;
	int n;

	if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE, NULL) !=
								SQLITE_OK) {
		lwsl_err("%s: unable to open %s\n", __func__, db_path);
		sqlite3_close(db);
		return 1;
	}

	n = sqlite3_exec(db, sql, NULL, NULL, &err);
	if (n != SQLITE_OK) {
		lwsl_err("%s: '%s' failed: %s\n", __func__, sql,
			 err ? err : "unknown");
		sqlite3_free(err);
	}
	sqlite3_close(db);

	return n != SQLITE_OK;
}

/*
 * A session token for uid 1 the way the auth server mints them, signed with
 * the key it generated at jwk_path
 */
static int
mint_cookie(void)
{
	unsigned long long now = (unsigned long long)time(NULL);
	char tok[1024], temp[2048];
	size_t tok_len = sizeof(tok);
	struct lws_jwk jwk;
	int r;

	memset(&jwk, 0, sizeof(jwk));
	if (lws_jwk_load(&jwk, jwk_path, NULL, NULL)) {
		lwsl_err("%s: no auth server key at %s\n", __func__, jwk_path);
		return 1;
	}

	r = lws_jwt_sign_compact(context, &jwk, "ES256", tok, &tok_len, temp,
				 sizeof(temp),
				 "{\"iss\":\"apitest\",\"sub\":\"alice\","
				 "\"uid\":1,\"sec\":5,\"iat\":%llu,"
				 "\"exp\":%llu,\"grants\":"
				 "{\"default-service\":1}}", now, now + 3600);
	lws_jwk_destroy(&jwk);
	if (r)
		return 1;

	lws_snprintf(cookie, sizeof(cookie), "auth_session=%s", tok);

	return 0;
}

/* a whole snapshot arrived on our subscription: what does it say? */
static void
feed_snapshot(const char *json, size_t len)
{
	lws_struct_args_t a;
	struct lejp_ctx ctx;
	lws_auth_feed_t *f;
	int m;

	memset(&a, 0, sizeof(a));
	a.map_st[0]		= lsm_auth_feed_schema;
	a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_auth_feed_schema);
	a.ac_block_size		= 4096;

	lws_struct_json_init_parse(&ctx, NULL, &a);
	m = lejp_parse(&ctx, (const uint8_t *)json, (int)len);
	lejp_destruct(&ctx);
	if (m < 0 || !a.dest) {
		lwsl_err("%s: unparseable snapshot\n", __func__);
		lwsac_free(&a.ac);
		return;
	}

	f = (lws_auth_feed_t *)a.dest;
	snapshots++;
	seen_uid1_sec = seen_uid1_grant = -1;

	lws_start_foreach_dll(struct lws_dll2 *, d, f->users.head) {
		lws_auth_feed_user_t *u = lws_container_of(d,
					lws_auth_feed_user_t, list);
		if (u->uid == 1)
			seen_uid1_sec = (int)u->sec;
	} lws_end_foreach_dll(d);

	lws_start_foreach_dll(struct lws_dll2 *, d, f->grants.head) {
		lws_auth_feed_grant_t *g = lws_container_of(d,
					lws_auth_feed_grant_t, list);
		if (g->uid == 1 && g->svc && !strcmp(g->svc, "default-service"))
			seen_uid1_grant = (int)g->level;
	} lws_end_foreach_dll(d);

	lwsl_user("  snapshot %d: uid 1 sec %d grant %d, jwk %s\n", snapshots,
		  seen_uid1_sec, seen_uid1_grant, f->jwk ? "present" : "absent");

	lwsac_free(&a.ac);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	enum role role = (enum role)(intptr_t)lws_get_opaque_user_data(wsi);
	unsigned char **p, *end;
	char *nb;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		p = (unsigned char **)in;
		end = (*p) + len;

		if (role == ROLE_FEED &&
		    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_AUTHORIZATION,
				(unsigned char *)"Bearer " FEED_SECRET,
				(int)strlen("Bearer " FEED_SECRET), p, end))
			return -1;
		if (role == ROLE_FEED_BAD_SECRET &&
		    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_AUTHORIZATION,
				(unsigned char *)"Bearer " FEED_SECRET "x",
				(int)strlen("Bearer " FEED_SECRET "x"), p, end))
			return -1;
		if (role == ROLE_GATED &&
		    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
				(unsigned char *)cookie, (int)strlen(cookie),
				p, end))
			return -1;
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		outcome[role] = 1;
		/*
		 * Only our subscriber stays.  Refusing CLIENT_ESTABLISHED
		 * would be reported as a connection error, so let it come
		 * up and close it from outside the callback
		 */
		if (role != ROLE_FEED)
			lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK,
					LWS_TO_KILL_ASYNC);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("%s: role %d refused: %s\n", __func__, (int)role,
			    in ? (const char *)in : "(null)");
		outcome[role] = -1;
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (role != ROLE_FEED)
			break;
		if (lws_is_first_fragment(wsi))
			feed_rx_len = 0;
		nb = realloc(feed_rx, feed_rx_len + len + 1);
		if (!nb)
			return -1;
		feed_rx = nb;
		memcpy(feed_rx + feed_rx_len, in, len);
		feed_rx_len += len;
		if (lws_is_final_fragment(wsi))
			feed_snapshot(feed_rx, feed_rx_len);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the stand-in for an application protocol behind lws-login */
static int
callback_priv(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
connect_role(enum role role)
{
	struct lws_client_connect_info i;
	char host[32];

	outcome[role] = 0;
	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	i.local_protocol_name	= "lws-api-test-auth-feed-cli";
	i.opaque_user_data	= (void *)(intptr_t)role;

	if (role == ROLE_GATED) {
		i.port		= port_app;
		i.path		= "/gated";
		i.protocol	= PRIV_PROTOCOL;
	} else {
		i.port		= port_auth;
		i.path		= "/";
		i.protocol	= LWS_AUTH_FEED_PROTOCOL;
	}

	lws_snprintf(host, sizeof(host), "127.0.0.1:%d", i.port);
	i.host = i.origin = host;

	if (!lws_client_connect_via_info(&i))
		outcome[role] = -1;
}

static void
next_phase(void)
{
	phase++;
	phase_deadline = lws_now_usecs() + PHASE_TIMEOUT_US;
}

static void
finish(void)
{
	done = 1;
	lws_cancel_service(context);
}

static void
sul_check_cb(lws_sorted_usec_list_t *sul)
{
	switch (phase) {
	case PH_SEED:
		/*
		 * The auth server creates its schema and key when its vhost's
		 * protocols are initialized, once the event loop is running.
		 * Then seed the records, and mint a token they back.
		 */
		if (access(jwk_path, R_OK))
			break;
		if (db_exec("INSERT INTO users (uid, username, session_epoch) "
			    "VALUES (1, 'alice', 5);"
			    "INSERT INTO services (service_id, name) "
			    "VALUES (1, 'default-service');"
			    "INSERT INTO grants (uid, service_id, grant_level) "
			    "VALUES (1, 1, 1);") || mint_cookie()) {
			expect(phase_names[phase], 0);
			finish();
			return;
		}
		next_phase();
		connect_role(ROLE_FEED);
		break;

	case PH_SUBSCRIBE:
		if (seen_uid1_sec != 5 || seen_uid1_grant != 1)
			break;
		expect(phase_names[phase], 1);
		next_phase();
		connect_role(ROLE_FEED_NO_SECRET);
		break;

	case PH_NO_SECRET:
	case PH_BAD_SECRET:
		if (!outcome[phase == PH_NO_SECRET ? ROLE_FEED_NO_SECRET :
						     ROLE_FEED_BAD_SECRET])
			break;
		expect(phase_names[phase], outcome[phase == PH_NO_SECRET ?
			ROLE_FEED_NO_SECRET : ROLE_FEED_BAD_SECRET] < 0);
		next_phase();
		if (phase == PH_BAD_SECRET)
			connect_role(ROLE_FEED_BAD_SECRET);
		else
			connect_role(ROLE_GATED);
		break;

	case PH_LIVE:
		/*
		 * lws-login takes the snapshot in its own time: until it has,
		 * it has no key and refuses the token, so keep asking
		 */
		if (!outcome[ROLE_GATED])
			break;
		if (outcome[ROLE_GATED] < 0) {
			connect_role(ROLE_GATED);
			break;
		}
		expect(phase_names[phase], 1);

		/* a write the snapshot doesn't reflect */
		snapshots_at_quiet = snapshots;
		if (db_exec("INSERT INTO auth_log (uid, issue_time, ip_address) "
			    "VALUES (1, 0, '192.0.2.1');")) {
			expect("write the audit log", 0);
			finish();
			return;
		}
		quiet_until = lws_now_usecs() + QUIET_US;
		next_phase();
		break;

	case PH_QUIET:
		if (snapshots != snapshots_at_quiet) {
			expect(phase_names[phase], 0);
			finish();
			return;
		}
		if (lws_now_usecs() < quiet_until)
			break;
		expect(phase_names[phase], 1);

		/* a password reset bumps the epoch */
		if (db_exec("UPDATE users SET session_epoch = 6 WHERE uid = 1;")) {
			expect("bump the session epoch", 0);
			finish();
			return;
		}
		next_phase();
		break;

	case PH_REVOKE_FEED:
		if (seen_uid1_sec != 6)
			break;
		expect(phase_names[phase], 1);
		next_phase();
		connect_role(ROLE_GATED);
		break;

	case PH_REVOKE_LOGIN:
		/* it may take lws-login a moment longer than us */
		if (!outcome[ROLE_GATED])
			break;
		if (outcome[ROLE_GATED] > 0) {
			connect_role(ROLE_GATED);
			break;
		}
		expect(phase_names[phase], 1);
		next_phase();
		finish();
		return;
	}

	if (lws_now_usecs() > phase_deadline) {
		expect(phase < PH_DONE ? phase_names[phase] : "phase", 0);
		finish();
		return;
	}

	lws_sul_schedule(context, 0, &sul_check, sul_check_cb,
			 100 * LWS_US_PER_MS);
}

static const struct lws_protocols
	pcol_cli = { "lws-api-test-auth-feed-cli", callback_cli, 0, 0, 0,
		     NULL, 0 },
	pcol_priv = { PRIV_PROTOCOL, callback_priv, 0, 0, 0, NULL, 0 };

static const struct lws_protocols *pprotocols_cli[] = { &pcol_cli, NULL },
				  *pprotocols_app[] = { &pcol_priv, NULL };

/* lws-login gates /gated, its own mount being / */
static const struct lws_http_mount
	mount_gated = {
		.mountpoint		= "/gated",
		.protocol		= PRIV_PROTOCOL,
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 6,
		.interceptor_path	= "/",
	},
	mount_login = {
		.mount_next		= &mount_gated,
		.mountpoint		= "/",
		.protocol		= "lws-login",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 1,
	};

/* the auth server, with its feed enabled */
static struct lws_protocol_vhost_options
	pvo_db		= { NULL, NULL, "db_path", db_path },
	pvo_jwk		= { &pvo_db, NULL, "jwk_path", jwk_path },
	pvo_fs		= { &pvo_jwk, NULL, "feed-secret", FEED_SECRET },
	pvo_feed	= { NULL, NULL, LWS_AUTH_FEED_PROTOCOL, "" },
	pvo_as		= { &pvo_feed, &pvo_fs, "lws-auth-server", "" };

/* lws-login, with no jwt-jwk: the key comes from the feed */
static char auth_url[64];
static struct lws_protocol_vhost_options
	pvo_lfs		= { NULL, NULL, "auth-feed-secret", FEED_SECRET },
	pvo_asu		= { &pvo_lfs, NULL, "auth-server-url", auth_url },
	pvo_lc		= { NULL, NULL, "lws_login_client", "" },
	pvo_login	= { &pvo_lc, &pvo_asu, "lws-login", "" };

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0, have_work = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	port_auth = 7681;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_auth = atoi(p);
	port_app = port_auth + 1;

	lwsl_user("LWS API selftest: auth feed, lws-auth-server to lws-login\n");

	/* a private dir of our own for the auth server's db and key */
	lws_strncpy(work, "/tmp/lws-af-XXXXXX", sizeof(work)); // NOSONAR
	if (!mkdtemp(work)) {
		lwsl_err("unable to create work dir\n");
		return 1;
	}
	have_work = 1;
	lws_snprintf(db_path, sizeof(db_path), "%s/auth.sqlite3", work);
	lws_snprintf(jwk_path, sizeof(jwk_path), "%s/auth.jwk", work);
	lws_snprintf(auth_url, sizeof(auth_url), "http://127.0.0.1:%d",
		     port_auth);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.fd_limit_per_thread = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		goto bail;
	}

	info.port		= port_auth;
	info.vhost_name		= "auth";
	info.pvo		= &pvo_as;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the auth vhost\n");
		goto bail;
	}

	info.port		= port_app;
	info.vhost_name		= "app";
	info.pprotocols		= pprotocols_app;
	info.mounts		= &mount_login;
	info.pvo		= &pvo_login;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the app vhost\n");
		goto bail;
	}

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.pprotocols		= pprotocols_cli;
	info.mounts		= NULL;
	info.pvo		= NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	phase_deadline = lws_now_usecs() + PHASE_TIMEOUT_US;
	lws_sul_schedule(context, 0, &sul_check, sul_check_cb,
			 100 * LWS_US_PER_MS);

	while (n >= 0 && !done)
		n = lws_service(context, 0);

	expect("every phase ran", phase == PH_DONE);

bail:
	lws_context_destroy(context);
	free(feed_rx);
	if (have_work)
		lws_dir(work, NULL, lws_dir_rm_rf_cb);

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  !tests || fail ? "FAIL" : "PASS", tests, fail);

	return !tests || fail;
}
