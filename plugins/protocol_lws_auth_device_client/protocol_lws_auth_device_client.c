/*
 * libwebsockets - protocol_lws_auth_device_client
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */

#define LWS_DLL
#define _GNU_SOURCE
#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <libwebsockets/lws-auth-device-client.h>

struct auth_device_session {
	lws_dll2_t list;
	struct lws_vhost *vh;
	char logical_name[64];
	char auth_server_url[256];
	char device_code[128];
	char user_code[32];
	char access_token[1024];
	lws_sorted_usec_list_t sul_poll;
	struct lws *wsi_preauth;
	struct lws_context *cx;
	/*
	 * RFC 8628 s3.2 / s3.5: the token endpoint tells us how often we may
	 * poll ("interval") and how long the device code lives ("expires_in"),
	 * and can ask us to back off with a "slow_down" error.  Honour both
	 * rather than hammering it at a fixed rate for ever.
	 */
	unsigned int interval_secs;
	unsigned long deadline;
};

struct per_vhost_data {
	struct lws_context *cx;
	struct lws_vhost *vh;
	struct lws_auth_device_client_ops *app_ops;
	lws_dll2_owner_t sessions;
};

struct client_action {
	struct auth_device_session *session;
	int phase;
};

/*
 * Exact, length-checked match of a lws_json_simple_find() value against a
 * string literal.  The bare strncmp(p, "...", al) it replaces was bounded by
 * the *received* length, so a one-character value compared equal to any
 * literal starting with it.
 */
#define json_val_is(p, al, lit) \
	((al) == sizeof(lit) - 1 && !memcmp((p), (lit), sizeof(lit) - 1))

/* default poll period when the server does not state an "interval" */
#define AUTH_DEVICE_DEFAULT_INTERVAL_SECS 5
/* sanity cap so a hostile / broken "interval" cannot park us for ever */
#define AUTH_DEVICE_MAX_INTERVAL_SECS 300
/* fallback device-code lifetime when the server states no "expires_in" */
#define AUTH_DEVICE_DEFAULT_EXPIRES_SECS 900

static void poll_cb(lws_sorted_usec_list_t *sul);

/*
 * Fish an unsigned decimal member out of a short, well-known JSON object,
 * returning \p def if it is absent or is not purely digits.
 */
static unsigned long
json_uint(const char *buf, size_t len, const char *name, unsigned long def)
{
	char tmp[16];
	const char *p;
	size_t al = 0, n;

	p = lws_json_simple_find(buf, len, name, &al);
	if (!p || !al || al >= sizeof(tmp))
		return def;

	for (n = 0; n < al; n++)
		if (p[n] < '0' || p[n] > '9')
			return def;

	memcpy(tmp, p, al);
	tmp[al] = '\0';

	return (unsigned long)atol(tmp);
}

/*
 * The client_action is malloc'd per outgoing connection and carried as the
 * wsi's opaque_user_data.  Free it exactly once from whichever terminal
 * callback that wsi gets -- CLIENT_CONNECTION_ERROR, CLIENT_CLOSED (ws leg)
 * or CLOSED_CLIENT_HTTP (every http leg) -- and clear the wsi's pointer to it
 * so no second callback can reach the freed block.
 *
 * CLOSED_CLIENT_HTTP used to free nothing, so each 5-second device_token poll
 * leaked one action for the life of the process.
 */
static void
client_action_free(struct lws *wsi, struct client_action *action)
{
	if (!action)
		return;

	lws_set_opaque_user_data(wsi, NULL);
	free(action);
}

static struct lws *
connect_to(struct lws_context *ctx, struct lws_vhost *vhost, const char *url_str,
           const char *path, const char *method, const char *protocol,
           int phase, struct auth_device_session *session)
{
	struct lws_client_connect_info i;
	lws_parse_uri_t *puri;
	struct lws *wsi;
	struct client_action *action;
	char combined_path[512];

	memset(&i, 0, sizeof(i));

	puri = lws_parse_uri_create(url_str);
	if (!puri)
		return NULL;

	action = malloc(sizeof(*action));
	if (!action) {
		lws_parse_uri_destroy(&puri);
		return NULL;
	}
	action->session = session;
	action->phase = phase;

	if (puri->path && puri->path[0]) {
		if (!strcmp(path, "/")) {
			lws_snprintf(combined_path, sizeof(combined_path), "/%s", puri->path);
		} else {
			size_t plen = strlen(puri->path);
			lws_snprintf(combined_path, sizeof(combined_path), "/%s%s%s",
				puri->path,
				(puri->path[plen - 1] != '/' && path[0] != '/') ? "/" : "",
				path[0] == '/' ? path + 1 : path);
		}
		i.path = combined_path;
	} else {
		i.path = path;
	}

	i.context                   = ctx;
	i.vhost                     = vhost;
	i.address                   = puri->host;
	i.port                      = puri->port;
	i.ssl_connection            = (!strcmp(puri->scheme, "https") || !strcmp(puri->scheme, "wss")) ? LCCSCF_USE_SSL : 0;
	i.host                      = i.address;
	i.origin                    = i.address;
	i.method                    = method;
	i.protocol                  = protocol;
	i.local_protocol_name       = "lws-auth-device-client";
	i.opaque_user_data          = action;

	wsi = lws_client_connect_via_info(&i);
	lws_parse_uri_destroy(&puri);

	if (!wsi) {
		lwsl_err("%s: failed to connect to %s\n", __func__, url_str);
		free(action);
	}

	return wsi;
}

static int
callback_auth_device_client(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
	struct per_vhost_data *vhd = (struct per_vhost_data *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	struct client_action *action = (struct client_action *)lws_get_opaque_user_data(wsi);
	struct auth_device_session *session = action ? action->session : NULL;
	/*
	 * POST body scratch.  The body proper starts LWS_PRE bytes in:
	 * lws_write() composes the h2/h3 DATA frame header into the bytes
	 * immediately BEFORE the pointer it is given, so writing from a bare
	 * buffer scribbles below it -- into other stack locals here.
	 */
	char payload[LWS_PRE + 256];
	const char *p;
	size_t al = 0;
	int plen;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT: {
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct per_vhost_data));
		if (!vhd)
			return -1;
		vhd->cx = lws_get_context(wsi);
		vhd->vh = lws_get_vhost(wsi);

		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "app-auth-ops"))
				vhd->app_ops = (struct lws_auth_device_client_ops *)pvo->value;

			pvo = pvo->next;
		}
		break;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_info("Auth client connection error: %s\n", in ? (char *)in : "(null)");
		client_action_free(wsi, action);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		if (action) {
			if (action->phase == 3 && session) {
				session->wsi_preauth = NULL;
				if (!session->access_token[0]) {
					lwsl_notice("%s: preauth timeout or rejected, stopping polling\n", __func__);
					lws_sul_cancel(&session->sul_poll);
				}
			}
			client_action_free(wsi, action);
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_REDIRECT: {
		char loc[256];
		char *q;

		if (!action || action->phase != 0)
			break;

		if (lws_hdr_copy(wsi, loc, sizeof(loc), WSI_TOKEN_HTTP_LOCATION) <= 0)
			break;

		lwsl_notice("Redirected to auth server: %s\n", loc);

		/* The redirect might not have a '/' before the query string, which breaks
		 * lws_parse_uri. We only need the base auth server URL anyway, so we
		 * can just strip the query string completely before parsing. */
		if ((q = (char *)strchr(loc, '?')))
			*q = '\0';

		lws_parse_uri_t *puri = lws_parse_uri_create(loc);
		if (!puri)
			break;

		/*
		 * Everything after this redirect -- the device_auth POST, the
		 * device_token poll and the preauth ws -- runs against the URL
		 * we are about to adopt, and the device's long-lived access
		 * token comes back over it and is written to disk.  So a
		 * mixer (or anyone on-path to it) must not be able to move all
		 * of that onto cleartext just by answering with an http://
		 * Location.  Refuse the downgrade; a deployment that is
		 * cleartext to begin with is unaffected.
		 */
		if (lws_is_ssl(lws_get_network_wsi(wsi)) &&
		    strcmp(puri->scheme, "https") &&
		    strcmp(puri->scheme, "wss")) {
			lwsl_err("%s: refusing redirect from TLS to plaintext "
				 "'%s'\n", __func__, puri->scheme);
			lws_parse_uri_destroy(&puri);
			return -1;
		}

		if (session) {
			if (puri->path && puri->path[0]) {
				lws_snprintf(session->auth_server_url, sizeof(session->auth_server_url), "%s://%s:%d/%s",
						puri->scheme, puri->host, puri->port,
						puri->path[0] == '/' ? puri->path + 1 : puri->path);
			} else {
				lws_snprintf(session->auth_server_url, sizeof(session->auth_server_url), "%s://%s:%d",
						puri->scheme, puri->host, puri->port);
			}

			if (!connect_to(lws_get_context(wsi), lws_get_vhost(wsi), session->auth_server_url, "/api/device_auth", "POST", "lws-auth-device-client", 1, session))
				lwsl_err("Failed to connect to auth server for device code\n");
		}
		lws_parse_uri_destroy(&puri);
		return -1; /* abort the redirect, we are initiating a new connection */
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: {
		unsigned int status = lws_http_client_http_response(wsi);
		lwsl_user("HTTP response %d\n", status);
		break;
	}

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **ptr = (unsigned char **)in;
		unsigned char *end = (*ptr) + len;
		char cl[16];
		if (!action || !session) break;

		switch (action->phase) {
		case 1:
			plen = lws_snprintf(payload + LWS_PRE,
					    sizeof(payload) - LWS_PRE,
					    "client_id=%s", session->logical_name);
			break;
		case 2:
			plen = lws_snprintf(payload + LWS_PRE,
					    sizeof(payload) - LWS_PRE,
					    "client_id=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s",
					    session->logical_name,
					    session->device_code);
			break;
		default:
			goto dummy;
		}

		/*
		 * Add headers via the lws API, not raw lws_snprintf text: the
		 * APPEND scratch buffer holds H1 text on h1, but HPACK on h2 /
		 * QPACK on h3.  Writing "Content-Type: ...\r\n" as plain text is
		 * correct for h1 but injects raw header bytes into the h2/h3
		 * encoded header block, which the peer's decoder misparses.
		 */
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"application/x-www-form-urlencoded",
				33, ptr, end) ||
		    (lws_snprintf(cl, sizeof(cl), "%d", plen),
		     lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
				(unsigned char *)cl, (int)strlen(cl), ptr, end)))
			return -1;

		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE: {
		if (!action || !session) break;
		switch (action->phase) {
		case 1:
			plen = lws_snprintf(payload + LWS_PRE,
					    sizeof(payload) - LWS_PRE,
					    "client_id=%s", session->logical_name);
			break;
		case 2:
			plen = lws_snprintf(payload + LWS_PRE,
					    sizeof(payload) - LWS_PRE,
					    "client_id=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s",
					    session->logical_name,
					    session->device_code);
			break;
		default:
			goto dummy;
		}

		if (lws_write(wsi, (unsigned char *)payload + LWS_PRE,
			      (size_t)plen, LWS_WRITE_HTTP_FINAL) != plen) {
			lwsl_err("%s: failed to write HTTP body\n", __func__);
			return -1;
		}

		lws_client_http_body_pending(wsi, 0);
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buffer[1024 + LWS_PRE];
		char *px = buffer + LWS_PRE;
		int lenx = sizeof(buffer) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;

		return 0;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		if (!action || !session) break;
		switch (action->phase) {
		case 1: {
			lwsl_notice("%s: Phase 1 HTTP Read: %.*s\n", __func__, (int)len, (const char *)in);
			if ((p = lws_json_simple_find((const char *)in, len, "\"device_code\":", &al)))
				lws_strnncpy(session->device_code, p, al, sizeof(session->device_code));
			if ((p = lws_json_simple_find((const char *)in, len, "\"user_code\":", &al)))
				lws_strnncpy(session->user_code, p, al, sizeof(session->user_code));

			/*
			 * RFC 8628 s3.2: the server states how often we may
			 * poll and how long the device code is good for.
			 * Clamp the interval so a bogus value cannot park the
			 * pairing for ever (or spin on the server).
			 */
			session->interval_secs = (unsigned int)json_uint(
					(const char *)in, len, "\"interval\":",
					AUTH_DEVICE_DEFAULT_INTERVAL_SECS);
			if (!session->interval_secs)
				session->interval_secs =
					AUTH_DEVICE_DEFAULT_INTERVAL_SECS;
			if (session->interval_secs > AUTH_DEVICE_MAX_INTERVAL_SECS)
				session->interval_secs =
					AUTH_DEVICE_MAX_INTERVAL_SECS;

			session->deadline = lws_now_secs() +
					json_uint((const char *)in, len,
						  "\"expires_in\":",
						  AUTH_DEVICE_DEFAULT_EXPIRES_SECS);

			if (vhd && vhd->app_ops && vhd->app_ops->display_code)
				vhd->app_ops->display_code(vhd->vh, session->logical_name, session->user_code);

			lws_sul_schedule(lws_get_context(wsi), 0,
					 &session->sul_poll, poll_cb,
					 (lws_usec_t)session->interval_secs *
							 LWS_US_PER_SEC);

			session->wsi_preauth = connect_to(lws_get_context(wsi), lws_get_vhost(wsi), session->auth_server_url, "/", NULL, "lws-oauth-preauth", 3, session);
			if (!session->wsi_preauth)
				lwsl_err("Failed to connect to waiting room\n");
			break;
		}
		case 2: {
			lwsl_notice("%s: Phase 2 HTTP Read: %.*s\n", __func__, (int)len, (const char *)in);
			p = lws_json_simple_find((const char *)in, len, "\"access_token\":", &al);
			if (p) {
				lws_strnncpy(session->access_token, p, al, sizeof(session->access_token));
				lwsl_notice("Successfully paired and retrieved access token for %s!\n", session->logical_name);

				char filename[128], safe[64];
				lws_strncpy(safe, session->logical_name, sizeof(safe));
				lws_filename_purify_inplace(safe);
				char *slash_p = safe;
				while ((slash_p = strchr(slash_p, '/')))
					*slash_p++ = '_';
				lws_snprintf(filename, sizeof(filename), ".lws-auth-token-%s", safe);
				int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
				if (fd >= 0) {
					if (write(fd, session->access_token, strlen(session->access_token)) < 0)
						lwsl_err("%s: failed to write token\n", __func__);
					close(fd);
				}

				if (session->wsi_preauth) {
					lws_set_timeout(session->wsi_preauth, 1, LWS_TO_KILL_ASYNC);
					session->wsi_preauth = NULL;
				}

				if (vhd && vhd->app_ops && vhd->app_ops->auth_success)
					vhd->app_ops->auth_success(vhd->vh, session->logical_name, session->access_token);
			} else {
				p = lws_json_simple_find((const char *)in, len, "\"error\":", &al);
				if (p && json_val_is(p, al, "slow_down")) {
					/*
					 * RFC 8628 s3.5: slow_down means keep
					 * polling but add 5s to the interval.
					 * Treating it as fatal (which the
					 * catch-all else did) threw away a
					 * pairing the server was still willing
					 * to complete.
					 */
					if (session->interval_secs + 5 <=
						  AUTH_DEVICE_MAX_INTERVAL_SECS)
						session->interval_secs += 5;
					lwsl_notice("%s: slow_down, polling every %us\n",
						    __func__, session->interval_secs);
				} else if (p && !json_val_is(p, al,
						"authorization_pending")) {
					lwsl_notice("%s: Authorization failed or expired, stopping polling\n", __func__);
					lws_sul_cancel(&session->sul_poll);
					if (session->wsi_preauth) {
						lws_set_timeout(session->wsi_preauth, 1, LWS_TO_KILL_ASYNC);
						session->wsi_preauth = NULL;
					}
				}
			}
			break;
		}
		default:
			goto dummy;
		}
		break;
	}

	case LWS_CALLBACK_CLIENT_ESTABLISHED: {
		if (action && action->phase == 3) {
			lwsl_notice("%s: Phase 3 WS established!\n", __func__);
			lws_callback_on_writable(wsi);
		}
		break;
	}

	case LWS_CALLBACK_CLIENT_WRITEABLE: {
		if (!action || !session) break;
		switch (action->phase) {
		case 3: {
			char msg[256];
			unsigned char buf[LWS_PRE + 256];
			int n;
			const char *display_name = session->logical_name;
			if (vhd && vhd->app_ops && vhd->app_ops->get_device_name) {
				const char *n_name = vhd->app_ops->get_device_name(vhd->vh, session->logical_name);
				if (n_name) display_name = n_name;
			}
			n = lws_snprintf(msg, sizeof(msg), "{\"user_code\":\"%s\",\"serial\":\"%s-headless\",\"name\":\"%s\"}", session->user_code, session->logical_name, display_name);
			lwsl_notice("%s: Phase 3 WS sending: %s\n", __func__, msg);
			memcpy(buf + LWS_PRE, msg, (size_t)n);
			if (lws_write(wsi, buf + LWS_PRE, (size_t)n, LWS_WRITE_TEXT) != n) {
				lwsl_err("%s: failed to write text\n", __func__);
				return -1;
			}
			break;
		}
		}
		break;
	}

	case LWS_CALLBACK_CLIENT_RECEIVE: {
		if (!action || !session) break;
		switch (action->phase) {
		case 3:
			if (lws_json_simple_find((const char *)in, len, "\"cmd\":\"identify\"", &al)) {
				if (vhd && vhd->app_ops && vhd->app_ops->pairing_indication)
					vhd->app_ops->pairing_indication(vhd->vh, session->logical_name, 1);
			}
			break;
		default:
			goto dummy;
		}
		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		/*
		 * The sessions and their poll suls live on the context, but
		 * they cache the vhost that lws is destroying right now: a
		 * still-armed poll_cb would fire afterwards and hand the freed
		 * vhost to lws_client_connect_via_info().  Cancel and free
		 * them here.  (vhd itself is freed by lws after this returns,
		 * so vhd->sessions must not outlive it either.)
		 */
		if (!vhd)
			break;

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->sessions)) {
			struct auth_device_session *s = lws_container_of(d,
					struct auth_device_session, list);

			lws_sul_cancel(&s->sul_poll);
			s->wsi_preauth = NULL;
			lws_dll2_remove(&s->list);
			free(s);
		} lws_end_foreach_dll_safe(d, d1);
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_notice("%s: HTTP client transaction completed\n", __func__);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_notice("%s: HTTP client connection closed\n", __func__);
		/*
		 * This -- not CLIENT_CLOSED, which only the ws role emits --
		 * is the terminal callback for the http legs (phase 0/1/2), so
		 * it is where their action is freed.  lws makes it mutually
		 * exclusive with CLIENT_CONNECTION_ERROR (already_did_cce), and
		 * client_action_free() clears the wsi's pointer, so this cannot
		 * double free.
		 */
		client_action_free(wsi, action);
		break;

	default:
		break;
	}

dummy:
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
poll_cb(lws_sorted_usec_list_t *sul) {
	struct auth_device_session *session = lws_container_of(sul, struct auth_device_session, sul_poll);

	if (session->access_token[0]) return; // already paired

	/*
	 * RFC 8628 s3.2: the device code has a lifetime.  Without this the
	 * poll re-armed unconditionally, so a pairing nobody ever approves --
	 * or one whose connections simply fail, since a failed connect reaches
	 * none of the error handling -- polled the auth server for ever.
	 */
	if (session->deadline && lws_now_secs() > session->deadline) {
		lwsl_notice("%s: device code expired, stopping polling\n",
			    __func__);
		if (session->wsi_preauth) {
			lws_set_timeout(session->wsi_preauth, 1, LWS_TO_KILL_ASYNC);
			session->wsi_preauth = NULL;
		}
		return;
	}

	if (!connect_to(session->cx, session->vh, session->auth_server_url, "/api/device_token", "POST", "lws-auth-device-client", 2, session))
		lwsl_err("Failed to poll token\n");

	if (!session->interval_secs)
		session->interval_secs = AUTH_DEVICE_DEFAULT_INTERVAL_SECS;

	lws_sul_schedule(session->cx, 0, &session->sul_poll, poll_cb,
			 (lws_usec_t)session->interval_secs * LWS_US_PER_SEC);
}

static void
start_auth_flow(struct lws_vhost *vh, const char *mixer_url, const char *logical_name) {
	struct per_vhost_data *vhd = (struct per_vhost_data *)lws_protocol_vh_priv_get(vh, lws_vhost_name_to_protocol(vh, "lws-auth-device-client"));
	if (!vhd) return;

	struct auth_device_session *session = malloc(sizeof(*session));
	if (!session) return;
	memset(session, 0, sizeof(*session));

	session->vh = vh;
	session->cx = vhd->cx;
	lws_strncpy(session->logical_name, logical_name, sizeof(session->logical_name));
	lws_dll2_add_tail(&session->list, &vhd->sessions);

	char filename[128], safe[64];
	lws_strncpy(safe, logical_name, sizeof(safe));
	lws_filename_purify_inplace(safe);
	char *slash_p = safe;
	while ((slash_p = strchr(slash_p, '/')))
		*slash_p++ = '_';
	lws_snprintf(filename, sizeof(filename), ".lws-auth-token-%s", safe);
	int fd = open(filename, O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, session->access_token, sizeof(session->access_token) - 1);
		close(fd);
		if (n > 0) {
			session->access_token[n] = '\0';
			lwsl_notice("Loaded saved auth token for %s.\n", logical_name);
			if (vhd->app_ops && vhd->app_ops->auth_success)
				vhd->app_ops->auth_success(vh, logical_name, session->access_token);
			return;
		}
	}

	if (!connect_to(vhd->cx, vh, mixer_url, "/", "GET", "lws-auth-device-client", 0, session))
		lwsl_err("Failed to initiate auth flow\n");
}

static struct lws_auth_device_client_api my_api = {
	.abi_version = LWS_AUTH_DEVICE_CLIENT_ABI_VERSION,
	.start_auth_flow = start_auth_flow,
};

static int
callback_auth_device_client_init(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
	if (reason == LWS_CALLBACK_PROTOCOL_INIT) {
		if (!in)
			return 0;

		lwsl_vhost_notice(lws_get_vhost(wsi), "LWS_CALLBACK_PROTOCOL_INIT: %s\n",
				  lws_get_protocol(wsi)->name);
		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "lws-auth-client-api")) {
				struct lws_auth_device_client_api **p = (struct lws_auth_device_client_api **)pvo->value;
				*p = &my_api;
			}
			pvo = pvo->next;
		}
	}
	return callback_auth_device_client(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		.name                   = "lws-auth-device-client",
		.callback               = callback_auth_device_client_init,
		.per_session_data_size  = 0,
		.rx_buffer_size         = 1024,
		.id                     = 0,
		.user                   = NULL,
		.tx_packet_size         = 0
	}
};

LWS_VISIBLE const lws_plugin_protocol_t lws_auth_device_client = {
	.hdr = {
		.name = "lws auth device client plugin",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
		.priority = 0
	},
	.protocols              = protocols,
	.count_protocols        = LWS_ARRAY_SIZE(protocols)
};
