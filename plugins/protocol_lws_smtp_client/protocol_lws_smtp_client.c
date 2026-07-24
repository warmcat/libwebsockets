/*
 * libwebsockets - small server side websockets and web server implementation
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

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif
#include <libwebsockets/lws-smtp-client.h>
#include <string.h>
#include <stdlib.h>

struct smtp_email {
	lws_dll2_t list;
	char *from;
	char *to;
	char *subject;
	char *body;
};

/* How the upstream MTA connection is secured. */
enum smtp_tls_mode {
	SMTP_TLS_NONE = 0,	/* plaintext, no TLS (the default; matches a
				 * local relay on :25 that needs no auth) */
	SMTP_TLS_IMPLICIT,	/* implicit TLS, wrap the socket at connect
				 * time (SMTPS on :465) */
	SMTP_TLS_STARTTLS,	/* plaintext connect, then STARTTLS upgrade
				 * mid-stream (submission on :587) */
};

struct per_vhost_data__smtp_client {
	struct lws_context *cx;
	struct lws_vhost *vh;
	lws_dll2_owner_t emails_ready;
	struct lws *wsi;

	char smtp_host[64];	/* upstream MTA host, default "127.0.0.1" */
	int smtp_port;		/* upstream MTA port, default 25 */
	int tls_mode;		/* enum smtp_tls_mode, default SMTP_TLS_NONE */
};

/*
 * smtp_state walks a single message transaction.  The STARTTLS states are
 * only visited on the SMTP_TLS_STARTTLS path; plaintext / implicit-TLS go
 * GREETING -> HELO -> MAIL_FROM -> ... directly.
 *
 * Each *_SEND state performs exactly one write then advances to its paired
 * *_WAIT state, so a writable re-entry before the reply arrives cannot
 * duplicate a command.
 */
enum smtp_state {
	SMTP_STATE_CONNECTING = 0,
	SMTP_STATE_GREETING,
	SMTP_STATE_EHLO_SEND,	/* STARTTLS: send EHLO */
	SMTP_STATE_EHLO_WAIT,	/* STARTTLS: EHLO sent, awaiting the final
				 * multiline "250 " line */
	SMTP_STATE_STARTTLS_SEND, /* STARTTLS: send STARTTLS */
	SMTP_STATE_STARTTLS_WAIT, /* STARTTLS: STARTTLS sent, awaiting "220" */
	SMTP_STATE_TLS_UPGRADING, /* STARTTLS: handshake in progress */
	SMTP_STATE_HELO,
	SMTP_STATE_MAIL_FROM,
	SMTP_STATE_RCPT_TO,
	SMTP_STATE_DATA,
	SMTP_STATE_BODY,
	SMTP_STATE_QUIT,
	SMTP_STATE_IDLE
};

struct per_session_data__smtp_client {
	int state;
	int starttls;		/* 1 if this connection is on the STARTTLS path */
	struct smtp_email *email;
};

static void
trigger_smtp_if_needed(struct per_vhost_data__smtp_client *vhd)
{
	struct lws_client_connect_info i;

	if (vhd->wsi)
		return;

	if (!vhd->emails_ready.count)
		return;

	/*
	 * Implicit TLS wraps the socket at connect time; plaintext and
	 * STARTTLS both connect cleartext (STARTTLS upgrades later via
	 * lws_tls_client_upgrade()).  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK
	 * relaxes only the hostname match; CA validation still applies, so
	 * the local relay's CA must be trusted via the vhost client SSL ctx.
	 */
	memset(&i, 0, sizeof(i));
	i.context = vhd->cx;
	i.port = vhd->smtp_port;
	i.ssl_connection = (vhd->tls_mode == SMTP_TLS_IMPLICIT)
			? (LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)
			: 0;
	i.address = vhd->smtp_host;
	i.host = i.address;
	i.origin = i.address;
	i.vhost = vhd->vh;
	i.protocol = "lws-smtp-client";
	i.local_protocol_name = "lws-smtp-client";
	i.method = "RAW";
	/* SMTP defines no ALPN; leave i.alpn NULL */

	vhd->wsi = lws_client_connect_via_info(&i);
}

static void
smtp_sanitize_crlf(char *str)
{
	if (!str) return;
	while (*str) {
		if (*str == '\r' || *str == '\n')
			*str = ' ';
		str++;
	}
}

static char *
smtp_dot_stuff(const char *body)
{
	size_t len = strlen(body);
	size_t i, j = 0, new_len = len;
	
	/* Calculate new length */
	for (i = 0; i < len; i++) {
		if (body[i] == '.' && (i == 0 || body[i-1] == '\n'))
			new_len++;
	}
	
	char *stuffed = malloc(new_len + 1);
	if (!stuffed) return NULL;
	
	for (i = 0; i < len; i++) {
		if (body[i] == '.' && (i == 0 || body[i-1] == '\n'))
			stuffed[j++] = '.';
		stuffed[j++] = body[i];
	}
	stuffed[j] = '\0';
	return stuffed;
}

static int
lws_smtp_client_send_email(struct lws_context *cx, struct lws_vhost *vh, const lws_smtp_email_t *email)
{
	const struct lws_protocols *pp = lws_vhost_name_to_protocol(vh, "lws-smtp-client");
	struct per_vhost_data__smtp_client *vhd;
	struct smtp_email *e;
	int i, to_len;

	if (!pp || !email || !email->to || !email->from || !email->subject || !email->body)
		return -1;

	to_len = (int)strlen(email->to);
	if (to_len < 3 || to_len > 127)
		return -1;

	for (i = 0; i < to_len; i++) {
		char c = email->to[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '@' || c == '.' ||
		      c == '-' || c == '_' || c == '+'))
			return -1;
	}

	vhd = lws_protocol_vh_priv_get(vh, pp);
	if (!vhd) return -1;

	e = malloc(sizeof(*e));
	if (!e) return -1;
	memset(e, 0, sizeof(*e));

	e->from = strdup(email->from);
	e->to = strdup(email->to);
	e->subject = strdup(email->subject);
	e->body = smtp_dot_stuff(email->body);

	smtp_sanitize_crlf(e->from);
	smtp_sanitize_crlf(e->to);
	smtp_sanitize_crlf(e->subject);

	if (!e->from || !e->to || !e->subject || !e->body) {
		if (e->from) free(e->from);
		if (e->to) free(e->to);
		if (e->subject) free(e->subject);
		if (e->body) free(e->body);
		free(e);
		return -1;
	}

	lws_dll2_add_tail(&e->list, &vhd->emails_ready);

	trigger_smtp_if_needed(vhd);
	return 0;
}

static lws_smtp_client_ops_t smtp_ops = {
	.send_email = lws_smtp_client_send_email,
};

static int
callback_smtp_client(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct per_session_data__smtp_client *pss =
			(struct per_session_data__smtp_client *)user;
	struct per_vhost_data__smtp_client *vhd =
			(struct per_vhost_data__smtp_client *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT: {
		const struct lws_protocol_vhost_options *pvo_in, *pvo;

		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;
		if (!in)
			return 0;
		pvo_in = (const struct lws_protocol_vhost_options *)in;

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__smtp_client));
		if (!vhd)
			return -1;
		vhd->cx = lws_get_context(wsi);
		vhd->vh = lws_get_vhost(wsi);

		/* Defaults: restore the pre-regression working behavior, i.e.
		 * a plaintext local relay on 127.0.0.1:25 needing no auth. */
		lws_strncpy(vhd->smtp_host, "127.0.0.1", sizeof(vhd->smtp_host));
		vhd->smtp_port = 25;
		vhd->tls_mode = SMTP_TLS_NONE;

		if ((pvo = lws_pvo_search(pvo_in, "smtp-host")) &&
		    pvo->value && pvo->value[0])
			lws_strncpy(vhd->smtp_host, pvo->value,
				    sizeof(vhd->smtp_host));

		if ((pvo = lws_pvo_search(pvo_in, "smtp-port")) &&
		    pvo->value && pvo->value[0])
			vhd->smtp_port = atoi(pvo->value);

		if ((pvo = lws_pvo_search(pvo_in, "smtp-tls")) &&
		    pvo->value && pvo->value[0]) {
			if (!strcmp(pvo->value, "implicit"))
				vhd->tls_mode = SMTP_TLS_IMPLICIT;
			else if (!strcmp(pvo->value, "starttls")) {
#if defined(LWS_WITH_TLS)
				vhd->tls_mode = SMTP_TLS_STARTTLS;
#else
				lwsl_vhost_err(vhd->vh, "%s: smtp-tls=starttls "
					       "requires a TLS-enabled lws build\n",
					       __func__);
				return -1;
#endif
			} else if (!strcmp(pvo->value, "none"))
				vhd->tls_mode = SMTP_TLS_NONE;
			else
				lwsl_vhost_warn(vhd->vh, "%s: unknown smtp-tls "
						"value '%s', using 'none'\n",
						__func__, pvo->value);
		}

		lwsl_vhost_notice(vhd->vh, "%s: smtp client -> %s:%d (tls=%d)\n",
				__func__, vhd->smtp_host, vhd->smtp_port,
				vhd->tls_mode);
		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   vhd->emails_ready.head) {
			struct smtp_email *e = lws_container_of(d, struct smtp_email, list);
			lws_dll2_remove(&e->list);
			free(e->from);
			free(e->to);
			free(e->subject);
			free(e->body);
			free(e);
		} lws_end_foreach_dll_safe(d, d1);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		pss->starttls = (vhd->tls_mode == SMTP_TLS_STARTTLS);
		pss->state = SMTP_STATE_GREETING;
		if (vhd->emails_ready.head) {
			pss->email = lws_container_of(vhd->emails_ready.head, struct smtp_email, list);
		} else {
			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		{
			char *resp = (char *)in;
			char *last_line = resp;
			int code;

			/*
			 * While the STARTTLS handshake is in flight, the
			 * raw-skt role feeds us decrypted bytes only once the
			 * handshake has completed; gate explicitly on the
			 * public handshake-completion check to be safe.
			 */
			if (pss->state == SMTP_STATE_TLS_UPGRADING) {
#if defined(LWS_WITH_TLS)
				char ebuf[128];
				if (lws_tls_client_connect(wsi, ebuf, sizeof(ebuf)) ==
				    LWS_SSL_CAPABLE_DONE) {
					pss->state = SMTP_STATE_HELO;
					lws_callback_on_writable(wsi);
				}
#else
				return -1;
#endif
				return 0;
			}

			for (size_t i = 0; i < len; i++) {
				if (resp[i] == '\n' && i + 1 < len)
					last_line = &resp[i + 1];
			}

			code = atoi(last_line);
			if (code >= 400) {
				lwsl_err("SMTP error: %.*s\n", (int)len, resp);
				return -1;
			}

			if ((resp + len) - last_line < 4 || last_line[3] != ' ') {
				return 0; /* Wait for more data, either incomplete or continuation */
			}

			if (pss->state == SMTP_STATE_IDLE)
				return -1;

			if (pss->state == SMTP_STATE_GREETING) {
				/*
				 * On the STARTTLS path, EHLO replaces HELO and
				 * is followed by the multiline capability list.
				 */
				if (pss->starttls)
					pss->state = SMTP_STATE_EHLO_SEND;
				else
					pss->state = SMTP_STATE_HELO;
				lws_callback_on_writable(wsi);
				break;
			}

			if (pss->state == SMTP_STATE_EHLO_WAIT) {
				/*
				 * RFC 5321: a multiline reply uses "250-" on
				 * every line except the last, which is "250 ".
				 * Wait for the terminating line before sending
				 * STARTTLS, so the server has advertised its
				 * capabilities.
				 */
				int found_250_final = 0;
				for (size_t k = 0; k + 4 <= len; k++) {
					if ((k == 0 || resp[k - 1] == '\n') &&
					    !strncmp(&resp[k], "250 ", 4)) {
						found_250_final = 1;
						break;
					}
				}
				if (found_250_final) {
					pss->state = SMTP_STATE_STARTTLS_SEND;
					lws_callback_on_writable(wsi);
				}
				break;
			}

			if (pss->state == SMTP_STATE_STARTTLS_WAIT) {
				/*
				 * "220 Ready to start TLS" -> upgrade the
				 * existing RAW connection to TLS in place.
				 */
#if defined(LWS_WITH_TLS)
				pss->state = SMTP_STATE_TLS_UPGRADING;
				if (lws_tls_client_upgrade(wsi,
						LCCSCF_USE_SSL |
						LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK) < 0) {
					lwsl_err("%s: STARTTLS upgrade failed\n",
						 __func__);
					return -1;
				}
				/*
				 * Drive the handshake from the next service;
				 * RX/WRITEABLE on SMTP_STATE_TLS_UPGRADING poll
				 * lws_tls_client_connect() for DONE.
				 */
				lws_callback_on_writable(wsi);
#else
				lwsl_err("%s: STARTTLS needs a TLS-enabled build\n",
					 __func__);
				return -1;
#endif
				break;
			}

			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			char buf[2048 + LWS_PRE];
			char *p = (char *)&buf[LWS_PRE];
			int n = 0;

			/* Until the STARTTLS handshake completes, emit nothing. */
			if (pss->state == SMTP_STATE_TLS_UPGRADING) {
#if defined(LWS_WITH_TLS)
				char ebuf[128];
				if (lws_tls_client_connect(wsi, ebuf, sizeof(ebuf)) ==
				    LWS_SSL_CAPABLE_DONE)
					pss->state = SMTP_STATE_HELO;
				else
					lws_callback_on_writable(wsi);
#else
				return -1;
#endif
				if (pss->state != SMTP_STATE_HELO)
					break;
			}

			if (!pss->email && pss->state != SMTP_STATE_QUIT &&
			    pss->state != SMTP_STATE_IDLE)
				pss->state = SMTP_STATE_QUIT;

			switch (pss->state) {
			case SMTP_STATE_GREETING:
			case SMTP_STATE_EHLO_WAIT:
			case SMTP_STATE_STARTTLS_WAIT:
			case SMTP_STATE_TLS_UPGRADING:
				return 0;
			case SMTP_STATE_EHLO_SEND:
				/* Issue EHLO, then wait for the terminating
				 * "250 " capability line. */
				n = lws_snprintf(p, 1024, "EHLO %s\r\n",
						 vhd->smtp_host);
				pss->state = SMTP_STATE_EHLO_WAIT;
				break;
			case SMTP_STATE_STARTTLS_SEND:
				/* Issue STARTTLS, then wait for "220". */
				n = lws_snprintf(p, 1024, "STARTTLS\r\n");
				pss->state = SMTP_STATE_STARTTLS_WAIT;
				break;
			case SMTP_STATE_HELO:
				/* EHLO was already issued on the STARTTLS path. */
				if (!pss->starttls)
					n = lws_snprintf(p, 1024, "HELO localhost\r\n");
				pss->state = SMTP_STATE_MAIL_FROM;
				/* On the STARTTLS path HELO is a no-op write; we
				 * still need to drive MAIL_FROM out next. */
				if (pss->starttls)
					lws_callback_on_writable(wsi);
				break;
			case SMTP_STATE_MAIL_FROM:
				n = lws_snprintf(p, 1024, "MAIL FROM:<%s>\r\n", pss->email->from);
				pss->state = SMTP_STATE_RCPT_TO;
				break;
			case SMTP_STATE_RCPT_TO:
				n = lws_snprintf(p, 1024, "RCPT TO:<%s>\r\n", pss->email->to);
				pss->state = SMTP_STATE_DATA;
				break;
			case SMTP_STATE_DATA:
				n = lws_snprintf(p, 1024, "DATA\r\n");
				pss->state = SMTP_STATE_BODY;
				break;
			case SMTP_STATE_BODY:
				n = lws_snprintf(p, 2048,
					"Subject: %s\r\n"
					"To: %s\r\n\r\n"
					"%s\r\n"
					".\r\n",
					pss->email->subject, pss->email->to, pss->email->body);
				pss->state = SMTP_STATE_QUIT;

				lws_dll2_remove(&pss->email->list);
				free(pss->email->from);
				free(pss->email->to);
				free(pss->email->subject);
				free(pss->email->body);
				free(pss->email);
				pss->email = NULL;
				break;
			case SMTP_STATE_QUIT:
				n = lws_snprintf(p, 1024, "QUIT\r\n");
				pss->state = SMTP_STATE_IDLE;
				break;
			default:
				return -1;
			}

			if (n > 0)
				lws_write(wsi, (unsigned char *)p, (unsigned int)n,
					  LWS_WRITE_TEXT);
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		vhd->wsi = NULL;
		trigger_smtp_if_needed(vhd);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_SMTP_CLIENT \
	{ \
		"lws-smtp-client", \
		callback_smtp_client, \
		sizeof(struct per_session_data__smtp_client), \
		1024, \
		0, (void *)&smtp_ops, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)
static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_SMTP_CLIENT
};

LWS_VISIBLE const lws_plugin_protocol_t lws_smtp_client = {
	.hdr = {
		.name = "SMTP Client API",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
		.priority = 0,
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
