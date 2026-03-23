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

struct per_vhost_data__smtp_client {
	struct lws_context *cx;
	struct lws_vhost *vh;
	lws_dll2_owner_t emails_ready;
	struct lws *wsi;
};

enum smtp_state {
	SMTP_STATE_CONNECTING = 0,
	SMTP_STATE_GREETING,
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
	struct smtp_email *email;
};

static void
trigger_smtp_if_needed(struct per_vhost_data__smtp_client *vhd)
{
	if (vhd->wsi)
		return;

	if (!vhd->emails_ready.count)
		return;

	struct lws_client_connect_info i;
	memset(&i, 0, sizeof(i));
	i.context = vhd->cx;
	i.port = 25;
	i.address = "127.0.0.1";
	i.host = i.address;
	i.origin = i.address;
	i.vhost = vhd->vh;
	i.protocol = "lws-smtp-client";
	i.local_protocol_name = "lws-smtp-client";
	i.method = "RAW";

	vhd->wsi = lws_client_connect_via_info(&i);
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
	e->body = strdup(email->body);

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
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__smtp_client));
		vhd->cx = lws_get_context(wsi);
		vhd->vh = lws_get_vhost(wsi);
		break;

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

			for (size_t i = 0; i < len; i++) {
				if (resp[i] == '\n' && i + 1 < len)
					last_line = &resp[i + 1];
			}

			int code = atoi(last_line);
			if (code >= 400) {
				lwsl_err("SMTP error: %.*s\n", (int)len, resp);
				return -1;
			}

			if ((resp + len) - last_line < 4 || last_line[3] != ' ') {
				return 0; /* Wait for more data, either incomplete or continuation */
			}

			if (pss->state == SMTP_STATE_IDLE)
				return -1;

			if (pss->state == SMTP_STATE_GREETING)
				pss->state = SMTP_STATE_HELO;

			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			char buf[2048 + LWS_PRE];
			char *p = (char *)&buf[LWS_PRE];
			int n = 0;

			if (!pss->email && pss->state != SMTP_STATE_QUIT && pss->state != SMTP_STATE_IDLE) {
				pss->state = SMTP_STATE_QUIT;
			}

			switch (pss->state) {
			case SMTP_STATE_GREETING:
				return 0;
			case SMTP_STATE_HELO:
				n = lws_snprintf(p, 1024, "HELO localhost\r\n");
				pss->state = SMTP_STATE_MAIL_FROM;
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
			lws_write(wsi, (unsigned char *)p, (unsigned int)n, LWS_WRITE_TEXT);
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
		"SMTP Client API",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
