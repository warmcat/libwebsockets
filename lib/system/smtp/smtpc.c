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
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * lws_smtpc: a queue of mails, and the raw client connection to the relay
 * that the sansIO SMTP session (lib/sansio/smtp) runs over, with the backoff
 * between connections and the accounting of how each mail went.
 */

#include "private-lib-core.h"

#define SMTPC_DEF_PORT		25
#define SMTPC_DEF_PORT_TLS	465
#define SMTPC_DEF_QUEUE		128
#define SMTPC_DEF_TRIES		5
#define SMTPC_DEF_TIMEOUT	60
/* how much the session is asked to fill per writeable */
#define SMTPC_TX_CHUNK		1024
/* the room for a name: a hostname, or a helo */
#define SMTPC_NAME_MAX		256

static const uint32_t smtpc_backoff_ms[] = { 100, 1000, 5000, 15000, 30000 };

static const lws_retry_bo_t smtpc_retry = {
	.retry_ms_table			= smtpc_backoff_ms,
	.retry_ms_table_count		= LWS_ARRAY_SIZE(smtpc_backoff_ms),
	.conceal_count			= LWS_RETRY_CONCEAL_ALWAYS,
	.jitter_percent			= 20,
};

struct lws_smtpc_mail {
	lws_dll2_t		list;
	lws_smtp_email_t	e;	/* its strings are after the struct */
	lws_smtpc_done_cb_t	cb;
	void			*opaque;
	int			code;	/* the last reply about it */
	char			text[sizeof(((lws_smtp_session_t *)0)->text)];
	uint8_t			tries;
};

struct lws_smtpc {
	lws_dll2_t		vh_list;	/* on vh->smtpc_owner */
	struct lws_context	*cx;
	struct lws_vhost	*vh;		/* NULL once the vhost went */
	lws_dll2_owner_t	queue;
	struct lws		*wsi;
	lws_sorted_usec_list_t	sul;		/* the next connection */
	lws_smtp_session_t	sess;
	struct lws_smtpc_mail	*cur;		/* the mail the session has */

	lws_smtpc_info_t	i;		/* its strings are ours, below */
	char			address[SMTPC_NAME_MAX];
	char			host[SMTPC_NAME_MAX];
	char			helo[SMTPC_NAME_MAX];

	uint16_t		retry_count;
	uint8_t			busy;		/* in our connection's callback */

	uint8_t			own:1;		/* the vhost's own */
	uint8_t			destroy_pending:1;
	uint8_t			destroying:1;
	uint8_t			in_connect:1;
	uint8_t			connect_died:1;
	uint8_t			upgrading:1;	/* STARTTLS handshake going */
	uint8_t			ended:1;	/* the session ended as asked */
	uint8_t			failed:1;	/* the session failed, saying why */
};

static void
smtpc_connect_sul_cb(lws_sorted_usec_list_t *sul);
static void
smtpc_free(struct lws_smtpc *s);

/* tell the user how his mail went, and forget it */

static void
smtpc_mail_done(struct lws_smtpc *s, struct lws_smtpc_mail *m,
		lws_smtpc_outcome_t outcome)
{
	lws_smtpc_result_t r;

	lws_dll2_remove(&m->list);
	if (s->cur == m)
		s->cur = NULL;

	r.outcome	= outcome;
	r.code		= m->code;
	r.text		= m->text;

	if (outcome != LWS_SMTPC_DELIVERED)
		lwsl_cx_warn(s->cx, "mail to %s not delivered (%d): %d %s",
			     m->e.to, (int)outcome, m->code, m->text);
	else
		lwsl_cx_info(s->cx, "mail to %s delivered: %d %s", m->e.to,
			     m->code, m->text);

	if (m->cb)
		m->cb(m->opaque, &m->e, &r);

	lws_free(m);
}

static void
smtpc_mail_note(struct lws_smtpc_mail *m, int code, const char *text)
{
	m->code = code;
	lws_strncpy(m->text, text, sizeof(m->text));
}

/* a try at the mail did not get it done with */

static void
smtpc_mail_tried(struct lws_smtpc *s, struct lws_smtpc_mail *m, int code,
		 const char *text)
{
	smtpc_mail_note(m, code, text);

	if (++m->tries >= s->i.max_tries)
		smtpc_mail_done(s, m, LWS_SMTPC_GAVE_UP);
}

static void
smtpc_abandon_all(struct lws_smtpc *s)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&s->queue)) {
		struct lws_smtpc_mail *m = lws_container_of(d,
					struct lws_smtpc_mail, list);

		smtpc_mail_done(s, m, LWS_SMTPC_ABANDONED);
	} lws_end_foreach_dll_safe(d, d1);
}

static int
smtpc_live(struct lws_smtpc *s)
{
	return s->vh && !s->vh->being_destroyed && !s->destroying &&
	       !s->destroy_pending;
}

/*
 * The relay could not be used for as many connections in a row as the retry
 * policy conceals: as for a Secure Stream at LWSSSCS_ALL_RETRIES_FAILED, the
 * failure stops being hidden from the user.  The mails waiting are given up,
 * and the next one queued starts a fresh backoff.
 */

static void
smtpc_all_retries_failed(struct lws_smtpc *s)
{
	size_t n = lws_dll2_count(&s->queue);

	lwsl_vhost_warn(s->vh, "relay %s:%u unavailable: %u mails given up",
			s->i.address, (unsigned int)s->i.port, (unsigned int)n);

	/* a mail queued from one of the callbacks starts over */
	s->retry_count = 0;

	/*
	 * The callbacks may queue more mail, which goes on the tail and is
	 * not given up with these, and may destroy the client, or its vhost:
	 * then it goes once we are out of here
	 */

	s->busy++;
	while (n-- && lws_dll2_get_head(&s->queue)) {
		struct lws_smtpc_mail *m = lws_container_of(
			lws_dll2_get_head(&s->queue), struct lws_smtpc_mail,
			list);

		if (!m->tries)
			/* no relay ever heard of it */
			smtpc_mail_note(m, 0, "relay unavailable");
		smtpc_mail_done(s, m, LWS_SMTPC_GAVE_UP);
	}
	s->busy--;

	if (!s->busy && s->destroy_pending)
		smtpc_free(s);
}

/*
 * Every end of a connection comes through here, as does every connect that
 * failed at once, so a relay that is down or that fails every session cannot
 * be reconnected to in a tight loop
 */

static void
smtpc_retry_later(struct lws_smtpc *s)
{
	if (s->wsi || !smtpc_live(s))
		return;

	if (!lws_dll2_count(&s->queue)) {
		/* nothing left to send: forget the backoff */
		lws_sul_cancel(&s->sul);
		s->retry_count = 0;

		return;
	}

	if (lws_retry_sul_schedule(s->cx, 0, &s->sul, s->i.retry,
				   smtpc_connect_sul_cb, &s->retry_count))
		/* nothing was scheduled: the policy is exhausted */
		smtpc_all_retries_failed(s);
}

/* a new mail: connect now, unless there is a connection, or a backoff */

static void
smtpc_kick(struct lws_smtpc *s)
{
	if (s->wsi || s->retry_count || !smtpc_live(s))
		return;

	lws_sul_schedule(s->cx, 0, &s->sul, smtpc_connect_sul_cb, 1);
}

static void
smtpc_connect_sul_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_smtpc *s = lws_container_of(sul, struct lws_smtpc, sul);
	struct lws_client_connect_info i;
	struct lws *w;

	if (s->wsi || !smtpc_live(s))
		return;

	if (!lws_dll2_count(&s->queue)) {
		s->retry_count = 0;

		return;
	}

	memset(&i, 0, sizeof(i));
	i.context		= s->cx;
	i.vhost			= s->vh;
	i.address		= s->i.address;
	i.host			= s->i.host;
	i.origin		= s->i.host;
	i.port			= s->i.port;
	i.method		= "RAW";
	i.protocol		= LWS_SMTPC_PROTOCOL_NAME;
	i.local_protocol_name	= LWS_SMTPC_PROTOCOL_NAME;
	i.opaque_user_data	= s;
	i.fi_wsi_name		= "smtpc";
	if (s->i.tls == LWS_SMTPC_TLS_IMPLICIT)
		i.ssl_connection = LCCSCF_USE_SSL | (int)s->i.tls_flags;

	s->ended	= 0;
	s->failed	= 0;
	s->upgrading	= 0;

	/*
	 * The connection can fail and be closed inside the connect, calling
	 * us back about it before it returns: then it is ours to go on from
	 * here, once
	 */
	s->connect_died	= 0;
	s->in_connect	= 1;
	w = lws_client_connect_via_info(&i);
	s->in_connect	= 0;

	if (!w || s->connect_died) {
		lwsl_vhost_warn(s->vh, "connect to relay %s:%u failed",
				s->i.address, (unsigned int)s->i.port);
		s->wsi = NULL;
		smtpc_retry_later(s);

		return;
	}

	s->wsi = w;
}

/* bound how long the relay may take over what we are waiting for */

static void
smtpc_await(struct lws_smtpc *s, struct lws *wsi)
{
	lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
			(int)s->i.reply_timeout_secs);
}

/* the session can take a mail: the next one, or none to end it */

static void
smtpc_offer(struct lws_smtpc *s, struct lws *wsi, int end)
{
	struct lws_smtpc_mail *m = NULL;

	if (!end && smtpc_live(s) && lws_dll2_get_head(&s->queue))
		m = lws_container_of(lws_dll2_get_head(&s->queue),
				     struct lws_smtpc_mail, list);

	s->cur = m;
	lws_smtp_session_mail(&s->sess, m ? &m->e : NULL);
	lws_callback_on_writable(wsi);
}

/*
 * The session concluded its mail: returns nonzero if the session should end
 * now, because the relay only refused it for now and trying it again at once
 * would be no different
 */

static int
smtpc_concluded(struct lws_smtpc *s)
{
	struct lws_smtpc_mail *m = s->cur;
	int c = s->sess.code;

	s->cur = NULL;
	if (!m)
		return 0;

	smtpc_mail_note(m, c, s->sess.text);

	if (c >= 400 && c < 500) {
		smtpc_mail_tried(s, m, c, s->sess.text);

		return 1;
	}

	/* the relay is working: whatever else is queued goes promptly */
	s->retry_count = 0;
	smtpc_mail_done(s, m, c < 300 ? LWS_SMTPC_DELIVERED : LWS_SMTPC_REFUSED);

	return 0;
}

static int
smtpc_rx(struct lws_smtpc *s, struct lws *wsi, const uint8_t *p, size_t len)
{
	size_t used;

	while (len) {
		lws_smtp_ev_t ev = lws_smtp_session_rx(&s->sess, p, len, &used);

		p += used;
		len -= used;

		switch (ev) {
		case LWS_SMTP_EV_NONE:
			break;

		case LWS_SMTP_EV_TX:
			lws_callback_on_writable(wsi);
			break;

		case LWS_SMTP_EV_STARTTLS:
			if (len) {
				/*
				 * Bytes after the 220 were not protected by
				 * the tls: that is an injection, not a relay
				 */
				lwsl_vhost_warn(s->vh, "relay sent plaintext "
						"after agreeing to STARTTLS");

				return -1;
			}
#if defined(LWS_WITH_TLS)
			switch (lws_tls_client_upgrade(wsi, LCCSCF_USE_SSL |
						       (int)s->i.tls_flags)) {
			case 0:
				/* RAW_CONNECTED again when it is up */
				s->upgrading = 1;
				return 0;
			case 1:
				lws_smtp_session_tls_up(&s->sess);
				lws_callback_on_writable(wsi);
				return 0;
			default:
				break;
			}
#endif
			return -1;

		case LWS_SMTP_EV_READY:
			smtpc_offer(s, wsi, 0);
			break;

		case LWS_SMTP_EV_MAIL_DONE:
			smtpc_offer(s, wsi, smtpc_concluded(s));
			break;

		case LWS_SMTP_EV_CLOSE:
			s->ended = 1;
			return -1;

		case LWS_SMTP_EV_FAILED:
			s->failed = 1;
			lwsl_vhost_warn(s->vh, "session with relay %s:%u "
					"failed: %d %s", s->i.address,
					(unsigned int)s->i.port, s->sess.code,
					s->sess.text);
			return -1;
		}
	}

	return 0;
}

static int
smtpc_tx(struct lws_smtpc *s, struct lws *wsi)
{
	uint8_t buf[LWS_PRE + SMTPC_TX_CHUNK];
	size_t n;
	int more;

	more = lws_smtp_session_tx(&s->sess, buf + LWS_PRE, SMTPC_TX_CHUNK, &n);
	if (more < 0)
		return -1;

	if (!n)
		return 0;

	if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) < (int)n)
		return -1;

	if (more)
		lws_callback_on_writable(wsi);

	/* what we sent is to be answered, or taken, in good time */
	smtpc_await(s, wsi);

	return 0;
}

/* the connection has gone, whether it was ever up or not */

static void
smtpc_conn_gone(struct lws_smtpc *s, struct lws *wsi, int was_up)
{
	struct lws_smtpc_mail *m = s->cur;

	lws_set_opaque_user_data(wsi, NULL);
	if (s->in_connect)
		s->connect_died = 1;
	s->wsi		= NULL;
	s->cur		= NULL;
	s->upgrading	= 0;

	/*
	 * A session that ended before the mail it was on, or the one it was
	 * about to start, was done with was a try at that mail.  Failing to
	 * connect at all is not: the mails wait for the relay.
	 */

	if (was_up && !s->ended) {
		if (!m && lws_dll2_get_head(&s->queue))
			m = lws_container_of(lws_dll2_get_head(&s->queue),
					     struct lws_smtpc_mail, list);
		if (m)
			smtpc_mail_tried(s, m, s->failed ? s->sess.code : 0,
					 s->failed ? s->sess.text :
						     "connection lost");
	}

	if (!s->in_connect)
		smtpc_retry_later(s);
}

static void
smtpc_free(struct lws_smtpc *s)
{
	s->destroying = 1;

	if (s->vh)
		lws_sul_cancel(&s->sul);

	if (s->wsi) {
		lws_set_opaque_user_data(s->wsi, NULL);
		lws_set_timeout(s->wsi, PENDING_TIMEOUT_KILLED_BY_PARENT,
				LWS_TO_KILL_ASYNC);
		s->wsi = NULL;
	}

	smtpc_abandon_all(s);
	lws_dll2_remove(&s->vh_list);
	lws_free(s);
}

static int
smtpc_wsi_cb(struct lws_smtpc *s, struct lws *wsi,
	     enum lws_callback_reasons reason, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_vhost_warn(s->vh, "relay %s:%u: %s", s->i.address,
				(unsigned int)s->i.port,
				in ? (const char *)in : "failed");
		smtpc_conn_gone(s, wsi, 0);
		return 0;

	case LWS_CALLBACK_RAW_CLOSE:
		smtpc_conn_gone(s, wsi, 1);
		return 0;

	case LWS_CALLBACK_RAW_CONNECTED:
		s->wsi = wsi;
		if (s->upgrading) {
			/* the STARTTLS handshake completed */
			s->upgrading = 0;
			lws_smtp_session_tls_up(&s->sess);
			lws_callback_on_writable(wsi);

			return 0;
		}
		lws_smtp_session_init(&s->sess, s->i.helo,
				      s->i.tls == LWS_SMTPC_TLS_STARTTLS);
		smtpc_await(s, wsi); /* the greeting */
		return 0;

	case LWS_CALLBACK_RAW_RX:
		if (!in)
			return -1;
		return smtpc_rx(s, wsi, (const uint8_t *)in, len);

	case LWS_CALLBACK_RAW_WRITEABLE:
		return smtpc_tx(s, wsi);

	default:
		return 0;
	}
}

static int
callback_smtpc(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	       void *in, size_t len)
{
	struct lws_smtpc *s;
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_RAW_CLOSE:
	case LWS_CALLBACK_RAW_CONNECTED:
	case LWS_CALLBACK_RAW_RX:
	case LWS_CALLBACK_RAW_WRITEABLE:
		break;
	default:
		return 0;
	}

	s = (struct lws_smtpc *)lws_get_opaque_user_data(wsi);
	if (!s)
		/* its client went: it is being closed */
		return reason == LWS_CALLBACK_RAW_CLOSE ||
		       reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR ? 0 : -1;

	/*
	 * A mail's callback may destroy the client: if so, it goes once we
	 * are out of here
	 */

	s->busy++;
	n = smtpc_wsi_cb(s, wsi, reason, in, len);
	s->busy--;

	if (!s->busy && s->destroy_pending) {
		smtpc_free(s);

		return 0;
	}

	return n;
}

const struct lws_protocols lws_smtpc_protocol =
	{ LWS_SMTPC_PROTOCOL_NAME, callback_smtpc, 0, 0, 0, NULL, 0 };

static int
smtpc_copy(char *dest, const char *src, const char *def, const char *what)
{
	if (!src)
		src = def;

	if (strlen(src) >= SMTPC_NAME_MAX) {
		lwsl_err("%s: %s too long\n", __func__, what);

		return 1;
	}

	lws_strncpy(dest, src, SMTPC_NAME_MAX);

	return 0;
}

struct lws_smtpc *
lws_smtpc_create(const lws_smtpc_info_t *info)
{
	struct lws_smtpc *s;

	if (!info || !info->vhost || info->vhost->being_destroyed ||
	    (unsigned int)info->tls > (unsigned int)LWS_SMTPC_TLS_STARTTLS) {
		lwsl_err("%s: bad info\n", __func__);

		return NULL;
	}

#if !defined(LWS_WITH_TLS)
	if (info->tls != LWS_SMTPC_TLS_NONE) {
		lwsl_err("%s: tls needs a build with tls\n", __func__);

		return NULL;
	}
#endif

	s = lws_zalloc(sizeof(*s), __func__);
	if (!s)
		return NULL;

	s->i = *info;

	if (smtpc_copy(s->address, info->address, "127.0.0.1", "address") ||
	    smtpc_copy(s->host, info->host, s->address, "host") ||
	    smtpc_copy(s->helo, info->helo, "localhost", "helo")) {
		lws_free(s);

		return NULL;
	}

	s->cx		= info->vhost->context;
	s->vh		= info->vhost;
	s->i.address	= s->address;
	s->i.host	= s->host;
	s->i.helo	= s->helo;
	if (!s->i.port)
		s->i.port = info->tls == LWS_SMTPC_TLS_IMPLICIT ?
				SMTPC_DEF_PORT_TLS : SMTPC_DEF_PORT;
	if (!s->i.retry)
		s->i.retry = &smtpc_retry;
	if (!s->i.max_queue)
		s->i.max_queue = SMTPC_DEF_QUEUE;
	if (!s->i.max_tries)
		s->i.max_tries = SMTPC_DEF_TRIES;
	if (!s->i.reply_timeout_secs)
		s->i.reply_timeout_secs = SMTPC_DEF_TIMEOUT;

	lws_dll2_add_tail(&s->vh_list, &s->vh->smtpc_owner);

	return s;
}

void
lws_smtpc_destroy(struct lws_smtpc **ps)
{
	struct lws_smtpc *s = *ps;

	*ps = NULL;
	if (!s || s->destroying || s->destroy_pending)
		return;

	if (s->own) {
		lwsl_cx_warn(s->cx, "a vhost's own client goes with the vhost");

		return;
	}

	if (s->busy) {
		/* we are inside its connection's callback: it goes after */
		s->destroy_pending = 1;

		return;
	}

	smtpc_free(s);
}

struct lws_smtpc *
lws_smtpc_vhost(struct lws_vhost *vh)
{
	const struct lws_protocol_vhost_options *pvo, *o;
	lws_smtpc_info_t info;
	int port;

	if (!vh || vh->being_destroyed)
		return NULL;
	if (vh->smtpc)
		return vh->smtpc;

	memset(&info, 0, sizeof(info));
	info.vhost = vh;

	pvo = lws_vhost_protocol_options(vh, LWS_SMTPC_PROTOCOL_NAME);
	pvo = pvo ? pvo->options : NULL;

	if ((o = lws_pvo_search(pvo, "smtp-host")) && o->value && o->value[0])
		info.address = o->value;

	if ((o = lws_pvo_search(pvo, "smtp-port")) && o->value && o->value[0]) {
		port = atoi(o->value);
		if (port <= 0 || port > 65535) {
			lwsl_vhost_err(vh, "bad smtp-port %s", o->value);

			return NULL;
		}
		info.port = (uint16_t)port;
	}

	if ((o = lws_pvo_search(pvo, "smtp-tls")) && o->value && o->value[0]) {
		if (!strcmp(o->value, "implicit"))
			info.tls = LWS_SMTPC_TLS_IMPLICIT;
		else if (!strcmp(o->value, "starttls"))
			info.tls = LWS_SMTPC_TLS_STARTTLS;
		else if (strcmp(o->value, "none")) {
			lwsl_vhost_err(vh, "bad smtp-tls %s", o->value);

			return NULL;
		}
	}

	/*
	 * Without smtp-tls-host, lws_smtpc_create() checks the relay's
	 * certificate against smtp-host itself, a name or an address literal.
	 * Only a relay reached by an address its certificate does not carry
	 * needs the name check skipped, and that is said explicitly.
	 */

	if ((o = lws_pvo_search(pvo, "smtp-tls-host")) && o->value &&
	    o->value[0])
		info.host = o->value;

	if ((o = lws_pvo_search(pvo, "smtp-tls-skip-hostname-check")) &&
	    o->value && atoi(o->value))
		info.tls_flags = LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

	if ((o = lws_pvo_search(pvo, "smtp-helo")) && o->value && o->value[0])
		info.helo = o->value;

	vh->smtpc = lws_smtpc_create(&info);
	if (!vh->smtpc)
		return NULL;

	vh->smtpc->own = 1;

	lwsl_vhost_notice(vh, "smtp relay %s:%u, tls %d, cert name %s",
			  vh->smtpc->i.address,
			  (unsigned int)vh->smtpc->i.port, (int)vh->smtpc->i.tls,
			  vh->smtpc->i.tls == LWS_SMTPC_TLS_NONE ? "n/a" :
			  (vh->smtpc->i.tls_flags &
			   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK) ? "unchecked" :
							  vh->smtpc->i.host);

	return vh->smtpc;
}

int
lws_smtpc_queue(struct lws_smtpc *s, const lws_smtp_email_t *email,
		lws_smtpc_done_cb_t cb, void *opaque)
{
	size_t lf, lt, ls, lb, lm, ld;
	struct lws_smtpc_mail *m;
	char msgid[LWS_SMTP_MSGID_MAX + 1];
	const char *mid, *dom;
	uint8_t rnd[12];
	char *p;

	if (!s || !smtpc_live(s) || lws_smtp_email_check(email))
		return -1;

	if (lws_dll2_count(&s->queue) >= s->i.max_queue) {
		lwsl_vhost_warn(s->vh, "mail queue full (%u)",
				(unsigned int)s->i.max_queue);

		return -1;
	}

	mid = email->message_id;
	if (!mid) {
		/* random, at the sender's domain if it fits */
		if (lws_get_random(s->cx, rnd, sizeof(rnd)) != sizeof(rnd))
			return -1;
		lws_hex_from_byte_array(rnd, sizeof(rnd), msgid, sizeof(msgid));
		dom = strchr(email->from, '@');
		ld = strlen(msgid);
		if (!dom || ld + strlen(dom) > LWS_SMTP_MSGID_MAX)
			dom = "@localhost";
		lws_strncpy(msgid + ld, dom, sizeof(msgid) - ld);
		mid = msgid;
	}

	lf = strlen(email->from) + 1;
	lt = strlen(email->to) + 1;
	ls = strlen(email->subject) + 1;
	lb = strlen(email->body) + 1;
	lm = strlen(mid) + 1;

	m = lws_malloc(sizeof(*m) + lf + lt + ls + lb + lm, __func__);
	if (!m)
		return -1;

	memset(m, 0, sizeof(*m));
	p = (char *)&m[1];

	memcpy(p, email->from, lf);
	m->e.from = p;
	p += lf;
	memcpy(p, email->to, lt);
	m->e.to = p;
	p += lt;
	memcpy(p, email->subject, ls);
	m->e.subject = p;
	p += ls;
	memcpy(p, email->body, lb);
	m->e.body = p;
	p += lb;
	memcpy(p, mid, lm);
	m->e.message_id = p;

	m->e.date = email->date ? email->date :
			(int64_t)lws_pt_now_wall(&s->cx->pt[0]);
	m->cb = cb;
	m->opaque = opaque;

	lws_dll2_add_tail(&m->list, &s->queue);
	smtpc_kick(s);

	return 0;
}

/*
 * The vhost is going: its own client goes with it, and any others made on it
 * can do nothing more, so their mails are abandoned now.  They are still
 * their creators' to destroy.
 */

void
lws_smtpc_destroy_all_on_vhost(struct lws_vhost *vh)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vh->smtpc_owner)) {
		struct lws_smtpc *s = lws_container_of(d, struct lws_smtpc,
						       vh_list);

		/*
		 * The vhost's own client goes with it... but if we are here
		 * from inside one of its mail callbacks, with no connection
		 * holding the vhost up, it goes once that has returned
		 */
		if (s->own && !s->busy) {
			smtpc_free(s);
			continue;
		}

		lws_sul_cancel(&s->sul);
		if (s->wsi) {
			lws_set_opaque_user_data(s->wsi, NULL);
			s->wsi = NULL;
		}
		s->vh = NULL;
		lws_dll2_remove(&s->vh_list);

		/* a mail's callback may destroy it: it goes once we are done */
		s->busy++;
		smtpc_abandon_all(s);
		s->busy--;
		if (s->own)
			s->destroy_pending = 1;
		if (!s->busy && s->destroy_pending)
			smtpc_free(s);
	} lws_end_foreach_dll_safe(d, d1);

	vh->smtpc = NULL;
}
