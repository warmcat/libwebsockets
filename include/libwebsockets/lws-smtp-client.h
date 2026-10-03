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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _LWS_SMTP_CLIENT_H
#define _LWS_SMTP_CLIENT_H

/** \defgroup smtpc SMTP client
 * ##SMTP client
 *
 * Queue mails, and lws delivers them to an SMTP relay in the background,
 * telling you how each one went.  The relay is typically the local MTA on
 * 127.0.0.1:25, which is the default.
 *
 * Every vhost has one, configured from its "lws-smtp-client" per-vhost
 * options if it has any, which you get with lws_smtpc_vhost().  You can
 * also make your own with lws_smtpc_create().
 *
 * Mails are queued in memory, not persisted, and delivered one at a time, in
 * order, over one connection to the relay that is kept for as long as there
 * are mails to send.  The SMTP itself is the sansIO session of lws-smtp.h.
 *
 *  - a mail the relay accepts, or refuses with a 5xx, is done with then
 *
 *  - a 4xx, a session the relay refuses, or a connection that ends before
 *    the mail at the head of the queue is done with, counts as a try for
 *    that mail: at max_tries it is given up, otherwise it is tried again on
 *    the next connection
 *
 *  - connections are made with backoff, so a relay that is down, or that
 *    keeps failing sessions, is not hammered.  Failing to connect at all
 *    does not count as a try: mails wait, up to max_queue of them, until the
 *    relay is back
 *
 * All of this is on the lws service thread: call the apis from there.
 */
///@{

#define LWS_SMTPC_PROTOCOL_NAME		"lws-smtp-client"

typedef enum lws_smtpc_tls {
	LWS_SMTPC_TLS_NONE,
	/**< plaintext, eg to a local relay on :25 */
	LWS_SMTPC_TLS_IMPLICIT,
	/**< tls from the start, eg submissions on :465 */
	LWS_SMTPC_TLS_STARTTLS,
	/**< plaintext, then STARTTLS before any mail, eg submission on :587.
	 * A relay that does not offer it, or refuses it, gets no mail */
} lws_smtpc_tls_t;

typedef enum lws_smtpc_outcome {
	LWS_SMTPC_DELIVERED,
	/**< the relay accepted the mail */
	LWS_SMTPC_REFUSED,
	/**< the relay refused it with a 5xx */
	LWS_SMTPC_GAVE_UP,
	/**< it was tried max_tries times without being done with */
	LWS_SMTPC_ABANDONED,
	/**< the lws_smtpc was destroyed, or its vhost was, before it was
	 * done with */
} lws_smtpc_outcome_t;

typedef struct lws_smtpc_result {
	lws_smtpc_outcome_t	outcome;
	int			code;
	/**< the relay's last reply code about the mail, 0 if none */
	const char		*text;
	/**< that reply's text, printable ASCII, "" if none */
} lws_smtpc_result_t;

/**
 * lws_smtpc_done_cb_t - how a queued mail went
 *
 * \param opaque: as given to lws_smtpc_queue()
 * \param email: the mail as it was sent, with its date and message_id; the
 *		 pointers are only valid during the callback
 * \param res: how it went
 *
 * Called exactly once for each mail lws_smtpc_queue() accepted, never from
 * inside lws_smtpc_queue() itself.  lws_smtpc_queue() may be called from
 * here, and lws_smtpc_destroy() on an lws_smtpc you created.
 */
typedef void (*lws_smtpc_done_cb_t)(void *opaque, const lws_smtp_email_t *email,
				    const lws_smtpc_result_t *res);

typedef struct lws_smtpc_info {
	struct lws_vhost	*vhost;
	/**< the vhost whose client tls context the connections use */
	const char		*address;
	/**< the relay to connect to, NULL for "127.0.0.1" */
	const char		*host;
	/**< the name the relay's certificate is checked against, NULL for
	 * .address */
	uint16_t		port;
	/**< 0 for 25, or 465 with LWS_SMTPC_TLS_IMPLICIT */
	lws_smtpc_tls_t		tls;
	/**< how the connection is secured */
	uint32_t		tls_flags;
	/**< further LCCSCF_ flags for the tls, eg
	 * LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK */
	const char		*helo;
	/**< our name for EHLO, NULL for "localhost" */
	const lws_retry_bo_t	*retry;
	/**< backoff between connections to the relay, NULL for 100ms, 1s, 5s,
	 * 15s then 30s, with 20% jitter.  It must outlive the lws_smtpc */
	uint16_t		max_queue;
	/**< the most mails queued at once, 0 for 128 */
	uint16_t		reply_timeout_secs;
	/**< how long to wait for each reply from the relay, 0 for 60s */
	uint8_t			max_tries;
	/**< tries before a mail is given up, 0 for 5 */
} lws_smtpc_info_t;

struct lws_smtpc;

#if defined(LWS_WITH_EMAIL)

/**
 * lws_smtpc_create() - make an SMTP client
 *
 * \param info: how to reach the relay; it is copied
 *
 * Nothing connects until a mail is queued.  It must be destroyed with
 * lws_smtpc_destroy(); if its vhost is destroyed first, its queued mails are
 * abandoned then and it queues no more, but it still needs destroying.
 *
 * Returns the client, or NULL on failure.
 */
LWS_VISIBLE LWS_EXTERN struct lws_smtpc *
lws_smtpc_create(const lws_smtpc_info_t *info);

/**
 * lws_smtpc_destroy() - destroy an SMTP client made with lws_smtpc_create()
 *
 * \param psmtpc: pointer to the client pointer, which is set to NULL
 *
 * Its queued mails are abandoned, their callbacks telling of it, and a
 * connection it has is dropped.  A vhost's own client, from
 * lws_smtpc_vhost(), goes with the vhost and is not destroyed with this.
 */
LWS_VISIBLE LWS_EXTERN void
lws_smtpc_destroy(struct lws_smtpc **psmtpc);

/**
 * lws_smtpc_vhost() - the vhost's own SMTP client
 *
 * \param vh: the vhost
 *
 * Made the first time it is asked for, from the vhost's per-vhost options
 * for "lws-smtp-client", if any:
 *
 *  - "smtp-host": the relay to connect to, default "127.0.0.1"
 *  - "smtp-port": its port, default 25
 *  - "smtp-tls": "none" (the default), "implicit" or "starttls"
 *  - "smtp-tls-host": the name to check the relay's certificate against,
 *    default the "smtp-host" (a name, or an address literal the certificate
 *    carries as an IP SAN)
 *  - "smtp-tls-skip-hostname-check": "1" to check the certificate only
 *    against the vhost's trusted CAs and not for its name, for a relay
 *    reached by an address its certificate does not carry
 *  - "smtp-helo": our name for EHLO, default "localhost"
 *
 * It lives as long as the vhost.
 *
 * Returns the client, or NULL on failure.
 */
LWS_VISIBLE LWS_EXTERN struct lws_smtpc *
lws_smtpc_vhost(struct lws_vhost *vh);

/**
 * lws_smtpc_queue() - queue a mail to be sent
 *
 * \param smtpc: the client
 * \param email: the mail; everything it points to is copied
 * \param cb: called when the mail is done with, or NULL
 * \param opaque: passed to \p cb
 *
 * The mail must pass lws_smtp_email_check().  If it has no date, the time
 * now is used, and if it has no message_id, a random one is made at the
 * sender's domain.
 *
 * Returns 0 if it was queued, when \p cb will be called once about it, or
 * -1 if it was not (the mail is not acceptable, the queue is full or the
 * client's vhost has gone), when \p cb will not be called.
 */
LWS_VISIBLE LWS_EXTERN int
lws_smtpc_queue(struct lws_smtpc *smtpc, const lws_smtp_email_t *email,
		lws_smtpc_done_cb_t cb, void *opaque);

#endif

///@}

#endif
