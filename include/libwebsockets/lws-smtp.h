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

#ifndef _LWS_SMTP_H
#define _LWS_SMTP_H

/** \defgroup smtp SMTP client session, sansIO
 * ##SMTP client session, sansIO
 *
 * The client side of an SMTP session (RFC 5321) with no transport under it:
 * it is handed the server's reply bytes as they arrive, and fills a buffer
 * it is given with the bytes to send next.  lws_smtpc (lws-smtp-client.h)
 * runs it over an lws client connection, and that is what most code wants;
 * anything else holding a byte stream to an SMTP server can run it the same
 * way.
 *
 * A mail is one transaction with one envelope sender and one recipient, and
 * several may be sent in turn on one session.  Commands are not pipelined:
 * each one waits for its reply.  The message is sent as text/plain in UTF-8,
 * with Date:, From:, To:, Subject: and Message-ID: headers; a Subject: that
 * is not plain ASCII, or is long, is sent as folded RFC 2047 encoded-words.
 * Line ends in the body are sent as CRLF whatever they were, and lines
 * starting with '.' are dot-stuffed.
 *
 * The session has no clock: how long to wait for a reply is the caller's
 * business.
 */
///@{

/* the limits lws_smtp_email_check() applies */
#define LWS_SMTP_ADDR_MAX	254	/* an address, without the <> */
#define LWS_SMTP_LOCAL_MAX	64	/* the part before the @ */
#define LWS_SMTP_SUBJECT_MAX	512	/* bytes of UTF-8 */
#define LWS_SMTP_MSGID_MAX	128	/* without the <> */
#define LWS_SMTP_LINE_MAX	998	/* a body line as sent, RFC 5322 2.1.1 */

/* the smallest buffer lws_smtp_session_tx() can always make progress in */
#define LWS_SMTP_TX_MIN		512

typedef struct lws_smtp_email {
	const char	*from;
	/**< envelope sender and From:, "local@domain" */
	const char	*to;
	/**< envelope recipient and To:, "local@domain" */
	const char	*subject;
	/**< UTF-8, with no control characters */
	const char	*body;
	/**< UTF-8 text, lines ending in LF or CRLF */
	const char	*message_id;
	/**< Message-ID: without the <>, or NULL to send none.
	 * lws_smtpc_queue() makes one when this is NULL */
	int64_t		date;
	/**< Date: as seconds since 1970 UTC, or 0 to send none.
	 * lws_smtpc_queue() uses the time it was queued when this is 0 */
} lws_smtp_email_t;

/** what the caller should do after lws_smtp_session_rx() */
typedef enum lws_smtp_ev {
	LWS_SMTP_EV_NONE,
	/**< nothing yet: the rest of the reply is still to come */
	LWS_SMTP_EV_TX,
	/**< there are bytes to send: call lws_smtp_session_tx() when the
	 * transport can take them */
	LWS_SMTP_EV_STARTTLS,
	/**< the server agreed to STARTTLS: start tls on the transport, then
	 * call lws_smtp_session_tls_up().  Anything the server sent after this
	 * reply was not protected by the tls and must be discarded */
	LWS_SMTP_EV_READY,
	/**< the session can take a mail: call lws_smtp_session_mail() with
	 * one, or with NULL to end the session */
	LWS_SMTP_EV_MAIL_DONE,
	/**< the mail given to lws_smtp_session_mail() is concluded, as
	 * .code says: 2xx it was accepted, 4xx refused for now, 5xx refused.
	 * Then the session can take a mail as for LWS_SMTP_EV_READY */
	LWS_SMTP_EV_CLOSE,
	/**< the session ended as it was asked to: close the transport */
	LWS_SMTP_EV_FAILED,
	/**< the session failed, or the server refused it: close the
	 * transport.  .code and .text say why, .code 0 being something
	 * the server sent that was not an SMTP reply to what we asked */
} lws_smtp_ev_t;

/**
 * The session's state.  The caller owns it and may embed it; its members
 * are not to be written, but .code and .text say what the last complete
 * reply was.
 */
typedef struct lws_smtp_session {
	const lws_smtp_email_t	*mail;	/* the mail in progress, or NULL */
	const char		*helo;	/* our name for EHLO and HELO */

	size_t			pos;	/* position in the tx item */
	int			code;	/* the last complete reply's code */
	char			text[96]; /* its last line's text */

	uint16_t		rx_line_len;
	uint16_t		rx_code;
	uint16_t		rx_first_code;
	uint8_t			rx_state;
	uint8_t			rx_text_len;
	uint8_t			rx_kw_len;
	uint8_t			rx_kw_end;
	char			rx_kw[16];

	uint8_t			state;
	uint8_t			item;	/* what of the message tx is at */
	uint8_t			flags;
} lws_smtp_session_t;

/**
 * lws_smtp_email_check() - is a mail acceptable to send
 *
 * \param e: the mail
 *
 * The addresses must be plain "local@domain" (no quoted local parts, no
 * address literals, no UTF-8), the subject UTF-8 with no control characters
 * and at most LWS_SMTP_SUBJECT_MAX bytes, each body line at most
 * LWS_SMTP_LINE_MAX once it is sent, and a message_id, if given, a
 * "left@right" of the characters an address may have.  What is checked here
 * is what keeps what the session sends well-formed, and
 * lws_smtp_session_mail() refuses a mail that fails it.
 *
 * Returns 0 if the mail is acceptable, else nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_smtp_email_check(const lws_smtp_email_t *e);

/**
 * lws_smtp_addr_check() - is this a plain "local@domain" address
 *
 * \param addr: the address, NUL-terminated
 *
 * Returns 0 if it is, else nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_smtp_addr_check(const char *addr);

/**
 * lws_smtp_session_init() - start a session
 *
 * \param s: the session state to initialize
 * \param helo: our name for EHLO and HELO (a domain), which must stay valid
 *		for the life of the session
 * \param starttls: nonzero to require STARTTLS before any mail is sent
 *
 * Call once the transport to the server is up; the session waits for the
 * server's greeting.  With \p starttls, a server that does not offer
 * STARTTLS, or refuses it, fails the session: no mail goes in plaintext.
 */
LWS_VISIBLE LWS_EXTERN void
lws_smtp_session_init(lws_smtp_session_t *s, const char *helo, int starttls);

/**
 * lws_smtp_session_rx() - the server sent these bytes
 *
 * \param s: the session
 * \param buf: the bytes
 * \param len: how many
 * \param used: set to how many of them were taken
 *
 * Takes bytes up to the end of the first complete reply, and says what the
 * caller is to do about it.  If fewer than \p len were used, call again
 * with the rest after acting on the result... except after
 * LWS_SMTP_EV_STARTTLS, where the rest must be discarded, and after
 * LWS_SMTP_EV_CLOSE and LWS_SMTP_EV_FAILED, where the session is over.
 */
LWS_VISIBLE LWS_EXTERN lws_smtp_ev_t
lws_smtp_session_rx(lws_smtp_session_t *s, const uint8_t *buf, size_t len,
		    size_t *used);

/**
 * lws_smtp_session_tx() - fill a buffer with the next bytes to send
 *
 * \param s: the session
 * \param buf: where to put them
 * \param max: how much room there is, at least LWS_SMTP_TX_MIN
 * \param produced: set to how many bytes were put in \p buf
 *
 * Returns 1 if there is more to send after these, 0 if nothing more is to be
 * sent until the server replies, or -1 if \p max is too small or the mail
 * could not be encoded.
 */
LWS_VISIBLE LWS_EXTERN int
lws_smtp_session_tx(lws_smtp_session_t *s, uint8_t *buf, size_t max,
		    size_t *produced);

/**
 * lws_smtp_session_tls_up() - tls is up after LWS_SMTP_EV_STARTTLS
 *
 * \param s: the session
 *
 * The session forgets what the server said before the tls and greets it
 * again: there is then something to send.
 */
LWS_VISIBLE LWS_EXTERN void
lws_smtp_session_tls_up(lws_smtp_session_t *s);

/**
 * lws_smtp_session_mail() - send a mail, or end the session
 *
 * \param s: the session
 * \param mail: the mail, or NULL to end the session
 *
 * Only after LWS_SMTP_EV_READY or LWS_SMTP_EV_MAIL_DONE.  \p mail must stay
 * valid until its LWS_SMTP_EV_MAIL_DONE, or the session ends.  There is then
 * something to send.
 *
 * Returns 0, or -1 if the session cannot take a mail now, or \p mail does not
 * pass lws_smtp_email_check(); the session is unchanged then.
 */
LWS_VISIBLE LWS_EXTERN int
lws_smtp_session_mail(lws_smtp_session_t *s, const lws_smtp_email_t *mail);

///@}

#endif /* _LWS_SMTP_H */
