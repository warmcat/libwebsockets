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
 * The client side of an SMTP session (RFC 5321), sansIO: the server's reply
 * bytes come in through lws_smtp_session_rx(), and lws_smtp_session_tx()
 * fills the caller's buffer with what to send next, from wherever it got to
 * last time.  Nothing here knows what carries the bytes, or reads the clock:
 * the mail brings its own Date.
 */

#include "private-lib-core.h"

/*
 * A *_TX state has a command to send, and the *_RX state after it waits for
 * the reply to it
 */

enum lws_smtp_state {
	SMS_GREETING_RX,
	SMS_EHLO_TX,
	SMS_EHLO_RX,
	SMS_HELO_TX,
	SMS_HELO_RX,
	SMS_STARTTLS_TX,
	SMS_STARTTLS_RX,
	SMS_TLS,		/* the transport is starting tls */
	SMS_IDLE,		/* waiting to be given a mail, or NULL */
	SMS_RSET_TX,
	SMS_RSET_RX,
	SMS_MAIL_TX,
	SMS_MAIL_RX,
	SMS_RCPT_TX,
	SMS_RCPT_RX,
	SMS_DATA_TX,
	SMS_DATA_RX,
	SMS_CONTENT_TX,
	SMS_CONTENT_RX,
	SMS_QUIT_TX,
	SMS_QUIT_RX,
	SMS_OVER,		/* CLOSE or FAILED was said */
};

#define SMF_STARTTLS		(1 << 0) /* no mail before STARTTLS */
#define SMF_EXT_STARTTLS	(1 << 1) /* the EHLO reply offered it */
#define SMF_EXT_8BITMIME	(1 << 2) /* the EHLO reply offered it */
#define SMF_RSET		(1 << 3) /* a transaction failed partway: RSET
					  * before the next one */
#define SMF_8BIT		(1 << 4) /* the mail's body is not 7-bit */
#define SMF_BOL			(1 << 5) /* body tx is at a line start */

/* the reply parser, per byte */

enum lws_smtp_rx_state {
	SMR_CODE,
	SMR_SEP,
	SMR_TEXT_MORE,		/* a "ddd-" line: more lines follow */
	SMR_TEXT_LAST,		/* a "ddd " line, or "ddd" alone */
	SMR_CR_MORE,
	SMR_CR_LAST,
};

/* the longest reply line we take, RFC 5321 4.5.3.1.5 allows 512 */
#define SMTP_REPLY_LINE_MAX	1000

/* what of the message the content tx is at */

enum lws_smtp_item {
	SMI_DATE,
	SMI_FROM,
	SMI_TO,
	SMI_SUBJECT,
	SMI_MSGID,
	SMI_MIME,
	SMI_BODY,
	SMI_DOT,
};

/*
 * room a header line needs, the longest being From: or To: with the longest
 * address; the subject is folded into encoded-words when it would be long
 */
#define SMTP_HDR_ROOM		(12 + LWS_SMTP_ADDR_MAX + 3)
/* a plain subject longer than this is sent as encoded-words */
#define SMTP_SUBJECT_PLAIN_MAX	64
/*
 * UTF-8 bytes per encoded-word: 42 bytes of base64 input is 56 characters,
 * so "Subject: =?UTF-8?B?...?=" is 77 columns, inside RFC 5322's 78
 */
#define SMTP_EW_BYTES		42

static const char * const smtp_wday = "SunMonTueWedThuFriSat",
		  * const smtp_mon = "JanFebMarAprMayJunJulAugSepOctNovDec";

/* RFC 5322 atext, less nothing: every one is safe in a path and a header */

static int
smtp_atext(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') ||
	       (c && !!strchr("!#$%&'*+-/=?^_`{|}~", c));
}

static int
smtp_dot_atom(const char *p, size_t len, int domain)
{
	size_t n, label = 0;

	if (!len || p[0] == '.' || p[len - 1] == '.')
		return 1;

	for (n = 0; n < len; n++) {
		if (p[n] == '.') {
			if (!n || p[n - 1] == '.')
				return 1;
			label = 0;
			continue;
		}
		if (domain) {
			/* a hostname's LDH labels, no '-' at either end */
			if (!((p[n] >= 'a' && p[n] <= 'z') ||
			      (p[n] >= 'A' && p[n] <= 'Z') ||
			      (p[n] >= '0' && p[n] <= '9') ||
			      (p[n] == '-' && label &&
			       n + 1 < len && p[n + 1] != '.')) ||
			    ++label > 63)
				return 1;
			continue;
		}
		if (!smtp_atext(p[n]))
			return 1;
	}

	return 0;
}

int
lws_smtp_addr_check(const char *addr)
{
	const char *at;
	size_t len;

	if (!addr)
		return 1;

	len = strlen(addr);
	at = strchr(addr, '@');
	if (len > LWS_SMTP_ADDR_MAX || !at ||
	    lws_ptr_diff_size_t(at, addr) > LWS_SMTP_LOCAL_MAX)
		return 1;

	return smtp_dot_atom(addr, lws_ptr_diff_size_t(at, addr), 0) ||
	       smtp_dot_atom(at + 1, len - lws_ptr_diff_size_t(at, addr) - 1, 1);
}

int
lws_smtp_email_check(const lws_smtp_email_t *e)
{
	unsigned char u = 0;
	size_t n, line;
	const char *p;

	if (!e || lws_smtp_addr_check(e->from) || lws_smtp_addr_check(e->to) ||
	    !e->subject || !e->body)
		return 1;

	n = strlen(e->subject);
	if (n > LWS_SMTP_SUBJECT_MAX ||
	    lws_check_utf8(&u, (unsigned char *)(uintptr_t)e->subject, n) || u)
		return 1;
	for (p = e->subject; *p; p++)
		if ((unsigned char)*p < 0x20 || *p == 0x7f)
			return 1;

	if (e->message_id) {
		/* left@right, both dot-atoms */
		p = strchr(e->message_id, '@');
		n = strlen(e->message_id);
		if (!p || n > LWS_SMTP_MSGID_MAX ||
		    smtp_dot_atom(e->message_id,
				  lws_ptr_diff_size_t(p, e->message_id), 0) ||
		    smtp_dot_atom(p + 1, n - lws_ptr_diff_size_t(p,
						e->message_id) - 1, 0))
			return 1;
	}

	/* every body line as it is sent, dot-stuffed, fits RFC 5322's limit */

	line = 0;
	for (p = e->body; *p; p++) {
		if (*p == '\r' || *p == '\n') {
			if (*p == '\r' && p[1] == '\n')
				p++;
			line = 0;
			continue;
		}
		if (!line && *p == '.')
			line++;
		if (++line > LWS_SMTP_LINE_MAX)
			return 1;
	}

	return 0;
}

/* an EHLO / HELO name: a domain, or an address literal "[...]" */

static int
smtp_helo_check(const char *h)
{
	size_t len = h ? strlen(h) : 0;

	if (!len || len > 253)
		return 1;

	if (h[0] == '[') {
		size_t n;

		if (len < 3 || h[len - 1] != ']')
			return 1;
		/* "[192.0.2.1]" or "[IPv6:2001:db8::1]" */
		for (n = 1; n < len - 1; n++)
			if (!((h[n] >= '0' && h[n] <= '9') ||
			      (h[n] >= 'a' && h[n] <= 'z') ||
			      (h[n] >= 'A' && h[n] <= 'Z') ||
			      h[n] == '.' || h[n] == ':'))
				return 1;

		return 0;
	}

	return smtp_dot_atom(h, len, 1);
}

void
lws_smtp_session_init(lws_smtp_session_t *s, const char *helo, int starttls)
{
	memset(s, 0, sizeof(*s));

	if (smtp_helo_check(helo)) {
		lwsl_warn("%s: unusable helo name, using localhost\n", __func__);
		helo = "localhost";
	}

	s->helo		= helo;
	s->state	= SMS_GREETING_RX;
	s->rx_state	= SMR_CODE;
	if (starttls)
		s->flags = SMF_STARTTLS;
}

void
lws_smtp_session_tls_up(lws_smtp_session_t *s)
{
	if (s->state != SMS_TLS)
		return;

	/* RFC 3207 4.2: what the server said before the tls is forgotten */
	s->flags = (uint8_t)(s->flags &
			     ~(SMF_STARTTLS | SMF_EXT_STARTTLS | SMF_EXT_8BITMIME));
	s->state = SMS_EHLO_TX;
}

int
lws_smtp_session_mail(lws_smtp_session_t *s, const lws_smtp_email_t *mail)
{
	const char *p;

	if (s->state != SMS_IDLE)
		return -1;

	/* what goes on the wire is only ever from a mail that is well-formed */
	if (mail && lws_smtp_email_check(mail))
		return -1;

	s->mail = mail;
	if (!mail) {
		s->state = SMS_QUIT_TX;

		return 0;
	}

	s->flags = (uint8_t)(s->flags & ~SMF_8BIT);
	for (p = mail->body; *p; p++)
		if ((unsigned char)*p >= 0x80) {
			s->flags |= SMF_8BIT;
			break;
		}

	s->state = (s->flags & SMF_RSET) ? SMS_RSET_TX : SMS_MAIL_TX;

	return 0;
}

static lws_smtp_ev_t
smtp_over(lws_smtp_session_t *s, int code, const char *why)
{
	s->state = SMS_OVER;
	s->mail = NULL;
	s->code = code;
	if (why)
		lws_strncpy(s->text, why, sizeof(s->text));

	return LWS_SMTP_EV_FAILED;
}

/*
 * The server refused something about the session itself, or said something
 * that is not an answer to what we asked: the session is over, and what it
 * said is kept to say why
 */

static lws_smtp_ev_t
smtp_refused(lws_smtp_session_t *s)
{
	return smtp_over(s, s->code, NULL);
}

static lws_smtp_ev_t
smtp_mail_done(lws_smtp_session_t *s, int rset)
{
	if (rset)
		s->flags |= SMF_RSET;
	s->mail = NULL;
	s->state = SMS_IDLE;

	return LWS_SMTP_EV_MAIL_DONE;
}

/* an EHLO reply line past the first names an extension */

static void
smtp_ehlo_keyword(lws_smtp_session_t *s)
{
	s->rx_kw[s->rx_kw_len] = '\0';

	if (!strcmp(s->rx_kw, "STARTTLS"))
		s->flags |= SMF_EXT_STARTTLS;
	if (!strcmp(s->rx_kw, "8BITMIME"))
		s->flags |= SMF_EXT_8BITMIME;
}

/* a whole reply has come: what it means depends on what it answers */

static lws_smtp_ev_t
smtp_reply(lws_smtp_session_t *s)
{
	int c = s->code, ok = c >= 200 && c < 300;

	/* the server is closing the session, whatever we were doing */
	if (c == 421)
		return smtp_over(s, c, NULL);

	switch (s->state) {
	case SMS_GREETING_RX:
		if (c != 220)
			return smtp_refused(s);
		s->state = SMS_EHLO_TX;
		break;

	case SMS_EHLO_RX:
		if (!ok) {
			/*
			 * An old server that does not know EHLO: HELO, unless
			 * we need STARTTLS, which only EHLO can offer
			 */
			if (c >= 500 && !(s->flags & SMF_STARTTLS)) {
				s->state = SMS_HELO_TX;
				break;
			}
			return smtp_refused(s);
		}
		if (s->flags & SMF_STARTTLS) {
			if (!(s->flags & SMF_EXT_STARTTLS)) {
				s->code = 0;
				lws_strncpy(s->text, "STARTTLS not offered",
					    sizeof(s->text));
				return smtp_refused(s);
			}
			s->state = SMS_STARTTLS_TX;
			break;
		}
		s->state = SMS_IDLE;

		return LWS_SMTP_EV_READY;

	case SMS_HELO_RX:
		if (!ok)
			return smtp_refused(s);
		s->state = SMS_IDLE;

		return LWS_SMTP_EV_READY;

	case SMS_STARTTLS_RX:
		if (c != 220)
			/* not in plaintext, then not at all */
			return smtp_refused(s);
		s->state = SMS_TLS;

		return LWS_SMTP_EV_STARTTLS;

	case SMS_RSET_RX:
		if (!ok)
			return smtp_refused(s);
		s->flags = (uint8_t)(s->flags & ~SMF_RSET);
		s->state = SMS_MAIL_TX;
		break;

	case SMS_MAIL_RX:
		if (!ok)
			return c < 400 ? smtp_refused(s) : smtp_mail_done(s, 1);
		s->state = SMS_RCPT_TX;
		break;

	case SMS_RCPT_RX:
		if (!ok)
			return c < 400 ? smtp_refused(s) : smtp_mail_done(s, 1);
		s->state = SMS_DATA_TX;
		break;

	case SMS_DATA_RX:
		if (c != 354)
			return c < 400 ? smtp_refused(s) : smtp_mail_done(s, 1);
		s->item		= SMI_DATE;
		s->pos		= 0;
		s->flags	|= SMF_BOL;
		s->state	= SMS_CONTENT_TX;
		break;

	case SMS_CONTENT_RX:
		if (!ok && c < 400)
			return smtp_refused(s);
		/* accepted or not, the transaction is over */
		return smtp_mail_done(s, 0);

	case SMS_QUIT_RX:
		s->state = SMS_OVER;

		return LWS_SMTP_EV_CLOSE;

	default:
		/* a reply to nothing we said */
		return smtp_over(s, 0, "unexpected reply");
	}

	return LWS_SMTP_EV_TX;
}

/* take one reply byte: 1 if it completed a reply, -1 if it is not SMTP */

static int
smtp_rx_byte(lws_smtp_session_t *s, char c)
{
	int eol = 0, last = 0;

	if (++s->rx_line_len > SMTP_REPLY_LINE_MAX)
		return -1;

	switch (s->rx_state) {
	case SMR_CODE:
		if (c < (s->rx_line_len == 1 ? '2' : '0') ||
		    c > (s->rx_line_len == 1 ? '5' : '9'))
			return -1;
		s->rx_code = (uint16_t)((s->rx_code * 10) + (c - '0'));
		if (s->rx_line_len == 3)
			s->rx_state = SMR_SEP;
		return 0;

	case SMR_SEP:
		s->rx_text_len = 0;
		s->rx_kw_len = 0;
		s->rx_kw_end = 0;
		s->text[0] = '\0';
		switch (c) {
		case '-':
			s->rx_state = SMR_TEXT_MORE;
			return 0;
		case ' ':
			s->rx_state = SMR_TEXT_LAST;
			return 0;
		case '\r':
			s->rx_state = SMR_CR_LAST;
			return 0;
		case '\n':
			eol = last = 1;
			break;
		default:
			return -1;
		}
		break;

	case SMR_TEXT_MORE:
	case SMR_TEXT_LAST:
		if (c == '\r') {
			s->rx_state = s->rx_state == SMR_TEXT_MORE ?
						SMR_CR_MORE : SMR_CR_LAST;
			return 0;
		}
		if (c == '\n') {
			eol = 1;
			last = s->rx_state == SMR_TEXT_LAST;
			break;
		}

		/* the text is kept for logging: printable ASCII only */
		if (s->rx_text_len < sizeof(s->text) - 1) {
			s->text[s->rx_text_len++] =
				(c >= ' ' && c < 0x7f) ? c : '?';
			s->text[s->rx_text_len] = '\0';
		}

		/*
		 * the first word of the line, uppercased, which past the first
		 * line of an EHLO reply is an extension's keyword
		 */
		if (!s->rx_kw_end) {
			if (c == ' ' || s->rx_kw_len == sizeof(s->rx_kw) - 1) {
				if (c != ' ')
					/* too long to be one we know */
					s->rx_kw_len = 0;
				s->rx_kw_end = 1;
			} else
				s->rx_kw[s->rx_kw_len++] =
					(c >= 'a' && c <= 'z') ?
						(char)(c - 'a' + 'A') : c;
		}
		return 0;

	case SMR_CR_MORE:
	case SMR_CR_LAST:
		if (c != '\n')
			return -1;
		eol = 1;
		last = s->rx_state == SMR_CR_LAST;
		break;
	}

	if (!eol)
		return 0;

	/* every line of a reply has its code */

	if (!s->rx_first_code)
		s->rx_first_code = s->rx_code;
	else {
		if (s->rx_code != s->rx_first_code)
			return -1;
		if (s->state == SMS_EHLO_RX)
			smtp_ehlo_keyword(s);
	}

	s->rx_line_len	= 0;
	s->rx_code	= 0;
	s->rx_state	= SMR_CODE;

	if (!last)
		return 0;

	s->code		= s->rx_first_code;
	s->rx_first_code = 0;

	return 1;
}

lws_smtp_ev_t
lws_smtp_session_rx(lws_smtp_session_t *s, const uint8_t *buf, size_t len,
		    size_t *used)
{
	size_t n = 0;

	*used = 0;

	if (s->state == SMS_OVER)
		return LWS_SMTP_EV_FAILED;

	/*
	 * Replies only come to what we said: not while the transport is
	 * starting tls, above all, when they would be plaintext injected
	 * ahead of the tls
	 */
	if (len && s->state != SMS_GREETING_RX && s->state != SMS_EHLO_RX &&
	    s->state != SMS_HELO_RX && s->state != SMS_STARTTLS_RX &&
	    s->state != SMS_RSET_RX && s->state != SMS_MAIL_RX &&
	    s->state != SMS_RCPT_RX && s->state != SMS_DATA_RX &&
	    s->state != SMS_CONTENT_RX && s->state != SMS_QUIT_RX)
		return smtp_over(s, 0, "unexpected reply");

	while (n < len) {
		switch (smtp_rx_byte(s, (char)buf[n++])) {
		case 1:
			*used = n;

			return smtp_reply(s);
		case -1:
			*used = n;

			return smtp_over(s, 0, "malformed reply");
		default:
			break;
		}
	}

	*used = n;

	return LWS_SMTP_EV_NONE;
}

/* RFC 5322 3.3 date-time, in UTC */

static int
smtp_date(char *buf, size_t len, int64_t secs)
{
	int64_t days = secs / 86400, rem = secs % 86400, z, era, doe, yoe, doy,
		mp, d, m, y;
	char wd[4], mo[4];
	int w;

	if (rem < 0) {
		rem += 86400;
		days--;
	}

	/* civil from days, day 0 being 1970-01-01, a Thursday */

	z	= days + 719468;
	era	= (z >= 0 ? z : z - 146096) / 146097;
	doe	= z - era * 146097;
	yoe	= (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	doy	= doe - (365 * yoe + yoe / 4 - yoe / 100);
	mp	= (5 * doy + 2) / 153;
	d	= doy - (153 * mp + 2) / 5 + 1;
	m	= mp < 10 ? mp + 3 : mp - 9;
	y	= yoe + era * 400 + (m <= 2);
	w	= (int)((days % 7 + 11) % 7); /* 0 is Sunday */

	memcpy(wd, smtp_wday + w * 3, 3);
	wd[3] = '\0';
	memcpy(mo, smtp_mon + (m - 1) * 3, 3);
	mo[3] = '\0';

	return lws_snprintf(buf, len, "Date: %s, %d %s %d %02d:%02d:%02d "
				      "+0000\r\n", wd, (int)d, mo, (int)y,
			    (int)(rem / 3600), (int)((rem / 60) % 60),
			    (int)(rem % 60));
}

/*
 * The message itself, from where it got to: the headers one line at a time,
 * then the body a byte at a time, with CRLF line ends and dot-stuffing.
 * Returns 1 if there is more, 0 once the terminating "." is out.
 */

static int
smtp_content_tx(lws_smtp_session_t *s, char *buf, size_t max, size_t *produced)
{
	const lws_smtp_email_t *e = s->mail;
	char *p = buf, *end = buf + max;
	size_t n;

	while (1) {
		switch (s->item) {
		case SMI_DATE:
			if (lws_ptr_diff_size_t(end, p) < SMTP_HDR_ROOM)
				goto more;
			if (e->date)
				p += smtp_date(p, lws_ptr_diff_size_t(end, p),
					       e->date);
			s->item = SMI_FROM;
			continue;

		case SMI_FROM:
		case SMI_TO:
			if (lws_ptr_diff_size_t(end, p) < SMTP_HDR_ROOM)
				goto more;
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "%s: %s\r\n",
					  s->item == SMI_FROM ? "From" : "To",
					  s->item == SMI_FROM ? e->from : e->to);
			s->item++;
			continue;

		case SMI_SUBJECT: {
			size_t len = strlen(e->subject);
			char b64[64];

			if (lws_ptr_diff_size_t(end, p) < SMTP_HDR_ROOM)
				goto more;

			for (n = 0; n < len; n++)
				if ((unsigned char)e->subject[n] >= 0x80)
					break;
			if (n == len && len <= SMTP_SUBJECT_PLAIN_MAX) {
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
						  "Subject: %s\r\n", e->subject);
				s->item = SMI_MSGID;
				continue;
			}

			/*
			 * RFC 2047 encoded-words, each on its own folded line
			 * and each whole characters: the whitespace between
			 * them is not part of the subject
			 */
			n = len - s->pos;
			if (n > SMTP_EW_BYTES) {
				n = SMTP_EW_BYTES;
				while (n &&
				       (e->subject[s->pos + n] & 0xc0) == 0x80)
					n--;
			}
			if (lws_b64_encode_string(e->subject + s->pos, (int)n,
						  b64, sizeof(b64)) < 0)
				return -1;
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "%s=?UTF-8?B?%s?=\r\n",
					  s->pos ? " " : "Subject: ", b64);
			s->pos += n;
			if (s->pos == len) {
				s->pos = 0;
				s->item = SMI_MSGID;
			}
			continue;
		}

		case SMI_MSGID:
			if (lws_ptr_diff_size_t(end, p) < SMTP_HDR_ROOM)
				goto more;
			if (e->message_id)
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
						  "Message-ID: <%s>\r\n",
						  e->message_id);
			s->item = SMI_MIME;
			continue;

		case SMI_MIME:
			if (lws_ptr_diff_size_t(end, p) < SMTP_HDR_ROOM)
				goto more;
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				"MIME-Version: 1.0\r\n"
				"Content-Type: text/plain; charset=UTF-8\r\n"
				"Content-Transfer-Encoding: %s\r\n\r\n",
				(s->flags & SMF_8BIT) ? "8bit" : "7bit");
			s->item = SMI_BODY;
			continue;

		case SMI_BODY:
			while (e->body[s->pos]) {
				char c = e->body[s->pos];

				/* the most one byte of body can become */
				if (lws_ptr_diff_size_t(end, p) < 2)
					goto more;

				s->pos++;
				if (c == '\r' || c == '\n') {
					/* CRLF, a lone LF or a lone CR */
					if (c == '\r' && e->body[s->pos] == '\n')
						s->pos++;
					*p++ = '\r';
					*p++ = '\n';
					s->flags |= SMF_BOL;
					continue;
				}
				if ((s->flags & SMF_BOL) && c == '.')
					*p++ = '.';
				*p++ = c;
				s->flags = (uint8_t)(s->flags & ~SMF_BOL);
			}
			s->item = SMI_DOT;
			continue;

		case SMI_DOT:
			/* the last line ends before the "." that ends it all */
			if (lws_ptr_diff_size_t(end, p) < 5)
				goto more;
			if (!(s->flags & SMF_BOL)) {
				*p++ = '\r';
				*p++ = '\n';
			}
			*p++ = '.';
			*p++ = '\r';
			*p++ = '\n';
			*produced = lws_ptr_diff_size_t(p, buf);
			s->state = SMS_CONTENT_RX;

			return 0;
		}
	}

more:
	*produced = lws_ptr_diff_size_t(p, buf);

	return 1;
}

int
lws_smtp_session_tx(lws_smtp_session_t *s, uint8_t *buf, size_t max,
		    size_t *produced)
{
	char *p = (char *)buf;
	int n = 0;

	*produced = 0;

	if (max < LWS_SMTP_TX_MIN)
		return -1;

	switch (s->state) {
	case SMS_EHLO_TX:
	case SMS_HELO_TX:
		n = lws_snprintf(p, max, "%s %s\r\n",
				 s->state == SMS_EHLO_TX ? "EHLO" : "HELO",
				 s->helo);
		s->state++;
		break;

	case SMS_STARTTLS_TX:
		n = lws_snprintf(p, max, "STARTTLS\r\n");
		s->state = SMS_STARTTLS_RX;
		break;

	case SMS_RSET_TX:
		n = lws_snprintf(p, max, "RSET\r\n");
		s->state = SMS_RSET_RX;
		break;

	case SMS_MAIL_TX:
		n = lws_snprintf(p, max, "MAIL FROM:<%s>%s\r\n", s->mail->from,
				 (s->flags & (SMF_8BIT | SMF_EXT_8BITMIME)) ==
					(SMF_8BIT | SMF_EXT_8BITMIME) ?
						" BODY=8BITMIME" : "");
		s->state = SMS_MAIL_RX;
		break;

	case SMS_RCPT_TX:
		n = lws_snprintf(p, max, "RCPT TO:<%s>\r\n", s->mail->to);
		s->state = SMS_RCPT_RX;
		break;

	case SMS_DATA_TX:
		n = lws_snprintf(p, max, "DATA\r\n");
		s->state = SMS_DATA_RX;
		break;

	case SMS_CONTENT_TX:
		return smtp_content_tx(s, p, max, produced);

	case SMS_QUIT_TX:
		n = lws_snprintf(p, max, "QUIT\r\n");
		s->state = SMS_QUIT_RX;
		break;

	default:
		/* nothing to send until the server says something */
		break;
	}

	*produced = (size_t)n;

	return 0;
}
