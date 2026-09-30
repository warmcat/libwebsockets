/*
 * lws-api-test-smtp-client
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests the SMTP client in two halves.
 *
 * First the sansIO session (lws-smtp.h) alone, with no transport: canned
 * server replies go in, and what it sends is compared with what it must
 * send, byte for byte, including replies fed a byte at a time.
 *
 * Then lws_smtpc (lws-smtp-client.h) end to end, against a fake relay run as
 * raw listeners in the same context: plaintext, implicit tls, and STARTTLS.
 * For STARTTLS the fake relay, once it has said 220, relays the connection's
 * bytes to a tls listener of its own, so the client's tls upgrade happens on
 * a real connection.  The relay refuses, defers and stays silent on cue, to
 * see each mail is reported the way it should be.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static int fails;

#define SMTPT_FAIL(...) do { lwsl_err(__VA_ARGS__); fails++; } while (0)

static const char * const ev_names[] = {
	"NONE", "TX", "STARTTLS", "READY", "MAIL_DONE", "CLOSE", "FAILED"
};

/* ---------------------------------------------------------------------
 * the mails
 */

/* 8-bit, every kind of line end and dot, a Date and a Message-ID */

static const lws_smtp_email_t m1 = {
	.from		= "sender@example.com",
	.to		= "rcpt@example.net",
	.subject	= "\xc3\x9c" "n" "\xc3\xaf" "c" "\xc3\xb6" "d" "\xc3\xa9"
			  " subject \xe2\x80\x94 test",
	.body		= "Hello na\xc3\xaf" "ve\n"
			  ".leading dot\r\n"
			  "..two dots\r"
			  "lone CR\n"
			  "\n"
			  "last line no newline",
	.message_id	= "m1@example.com",
	.date		= 1790000000,
};

static const char m1_content[] =
	"Date: Mon, 21 Sep 2026 14:13:20 +0000\r\n"
	"From: sender@example.com\r\n"
	"To: rcpt@example.net\r\n"
	"Subject: =?UTF-8?B?w5xuw69jw7Zkw6kgc3ViamVjdCDigJQgdGVzdA==?=\r\n"
	"Message-ID: <m1@example.com>\r\n"
	"MIME-Version: 1.0\r\n"
	"Content-Type: text/plain; charset=UTF-8\r\n"
	"Content-Transfer-Encoding: 8bit\r\n"
	"\r\n"
	"Hello na\xc3\xaf" "ve\r\n"
	"..leading dot\r\n"
	"...two dots\r\n"
	"lone CR\r\n"
	"\r\n"
	"last line no newline\r\n"
	".\r\n";

/* 7-bit, a long ASCII subject, no Date or Message-ID; its body is made */

#define M2_SUBJECT "This is a rather long plain ASCII subject line that " \
		   "goes past sixty-four characters"
#define M2_LINES 24

static char m2_body[2048], m2_content[4096];
static const char *m2_tail;	/* from MIME-Version: on */
#define M2_HEAD "From: other@example.org\r\n" \
		"To: rcpt@example.net\r\n" \
		"Subject: =?UTF-8?B?VGhpcyBpcyBhIHJhdGhlciBsb25nIHBsYWluIEFTQ0lJ" \
			"IHN1YmplY3Qg?=\r\n" \
		" =?UTF-8?B?bGluZSB0aGF0IGdvZXMgcGFzdCBzaXh0eS1mb3VyIGNoYXJhY3Rl" \
			"cnM=?=\r\n"
static lws_smtp_email_t m2 = {
	.from		= "other@example.org",
	.to		= "rcpt@example.net",
	.subject	= M2_SUBJECT,
	.body		= m2_body,
};

/* an encoded-word may not split a character: the 42nd byte is inside one */

static const lws_smtp_email_t m3 = {
	.from		= "third@example.com",
	.to		= "rcpt@example.net",
	.subject	= "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "\xc3\xa9" "b",
	.body		= "short\n",
};

static const char m3_subject[] =
	"Subject: =?UTF-8?B?YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
		"YWFhYWE=?=\r\n"
	" =?UTF-8?B?w6li?=\r\n";

static void
make_m2(void)
{
	char *b = m2_body, *c = m2_content;
	int n;

	c += lws_snprintf(c, sizeof(m2_content), M2_HEAD);
	m2_tail = c;
	c += lws_snprintf(c, sizeof(m2_content) -
				lws_ptr_diff_size_t(c, m2_content),
		"MIME-Version: 1.0\r\n"
		"Content-Type: text/plain; charset=UTF-8\r\n"
		"Content-Transfer-Encoding: 7bit\r\n\r\n");

	for (n = 0; n < M2_LINES; n++) {
		b += lws_snprintf(b, sizeof(m2_body) -
					lws_ptr_diff_size_t(b, m2_body),
				  "%sline %02d: the quick brown fox jumps\n",
				  n == 12 ? "." : "", n);
		c += lws_snprintf(c, sizeof(m2_content) -
					lws_ptr_diff_size_t(c, m2_content),
				  "%sline %02d: the quick brown fox jumps\r\n",
				  n == 12 ? ".." : "", n);
	}
	lws_snprintf(c, sizeof(m2_content) - lws_ptr_diff_size_t(c, m2_content),
		     ".\r\n");
}

/* ---------------------------------------------------------------------
 * part one: the sansIO session, with no transport
 */

/* the server says this: expect all of it taken, and that event at its end */

static int
t_rx(lws_smtp_session_t *s, const char *reply, lws_smtp_ev_t want, int bytewise)
{
	size_t len = strlen(reply), used, n = 0, chunk;
	lws_smtp_ev_t ev = LWS_SMTP_EV_NONE;

	while (n < len) {
		chunk = bytewise ? 1 : len - n;
		ev = lws_smtp_session_rx(s, (const uint8_t *)reply + n, chunk,
					 &used);
		n += used;
		if (ev == LWS_SMTP_EV_FAILED)
			/* the session stops taking bytes where it failed */
			break;
		if (n < len && ev != LWS_SMTP_EV_NONE) {
			SMTPT_FAIL("%s: %s before the end of '%s'\n", __func__,
				   ev_names[ev], reply);
			return 1;
		}
		if (!used)
			break;
	}

	if (ev != want) {
		SMTPT_FAIL("%s: '%s' gave %s, wanted %s (%d %s)\n", __func__,
			   reply, ev_names[ev], ev_names[want], s->code,
			   s->text);
		return 1;
	}

	return 0;
}

/* all the session sends next, taken in the smallest buffer it allows */

static int
t_tx_collect(lws_smtp_session_t *s, char *all, size_t max)
{
	uint8_t buf[LWS_SMTP_TX_MIN];
	size_t n, len = 0;
	int more;

	do {
		more = lws_smtp_session_tx(s, buf, sizeof(buf), &n);
		if (more < 0 || len + n >= max) {
			SMTPT_FAIL("%s: tx failed\n", __func__);
			return 1;
		}
		memcpy(all + len, buf, n);
		len += n;
	} while (more);

	all[len] = '\0';

	return 0;
}

static int
t_tx(lws_smtp_session_t *s, const char *want)
{
	static char all[8192];

	if (t_tx_collect(s, all, sizeof(all)))
		return 1;

	if (strcmp(all, want)) {
		SMTPT_FAIL("%s: sent\n'%s'\nwanted\n'%s'\n", __func__, all,
			   want);
		return 1;
	}

	return 0;
}

/* greeting and EHLO, offering 8BITMIME (and STARTTLS, which is not used) */

static int
t_ready(lws_smtp_session_t *s, int bytewise)
{
	lws_smtp_session_init(s, "client.example", 0);

	return t_tx(s, "") ||
	       t_rx(s, "220 mx.example ESMTP ready\r\n", LWS_SMTP_EV_TX,
		    bytewise) ||
	       t_tx(s, "EHLO client.example\r\n") ||
	       t_rx(s, "250-mx.example greets you\r\n"
		       "250-SIZE 10240000\r\n"
		       "250-8bitmime\r\n"
		       "250-STARTTLS\r\n"
		       "250 SMTPUTF8\r\n", LWS_SMTP_EV_READY, bytewise);
}

/* one mail accepted, what it sent compared */

static int
t_mail(lws_smtp_session_t *s, const lws_smtp_email_t *m, const char *mail_from,
       const char *content, int bytewise)
{
	char rcpt[300];

	lws_snprintf(rcpt, sizeof(rcpt), "RCPT TO:<%s>\r\n", m->to);

	if (lws_smtp_session_mail(s, m)) {
		SMTPT_FAIL("%s: session would not take the mail\n", __func__);
		return 1;
	}

	if (t_tx(s, mail_from) ||
	    t_rx(s, "250 2.1.0 Ok\r\n", LWS_SMTP_EV_TX, bytewise) ||
	    t_tx(s, rcpt) ||
	    t_rx(s, "250 2.1.5 Ok\r\n", LWS_SMTP_EV_TX, bytewise) ||
	    t_tx(s, "DATA\r\n") ||
	    t_rx(s, "354 End data with <CR><LF>.<CR><LF>\r\n", LWS_SMTP_EV_TX,
		 bytewise) ||
	    t_tx(s, content) ||
	    t_rx(s, "250 2.0.0 Ok: queued as ABC\r\n", LWS_SMTP_EV_MAIL_DONE,
		 bytewise))
		return 1;

	if (s->code != 250 || strcmp(s->text, "2.0.0 Ok: queued as ABC")) {
		SMTPT_FAIL("%s: concluded as %d '%s'\n", __func__, s->code,
			   s->text);
		return 1;
	}

	return 0;
}

static void
test_session_mails(int bytewise)
{
	lws_smtp_session_t s;

	lwsl_user("%s: bytewise %d\n", __func__, bytewise);

	if (t_ready(&s, bytewise))
		return;

	if (t_mail(&s, &m1, "MAIL FROM:<sender@example.com> BODY=8BITMIME\r\n",
		   m1_content, bytewise) ||
	    t_mail(&s, &m2, "MAIL FROM:<other@example.org>\r\n", m2_content,
		   bytewise))
		return;

	if (lws_smtp_session_mail(&s, NULL) || t_tx(&s, "QUIT\r\n") ||
	    t_rx(&s, "221 2.0.0 Bye\r\n", LWS_SMTP_EV_CLOSE, bytewise))
		return;

	/* the session is over */
	t_rx(&s, "250 more\r\n", LWS_SMTP_EV_FAILED, 0);
}

static void
test_session_subject_split(void)
{
	lws_smtp_session_t s;
	char all[2048];

	lwsl_user("%s\n", __func__);

	if (t_ready(&s, 0) || lws_smtp_session_mail(&s, &m3) ||
	    t_tx(&s, "MAIL FROM:<third@example.com>\r\n") ||
	    t_rx(&s, "250 ok\r\n", LWS_SMTP_EV_TX, 0) ||
	    t_tx(&s, "RCPT TO:<rcpt@example.net>\r\n") ||
	    t_rx(&s, "250 ok\r\n", LWS_SMTP_EV_TX, 0) ||
	    t_tx(&s, "DATA\r\n") ||
	    t_rx(&s, "354 go\r\n", LWS_SMTP_EV_TX, 0) ||
	    t_tx_collect(&s, all, sizeof(all)))
		return;

	if (!strstr(all, m3_subject))
		SMTPT_FAIL("%s: subject not split on a character: '%s'\n",
			   __func__, all);
}

static void
test_session_dates(void)
{
	static const struct {
		int64_t		t;
		const char	*date;
	} dates[] = {
		{ 951782400,	"Date: Tue, 29 Feb 2000 00:00:00 +0000\r\n" },
		{ 4102444799ll,	"Date: Thu, 31 Dec 2099 23:59:59 +0000\r\n" },
		{ -1,		"Date: Wed, 31 Dec 1969 23:59:59 +0000\r\n" },
	};
	lws_smtp_email_t m = m3;
	lws_smtp_session_t s;
	char all[2048];
	size_t n;

	lwsl_user("%s\n", __func__);

	for (n = 0; n < LWS_ARRAY_SIZE(dates); n++) {
		m.date = dates[n].t;
		if (t_ready(&s, 0) || lws_smtp_session_mail(&s, &m) ||
		    t_tx_collect(&s, all, sizeof(all)) ||
		    t_rx(&s, "250 ok\r\n", LWS_SMTP_EV_TX, 0) ||
		    t_tx_collect(&s, all, sizeof(all)) ||
		    t_rx(&s, "250 ok\r\n", LWS_SMTP_EV_TX, 0) ||
		    t_tx_collect(&s, all, sizeof(all)) ||
		    t_rx(&s, "354 go\r\n", LWS_SMTP_EV_TX, 0) ||
		    t_tx_collect(&s, all, sizeof(all)))
			return;

		if (strncmp(all, dates[n].date, strlen(dates[n].date)))
			SMTPT_FAIL("%s: %lld gave '%.40s'\n", __func__,
				   (long long)dates[n].t, all);
	}
}

static void
test_session_starttls(void)
{
	lws_smtp_session_t s;
	size_t used;

	lwsl_user("%s\n", __func__);

	lws_smtp_session_init(&s, "client.example", 1);
	if (t_rx(&s, "220 mx\r\n", LWS_SMTP_EV_TX, 0) ||
	    t_tx(&s, "EHLO client.example\r\n") ||
	    /* no mail before the tls: STARTTLS, not READY */
	    t_rx(&s, "250-mx\r\n250-8BITMIME\r\n250 STARTTLS\r\n",
		 LWS_SMTP_EV_TX, 1) ||
	    t_tx(&s, "STARTTLS\r\n") ||
	    t_rx(&s, "220 2.0.0 Ready to start TLS\r\n", LWS_SMTP_EV_STARTTLS, 0))
		return;

	/* nothing may arrive while the transport starts tls */
	t_tx(&s, "");

	lws_smtp_session_tls_up(&s);

	/* what was offered before the tls is forgotten, and asked again */
	if (t_tx(&s, "EHLO client.example\r\n") ||
	    t_rx(&s, "250-mx\r\n250 SIZE 100000\r\n", LWS_SMTP_EV_READY, 0) ||
	    lws_smtp_session_mail(&s, &m1) ||
	    t_tx(&s, "MAIL FROM:<sender@example.com>\r\n"))
		return;

	/* plaintext injected behind the 220 is refused */

	lws_smtp_session_init(&s, "client.example", 1);
	if (t_rx(&s, "220 mx\r\n", LWS_SMTP_EV_TX, 0) ||
	    t_tx(&s, "EHLO client.example\r\n") ||
	    t_rx(&s, "250-mx\r\n250 STARTTLS\r\n", LWS_SMTP_EV_TX, 0) ||
	    t_tx(&s, "STARTTLS\r\n"))
		return;
	if (lws_smtp_session_rx(&s, (const uint8_t *)"220 go\r\n250 x\r\n",
				strlen("220 go\r\n250 x\r\n"), &used) !=
					LWS_SMTP_EV_STARTTLS || used != 8)
		SMTPT_FAIL("%s: 220 not seen alone\n", __func__);
	if (lws_smtp_session_rx(&s, (const uint8_t *)"250 x\r\n", 7, &used) !=
							LWS_SMTP_EV_FAILED)
		SMTPT_FAIL("%s: plaintext after the 220 accepted\n", __func__);

	/* a server that does not offer it gets nothing */

	lws_smtp_session_init(&s, "client.example", 1);
	if (!t_rx(&s, "220 mx\r\n", LWS_SMTP_EV_TX, 0) &&
	    !t_tx(&s, "EHLO client.example\r\n") &&
	    !t_rx(&s, "250-mx\r\n250 8BITMIME\r\n", LWS_SMTP_EV_FAILED, 0) &&
	    strcmp(s.text, "STARTTLS not offered"))
		SMTPT_FAIL("%s: not offered said '%s'\n", __func__, s.text);

	/* nor one that refuses it */

	lws_smtp_session_init(&s, "client.example", 1);
	if (!t_rx(&s, "220 mx\r\n", LWS_SMTP_EV_TX, 0) &&
	    !t_tx(&s, "EHLO client.example\r\n") &&
	    !t_rx(&s, "250-mx\r\n250 STARTTLS\r\n", LWS_SMTP_EV_TX, 0) &&
	    !t_tx(&s, "STARTTLS\r\n") &&
	    !t_rx(&s, "454 4.7.0 TLS not available\r\n", LWS_SMTP_EV_FAILED,
		  0) && s.code != 454)
		SMTPT_FAIL("%s: refusal code %d\n", __func__, s.code);

	/* nor one that only knows HELO */

	lws_smtp_session_init(&s, "client.example", 1);
	if (!t_rx(&s, "220 mx\r\n", LWS_SMTP_EV_TX, 0) &&
	    !t_tx(&s, "EHLO client.example\r\n"))
		t_rx(&s, "502 5.5.2 what\r\n", LWS_SMTP_EV_FAILED, 0);
}

static void
test_session_helo(void)
{
	lws_smtp_session_t s;

	lwsl_user("%s\n", __func__);

	/* an unusable helo name is not sent */
	lws_smtp_session_init(&s, "bad\r\nRSET", 0);
	if (t_rx(&s, "220 mx\r\n", LWS_SMTP_EV_TX, 0) ||
	    t_tx(&s, "EHLO localhost\r\n") ||
	    t_rx(&s, "502 5.5.2 Error: command not recognized\r\n",
		 LWS_SMTP_EV_TX, 0) ||
	    t_tx(&s, "HELO localhost\r\n") ||
	    t_rx(&s, "250 mx\r\n", LWS_SMTP_EV_READY, 0) ||
	    lws_smtp_session_mail(&s, &m1))
		return;

	/* 8-bit, but not offered 8BITMIME */
	t_tx(&s, "MAIL FROM:<sender@example.com>\r\n");
}

static void
test_session_refusals(void)
{
	lws_smtp_session_t s;

	lwsl_user("%s\n", __func__);

	if (t_ready(&s, 0) || lws_smtp_session_mail(&s, &m1) ||
	    t_tx(&s, "MAIL FROM:<sender@example.com> BODY=8BITMIME\r\n") ||
	    t_rx(&s, "250 ok\r\n", LWS_SMTP_EV_TX, 0) ||
	    t_tx(&s, "RCPT TO:<rcpt@example.net>\r\n") ||
	    t_rx(&s, "550 5.1.1 no such user\r\n", LWS_SMTP_EV_MAIL_DONE, 0))
		return;
	if (s.code != 550)
		SMTPT_FAIL("%s: code %d\n", __func__, s.code);

	/* the failed transaction is reset before the next */
	if (lws_smtp_session_mail(&s, &m2) || t_tx(&s, "RSET\r\n") ||
	    t_rx(&s, "250 ok\r\n", LWS_SMTP_EV_TX, 0) ||
	    t_tx(&s, "MAIL FROM:<other@example.org>\r\n") ||
	    t_rx(&s, "451 4.7.1 greylisted\r\n", LWS_SMTP_EV_MAIL_DONE, 0))
		return;
	if (s.code != 451)
		SMTPT_FAIL("%s: code %d\n", __func__, s.code);

	/* ending the session needs no reset */
	if (lws_smtp_session_mail(&s, NULL) || t_tx(&s, "QUIT\r\n") ||
	    t_rx(&s, "221 bye\r\n", LWS_SMTP_EV_CLOSE, 0))
		return;

	/* a reply that is no kind of answer to MAIL fails the session */
	if (t_ready(&s, 0) || lws_smtp_session_mail(&s, &m2) ||
	    t_tx(&s, "MAIL FROM:<other@example.org>\r\n"))
		return;
	t_rx(&s, "354 what\r\n", LWS_SMTP_EV_FAILED, 0);

	/* the session cannot take a mail while it is not ready for one */
	lws_smtp_session_init(&s, "client.example", 0);
	if (!lws_smtp_session_mail(&s, &m1))
		SMTPT_FAIL("%s: mail taken before the greeting\n", __func__);

	/* nor one that could inject into what it sends, and is still ready */
	if (!t_ready(&s, 0)) {
		lws_smtp_email_t m = m2;

		m.to = "rcpt@example.net>\r\nRCPT TO:<x@y";
		if (!lws_smtp_session_mail(&s, &m))
			SMTPT_FAIL("%s: took an injected recipient\n",
				   __func__);
		if (!lws_smtp_session_mail(&s, &m2))
			t_tx(&s, "MAIL FROM:<other@example.org>\r\n");
		else
			SMTPT_FAIL("%s: not ready after refusing\n", __func__);
	}
}

static void
test_session_bad_replies(void)
{
	static const struct {
		const char	*greeting;
		lws_smtp_ev_t	ev;
		int		code;
	} g[] = {
		{ "220\r\n",			LWS_SMTP_EV_TX,		220 },
		{ "220 bare lf\n",		LWS_SMTP_EV_TX,		220 },
		{ "220-multi\r\n220 line\r\n",	LWS_SMTP_EV_TX,		220 },
		{ "554 go away\r\n",		LWS_SMTP_EV_FAILED,	554 },
		{ "421 closing\r\n",		LWS_SMTP_EV_FAILED,	421 },
		{ "2x0 hi\r\n",			LWS_SMTP_EV_FAILED,	0 },
		{ "620 hi\r\n",			LWS_SMTP_EV_FAILED,	0 },
		{ "220 hi\rX",			LWS_SMTP_EV_FAILED,	0 },
		{ "220_hi\r\n",			LWS_SMTP_EV_FAILED,	0 },
		{ "220-a\r\n221 b\r\n",		LWS_SMTP_EV_FAILED,	0 },
	};
	lws_smtp_session_t s;
	char big[1200];
	size_t n;

	lwsl_user("%s\n", __func__);

	for (n = 0; n < LWS_ARRAY_SIZE(g); n++) {
		lws_smtp_session_init(&s, "client.example", 0);
		if (!t_rx(&s, g[n].greeting, g[n].ev, 0) &&
		    s.code != g[n].code)
			SMTPT_FAIL("%s: '%s' code %d\n", __func__,
				   g[n].greeting, s.code);
	}

	/* a line too long to be SMTP */
	memset(big, 'x', sizeof(big) - 1);
	memcpy(big, "220 ", 4);
	big[sizeof(big) - 1] = '\0';
	lws_smtp_session_init(&s, "client.example", 0);
	t_rx(&s, big, LWS_SMTP_EV_FAILED, 0);

	/* a reply to nothing we said */
	lws_smtp_session_init(&s, "client.example", 0);
	if (!t_rx(&s, "220 mx\r\n", LWS_SMTP_EV_TX, 0))
		t_rx(&s, "250 unasked\r\n", LWS_SMTP_EV_FAILED, 0);

	/* 421 in the middle of a transaction */
	if (!t_ready(&s, 0) && !lws_smtp_session_mail(&s, &m2) &&
	    !t_tx(&s, "MAIL FROM:<other@example.org>\r\n"))
		t_rx(&s, "421 4.3.2 shutting down\r\n", LWS_SMTP_EV_FAILED, 0);
}

static void
test_checks(void)
{
	static const char * const good[] = {
		"a@b", "x@localhost", "first.last+tag@sub.example.co.uk",
		"o'brien!#$%&*/=?^_`{|}~-@example.com", "a@b-c.d9",
	};
	static const char * const bad[] = {
		"", "a", "@b", "a@", ".a@b", "a.@b", "a..b@c", "a@-b.com",
		"a@b-.com", "a@b..c", "a@.b", "a@b.", "a b@c", "a@b@c",
		"<a@b>", "a@b\r\nRCPT TO:<x@y>", "a\"b@c", "a@b_c",
		"\xc3\xa4@b", "a@[127.0.0.1]",
		/* 65 before the @ */
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"@b",
	};
	lws_smtp_email_t m;
	char body[1100];
	size_t n;

	lwsl_user("%s\n", __func__);

	for (n = 0; n < LWS_ARRAY_SIZE(good); n++)
		if (lws_smtp_addr_check(good[n]))
			SMTPT_FAIL("%s: refused '%s'\n", __func__, good[n]);
	for (n = 0; n < LWS_ARRAY_SIZE(bad); n++)
		if (!lws_smtp_addr_check(bad[n]))
			SMTPT_FAIL("%s: took '%s'\n", __func__, bad[n]);

	if (lws_smtp_email_check(&m1) || lws_smtp_email_check(&m2) ||
	    lws_smtp_email_check(&m3))
		SMTPT_FAIL("%s: refused a test mail\n", __func__);

	m = m1;
	m.subject = "two\r\nlines";
	if (!lws_smtp_email_check(&m))
		SMTPT_FAIL("%s: took a CRLF subject\n", __func__);
	m.subject = "tab\there";
	if (!lws_smtp_email_check(&m))
		SMTPT_FAIL("%s: took a control in the subject\n", __func__);
	m.subject = "cut \xc3";
	if (!lws_smtp_email_check(&m))
		SMTPT_FAIL("%s: took broken utf-8\n", __func__);

	m = m1;
	m.message_id = "no-at";
	if (!lws_smtp_email_check(&m))
		SMTPT_FAIL("%s: took message_id with no @\n", __func__);
	m.message_id = "a@b>\r\nBcc: x@y";
	if (!lws_smtp_email_check(&m))
		SMTPT_FAIL("%s: took an injected message_id\n", __func__);

	/* a body line may be 998 as sent, with its dot-stuffing */
	m = m1;
	m.body = body;
	memset(body, 'x', 998);
	body[998] = '\0';
	if (lws_smtp_email_check(&m))
		SMTPT_FAIL("%s: refused a 998 line\n", __func__);
	body[0] = '.';
	if (!lws_smtp_email_check(&m))
		SMTPT_FAIL("%s: took a 999 line once stuffed\n", __func__);
	body[997] = '\n';
	if (lws_smtp_email_check(&m))
		SMTPT_FAIL("%s: refused a 998 stuffed line\n", __func__);

	m = m1;
	m.to = NULL;
	if (!lws_smtp_email_check(&m))
		SMTPT_FAIL("%s: took no recipient\n", __func__);
}

/* ---------------------------------------------------------------------
 * part two: lws_smtpc end to end, against a fake relay
 */

enum {
	MTA_PLAIN,		/* greets; STARTTLS if srv.offer_starttls */
	MTA_TLS,		/* implicit tls, greets */
	MTA_TLS_BACKEND,	/* tls, what a STARTTLS continues to: no greeting */
	MTA_SILENT,		/* accepts and says nothing */
	MTA_RELAY_LEG,		/* our client leg to MTA_TLS_BACKEND */
};

struct mta_msg {
	char		from[64];
	char		to[64];
	char		content[4096];
	int		kind;
};

static struct {
	struct mta_msg	msg[8];
	int		nmsg;
	int		connections;
	int		rsets;
	int		relayed;
	int		plaintext_mail;	/* MAIL on a plain listener offering
					 * STARTTLS */
	int		greylist_left;
	int		offer_starttls;
} srv;

struct pss_mta {
	struct lws_buflist	*tx;
	struct lws		*peer;	/* the other leg of a relay */
	char			line[1100];
	size_t			ll;
	char			from[64];
	char			to[64];
	char			content[4096];
	size_t			cl;
	int			kind;
	uint8_t			data;
	uint8_t			relay;
	uint8_t			quit;
};

static int kinds[] = { MTA_PLAIN, MTA_TLS, MTA_TLS_BACKEND, MTA_SILENT };
static int port_plain = 7700, port_tls = 7701, port_tlsb = 7702,
	   port_silent = 7703;
static struct lws_context *context;
static struct lws_vhost *vh_cli;

static void
mta_say(struct lws *wsi, struct pss_mta *pss, const char *s)
{
	if (lws_buflist_append_segment(&pss->tx, (const uint8_t *)s,
				       strlen(s)) < 0)
		lwsl_err("%s: OOM\n", __func__);
	lws_callback_on_writable(wsi);
}

/* after STARTTLS, the connection's bytes go to our tls listener, and back */

static int
mta_relay_start(struct lws *wsi, struct pss_mta *pss)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= lws_get_vhost(wsi);
	i.address		= "127.0.0.1";
	i.host			= i.address;
	i.origin		= i.address;
	i.port			= port_tlsb;
	i.method		= "RAW";
	i.local_protocol_name	= "fake-mta";
	i.opaque_user_data	= wsi;

	pss->relay = 1;
	pss->peer = lws_client_connect_via_info(&i);

	return !pss->peer;
}

static void
mta_relay(struct pss_mta *pss, const uint8_t *buf, size_t len)
{
	struct pss_mta *ppss;

	if (!pss->peer || !len)
		return;

	ppss = (struct pss_mta *)lws_wsi_user(pss->peer);
	if (lws_buflist_append_segment(&ppss->tx, buf, len) < 0)
		lwsl_err("%s: OOM\n", __func__);
	lws_callback_on_writable(pss->peer);
}

static void
mta_line(struct lws *wsi, struct pss_mta *pss)
{
	char r[256];

	if (pss->data) {
		if (pss->cl + pss->ll + 3 < sizeof(pss->content)) {
			memcpy(pss->content + pss->cl, pss->line, pss->ll);
			pss->cl += pss->ll;
			memcpy(pss->content + pss->cl, "\r\n", 3);
			pss->cl += 2;
		}
		if (strcmp(pss->line, "."))
			return;

		pss->data = 0;
		if (srv.nmsg < (int)LWS_ARRAY_SIZE(srv.msg)) {
			struct mta_msg *m = &srv.msg[srv.nmsg++];

			lws_strncpy(m->from, pss->from, sizeof(m->from));
			lws_strncpy(m->to, pss->to, sizeof(m->to));
			lws_strncpy(m->content, pss->content,
				    sizeof(m->content));
			m->kind = pss->kind;
		}
		mta_say(wsi, pss, "250 2.0.0 Ok: queued\r\n");

		return;
	}

	if (!strncmp(pss->line, "EHLO ", 5)) {
		lws_snprintf(r, sizeof(r), "250-fake.example\r\n"
			     "250-8BITMIME\r\n%s250 SIZE 1000000\r\n",
			     pss->kind == MTA_PLAIN && srv.offer_starttls ?
					"250-STARTTLS\r\n" : "");
		mta_say(wsi, pss, r);
		return;
	}

	if (!strncmp(pss->line, "HELO ", 5)) {
		mta_say(wsi, pss, "250 fake.example\r\n");
		return;
	}

	if (!strcmp(pss->line, "STARTTLS") && pss->kind == MTA_PLAIN &&
	    srv.offer_starttls) {
		mta_say(wsi, pss, "220 2.0.0 go ahead\r\n");
		if (mta_relay_start(wsi, pss))
			lwsl_err("%s: relay leg failed\n", __func__);
		return;
	}

	if (!strncmp(pss->line, "MAIL FROM:<", 11)) {
		char *e = strchr(pss->line + 11, '>');

		if (e)
			*e = '\0';
		lws_strncpy(pss->from, pss->line + 11, sizeof(pss->from));
		if (pss->kind == MTA_PLAIN && srv.offer_starttls)
			srv.plaintext_mail++;

		if (!strncmp(pss->from, "greylist@", 9) && srv.greylist_left) {
			srv.greylist_left--;
			mta_say(wsi, pss, "451 4.7.1 greylisted\r\n");
			return;
		}
		if (!strncmp(pss->from, "always451@", 10)) {
			mta_say(wsi, pss, "451 4.3.0 try later\r\n");
			return;
		}
		mta_say(wsi, pss, "250 2.1.0 Ok\r\n");
		return;
	}

	if (!strncmp(pss->line, "RCPT TO:<", 9)) {
		char *e = strchr(pss->line + 9, '>');

		if (e)
			*e = '\0';
		lws_strncpy(pss->to, pss->line + 9, sizeof(pss->to));
		mta_say(wsi, pss, strncmp(pss->to, "reject@", 7) ?
				"250 2.1.5 Ok\r\n" :
				"550 5.1.1 no such user\r\n");
		return;
	}

	if (!strcmp(pss->line, "DATA")) {
		pss->data = 1;
		pss->cl = 0;
		mta_say(wsi, pss, "354 End data with <CR><LF>.<CR><LF>\r\n");
		return;
	}

	if (!strcmp(pss->line, "RSET")) {
		srv.rsets++;
		mta_say(wsi, pss, "250 2.0.0 Ok\r\n");
		return;
	}

	if (!strcmp(pss->line, "QUIT")) {
		pss->quit = 1;
		mta_say(wsi, pss, "221 2.0.0 Bye\r\n");
		return;
	}

	mta_say(wsi, pss, "502 5.5.2 not recognized\r\n");
}

static int
callback_mta(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct pss_mta *pss = (struct pss_mta *)user;
	const uint8_t *p = (const uint8_t *)in;
	uint8_t *seg, buf[LWS_PRE + 2048];
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		pss->kind = *(int *)lws_vhost_user(lws_get_vhost(wsi));
		srv.connections++;
		if (pss->kind == MTA_PLAIN || pss->kind == MTA_TLS)
			mta_say(wsi, pss, "220 fake.example ESMTP\r\n");
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		/* our relay leg to the tls backend is up */
		pss->kind = MTA_RELAY_LEG;
		pss->peer = (struct lws *)lws_get_opaque_user_data(wsi);
		srv.relayed++;
		if (lws_buflist_next_segment_len(&pss->tx, NULL))
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (pss->kind == MTA_SILENT)
			break;
		if (pss->relay || pss->kind == MTA_RELAY_LEG) {
			mta_relay(pss, p, len);
			break;
		}
		for (n = 0; n < len; n++) {
			if (p[n] != '\n') {
				if (pss->ll < sizeof(pss->line) - 1)
					pss->line[pss->ll++] = (char)p[n];
				continue;
			}
			if (pss->ll && pss->line[pss->ll - 1] == '\r')
				pss->ll--;
			pss->line[pss->ll] = '\0';
			mta_line(wsi, pss);
			pss->ll = 0;
			if (pss->relay) {
				/* anything after STARTTLS goes to the tls */
				mta_relay(pss, p + n + 1, len - n - 1);
				break;
			}
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		n = lws_buflist_next_segment_len(&pss->tx, &seg);
		if (!n)
			return pss->quit ? -1 : 0;
		if (n > sizeof(buf) - LWS_PRE)
			n = sizeof(buf) - LWS_PRE;
		memcpy(buf + LWS_PRE, seg, n);
		if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) < (int)n)
			return -1;
		lws_buflist_use_segment(&pss->tx, n);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: relay leg failed: %s\n", __func__,
			 in ? (const char *)in : "");
		/* fallthru */
	case LWS_CALLBACK_RAW_CLOSE:
		if (pss) {
			if (pss->peer) {
				struct pss_mta *ppss = (struct pss_mta *)
						lws_wsi_user(pss->peer);

				if (ppss)
					ppss->peer = NULL;
				lws_set_timeout(pss->peer,
					PENDING_TIMEOUT_KILLED_BY_PARENT,
					LWS_TO_KILL_ASYNC);
				pss->peer = NULL;
			}
			lws_buflist_destroy_all_segments(&pss->tx);
		}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "fake-mta", callback_mta, sizeof(struct pss_mta), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* the cases */

struct outcome {
	char			to[64];
	lws_smtpc_outcome_t	outcome;
	int			code;
	char			text[96];
};

static struct {
	struct outcome		o[8];
	int			n;
} got;

static const uint32_t fast_backoff_ms[] = { 50, 100, 150 };
static const lws_retry_bo_t fast_retry = {
	.retry_ms_table		= fast_backoff_ms,
	.retry_ms_table_count	= LWS_ARRAY_SIZE(fast_backoff_ms),
	.conceal_count		= LWS_RETRY_CONCEAL_ALWAYS,
};

static struct lws_smtpc *smtpc;
static struct lws_vhost *vh_case;
static lws_sorted_usec_list_t sul_next, sul_watchdog, sul_step;
static int cur = -1, case_done, destroy_in_cb, only_case = -1;

struct smtpt_case {
	const char	*name;
	int		(*start)(void);
	int		expect;		/* outcomes to wait for */
	int		(*check)(void);	/* 0 for pass */
};

static void next_case(lws_sorted_usec_list_t *sul);

static const struct smtpt_case *cases_cur(void);

static void
case_finish(int pass, const char *why)
{
	if (case_done)
		return;
	case_done = 1;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_step);

	lwsl_user("--- case %d: %s: %s%s%s ---\n", cur, cases_cur()->name,
		  pass ? "PASS" : "FAIL", why ? ": " : "", why ? why : "");
	if (!pass)
		fails++;

	lws_smtpc_destroy(&smtpc);

	lws_sul_schedule(context, 0, &sul_next, next_case,
			 50 * LWS_US_PER_MS);
}

static void
case_evaluate(void)
{
	if (got.n < cases_cur()->expect || case_done)
		return;

	case_finish(!cases_cur()->check(), NULL);
}

static void
done_cb(void *opaque, const lws_smtp_email_t *email,
	const lws_smtpc_result_t *res)
{
	struct outcome *o;

	(void)opaque;

	lwsl_user("%s: mail %d to %s: outcome %d, %d %s\n", __func__, got.n,
		  email->to, (int)res->outcome, res->code, res->text);

	if (got.n == (int)LWS_ARRAY_SIZE(got.o))
		return;

	o = &got.o[got.n++];
	lws_strncpy(o->to, email->to, sizeof(o->to));
	o->outcome = res->outcome;
	o->code = res->code;
	lws_strncpy(o->text, res->text, sizeof(o->text));

	if (destroy_in_cb) {
		/* the client is being used by the connection calling us */
		destroy_in_cb = 0;
		lws_smtpc_destroy(&smtpc);
	}

	case_evaluate();
}

static int
make_smtpc(struct lws_vhost *vh, int port, lws_smtpc_tls_t tls, int tries,
	   int timeout, int max_queue)
{
	lws_smtpc_info_t info;

	memset(&info, 0, sizeof(info));
	info.vhost		= vh;
	info.address		= "127.0.0.1";
	info.host		= "localhost";
	info.port		= (uint16_t)port;
	info.tls		= tls;
	info.helo		= "client.example";
	info.retry		= &fast_retry;
	info.max_tries		= (uint8_t)tries;
	info.reply_timeout_secs	= (uint16_t)timeout;
	info.max_queue		= (uint16_t)max_queue;

	smtpc = lws_smtpc_create(&info);

	return !smtpc;
}

static int
queue(const lws_smtp_email_t *m)
{
	return lws_smtpc_queue(smtpc, m, done_cb, NULL);
}

static int
queue_from_to(const char *from, const char *to)
{
	lws_smtp_email_t m = m2;

	m.from = from;
	m.to = to;

	return queue(&m);
}

static int
expect_outcome(int n, lws_smtpc_outcome_t o, int code)
{
	if (got.o[n].outcome == o && got.o[n].code == code)
		return 0;

	lwsl_err("outcome %d: %d %d '%s', wanted %d %d\n", n,
		 (int)got.o[n].outcome, got.o[n].code, got.o[n].text, (int)o,
		 code);

	return 1;
}

/* 1: several mails on one plaintext connection, exactly as they should be */

static int
start_plain(void)
{
	return make_smtpc(vh_cli, port_plain, LWS_SMTPC_TLS_NONE, 0, 0, 0) ||
	       queue(&m1) || queue(&m2) || queue(&m3);
}

static int
check_plain(void)
{
	if (expect_outcome(0, LWS_SMTPC_DELIVERED, 250) ||
	    expect_outcome(1, LWS_SMTPC_DELIVERED, 250) ||
	    expect_outcome(2, LWS_SMTPC_DELIVERED, 250) ||
	    srv.connections != 1 || srv.nmsg != 3) {
		lwsl_err("%d connections, %d messages\n", srv.connections,
			 srv.nmsg);
		return 1;
	}

	if (strcmp(srv.msg[0].content, m1_content)) {
		lwsl_err("m1 arrived as\n'%s'\n", srv.msg[0].content);
		return 1;
	}

	/* m2 was given a Date and a Message-ID at the sender's domain */
	if (strncmp(srv.msg[1].content, "Date: ", 6) ||
	    !strstr(srv.msg[1].content, M2_HEAD "Message-ID: <") ||
	    !strstr(srv.msg[1].content, "@example.org>\r\n") ||
	    !strstr(srv.msg[1].content, m2_tail)) {
		lwsl_err("m2 arrived as\n'%s'\n", srv.msg[1].content);
		return 1;
	}

	return 0;
}

/* 2: a refused mail does not hold up the one after it */

static int
start_refused(void)
{
	return make_smtpc(vh_cli, port_plain, LWS_SMTPC_TLS_NONE, 0, 0, 0) ||
	       queue_from_to("other@example.org", "reject@example.net") ||
	       queue(&m1);
}

static int
check_refused(void)
{
	return expect_outcome(0, LWS_SMTPC_REFUSED, 550) ||
	       expect_outcome(1, LWS_SMTPC_DELIVERED, 250) ||
	       srv.rsets != 1 || srv.connections != 1;
}

/* 3: deferred once, delivered on the next connection */

static int
start_greylist(void)
{
	srv.greylist_left = 1;

	return make_smtpc(vh_cli, port_plain, LWS_SMTPC_TLS_NONE, 0, 0, 0) ||
	       queue_from_to("greylist@example.org", "rcpt@example.net");
}

static int
check_greylist(void)
{
	return expect_outcome(0, LWS_SMTPC_DELIVERED, 250) ||
	       srv.connections != 2;
}

/* 4: deferred every time, given up after max_tries */

static int
start_always451(void)
{
	return make_smtpc(vh_cli, port_plain, LWS_SMTPC_TLS_NONE, 2, 0, 0) ||
	       queue_from_to("always451@example.org", "rcpt@example.net");
}

static int
check_always451(void)
{
	return expect_outcome(0, LWS_SMTPC_GAVE_UP, 451) ||
	       srv.connections != 2;
}

/* 5: a relay that never answers is timed out */

static int
start_silent(void)
{
	return make_smtpc(vh_cli, port_silent, LWS_SMTPC_TLS_NONE, 1, 1, 0) ||
	       queue(&m1);
}

static int
check_silent(void)
{
	return expect_outcome(0, LWS_SMTPC_GAVE_UP, 0) ||
	       strcmp(got.o[0].text, "connection lost");
}

/* 6: destroying the client abandons what it still has queued */

static void
step_destroy(lws_sorted_usec_list_t *sul)
{
	if (srv.connections != 1)
		lwsl_err("%s: not connected\n", __func__);

	lws_smtpc_destroy(&smtpc);
	/* the callbacks came inside the destroy */
	if (got.n != 2 || smtpc)
		case_finish(0, "not abandoned at destroy");
}

static int
start_abandon(void)
{
	if (make_smtpc(vh_cli, port_silent, LWS_SMTPC_TLS_NONE, 0, 0, 0) ||
	    queue(&m1) || queue(&m2))
		return 1;

	lws_sul_schedule(context, 0, &sul_step, step_destroy,
			 300 * LWS_US_PER_MS);

	return 0;
}

static int
check_abandon(void)
{
	return expect_outcome(0, LWS_SMTPC_ABANDONED, 0) ||
	       expect_outcome(1, LWS_SMTPC_ABANDONED, 0);
}

/* 7: a mail's callback destroying the client */

static int
start_destroy_in_cb(void)
{
	destroy_in_cb = 1;

	return make_smtpc(vh_cli, port_plain, LWS_SMTPC_TLS_NONE, 0, 0, 0) ||
	       queue(&m1) || queue(&m3);
}

static int
check_destroy_in_cb(void)
{
	return expect_outcome(0, LWS_SMTPC_DELIVERED, 250) ||
	       expect_outcome(1, LWS_SMTPC_ABANDONED, 0) || !!smtpc;
}

/* 8: what the queue refuses, it never calls back about */

static int
start_refuse_queue(void)
{
	lws_smtp_email_t m = m1;

	if (make_smtpc(vh_cli, port_plain, LWS_SMTPC_TLS_NONE, 0, 0, 1))
		return 1;

	m.to = "bad address@example.net";
	if (!queue(&m)) {
		lwsl_err("%s: took a bad mail\n", __func__);
		return 1;
	}
	if (queue(&m1))
		return 1;
	if (!queue(&m3)) {
		lwsl_err("%s: took a mail past max_queue\n", __func__);
		return 1;
	}

	return 0;
}

static int
check_refuse_queue(void)
{
	return expect_outcome(0, LWS_SMTPC_DELIVERED, 250) || got.n != 1;
}

#if defined(LWS_WITH_TLS)

/* 9: implicit tls */

static int
start_implicit(void)
{
	return make_smtpc(vh_cli, port_tls, LWS_SMTPC_TLS_IMPLICIT, 0, 0, 0) ||
	       queue(&m1);
}

static int
check_implicit(void)
{
	return expect_outcome(0, LWS_SMTPC_DELIVERED, 250) ||
	       srv.nmsg != 1 || srv.msg[0].kind != MTA_TLS ||
	       strcmp(srv.msg[0].content, m1_content);
}

/* 10: STARTTLS, the rest of the session over the tls */

static int
start_starttls(void)
{
	srv.offer_starttls = 1;

	return make_smtpc(vh_cli, port_plain, LWS_SMTPC_TLS_STARTTLS, 0, 0,
			  0) || queue(&m1) || queue(&m2);
}

static int
check_starttls(void)
{
	return expect_outcome(0, LWS_SMTPC_DELIVERED, 250) ||
	       expect_outcome(1, LWS_SMTPC_DELIVERED, 250) ||
	       srv.relayed != 1 || srv.plaintext_mail || srv.nmsg != 2 ||
	       srv.msg[0].kind != MTA_TLS_BACKEND ||
	       strcmp(srv.msg[0].content, m1_content);
}

/* 11: STARTTLS required, and not offered: no mail in plaintext */

static int
start_starttls_missing(void)
{
	return make_smtpc(vh_cli, port_plain, LWS_SMTPC_TLS_STARTTLS, 1, 0,
			  0) || queue(&m1);
}

static int
check_starttls_missing(void)
{
	return expect_outcome(0, LWS_SMTPC_GAVE_UP, 0) ||
	       strcmp(got.o[0].text, "STARTTLS not offered") || srv.nmsg;
}

#else

/* without tls in the build, a client asking for it is refused */

static int
start_no_tls(void)
{
	if (!make_smtpc(vh_cli, port_plain, LWS_SMTPC_TLS_STARTTLS, 0, 0, 0) ||
	    !make_smtpc(vh_cli, port_tls, LWS_SMTPC_TLS_IMPLICIT, 0, 0, 0)) {
		lwsl_err("%s: made a tls client\n", __func__);
		return 1;
	}

	case_finish(1, NULL);

	return 0;
}

static int
check_no_tls(void)
{
	return 0;
}

#endif

/* 12: the vhost's own client, from its pvos */

static struct lws_protocol_vhost_options pvo_port = {
	NULL, NULL, "smtp-port", ""
}, pvo_helo = {
	&pvo_port, NULL, "smtp-helo", "own.example"
}, pvo_host = {
	&pvo_helo, NULL, "smtp-host", "127.0.0.1"
}, pvo_smtpc = {
	NULL, &pvo_host, LWS_SMTPC_PROTOCOL_NAME, ""
};
static char port_plain_str[8];

static int
start_own(void)
{
	struct lws_smtpc *own = lws_smtpc_vhost(vh_case), *again;

	again = lws_smtpc_vhost(vh_case);
	if (!own || own != again) {
		lwsl_err("%s: no vhost client, or two\n", __func__);
		return 1;
	}

	/* it is not ours to destroy */
	lws_smtpc_destroy(&again);
	if (lws_smtpc_vhost(vh_case) != own)
		return 1;

	return lws_smtpc_queue(own, &m1, done_cb, NULL);
}

static int
check_own(void)
{
	return expect_outcome(0, LWS_SMTPC_DELIVERED, 250) || srv.nmsg != 1;
}

/* 13: the vhost goes from under a client with mails queued */

static void
step_vhost_destroy(lws_sorted_usec_list_t *sul)
{
	lws_vhost_destroy(vh_case);
	vh_case = NULL;
}

static int
start_vhost_gone(void)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "doomed";
	info.protocols = protocols;
	vh_case = lws_create_vhost(context, &info);

	if (!vh_case ||
	    make_smtpc(vh_case, port_silent, LWS_SMTPC_TLS_NONE, 0, 0, 0) ||
	    queue(&m1) || queue(&m2))
		return 1;

	lws_sul_schedule(context, 0, &sul_step, step_vhost_destroy,
			 300 * LWS_US_PER_MS);

	return 0;
}

static int
check_vhost_gone(void)
{
	/* the client lives on, orphaned: it is still ours to destroy */
	if (!smtpc || lws_smtpc_queue(smtpc, &m1, done_cb, NULL) != -1)
		return 1;

	return expect_outcome(0, LWS_SMTPC_ABANDONED, 0) ||
	       expect_outcome(1, LWS_SMTPC_ABANDONED, 0);
}

static const struct smtpt_case cases[] = {
	{ "plaintext, three mails on one connection",
		start_plain, 3, check_plain },
	{ "a refused mail, then one delivered",
		start_refused, 2, check_refused },
	{ "deferred once, delivered next time",
		start_greylist, 1, check_greylist },
	{ "deferred every time, given up",
		start_always451, 1, check_always451 },
	{ "silent relay, reply timeout",
		start_silent, 1, check_silent },
	{ "destroyed with mails queued",
		start_abandon, 2, check_abandon },
	{ "destroyed from a mail's callback",
		start_destroy_in_cb, 2, check_destroy_in_cb },
	{ "queue refusals",
		start_refuse_queue, 1, check_refuse_queue },
#if defined(LWS_WITH_TLS)
	{ "implicit tls",
		start_implicit, 1, check_implicit },
	{ "STARTTLS, then the session over tls",
		start_starttls, 2, check_starttls },
	{ "STARTTLS required but not offered",
		start_starttls_missing, 1, check_starttls_missing },
#else
	{ "tls refused without tls in the build",
		start_no_tls, 0, check_no_tls },
#endif
	{ "the vhost's own client from pvos",
		start_own, 1, check_own },
	{ "vhost destroyed under a client",
		start_vhost_gone, 2, check_vhost_gone },
};

static const struct smtpt_case *
cases_cur(void)
{
	return &cases[cur];
}

static void
watchdog(lws_sorted_usec_list_t *sul)
{
	case_finish(0, "timed out");
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_context_creation_info info;

	if (cur >= 0 && cases[cur].start == start_own && vh_case) {
		lws_vhost_destroy(vh_case);
		vh_case = NULL;
	}

	if (only_case >= 0 && cur < only_case)
		cur = only_case - 1;
	if (++cur == (int)LWS_ARRAY_SIZE(cases) ||
	    (only_case >= 0 && cur > only_case)) {
		cur = (int)LWS_ARRAY_SIZE(cases);
		lws_default_loop_exit(context);
		return;
	}

	memset(&srv, 0, sizeof(srv));
	memset(&got, 0, sizeof(got));
	case_done = 0;
	destroy_in_cb = 0;

	lwsl_user("--- case %d: %s ---\n", cur, cases[cur].name);

	if (cases[cur].start == start_own) {
		memset(&info, 0, sizeof(info));
		info.port = CONTEXT_PORT_NO_LISTEN;
		info.vhost_name = "own";
		info.protocols = protocols;
		info.pvo = &pvo_smtpc;
		vh_case = lws_create_vhost(context, &info);
		if (!vh_case) {
			case_finish(0, "no vhost");
			return;
		}
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog,
			 20 * LWS_US_PER_SEC);

	if (cases[cur].start())
		case_finish(0, "start failed");
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

#if defined(LWS_WITH_TLS)
/* the fake relay's self-signed certificate, for localhost, as its own CA */

static const char * const test_cert =
"-----BEGIN CERTIFICATE-----\n"
"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\n"
"e2Hl/7M0c/lbZ4FvXgARlex2rkgS0Ka06HE=\n"
"-----END CERTIFICATE-----\n";

static const char * const test_key =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"fBrpEY1IATtPq1taBZZogRqI3rOkkPk=\n"
"-----END PRIVATE KEY-----\n";
#endif

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	size_t n;

	signal(SIGINT, sigint_handler);
	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_plain = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--tls-port")))
		port_tls = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--tlsb-port")))
		port_tlsb = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--silent-port")))
		port_silent = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--case")))
		only_case = atoi(p);

	lwsl_user("LWS API selftest: SMTP client\n");

	make_m2();

	/* part one: the sansIO session */

	test_checks();
	test_session_mails(0);
	test_session_mails(1);
	test_session_subject_split();
	test_session_dates();
	test_session_starttls();
	test_session_helo();
	test_session_refusals();
	test_session_bad_replies();

	lwsl_user("sansIO session: %d failures\n", fails);

	/* part two: lws_smtpc against the fake relay */

	lws_snprintf(port_plain_str, sizeof(port_plain_str), "%d", port_plain);
	pvo_port.value = port_plain_str;

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.fd_limit_per_thread = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the fake relay's listeners */

	info.protocols = protocols;
	info.options |= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "fake-mta";

	for (n = 0; n < LWS_ARRAY_SIZE(kinds); n++) {
		static const char * const names[] = {
			"mta-plain", "mta-tls", "mta-tls-backend", "mta-silent"
		};
#if !defined(LWS_WITH_TLS)
		if (kinds[n] == MTA_TLS || kinds[n] == MTA_TLS_BACKEND)
			continue;
#else
		if (kinds[n] == MTA_TLS || kinds[n] == MTA_TLS_BACKEND) {
			info.server_ssl_cert_mem = test_cert;
			info.server_ssl_cert_mem_len =
					(unsigned int)strlen(test_cert);
			info.server_ssl_private_key_mem = test_key;
			info.server_ssl_private_key_mem_len =
					(unsigned int)strlen(test_key);
			/*
			 * not the default alpn, which offers h3 and would
			 * bring a quic listener into the fake relay's protocol
			 */
			info.alpn = "smtp";
		} else {
			info.alpn = NULL;
			info.server_ssl_cert_mem = NULL;
			info.server_ssl_cert_mem_len = 0;
			info.server_ssl_private_key_mem = NULL;
			info.server_ssl_private_key_mem_len = 0;
		}
#endif
		info.vhost_name = names[n];
		info.port = kinds[n] == MTA_PLAIN ? port_plain :
			    kinds[n] == MTA_TLS ? port_tls :
			    kinds[n] == MTA_TLS_BACKEND ? port_tlsb :
						       port_silent;
		info.user = &kinds[n];

		if (!lws_create_vhost(context, &info)) {
			lwsl_err("failed to create %s\n", names[n]);
			goto bail;
		}
	}

	/* the client vhost: it trusts the fake relay's certificate */

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#if defined(LWS_WITH_TLS)
	info.client_ssl_ca_mem = test_cert;
	info.client_ssl_ca_mem_len = (unsigned int)strlen(test_cert);
	/*
	 * mbedtls offers the vhost's alpn on a raw client connection, the
	 * default "h2,http/1.1" when it has none, and its server refuses a
	 * client whose list has nothing in common with its own
	 */
	info.alpn = "smtp";
#endif
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	lws_context_default_loop_run_destroy(context);
	context = NULL;

bail:
	if (context)
		lws_context_destroy(context);
	/* orphaned by the context going, if the run was cut short */
	lws_smtpc_destroy(&smtpc);

	if (cur != (int)LWS_ARRAY_SIZE(cases))
		fails++;

	lwsl_user("Completed: %s (%d failures)\n", fails ? "FAIL" : "PASS",
		  fails);

	return fails != 0;
}
