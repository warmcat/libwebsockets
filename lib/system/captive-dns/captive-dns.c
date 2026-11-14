 /*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
 * A captive portal's dns: every name is us.  Whoever joins a network we serve,
 * eg, our own wifi AP, and is given us as their dns server, finds that every
 * name they look up is our address, so whatever url their OS or browser checks
 * the network with comes to our http server, which shows them our page.
 *
 * All of each datagram is untrusted: it's from whoever joined.
 */

#include "private-lib-core.h"

#define LWS_CDNS_PORT_DEFAULT	53
#define LWS_CDNS_HDR_LEN	12
/* the name, its labels and their lengths, and the root's 0 (RFC 1035 2.3.4) */
#define LWS_CDNS_NAME_MAX	255
/* an answer: the name, as a pointer to the question's, type, class, ttl, len */
#define LWS_CDNS_RR_FIXED	(2 + 2 + 2 + 4 + 2)

#define LWS_CDNS_QR		0x8000
#define LWS_CDNS_OPCODE_SHIFT	11
#define LWS_CDNS_OPCODE_MASK	0xf
#define LWS_CDNS_AA		0x0400
#define LWS_CDNS_RD		0x0100
#define LWS_CDNS_RCODE_NOTIMP	4

#define LWS_CDNS_TYPE_A		1
#define LWS_CDNS_TYPE_AAAA	28
#define LWS_CDNS_TYPE_ANY	255
#define LWS_CDNS_CLASS_IN	1
#define LWS_CDNS_CLASS_ANY	255

size_t
lws_captive_dns_answer(const uint8_t *q, size_t ql, const lws_sockaddr46 *ans,
		       uint8_t *r, size_t rl)
{
	uint16_t flags, qtype, qclass, rtype, opcode;
	size_t pos = LWS_CDNS_HDR_LEN, nl = 0, qend, alen, need;
	const uint8_t *rdata;
	uint8_t l;
	int an;

	if (!q || !ans || !r || ql < LWS_CDNS_HDR_LEN ||
	    rl < LWS_CDNS_HDR_LEN)
		return 0;

	flags = lws_ser_ru16be(q + 2);

	/* never answer an answer: two of us would answer each other forever */
	if (flags & LWS_CDNS_QR)
		return 0;

	opcode = (uint16_t)((flags >> LWS_CDNS_OPCODE_SHIFT) &
			    LWS_CDNS_OPCODE_MASK);
	if (opcode) {
		/* only a QUERY means anything to us: just the header back */
		memcpy(r, q, 2);
		lws_ser_wu16be(r + 2, (uint16_t)(LWS_CDNS_QR |
				(opcode << LWS_CDNS_OPCODE_SHIFT) |
				(flags & LWS_CDNS_RD) | LWS_CDNS_RCODE_NOTIMP));
		memset(r + 4, 0, LWS_CDNS_HDR_LEN - 4);

		return LWS_CDNS_HDR_LEN;
	}

	/*
	 * One question, with no answers or authority.  Anything additional,
	 * eg, an EDNS OPT record, is after the question and ignored: we don't
	 * do EDNS, and our answer is small.
	 */
	if (lws_ser_ru16be(q + 4) != 1 || lws_ser_ru16be(q + 6) ||
	    lws_ser_ru16be(q + 8))
		return 0;

	/*
	 * The question's name, as length-prefixed labels up to the root's 0.
	 * A label is at most 63, which is what's left when the top two bits,
	 * which would make it a pointer or something else, are clear.  The
	 * question is the first name in the datagram, there's nothing earlier
	 * for it to point to.
	 */

	do {
		if (pos >= ql)
			return 0;

		l = q[pos];
		if (l & 0xc0)
			return 0;

		nl += 1u + l;
		if (nl > LWS_CDNS_NAME_MAX)
			return 0;

		pos += 1u + l;
	} while (l);

	/* its type and class */
	if (pos + 4 > ql)
		return 0;

	qtype = lws_ser_ru16be(q + pos);
	qclass = lws_ser_ru16be(q + pos + 2);
	qend = pos + 4;

	if (ans->sa4.sin_family == AF_INET) {
		rtype = LWS_CDNS_TYPE_A;
		rdata = (const uint8_t *)&ans->sa4.sin_addr;
		alen = 4;
	} else
#if defined(LWS_WITH_IPV6)
	if (ans->sa4.sin_family == AF_INET6) {
		rtype = LWS_CDNS_TYPE_AAAA;
		rdata = (const uint8_t *)&ans->sa6.sin6_addr;
		alen = 16;
	} else
#endif
		return 0;

	/*
	 * The name exists whatever the type, so a type we have nothing for
	 * is answered with no records: the client goes on to the type we have
	 * at once, rather than retrying
	 */
	an = (qclass == LWS_CDNS_CLASS_IN || qclass == LWS_CDNS_CLASS_ANY) &&
	     (qtype == rtype || qtype == LWS_CDNS_TYPE_ANY);

	need = qend + (an ? LWS_CDNS_RR_FIXED + alen : 0);
	if (need > rl)
		return 0;

	/* the header and question, as they came */
	memcpy(r, q, qend);

	lws_ser_wu16be(r + 2, (uint16_t)(LWS_CDNS_QR | LWS_CDNS_AA |
					 (flags & LWS_CDNS_RD)));
	lws_ser_wu16be(r + 6, (uint16_t)an);	/* answers */
	lws_ser_wu16be(r + 8, 0);		/* authority */
	lws_ser_wu16be(r + 10, 0);		/* additional */

	if (!an)
		return need;

	r[qend] = 0xc0;			/* the name: a pointer to the question's */
	r[qend + 1] = LWS_CDNS_HDR_LEN;
	lws_ser_wu16be(r + qend + 2, rtype);
	lws_ser_wu16be(r + qend + 4, LWS_CDNS_CLASS_IN);
	lws_ser_wu32be(r + qend + 6, 0);	/* ttl: don't remember it */
	lws_ser_wu16be(r + qend + 10, (uint16_t)alen);
	memcpy(r + qend + LWS_CDNS_RR_FIXED, rdata, alen);

	return need;
}

static int
callback_captive_dns(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct lws_context *cx = lws_get_context(wsi);
	uint8_t buf[LWS_PRE + 512];
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (!in || wsi != cx->captive_dns_wsi)
			break;

		n = lws_captive_dns_answer((const uint8_t *)in, len,
					   &cx->captive_dns_ans,
					   buf + LWS_PRE,
					   sizeof(buf) - LWS_PRE);
		/*
		 * The answer goes to whoever asked, where recvfrom() left them
		 * in the wsi.  If an earlier answer couldn't go yet, that one
		 * is waiting with its own asker's address: drop this one rather
		 * than send it to them, the client asks again.
		 */
		if (!n || lws_has_buffered_out(wsi))
			break;

		if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) != (int)n)
			lwsl_wsi_info(wsi, "unable to answer");
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (wsi == cx->captive_dns_wsi)
			cx->captive_dns_wsi = NULL;
		break;

	default:
		break;
	}

	return 0;
}

const struct lws_protocols lws_system_protocol_captive_dns =
	{ "lws-captive-dns", callback_captive_dns, 0, 512, 0, NULL, 0 };

int
lws_captive_dns_start(struct lws_context *cx, const char *ads, int port)
{
	lws_sockaddr46 sa46;

	if (!cx || !ads || !cx->vhost_system || port < 0 || port > 65535)
		return 1;

	/* we answer with where we listen, so it must be an address */
	memset(&sa46, 0, sizeof(sa46));
	if (lws_sa46_parse_numeric_address(ads, &sa46))
		return 1;

	lws_captive_dns_stop(cx);

	cx->captive_dns_ans = sa46;
	cx->captive_dns_wsi = lws_create_adopt_udp(cx->vhost_system, ads,
				port ? port : LWS_CDNS_PORT_DEFAULT,
				LWS_CAUDP_BIND,
				lws_system_protocol_captive_dns.name, NULL,
				NULL, NULL, NULL, "captive-dns");
	if (!cx->captive_dns_wsi) {
		lwsl_cx_err(cx, "unable to listen on %s:%d", ads,
			    port ? port : LWS_CDNS_PORT_DEFAULT);
		return 1;
	}

	lwsl_cx_notice(cx, "every name is %s", ads);

	return 0;
}

void
lws_captive_dns_stop(struct lws_context *cx)
{
	struct lws *wsi;

	if (!cx || !cx->captive_dns_wsi)
		return;

	wsi = cx->captive_dns_wsi;
	cx->captive_dns_wsi = NULL;

	/* now, so its port is free to listen on again at once */
	lws_set_timeout(wsi, 1, LWS_TO_KILL_SYNC);
}
