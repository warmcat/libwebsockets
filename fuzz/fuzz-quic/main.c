/*
 * lws fuzz target: a QUIC server's datagram processing, with the fuzzer as
 * its clients, the network and the clock
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Every datagram of every QUIC connection of a server comes in through its
 * udp listener, and every one it sends goes out through it.  So one transport
 * under the listener (lws_set_transport(), its datagram ops) is the whole
 * network, and with the time ours too (lws_service_set_now()), each input is
 * a little program of what the server's clients and the network do, in order:
 *
 *   op byte: bits 0-2 the op, bits 3-7 its argument a (0 .. 31)
 *
 *   0	DGRAM:	    a datagram of the next a + 1 bytes of the input, or, if a
 *		    is 31, the next u16 + 32 of them, from the current peer
 *   1  PACKET:	    a packet of client a & 3, protected as a client's is,
 *		    whose payload is the next byte + 1 bytes of the input, at
 *		    the level (a >> 2) & 3: 0 an Initial, padded to fill a
 *		    1200-byte datagram, 1 Handshake, 2 1-RTT, 3 1-RTT in the
 *		    next key phase, a key update.  Bit 4 repeats the last
 *		    packet number of its space
 *   2  TIME:	    the time moves on by 2^(a + 8)us, 256us .. 6 days
 *   3  TX:	    a 0, the network takes what the server sends; otherwise,
 *		    it takes nothing until the next TX op
 *   4  PEER:	    datagrams come from another address and port from now:
 *		    a's bits 0-1 the address, 2-3 the port, and bit 4 marks
 *		    them ECN CE
 *   5  SHORT:	    a short header datagram to the CID the server gave client
 *		    a & 3, then the next (a >> 2) + 1 bytes of the input: it
 *		    can't be authenticated, but its header is parsed
 *   6  CRYPTO:	    a packet as op 1 of client a & 3 whose payload is one
 *		    CRYPTO frame at the client's crypto offset, carrying the
 *		    next byte + 1 bytes of the input: in an Initial, its
 *		    ClientHello in as many pieces as the fuzzer likes, with the
 *		    framing always right, or with bit 2, in a Handshake packet.
 *		    With bit 3, it is the client's Finished, in a Handshake
 *		    packet with an ACK of the server's, and takes no input
 *   7  STREAM:	    a 1-RTT packet of client a & 3 with an ACK of the server's
 *		    1-RTT packets and a STREAM frame carrying the next byte + 1
 *		    bytes of the input, on the stream (a >> 2) & 3 picks:
 *		    the bidi streams 0 and 4, or the uni streams 2 and 6 (h3's
 *		    control stream and qpack encoder stream), at the stream's
 *		    offset; bit 4 is its FIN
 *
 * There are four clients, each with its own SCID, packet number spaces and
 * crypto and stream offsets.  Until the server answers one, its Initials go
 * to the DCID it picked itself; after, to the SCID of the server's answer,
 * as a client's do.
 *
 * Past Initial, a client's packets are protected with secrets from a TLS
 * handshake it hasn't done, and its Finished authenticates bytes that
 * differ every run.  The fuzzing build of lws tells the harness each
 * secret its connections install, and the handshake bytes they send
 * (lws_quic_fuzz_set_taps()): with the ClientHello the fuzzer gave, that's
 * the transcript, so the harness can make the Finished, and protect
 * Handshake and 1-RTT packets (lws_quic_seal_packet()).  Then everything an
 * established connection does is in reach: its frames, streams and flow
 * control, key updates, and h3 above it, with WebTransport sessions to a
 * protocol that answers on their streams.
 *
 * Lengths past what the input has left are cut to it, so any input is a
 * valid program.  After the program, the time runs on until the server has
 * given up on every connection, and the listener is closed: each input has
 * a listener, and its connections, of its own.
 */

#include <libwebsockets.h>
#if defined(LWS_ROLE_WT)
#include <libwebsockets/lws-webtransport.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define FZQ_ROUNDS		64	/* service passes per thing happening */
#define FZQ_QUEUE		8	/* datagrams waiting for the server */
#define FZQ_DGRAM_MAX		1500
#define FZQ_INITIAL_LEN		1200	/* RFC 9000 14.1 */
#define FZQ_CLIENTS		4
#define FZQ_CID_LEN		8
#define FZQ_END_STEPS		16

#define FZQ_HS_MAX		4096	/* each handshake stream kept */
#define FZQ_SECRET_MAX		48

enum {
	FZQ_OP_DGRAM,
	FZQ_OP_PACKET,
	FZQ_OP_TIME,
	FZQ_OP_TX,
	FZQ_OP_PEER,
	FZQ_OP_SHORT,
	FZQ_OP_CRYPTO,
	FZQ_OP_STREAM,
};

/* packet number spaces, and the levels a client's packets go at */
enum {
	FZQ_INITIAL,
	FZQ_HANDSHAKE,
	FZQ_APP,
	FZQ_SPACES,

	FZQ_APP_NEXT_PHASE = FZQ_SPACES,
};

/* what a client knows of one direction's secret at a level */
struct fzq_secret {
	uint8_t		s[FZQ_SECRET_MAX];
	uint8_t		len;			/* 0: not had it yet */
	enum lws_tls_quic_aead aead;
};

/* a handshake stream, the first FZQ_HS_MAX bytes of it */
struct fzq_hs {
	uint8_t		b[FZQ_HS_MAX];
	size_t		len;
};

struct fzq_client {
	uint8_t		odcid[FZQ_CID_LEN];	/* the DCID it picked */
	uint8_t		scid[FZQ_CID_LEN];
	uint8_t		srv_cid[20];		/* the server's SCID */
	uint8_t		srv_cid_len;		/* 0: not answered yet */
	uint64_t	pn[FZQ_SPACES];		/* its next packet numbers */
	uint64_t	srv_pkts[FZQ_SPACES];	/* packets the server sent */
	uint64_t	crypto_ofs[2];		/* Initial, Handshake */
	uint64_t	stream_ofs[4];

	struct fzq_secret hs, app;		/* ours, to protect with */
	unsigned int	key_updates;		/* ours, since the handshake */

	/* the transcript: our ClientHello, then what the server sent */
	struct fzq_hs	cli_initial, srv_initial, srv_handshake;
};

struct fzq_dgram {
	uint8_t		buf[FZQ_DGRAM_MAX];
	size_t		len;
	lws_sockaddr46	peer;
	uint8_t		ecn;
};

static struct {
	struct fzq_dgram	q[FZQ_QUEUE];	/* waiting for the server */
	int			q_head, q_count;

	struct fzq_client	cli[FZQ_CLIENTS];
	lws_sockaddr46		peer;		/* where datagrams come from */
	uint8_t			ecn;

	struct lws		*lwsi;		/* the listener */
	int			fd;		/* its place in the poll set */
	int			refuse;		/* the network takes nothing */
	size_t			tx_count;	/* datagrams the server sent */
} fzq;

static struct lws_context *cx;
static struct lws_vhost *vh;
static lws_io_ops_t fzq_io_ops;
static lws_usec_t fzq_now = (lws_usec_t)1000 * LWS_US_PER_SEC;

static void
fzq_set_now(void)
{
	lws_service_set_now(cx, 0, fzq_now, (time_t)1767225600 +
					    (time_t)(fzq_now / LWS_US_PER_SEC));
}

static int
fzq_recv_dgram(struct lws *wsi, void *opaque, uint8_t *buf, size_t len,
	       lws_sockaddr46 *peer, uint8_t *ecn)
{
	struct fzq_dgram *d;

	(void)wsi;
	(void)opaque;

	if (!fzq.q_count)
		return 0;

	d = &fzq.q[fzq.q_head];
	fzq.q_head = (fzq.q_head + 1) % FZQ_QUEUE;
	fzq.q_count--;

	/* a datagram bigger than the buffer is cut short, as recv would */
	if (len > d->len)
		len = d->len;
	memcpy(buf, d->buf, len);
	*peer = d->peer;
	*ecn = d->ecn;

	return (int)len;
}

/* a QUIC varint at *p, or -1 if it runs past end */
static int64_t
fzq_varint(const uint8_t **p, const uint8_t *end)
{
	size_t n, l;
	int64_t v;

	if (*p >= end)
		return -1;
	l = (size_t)1 << (**p >> 6);
	if ((size_t)(end - *p) < l)
		return -1;
	v = **p & 0x3f;
	for (n = 1; n < l; n++)
		v = (v << 8) | (*p)[n];
	*p += l;

	return v;
}

static struct fzq_client *
fzq_client_of(const uint8_t *cid, size_t len)
{
	int n;

	if (len != FZQ_CID_LEN)
		return NULL;

	for (n = 0; n < FZQ_CLIENTS; n++)
		if (!memcmp(cid, fzq.cli[n].scid, FZQ_CID_LEN))
			return &fzq.cli[n];

	return NULL;
}

/*
 * What the server sends a client: its long header answers tell the client
 * the server's SCID, which the client's later packets go to, and we count
 * its packets of each space, whose numbers go up from 0, to ACK them
 */
static void
fzq_learn(const uint8_t *buf, size_t len)
{
	const uint8_t *p = buf, *end = buf + len;
	struct fzq_client *c;
	int64_t l;
	size_t sl;

	while (end - p >= 1 + FZQ_CID_LEN) {
		if (!(*p & 0x80)) {
			/* a short header: the rest of the datagram */
			c = fzq_client_of(p + 1, FZQ_CID_LEN);
			if (c)
				c->srv_pkts[FZQ_APP]++;
			return;
		}

		if (end - p < 7 || !(p[1] | p[2] | p[3] | p[4]))
			return; /* VN */

		c = fzq_client_of(p + 6, p[5]);
		if (!c || end - p < 7 + FZQ_CID_LEN)
			return;
		sl = p[6 + FZQ_CID_LEN];
		if (!sl || sl > sizeof(c->srv_cid) ||
		    (size_t)(end - p) < 7 + FZQ_CID_LEN + sl)
			return;
		memcpy(c->srv_cid, p + 7 + FZQ_CID_LEN, sl);
		c->srv_cid_len = (uint8_t)sl;

		switch ((*p >> 4) & 3) {
		case 0: /* Initial */
			p += 7 + FZQ_CID_LEN + sl;
			l = fzq_varint(&p, end);
			if (l < 0 || end - p < l)
				return;
			p += l;
			c->srv_pkts[FZQ_INITIAL]++;
			break;
		case 2: /* Handshake */
			p += 7 + FZQ_CID_LEN + sl;
			c->srv_pkts[FZQ_HANDSHAKE]++;
			break;
		default:
			return;
		}

		l = fzq_varint(&p, end);
		if (l < 0 || end - p < l)
			return;
		p += l;
	}
}

/*
 * The fuzzing build's taps: each connection tells us the secrets it
 * installs, and the handshake it sends, which with our ClientHello is
 * the transcript our Finished is made from
 */
static void
fzq_tap_secret(struct lws *wsi, const uint8_t *peer_scid, size_t peer_scid_len,
	       enum lws_tls_quic_secret_type type, enum lws_tls_quic_aead aead,
	       const uint8_t *secret, size_t secret_len)
{
	struct fzq_client *c = fzq_client_of(peer_scid, peer_scid_len);
	struct fzq_secret *sec;

	(void)wsi;

	if (!c || secret_len > FZQ_SECRET_MAX)
		return;

	switch (type) {
	case LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE:
		sec = &c->hs;
		break;
	case LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION:
		sec = &c->app;
		c->key_updates = 0;
		break;
	default:
		return;
	}

	memcpy(sec->s, secret, secret_len);
	sec->len = (uint8_t)secret_len;
	sec->aead = aead;
}

static void
fzq_hs_add(struct fzq_hs *h, const uint8_t *buf, size_t len)
{
	if (len > sizeof(h->b) - h->len)
		len = sizeof(h->b) - h->len;
	memcpy(h->b + h->len, buf, len);
	h->len += len;
}

static void
fzq_tap_crypto_tx(struct lws *wsi, const uint8_t *peer_scid,
		  size_t peer_scid_len, int level, const uint8_t *buf,
		  size_t len)
{
	struct fzq_client *c = fzq_client_of(peer_scid, peer_scid_len);

	(void)wsi;

	if (!c)
		return;

	switch (level) {
	case 0:
		fzq_hs_add(&c->srv_initial, buf, len);
		break;
	case 2:
		fzq_hs_add(&c->srv_handshake, buf, len);
		break;
	}
}

static const lws_quic_fuzz_taps_t fzq_taps = {
	.secret		= fzq_tap_secret,
	.crypto_tx	= fzq_tap_crypto_tx,
};

static int
fzq_send_dgram(struct lws *wsi, void *opaque, const uint8_t *buf, size_t len,
	       const lws_sockaddr46 *dest)
{
	(void)wsi;
	(void)opaque;
	(void)dest;

	if (fzq.refuse)
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	fzq_learn(buf, len);
	if (!fzq.tx_count++) {
		lwsl_notice("%s: the server's first datagram, %zu bytes:\n",
			    __func__, len);
		lwsl_hexdump_notice(buf, len < 64 ? len : 64);
	}

	return (int)len;
}

static const lws_transport_ops_t fzq_tops = {
	.recv_dgram	= fzq_recv_dgram,
	.send_dgram	= fzq_send_dgram,
};

static int
fzq_close(struct lws *wsi, int phase)
{
	if (phase == LWS_IOCLOSE_RELEASE && wsi == fzq.lwsi)
		fzq.lwsi = NULL;

	return lws_io_ops_default.close(wsi, phase);
}

/*
 * The server is offered what is waiting for it and a turn to send, until
 * nothing more moves
 */
static void
fzq_pump(void)
{
	struct lws_pollfd pfd;
	size_t tx;
	int n, q;

	for (n = 0; n < FZQ_ROUNDS && fzq.lwsi; n++) {
		q = fzq.q_count;
		tx = fzq.tx_count;

		pfd.fd = fzq.fd;
		pfd.events = LWS_POLLIN | LWS_POLLOUT;
		pfd.revents = (short)((q ? LWS_POLLIN : 0) |
				      (fzq.refuse ? 0 : LWS_POLLOUT));
		if (!pfd.revents)
			return;

		lws_service_fd(cx, &pfd);

		if (fzq.q_count == q && fzq.tx_count == tx)
			return;
	}
}

static void
fzq_advance(lws_usec_t us)
{
	fzq_now += us;
	fzq_set_now();
	fzq_pump();
}

/* a datagram arrives from the current peer, a little later than the last */
static void
fzq_deliver(const uint8_t *p, size_t len)
{
	struct fzq_dgram *d;

	if (len > FZQ_DGRAM_MAX)
		len = FZQ_DGRAM_MAX;

	d = &fzq.q[(fzq.q_head + fzq.q_count) % FZQ_QUEUE];
	memcpy(d->buf, p, len);
	d->len = len;
	d->peer = fzq.peer;
	d->ecn = fzq.ecn;
	fzq.q_count++;

	fzq_now += LWS_US_PER_MS;
	fzq_set_now();
	fzq_pump();

	/* whatever the server didn't take, it never will */
	fzq.q_head = fzq.q_count = 0;
}

static uint8_t *
fzq_put_varint(uint8_t *p, uint64_t v)
{
	if (v < 0x40) {
		*p++ = (uint8_t)v;
		return p;
	}
	if (v < 0x4000) {
		*p++ = (uint8_t)(0x40 | (v >> 8));
		*p++ = (uint8_t)v;
		return p;
	}
	*p++ = (uint8_t)(0x80 | ((v >> 24) & 0x3f));
	*p++ = (uint8_t)(v >> 16);
	*p++ = (uint8_t)(v >> 8);
	*p++ = (uint8_t)v;

	return p;
}

static enum lws_genhmac_types
fzq_hmac_type(const struct fzq_secret *sec)
{
	return sec->len == 48 ? LWS_GENHMAC_TYPE_SHA384 :
				LWS_GENHMAC_TYPE_SHA256;
}

/*
 * Client c's next packet at level, its payload pl of len bytes, protected
 * as the client would.  An Initial is padded with PADDING frames (zeros) to
 * fill its datagram; a packet at a level whose secret the client doesn't
 * have yet isn't sent.
 */
static void
fzq_packet(struct fzq_client *c, int level, const uint8_t *pl, size_t len,
	   int repeat)
{
	int space = level > FZQ_APP ? FZQ_APP : level, n;
	uint8_t pkt[FZQ_DGRAM_MAX + 16], *p = pkt, *plen = NULL;
	struct fzq_secret *sec = NULL;
	size_t pn_ofs, room;
	uint64_t pn;

	if (level != FZQ_INITIAL) {
		sec = level == FZQ_HANDSHAKE ? &c->hs : &c->app;
		if (!sec->len)
			return;
	}

	if (level == FZQ_APP_NEXT_PHASE)
		c->key_updates++;

	if (space == FZQ_APP) {
		*p++ = (uint8_t)(0x40 | ((c->key_updates & 1) << 2));
	} else {
		/* long header, Initial or Handshake, pn length to come */
		*p++ = level == FZQ_INITIAL ? 0xc0 : 0xe0;
		*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 1; /* QUIC v1 */
	}

	if (c->srv_cid_len) {
		if (space != FZQ_APP)
			*p++ = c->srv_cid_len;
		memcpy(p, c->srv_cid, c->srv_cid_len);
		p += c->srv_cid_len;
	} else {
		if (space != FZQ_APP)
			*p++ = FZQ_CID_LEN;
		memcpy(p, c->odcid, FZQ_CID_LEN);
		p += FZQ_CID_LEN;
	}

	if (space != FZQ_APP) {
		*p++ = FZQ_CID_LEN;
		memcpy(p, c->scid, FZQ_CID_LEN);
		p += FZQ_CID_LEN;
		if (level == FZQ_INITIAL)
			*p++ = 0;	/* no token */
		plen = p;		/* the Length, filled in below */
		p += 2;
	}

	pn_ofs = lws_ptr_diff_size_t(p, pkt);
	pn = repeat && c->pn[space] ? c->pn[space] - 1 : c->pn[space]++;
	*p++ = (uint8_t)(pn >> 24);
	*p++ = (uint8_t)(pn >> 16);
	*p++ = (uint8_t)(pn >> 8);
	*p++ = (uint8_t)pn;

	room = (level == FZQ_INITIAL ? FZQ_INITIAL_LEN : FZQ_DGRAM_MAX) - 16 -
						lws_ptr_diff_size_t(p, pkt);
	if (len > room)
		len = room;
	memcpy(p, pl, len);
	if (level == FZQ_INITIAL) {
		memset(p + len, 0, room - len);
		len = room;
	}
	p += len;

	if (plen) {
		/* the Length is the pn, payload and tag */
		room = 4 + len + 16;
		plen[0] = (uint8_t)(0x40 | (room >> 8));
		plen[1] = (uint8_t)room;
	}

	if (level == FZQ_INITIAL)
		/* the keys are always those of the DCID it picked itself */
		n = lws_quic_seal_client_initial(pkt,
				lws_ptr_diff_size_t(p, pkt), pn_ofs, 4, pn,
				c->odcid, FZQ_CID_LEN);
	else
		n = lws_quic_seal_packet(pkt, lws_ptr_diff_size_t(p, pkt),
					 pn_ofs, 4, pn, sec->aead, sec->s,
					 sec->len, space == FZQ_APP ?
							c->key_updates : 0);
	if (n < 0)
		return;

	fzq_deliver(pkt, (size_t)n);
}

/* an ACK of every packet of a space the server sent the client */
static uint8_t *
fzq_ack(struct fzq_client *c, int space, uint8_t *p)
{
	uint64_t largest;

	if (!c->srv_pkts[space])
		return p;

	largest = c->srv_pkts[space] - 1;
	*p++ = 0x02;
	p = fzq_put_varint(p, largest);
	*p++ = 0;			/* ack delay */
	*p++ = 0;			/* no more ranges */

	return fzq_put_varint(p, largest);
}

/*
 * A CRYPTO frame carrying the next len bytes of client c's crypto stream at
 * the Initial or Handshake level, with an ACK of what the server sent there
 */
static void
fzq_crypto(struct fzq_client *c, int level, const uint8_t *in, size_t len)
{
	uint8_t pl[FZQ_DGRAM_MAX], *p = pl;
	uint64_t *ofs = &c->crypto_ofs[level == FZQ_HANDSHAKE];

	if (len > 1024)
		len = 1024;

	p = fzq_ack(c, level, p);
	*p++ = 0x06;
	p = fzq_put_varint(p, *ofs);
	p = fzq_put_varint(p, len);
	memcpy(p, in, len);
	if (level == FZQ_INITIAL)
		fzq_hs_add(&c->cli_initial, in, len);
	*ofs += len;

	fzq_packet(c, level, pl, lws_ptr_diff_size_t(p, pl) + len, 0);
}

static uint32_t
fzq_u24(const uint8_t *p)
{
	return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/*
 * The hash of the transcript the client's Finished authenticates: its
 * ClientHello, the server's ServerHello, then the server's handshake
 * messages through its Finished.  Returns 0, or -1 if it hasn't all come.
 */
static int
fzq_transcript(struct fzq_client *c, enum lws_genhash_types ht, uint8_t *hash)
{
	const struct fzq_hs *sh = &c->srv_handshake;
	struct lws_genhash_ctx ctx;
	size_t ch, n = 0, m;
	uint8_t type = 0;

	if (c->cli_initial.len < 4)
		return -1;
	ch = 4 + (size_t)fzq_u24(c->cli_initial.b + 1);
	if (ch > c->cli_initial.len)
		return -1;

	while (type != 20) {			/* Finished */
		if (sh->len - n < 4)
			return -1;
		m = 4 + (size_t)fzq_u24(sh->b + n + 1);
		if (sh->len - n < m)
			return -1;
		type = sh->b[n];
		n += m;
	}

	if (lws_genhash_init(&ctx, ht))
		return -1;
	if (lws_genhash_update(&ctx, c->cli_initial.b, ch) ||
	    lws_genhash_update(&ctx, c->srv_initial.b, c->srv_initial.len) ||
	    lws_genhash_update(&ctx, sh->b, n)) {
		lws_genhash_destroy(&ctx, NULL);
		return -1;
	}

	return lws_genhash_destroy(&ctx, hash) ? -1 : 0;
}

/*
 * The client's Finished (RFC 8446 4.4.4): the HMAC of the transcript's
 * hash, keyed from its handshake secret
 */
static void
fzq_finished(struct fzq_client *c)
{
	enum lws_genhmac_types hmt = fzq_hmac_type(&c->hs);
	uint8_t th[FZQ_SECRET_MAX], fk[FZQ_SECRET_MAX], msg[4 + FZQ_SECRET_MAX];
	size_t hl = c->hs.len;
	struct lws_genhmac_ctx hm;

	if (!hl || fzq_transcript(c, hl == 48 ? LWS_GENHASH_TYPE_SHA384 :
					LWS_GENHASH_TYPE_SHA256, th) ||
	    lws_genhkdf_expand_label(hmt, c->hs.s, hl, "finished", NULL, 0,
				     fk, hl) ||
	    lws_genhmac_init(&hm, hmt, fk, hl))
		return;
	if (lws_genhmac_update(&hm, th, hl)) {
		lws_genhmac_destroy(&hm, NULL);
		return;
	}
	if (lws_genhmac_destroy(&hm, msg + 4))
		return;

	msg[0] = 20;
	msg[1] = 0;
	msg[2] = 0;
	msg[3] = (uint8_t)hl;

	fzq_crypto(c, FZQ_HANDSHAKE, msg, 4 + hl);
}

/* the streams the STREAM op writes on */
static const uint8_t fzq_sids[] = { 0, 4, 2, 6 };

static void
fzq_stream(struct fzq_client *c, int s, int fin, const uint8_t *in, size_t len)
{
	uint8_t pl[FZQ_DGRAM_MAX], *p = pl;

	if (len > 1024)
		len = 1024;

	p = fzq_ack(c, FZQ_APP, p);
	*p++ = (uint8_t)(0x0e | fin);	/* STREAM, with OFF and LEN */
	*p++ = fzq_sids[s];
	p = fzq_put_varint(p, c->stream_ofs[s]);
	p = fzq_put_varint(p, len);
	memcpy(p, in, len);
	c->stream_ofs[s] += len;

	fzq_packet(c, FZQ_APP, pl, lws_ptr_diff_size_t(p, pl) + len, 0);
}

/* datagrams come from 127.0.0.(a + 1), at port 40000 + b */
static void
fzq_set_peer(int a)
{
	memset(&fzq.peer, 0, sizeof(fzq.peer));
	fzq.peer.sa4.sin_family = AF_INET;
	fzq.peer.sa4.sin_addr.s_addr = htonl(0x7f000001u + (uint32_t)(a & 3));
	fzq.peer.sa4.sin_port = htons((uint16_t)(40000 + ((a >> 2) & 3)));
	fzq.ecn = (a & 0x10) ? 3 : 0;
}

/* the length of an op's input: the next byte + 1, cut to what's left */
static size_t
fzq_len8(const uint8_t *in, size_t len, size_t *pos)
{
	size_t n = *pos < len ? (size_t)in[(*pos)++] + 1 : 0;

	return n > len - *pos ? len - *pos : n;
}

static void
fzq_run(const uint8_t *in, size_t len)
{
	uint8_t sh[1 + 20 + 32];
	struct fzq_client *c;
	size_t pos = 0, n;
	int op, a, i;

	while (pos < len && fzq.lwsi) {
		op = in[pos] & 7;
		a = in[pos++] >> 3;

		switch (op) {
		case FZQ_OP_PACKET:
			c = &fzq.cli[a & 3];
			n = fzq_len8(in, len, &pos);
			fzq_packet(c, (a >> 2) & 3, in + pos, n, !!(a & 0x10));
			pos += n;
			break;

		case FZQ_OP_CRYPTO:
			c = &fzq.cli[a & 3];
			if (a & 8) {
				fzq_finished(c);
				break;
			}
			n = fzq_len8(in, len, &pos);
			fzq_crypto(c, a & 4 ? FZQ_HANDSHAKE : FZQ_INITIAL,
				   in + pos, n);
			pos += n;
			break;

		case FZQ_OP_STREAM:
			c = &fzq.cli[a & 3];
			n = fzq_len8(in, len, &pos);
			fzq_stream(c, (a >> 2) & 3, !!(a & 0x10), in + pos, n);
			pos += n;
			break;

		case FZQ_OP_TIME:
			fzq_advance((lws_usec_t)1 << (a + 8));
			break;

		case FZQ_OP_TX:
			fzq.refuse = !!a;
			fzq_pump();
			break;

		case FZQ_OP_PEER:
			fzq_set_peer(a);
			break;

		case FZQ_OP_SHORT:
			c = &fzq.cli[a & 3];
			sh[0] = 0x40;
			i = c->srv_cid_len ? c->srv_cid_len : FZQ_CID_LEN;
			memcpy(&sh[1], c->srv_cid_len ? c->srv_cid : c->odcid,
			       (size_t)i);
			n = (size_t)(a >> 2) + 1;
			if (n > len - pos)
				n = len - pos;
			memcpy(&sh[1 + i], in + pos, n);
			pos += n;
			fzq_deliver(sh, 1 + (size_t)i + n);
			break;

		default: /* DGRAM */
			n = (size_t)a + 1;
			if (a == 31) {
				n = 32;
				if (len - pos >= 2) {
					n += ((size_t)in[pos] << 8) | in[pos + 1];
					pos += 2;
				}
			}
			if (n > len - pos)
				n = len - pos;
			fzq_deliver(in + pos, n);
			pos += n;
			break;
		}
	}

	/* the network takes everything, and the time runs on */
	fzq.refuse = 0;
	for (i = 0; i < FZQ_END_STEPS && fzq.lwsi; i++)
		fzq_advance((lws_usec_t)1 << (i + 18));

	lwsl_notice("%s: the server sent %zu datagrams\n", __func__,
		    fzq.tx_count);
}

static int
fzq_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#if defined(LWS_ROLE_WT)
/*
 * WebTransport sessions get a stream of each kind from us, and each stream
 * something written whenever the client sent it something, so the session's
 * streams carry data both ways
 */
static int
fzq_wt_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user,
		void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 8];
	struct lws *s;

	(void)user;
	(void)in;
	(void)len;

	switch (reason) {
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		if (!lws_wt_is_session(wsi))
			break;
		s = lws_wt_create_stream(wsi, 0);
		if (s)
			lws_callback_on_writable(s);
		s = lws_wt_create_stream(wsi, 1);
		if (s)
			lws_callback_on_writable(s);
		break;

	case LWS_CALLBACK_RECEIVE:
		if (!lws_wt_is_session(wsi) && !lws_wt_is_unidi(wsi))
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (lws_wt_is_session(wsi))
			break;
		memcpy(&buf[LWS_PRE], "fzq-wt!", 8);
		if (lws_write(wsi, &buf[LWS_PRE], 8, LWS_WRITE_BINARY) != 8)
			return -1;
		break;

	default:
		break;
	}

	return 0;
}

/* only a protocol whose pvo says "webtransport" is given sessions */
static const struct lws_protocol_vhost_options fzq_pvo_wt_opt = {
	NULL, NULL, "webtransport", ""
}, fzq_pvo_wt = {
	NULL, &fzq_pvo_wt_opt, "webtransport", ""
};
#endif

static const struct lws_protocols protocols[] = {
	{ "http", fzq_callback, 0, 0, 0, NULL, 0 },
#if defined(LWS_ROLE_WT)
	{ "webtransport", fzq_wt_callback, 0, 1024, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct lws_context_creation_info info;

	(void)argc;
	(void)argv;

	signal(SIGPIPE, SIG_IGN);

	if (getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO |
				  LLL_USER | LLLF_LOG_SPEW_OFF, NULL);
	else
		lws_set_log_level(0, NULL);

	lws_io_ops_init(&fzq_io_ops);
	fzq_io_ops.close = fzq_close;

	memset(&info, 0, sizeof(info));
	info.port	= CONTEXT_PORT_NO_LISTEN;
	info.options	= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.io_ops	= &fzq_io_ops;

	cx = lws_create_context(&info);
	if (!cx)
		return 1;
	fzq_set_now();
	lws_quic_fuzz_set_taps(cx, &fzq_taps);

	/*
	 * A vhost doing tls with h3 in its alpn, but listening on nothing:
	 * we make its udp listener ourselves for each input
	 */
	info.port			= CONTEXT_PORT_NO_LISTEN_SERVER;
	info.vhost_name			= "fuzz";
	info.protocols			= protocols;
	info.ssl_cert_filepath		= FZQ_CERT_DIR "/fuzz-quic.cert";
	info.ssl_private_key_filepath	= FZQ_CERT_DIR "/fuzz-quic.key";
	info.alpn			= "h3";
#if defined(LWS_ROLE_WT)
	info.pvo			= &fzq_pvo_wt;
#endif

	vh = lws_create_vhost(cx, &info);

	return !vh;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int n;

	memset(&fzq, 0, sizeof(fzq));
	for (n = 0; n < FZQ_CLIENTS; n++) {
		memcpy(fzq.cli[n].odcid, "fzqodcid", FZQ_CID_LEN);
		memcpy(fzq.cli[n].scid, "fzqscid", FZQ_CID_LEN - 1);
		fzq.cli[n].odcid[FZQ_CID_LEN - 1] = (uint8_t)('0' + n);
		fzq.cli[n].scid[FZQ_CID_LEN - 1] = (uint8_t)('0' + n);
	}
	fzq_set_peer(0);

	fzq.lwsi = lws_create_adopt_udp(vh, "127.0.0.1", 0, LWS_CAUDP_BIND,
					"quic", NULL, NULL, NULL, NULL,
					"fuzz-quic");
	if (!fzq.lwsi)
		return 0;
	fzq.fd = (int)lws_get_socket_fd(fzq.lwsi);
	lws_set_transport(fzq.lwsi, &fzq_tops, NULL);

	fzq_run(data, size);

	/* the listener goes, and its connections with it */
	if (fzq.lwsi) {
		lws_set_timeout(fzq.lwsi, PENDING_TIMEOUT_CLOSE_SEND,
				LWS_TO_KILL_SYNC);
		fzq_advance(LWS_US_PER_SEC);
	}

	return 0;
}
