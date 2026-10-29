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
 *   0, 7  DGRAM:   a datagram of the next a + 1 bytes of the input, or, if a
 *		    is 31, the next u16 + 32 of them, from the current peer
 *   1  INITIAL:    a client Initial, protected as a client's is, whose
 *		    payload is the next byte + 1 bytes of the input, padded
 *		    to fill a 1200-byte datagram: a's bits 0-1 pick the client
 *		    (see below), bit 2 repeats its last packet number
 *   2  TIME:	    the time moves on by 2^(a + 8)us, 256us .. 6 days
 *   3  TX:	    a 0, the network takes what the server sends; otherwise,
 *		    it takes nothing until the next TX op
 *   4  PEER:	    datagrams come from another address and port from now:
 *		    a's bits 0-1 the address, 2-3 the port, and bit 4 marks
 *		    them ECN CE
 *   5  SHORT:	    a short header datagram to the CID the server gave client
 *		    a & 3, then the next (a >> 2) + 1 bytes of the input: it
 *		    can't be authenticated, but its header is parsed
 *   6  CRYPTO:	    an Initial as op 1, whose payload is one CRYPTO frame
 *		    carrying the next byte + 1 bytes of the input at the
 *		    client's crypto offset: its ClientHello, in as many pieces
 *		    as the fuzzer likes, with the framing always right
 *
 * There are four clients, each with its own SCID, packet numbers and crypto
 * offset.  Until the server answers one, its Initials go to the DCID it
 * picked itself; after, to the SCID of the server's answer, as a client's do.
 *
 * Lengths past what the input has left are cut to it, so any input is a
 * valid program.  After the program, the time runs on until the server has
 * given up on every connection, and the listener is closed: each input has
 * a listener, and its connections, of its own.
 *
 * Without the Handshake keys, which only a real TLS client gets, nothing
 * past Initial processing can be reached: header parsing, Initial frames,
 * the ClientHello, the server's whole first flight and its loss recovery,
 * amplification limits, version negotiation, stateless resets and paths.
 */

#include <libwebsockets.h>
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

enum {
	FZQ_OP_DGRAM,
	FZQ_OP_INITIAL,
	FZQ_OP_TIME,
	FZQ_OP_TX,
	FZQ_OP_PEER,
	FZQ_OP_SHORT,
	FZQ_OP_CRYPTO,
};

struct fzq_client {
	uint8_t		odcid[FZQ_CID_LEN];	/* the DCID it picked */
	uint8_t		scid[FZQ_CID_LEN];
	uint8_t		srv_cid[20];		/* the server's SCID */
	uint8_t		srv_cid_len;		/* 0: not answered yet */
	uint64_t	pn;			/* its next packet number */
	uint64_t	crypto_ofs;
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

/*
 * What the server sends to a client: its long header answers tell the
 * client the server's SCID, which the client's later Initials go to
 */
static void
fzq_learn(const uint8_t *buf, size_t len)
{
	size_t dl, sl;
	int n;

	if (len < 7 || !(buf[0] & 0x80) ||
	    !(buf[1] | buf[2] | buf[3] | buf[4])) /* not a long header, or VN */
		return;

	dl = buf[5];
	if (dl != FZQ_CID_LEN || len < 7 + dl)
		return;
	sl = buf[6 + dl];
	if (!sl || sl > sizeof(fzq.cli[0].srv_cid) || len < 7 + dl + sl)
		return;

	for (n = 0; n < FZQ_CLIENTS; n++)
		if (!memcmp(&buf[6], fzq.cli[n].scid, FZQ_CID_LEN)) {
			memcpy(fzq.cli[n].srv_cid, &buf[7 + dl], sl);
			fzq.cli[n].srv_cid_len = (uint8_t)sl;
		}
}

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

/*
 * Client c's next Initial, its payload pl of len bytes, padded with PADDING
 * frames (zeros) to fill the datagram, protected as the client would
 */
static void
fzq_initial(struct fzq_client *c, const uint8_t *pl, size_t len, int repeat)
{
	uint8_t pkt[FZQ_INITIAL_LEN + 16], *p = pkt;
	size_t pn_ofs, room;
	uint64_t pn;

	*p++ = 0xc0;		/* long header, Initial, pn length to come */
	*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 1; /* QUIC v1 */
	if (c->srv_cid_len) {
		*p++ = c->srv_cid_len;
		memcpy(p, c->srv_cid, c->srv_cid_len);
		p += c->srv_cid_len;
	} else {
		*p++ = FZQ_CID_LEN;
		memcpy(p, c->odcid, FZQ_CID_LEN);
		p += FZQ_CID_LEN;
	}
	*p++ = FZQ_CID_LEN;
	memcpy(p, c->scid, FZQ_CID_LEN);
	p += FZQ_CID_LEN;
	*p++ = 0;		/* no token */

	/* the Length is the rest of the datagram: pn, payload and tag */
	room = FZQ_INITIAL_LEN - lws_ptr_diff_size_t(p, pkt) - 2;
	*p++ = (uint8_t)(0x40 | (room >> 8));
	*p++ = (uint8_t)room;

	pn_ofs = lws_ptr_diff_size_t(p, pkt);
	pn = repeat && c->pn ? c->pn - 1 : c->pn++;
	*p++ = (uint8_t)(pn >> 24);
	*p++ = (uint8_t)(pn >> 16);
	*p++ = (uint8_t)(pn >> 8);
	*p++ = (uint8_t)pn;

	room = FZQ_INITIAL_LEN - 16 - lws_ptr_diff_size_t(p, pkt);
	if (len > room)
		len = room;
	memcpy(p, pl, len);
	memset(p + len, 0, room - len);

	/* the keys are always those of the DCID it picked itself */
	if (lws_quic_seal_client_initial(pkt, FZQ_INITIAL_LEN - 16, pn_ofs, 4,
					 pn, c->odcid, FZQ_CID_LEN) !=
							FZQ_INITIAL_LEN)
		return;

	fzq_deliver(pkt, FZQ_INITIAL_LEN);
}

/* a CRYPTO frame carrying the next len bytes of client c's crypto stream */
static void
fzq_crypto(struct fzq_client *c, const uint8_t *in, size_t len)
{
	uint8_t pl[FZQ_INITIAL_LEN], *p = pl;

	if (len > 1024)
		len = 1024;

	*p++ = 0x06;
	/* both varints in their 4-byte form */
	*p++ = (uint8_t)(0x80 | ((c->crypto_ofs >> 24) & 0x3f));
	*p++ = (uint8_t)(c->crypto_ofs >> 16);
	*p++ = (uint8_t)(c->crypto_ofs >> 8);
	*p++ = (uint8_t)c->crypto_ofs;
	*p++ = 0x80;
	*p++ = 0;
	*p++ = (uint8_t)(len >> 8);
	*p++ = (uint8_t)len;
	memcpy(p, in, len);
	c->crypto_ofs += len;

	fzq_initial(c, pl, (size_t)(p - pl) + len, 0);
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
		case FZQ_OP_INITIAL:
			c = &fzq.cli[a & 3];
			n = fzq_len8(in, len, &pos);
			fzq_initial(c, in + pos, n, !!(a & 4));
			pos += n;
			break;

		case FZQ_OP_CRYPTO:
			c = &fzq.cli[a & 3];
			n = fzq_len8(in, len, &pos);
			fzq_crypto(c, in + pos, n);
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

static const struct lws_protocols protocols[] = {
	{ "http", fzq_callback, 0, 0, 0, NULL, 0 },
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
