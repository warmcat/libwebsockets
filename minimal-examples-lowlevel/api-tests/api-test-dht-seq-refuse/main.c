/*
 * lws-api-test-dht-seq-refuse
 *
 * What lws_dht_send_data() does with messages it cannot take, and how the
 * sender hears when it can send again:
 *
 *  - to a peer the consumer's blacklist_cb blacklists, it refuses the
 *    message at once (LWS_DHT_SEND_REFUSED), without making a sequencer to
 *    queue it in, where it would only be retransmitted to nobody until the
 *    session failed
 *
 *  - to a peer that never acks, it takes messages until its sequencer's
 *    fixed tx buffer is full, and refuses the rest with LWS_DHT_SEND_BUSY.
 *    What it took stays queued until the retransmits of the oldest message
 *    run out: then the send is reported failed, the sequencer and its buffer
 *    are freed, and a new message to that peer is taken again
 *
 *  - a raw UDP peer P that holds back its acks until B is busy sending to it,
 *    then acks everything, gets B LWS_DHT_EVENT_WRITEABLE for P, after which
 *    B's next message to P is taken, and completes when P acks it
 *
 * Nothing listens on the fan port, at 127.0.0.2 (silent) or 127.0.0.3
 * (blacklisted).  The UDP ports are allocated uniquely at build time and
 * passed in on the command line, so parallel ctest instances do not collide.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define SF_POLL_US	(50 * LWS_US_PER_MS)
#define SF_DEADLINE_US	(10 * LWS_US_PER_SEC)

#define SF_MSG_LEN	1024
/* far more than a sequencer's tx buffer can hold of them */
#define SF_MSG_MAX	1000
/* 64KB window: a sequencer must take at least this much before refusing */
#define SF_MIN_ACCEPTED	(65536 / SF_MSG_LEN)

enum {
	SF_FILL,	/* refuse the blacklisted peer, fill silent and P */
	SF_P_ACK,	/* P acks all it was sent, once it knows B's tid */
	SF_WRITEABLE,	/* B hears P has room: send P one more */
	SF_DONE,	/* P acks that, and silent's session fails */
};

static struct lws_context *cx;
static struct lws_dht_ctx *dht;
static struct lws *wsi_p;
static struct sockaddr_in sa_dht, sa_silent, sa_black, sa_p;
static lws_sorted_usec_list_t sul_poll, sul_deadline;
static int state, retcode = 1;
static uint8_t msg[SF_MSG_LEN];

static struct {
	uint8_t		tid[16];	/* B's tid for its chunks to P */
	size_t		tid_len;
	int		accepted_silent;
	int		accepted_p;
	unsigned int	silent_failed:1;
	unsigned int	p_writeable:1;
	unsigned int	p_completed:1;
	unsigned int	p_failed:1;
	unsigned int	stray_writeable:1;
} sf;

static int
blacklist_cb(const struct sockaddr *sa, size_t salen)
{
	return sa->sa_family == AF_INET &&
	       salen >= sizeof(struct sockaddr_in) &&
	       ((const struct sockaddr_in *)sa)->sin_addr.s_addr ==
						sa_black.sin_addr.s_addr;
}

static int
sf_is(const struct sockaddr *sa, const struct sockaddr_in *sin)
{
	return sa && sa->sa_family == AF_INET &&
	       ((const struct sockaddr_in *)sa)->sin_addr.s_addr ==
						sin->sin_addr.s_addr &&
	       ((const struct sockaddr_in *)sa)->sin_port == sin->sin_port;
}

static void
cb_dht(void *closure, int event, const lws_dht_hash_t *info_hash,
       const void *data, size_t data_len, const struct sockaddr *from,
       size_t fromlen)
{
	switch (event) {
	case LWS_DHT_EVENT_WRITE_FAILED:
		if (sf_is(from, &sa_silent))
			sf.silent_failed = 1;
		if (sf_is(from, &sa_p))
			sf.p_failed = 1;
		break;
	case LWS_DHT_EVENT_WRITE_COMPLETED:
		if (sf_is(from, &sa_p))
			sf.p_completed = 1;
		break;
	case LWS_DHT_EVENT_WRITEABLE:
		if (sf_is(from, &sa_p))
			sf.p_writeable = 1;
		else
			sf.stray_writeable = 1;
		break;
	}
}

static ssize_t
sf_find(const uint8_t *buf, size_t len, const char *needle)
{
	size_t nl = strlen(needle), n;

	for (n = 0; n + nl <= len; n++)
		if (!memcmp(buf + n, needle, nl))
			return (ssize_t)n;

	return -1;
}

/*
 * A chunk of B's to P: ...e1:q4:data1:t<len>:<tid>1:y1:qe.  Keep its tid,
 * which P's acks have to echo.
 */

static void
sf_p_rx(const uint8_t *buf, size_t len)
{
	ssize_t at = sf_find(buf, len, "1:q4:data1:t");
	size_t n, l = 0;

	if (at < 0 || sf.tid_len)
		return;

	for (n = (size_t)at + 12; n < len && buf[n] >= '0' && buf[n] <= '9'; n++)
		l = (l * 10) + (size_t)(buf[n] - '0');

	if (n >= len || buf[n] != ':' || !l || l > sizeof(sf.tid) ||
	    n + 1 + l > len)
		return;

	memcpy(sf.tid, buf + n + 1, l);
	sf.tid_len = l;
}

/* P's ack of B's chunks below offset: d1:rd2:id..3:len..6:offset..e1:t..e */

static void
sf_p_send_ack(uint64_t offset)
{
	lws_sockfd_type fd = lws_get_socket_fd(wsi_p);
	char q[160];
	ssize_t r;
	size_t l;
	int n;

	n = lws_snprintf(q, sizeof(q), "d1:rd2:id20:66666666666666666666"
			 "3:leni0e6:offseti%llue" "e1:t%u:",
			 (unsigned long long)offset, (unsigned int)sf.tid_len);
	if (fd == LWS_SOCK_INVALID || n <= 0 ||
	    (size_t)n + sf.tid_len + 7 > sizeof(q))
		return;

	memcpy(q + n, sf.tid, sf.tid_len);
	memcpy(q + (size_t)n + sf.tid_len, "1:y1:re", 7);
	l = (size_t)n + sf.tid_len + 7;

	r = sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   q,
#if defined(WIN32)
		   (int)
#endif
		   l, 0, (const struct sockaddr *)&sa_dht, sizeof(sa_dht));
	if (r != (ssize_t)l)
		lwsl_err("%s: sendto returned %d\n", __func__, (int)r);
}

static int
cb_peer(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	void *in, size_t len)
{
	const struct lws_udp *udp;

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	udp = lws_get_udp(wsi);
	if (udp && udp->sa46.sa4.sin_family == AF_INET &&
	    udp->sa46.sa4.sin_port == sa_dht.sin_port)
		sf_p_rx(in, len);

	return 0;
}

static int
has_ts(struct sockaddr_in *sin)
{
	return !!lws_dht_get_ts(dht, (struct sockaddr *)sin, sizeof(*sin), 0);
}

/* send to sin until B is busy: how many it took, or -1 */

static int
sf_fill(struct sockaddr_in *sin, const char *who)
{
	int n = 0, r = LWS_DHT_SEND_QUEUED;

	while (n < SF_MSG_MAX &&
	       (r = lws_dht_send_data(dht, (struct sockaddr *)sin, msg,
				      sizeof(msg))) == LWS_DHT_SEND_QUEUED)
		n++;

	lwsl_user("%s: %d x %d taken, then %d\n", who, n, SF_MSG_LEN, r);
	if (r != LWS_DHT_SEND_BUSY || n < SF_MIN_ACCEPTED) {
		lwsl_err("%s: tx buffer bound not where expected\n", who);
		return -1;
	}
	if (!has_ts(sin)) {
		lwsl_err("%s: refusal lost the queued messages\n", who);
		return -1;
	}

	return n;
}

/* 0 = keep polling, 1 = passed, -1 = failed */

static int
step(void)
{
	switch (state) {
	case SF_FILL:
		if (lws_dht_send_data(dht, (struct sockaddr *)&sa_black, msg,
				      sizeof(msg)) != LWS_DHT_SEND_REFUSED) {
			lwsl_err("message to blacklisted peer not refused\n");
			return -1;
		}
		if (has_ts(&sa_black)) {
			lwsl_err("sequencer made for blacklisted peer\n");
			return -1;
		}

		sf.accepted_silent = sf_fill(&sa_silent, "silent");
		sf.accepted_p = sf_fill(&sa_p, "P");
		if (sf.accepted_silent < 0 || sf.accepted_p < 0)
			return -1;
		state++;
		return 0;

	case SF_P_ACK:
		if (!sf.tid_len)
			return 0;
		sf_p_send_ack((uint64_t)sf.accepted_p * SF_MSG_LEN);
		state++;
		return 0;

	case SF_WRITEABLE:
		if (!sf.p_writeable)
			return 0;
		if (lws_dht_send_data(dht, (struct sockaddr *)&sa_p, msg,
				      sizeof(msg)) != LWS_DHT_SEND_QUEUED) {
			lwsl_err("P not taken once writeable\n");
			return -1;
		}
		sf_p_send_ack((uint64_t)(sf.accepted_p + 1) * SF_MSG_LEN);
		state++;
		return 0;

	case SF_DONE:
		if (sf.p_failed) {
			lwsl_err("P's session failed\n");
			return -1;
		}
		/* the queued messages go when the session fails */
		if (!sf.p_completed || !sf.silent_failed)
			return 0;
		if (sf.stray_writeable) {
			lwsl_err("writeable for a peer that never acked\n");
			return -1;
		}
		if (has_ts(&sa_silent)) {
			lwsl_err("failed session's sequencer survived\n");
			return -1;
		}
		if (lws_dht_send_data(dht, (struct sockaddr *)&sa_silent, msg,
				      sizeof(msg)) != LWS_DHT_SEND_QUEUED) {
			lwsl_err("silent peer refused after session freed\n");
			return -1;
		}

		return 1;
	}

	return -1;
}

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	int n = step();

	if (n) {
		retcode = n < 0;
		lws_default_loop_exit(cx);
		return;
	}

	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SF_POLL_US);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out in state %d\n", __func__, state);
	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	static const struct lws_protocols protocols[] = {
		{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
		{ "sf-peer", cb_peer, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	int port_dht = 0, port_fan = 0, port_p = 0, n = 0;
	struct lws_vhost *vh;
	lws_dht_info_t di;
	uint8_t idb[20];
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-dht")))
		port_dht = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-fan")))
		port_fan = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-p")))
		port_p = atoi(p);

	if (port_dht < 1 || port_dht > 65535 || port_fan < 1 ||
	    port_fan > 65535 || port_p < 1 || port_p > 65535 ||
	    port_dht == port_fan || port_dht == port_p || port_fan == port_p) {
		lwsl_err("usage: --port-dht <udp port> --port-p <udp port> "
			 "--port-fan <unused udp port>\n");
		return 1;
	}

	lwsl_user("LWS API selftest: dht sequencer refusals\n");

	signal(SIGINT, sigint_handler);

	memset(msg, 'x', sizeof(msg));

	memset(&sa_dht, 0, sizeof(sa_dht));
	sa_dht.sin_family = AF_INET;
	sa_dht.sin_port = htons((uint16_t)port_dht);
	sa_dht.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa_p = sa_dht;
	sa_p.sin_port = htons((uint16_t)port_p);
	sa_silent = sa_dht;
	sa_silent.sin_port = htons((uint16_t)port_fan);
	sa_silent.sin_addr.s_addr = htonl(0x7f000002);
	sa_black = sa_silent;
	sa_black.sin_addr.s_addr = htonl(0x7f000003);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name = "dht-sf";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	memset(idb, 0x33, sizeof(idb));
	memset(&di, 0, sizeof(di));
	di.allow_private_ads	= 1; /* everything is on loopback */
	di.vhost		= vh;
	di.cb			= cb_dht;
	di.blacklist_cb		= blacklist_cb;
	di.name			= "sf";
	di.port			= port_dht;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}
	if (!dht) {
		lwsl_err("dht creation failed\n");
		goto bail;
	}

	wsi_p = lws_create_adopt_udp(vh, "127.0.0.1", port_p, LWS_CAUDP_BIND,
				     protocols[1].name, NULL, NULL, NULL, NULL,
				     "sf-p");
	if (!wsi_p) {
		lwsl_err("raw udp socket creation failed\n");
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, SF_DEADLINE_US);
	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SF_POLL_US);

	while (n >= 0)
		n = lws_service(cx, 0);

	lwsl_user("Completed: %s\n", retcode ? "FAIL" : "PASS");

bail:
	lws_sul_cancel(&sul_poll);
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	return retcode;
}
