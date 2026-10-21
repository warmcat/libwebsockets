/*
 * lws-api-test-dht-seq-refuse
 *
 * What lws_dht_send_data() does with messages it cannot deliver:
 *
 *  - to a peer the consumer's blacklist_cb blacklists, it refuses the
 *    message at once, without making a sequencer to queue it in, where it
 *    would only be retransmitted to nobody until the session failed
 *
 *  - to a peer that never acks, it accepts messages until its sequencer's
 *    fixed tx buffer is full, and refuses the rest.  What it accepted stays
 *    queued until the retransmits of the oldest message run out: then the
 *    send is reported failed, the sequencer and its buffer are freed, and a
 *    new message to that peer is accepted again
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

static struct lws_context *cx;
static struct lws_dht_ctx *dht;
static struct sockaddr_in sa_silent, sa_black;
static lws_sorted_usec_list_t sul_poll, sul_deadline;
static int state, accepted, silent_failed, retcode = 1;
static uint8_t msg[SF_MSG_LEN];

static int
blacklist_cb(const struct sockaddr *sa, size_t salen)
{
	return sa->sa_family == AF_INET &&
	       salen >= sizeof(struct sockaddr_in) &&
	       ((const struct sockaddr_in *)sa)->sin_addr.s_addr ==
						sa_black.sin_addr.s_addr;
}

static void
cb_dht(void *closure, int event, const lws_dht_hash_t *info_hash,
       const void *data, size_t data_len, const struct sockaddr *from,
       size_t fromlen)
{
	if (event == LWS_DHT_EVENT_WRITE_FAILED && from &&
	    from->sa_family == AF_INET &&
	    ((const struct sockaddr_in *)from)->sin_addr.s_addr ==
						sa_silent.sin_addr.s_addr)
		silent_failed = 1;
}

static int
has_ts(struct sockaddr_in *sin)
{
	return !!lws_dht_get_ts(dht, (struct sockaddr *)sin, sizeof(*sin), 0);
}

/* 0 = keep polling, 1 = passed, -1 = failed */

static int
step(void)
{
	switch (state) {
	case 0:
		if (!lws_dht_send_data(dht, (struct sockaddr *)&sa_black, msg,
				       sizeof(msg))) {
			lwsl_err("message to blacklisted peer accepted\n");
			return -1;
		}
		if (has_ts(&sa_black)) {
			lwsl_err("sequencer made for blacklisted peer\n");
			return -1;
		}

		while (accepted < SF_MSG_MAX &&
		       !lws_dht_send_data(dht, (struct sockaddr *)&sa_silent,
					  msg, sizeof(msg)))
			accepted++;

		lwsl_user("silent peer: %d x %d accepted before refusal\n",
			  accepted, SF_MSG_LEN);
		if (accepted == SF_MSG_MAX || accepted < SF_MIN_ACCEPTED) {
			lwsl_err("tx buffer bound not where expected\n");
			return -1;
		}
		if (!has_ts(&sa_silent)) {
			lwsl_err("refusal lost the queued messages\n");
			return -1;
		}
		state++;
		return 0;

	case 1:
		/* the queued messages go when the session fails */
		if (!silent_failed)
			return 0;
		if (has_ts(&sa_silent)) {
			lwsl_err("failed session's sequencer survived\n");
			return -1;
		}
		if (lws_dht_send_data(dht, (struct sockaddr *)&sa_silent, msg,
				      sizeof(msg))) {
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
		LWS_PROTOCOL_LIST_TERM
	};
	int port_dht = 0, port_fan = 0, n = 0;
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

	if (port_dht < 1 || port_dht > 65535 || port_fan < 1 ||
	    port_fan > 65535 || port_dht == port_fan) {
		lwsl_err("usage: --port-dht <udp port> "
			 "--port-fan <unused udp port>\n");
		return 1;
	}

	lwsl_user("LWS API selftest: dht sequencer refusals\n");

	signal(SIGINT, sigint_handler);

	memset(msg, 'x', sizeof(msg));

	memset(&sa_silent, 0, sizeof(sa_silent));
	sa_silent.sin_family = AF_INET;
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
