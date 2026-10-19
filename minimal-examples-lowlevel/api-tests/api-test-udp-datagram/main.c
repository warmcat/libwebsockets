/*
 * lws-api-test-udp-datagram
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Each lws_write() on a UDP wsi must go out as exactly one datagram, however
 * big, as long as the socket can send it.  lws used to cut every write to
 * the protocol's tx_packet_size, or rx_buffer_size, + LWS_PRE + 4 bytes and
 * send the rest later, which on UDP sent the pieces as separate datagrams:
 * eg, an auth-dns answer over 1060 bytes reached the client as several
 * datagrams, the first claiming the full record counts.
 *
 * A UDP wsi bound on loopback receives what a second UDP wsi sends it: one
 * datagram several times the sender protocol's rx_buffer_size, then a smaller
 * one still over it.  The receiver must see exactly those two datagrams, each
 * whole and intact, in that order.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

/*
 * The sender's protocol uses the rx_buffer_size auth-dns uses, which was what
 * its writes were cut to.  The receiver's is 0, so it can read a datagram up
 * to the pt_serv_buf_size (less LWS_PRE): rx_buffer_size limits what one
 * RAW_RX may deliver, and a bigger datagram is truncated to it.
 */
#define UDPD_TX_RX_BUFFER_SIZE	1024
/* the largest datagram we send, under the 4096 - LWS_PRE we can read */
#define UDPD_MAX_DGRAM		3000

static const size_t dgram_len[] = { UDPD_MAX_DGRAM, 1500 };

static int result = 1, interrupted, sent, rxed;
static lws_sorted_usec_list_t sul_deadline;
static struct lws_context *cx;

/* everything is local: it all arrives well inside this */
#define UDPD_DEADLINE_US	(2 * LWS_US_PER_SEC)

static uint8_t
pattern(size_t dg, size_t i)
{
	return (uint8_t)((i * 7) + (dg * 31) + 3);
}

static void
finish(int ok)
{
	if (interrupted)
		return;

	result = !ok;
	interrupted = 1;
	lws_cancel_service(cx);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	if (rxed == (int)LWS_ARRAY_SIZE(dgram_len)) {
		/* no trailing pieces turned up after the last one */
		finish(1);
		return;
	}

	/*
	 * Split datagrams arrive as more than we expect and fail at once, so
	 * getting here means fewer datagrams arrived than were sent
	 */
	lwsl_err("%s: %d datagram(s) of %d arrived\n", __func__, rxed,
		 (int)LWS_ARRAY_SIZE(dgram_len));
	finish(0);
}

static int
callback_udpd_rx(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	const uint8_t *p = (const uint8_t *)in;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (rxed >= (int)LWS_ARRAY_SIZE(dgram_len)) {
			lwsl_err("%s: unexpected extra datagram, %u bytes\n",
				 __func__, (unsigned int)len);
			finish(0);
			break;
		}

		if (len != dgram_len[rxed]) {
			lwsl_err("%s: datagram %d is %u bytes, sent %u\n",
				 __func__, rxed, (unsigned int)len,
				 (unsigned int)dgram_len[rxed]);
			finish(0);
			break;
		}

		for (n = 0; n < len; n++)
			if (p[n] != pattern((size_t)rxed, n)) {
				lwsl_err("%s: datagram %d differs at %u\n",
					 __func__, rxed, (unsigned int)n);
				finish(0);
				return 0;
			}

		lwsl_user("%s: datagram %d arrived whole, %u bytes\n",
			  __func__, rxed, (unsigned int)len);

		if (++rxed == (int)LWS_ARRAY_SIZE(dgram_len))
			/*
			 * Let any trailing pieces of a split datagram turn up
			 * as unexpected extras before deciding it passed
			 */
			lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb,
					 LWS_US_PER_SEC / 4);
		break;

	default:
		break;
	}

	return 0;
}

static int
callback_udpd_tx(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + UDPD_MAX_DGRAM];
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (sent >= (int)LWS_ARRAY_SIZE(dgram_len))
			break;

		for (n = 0; n < dgram_len[sent]; n++)
			buf[LWS_PRE + n] = pattern((size_t)sent, n);

		if (lws_write(wsi, buf + LWS_PRE, dgram_len[sent],
			      LWS_WRITE_RAW) != (int)dgram_len[sent]) {
			lwsl_err("%s: write of datagram %d failed\n", __func__,
				 sent);
			finish(0);
			break;
		}

		if (++sent < (int)LWS_ARRAY_SIZE(dgram_len))
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: sender failed\n", __func__);
		finish(0);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "udpd-rx", callback_udpd_rx, 0, 0, 0, NULL, 0 },
	{ "udpd-tx", callback_udpd_tx, 0, UDPD_TX_RX_BUFFER_SIZE, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p, *ads;
	int port = 7690;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	lwsl_user("LWS API selftest: UDP datagrams go whole\n");

#if defined(LWS_WITH_IPV4)
	ads = "127.0.0.1";
#else
	ads = "::1";
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("%s: vhost failed\n", __func__);
		goto bail;
	}

	if (!lws_create_adopt_udp(vh, ads, port, LWS_CAUDP_BIND,
				  protocols[0].name, NULL, NULL, NULL, NULL,
				  "udpd-rx")) {
		lwsl_err("%s: binding the receiver to %s port %d failed\n",
			 __func__, ads, port);
		goto bail;
	}

	if (!lws_create_adopt_udp(vh, ads, port, 0, protocols[1].name,
				  NULL, NULL, NULL, NULL, "udpd-tx")) {
		lwsl_err("%s: creating the sender failed\n", __func__);
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, UDPD_DEADLINE_US);

	while (!interrupted && lws_service(cx, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
