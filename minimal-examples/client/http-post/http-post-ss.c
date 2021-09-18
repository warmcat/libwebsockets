/*
 * SS http-post example
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Demonstrates http post using the LWS high-level SS apis.
 *
 *  - main.c:              boilerplate to create the lws_context and event loop
 *  - http-post-ss.c:      (this file) the secure stream user code
 *  - example-policy.json: the example policy
 */

#include <libwebsockets.h>
#include <signal.h>

extern int test_result;

static const char * const postbody =
	"--boundary\r\n"
	"Content-Disposition: form-data; name=\"text\"\r\n"
	"\r\n"
	"value1\r\n"
	"--boundary\r\n"
	"Content-Disposition: form-data; "
		"name=\"field2\"; filename=\"example.txt\"\r\n"
	"\r\n"
	"value2\r\n"
	"00-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"01-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"02-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"04-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"05-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"06-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"07-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"08-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"09-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"0a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"0b-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"0c-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"0d-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"0e-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"0f-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"10-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"11-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"12-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"13-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"14-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"15-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"16-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"17-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"18-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"19-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"1a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"1b-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"1c-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"1d-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"1e-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"1f-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"20-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"21-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"22-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"23-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"24-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"25-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"26-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"27-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"28-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"29-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"2a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"2b-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"2c-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"2d-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"2e-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"2f-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"30-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"31-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"32-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"33-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"34-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"35-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"36-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"37-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"38-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"39-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"3a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"3b-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"3c-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"3d-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"3e-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"3f-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"40-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"41-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"42-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"43-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"44-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"45-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"46-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"47-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"48-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"49-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"4a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"4b-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"4c-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"4d-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"4e-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"4f-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"50-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"51-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"52-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"53-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"
	"--boundary--\r\n";

LWS_SS_USER_TYPEDEF
	const char		*payload;
	size_t			size;
	size_t			pos;
} http_post_t;

static lws_ss_state_return_t
http_post_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	     int *flags)
{
	http_post_t *g = (http_post_t *)userobj;
	lws_ss_state_return_t r = LWSSSSRET_OK;

	if (g->size == g->pos)
		return LWSSSSRET_TX_DONT_SEND;

	if (*len > g->size - g->pos)
		*len = g->size - g->pos;

	if (!g->pos)
		*flags |= LWSSS_FLAG_SOM;

	memcpy(buf, g->payload + g->pos, *len);
	g->pos += *len;

	if (g->pos != g->size)
		/* more to do */
		r = lws_ss_request_tx(lws_ss_from_user(g));
	else
		*flags |= LWSSS_FLAG_EOM;

	lwsl_ss_user(lws_ss_from_user(g), "TX %zu, flags 0x%x, r %d", *len,
					  (unsigned int)*flags, (int)r);

	return r;
}

static lws_ss_state_return_t
http_post_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	http_post_t *g = (http_post_t *)userobj;

	lwsl_ss_user(lws_ss_from_user(g), "RX %zu, flags 0x%x", len,
					  (unsigned int)flags);

	lwsl_hexdump_notice(in, len);

	if ((flags & LWSSS_FLAG_EOM) == LWSSS_FLAG_EOM)
		/* We received the whole response */
		test_result &= ~2;

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
http_post_state(void *userobj, void *h_src, lws_ss_constate_t state,
		lws_ss_tx_ordinal_t ack)
{
	http_post_t *g = (http_post_t *)userobj;

	switch ((int)state) {
	case LWSSSCS_CREATING:
		if (lws_ss_set_metadata(lws_ss_from_user(g), "ctype",
				    "multipart/form-data;boundary=\"boundary\"",
				    39))
			return LWSSSSRET_DISCONNECT_ME;

		/* provide a hint about the payload size */
		g->pos = 0;
		g->payload = postbody;
		g->size = strlen(g->payload);

		lwsl_ss_user(lws_ss_from_user(g), "Preparing to send %zu",
						  g->size);

		return lws_ss_request_tx_len(lws_ss_from_user(g),
						(unsigned long)g->size);

	case LWSSSCS_CONNECTED:
		return lws_ss_request_tx(lws_ss_from_user(g));

	case LWSSSCS_QOS_ACK_REMOTE: /* server liked our request */
		test_result &= ~1;
		break;

	case LWSSSCS_DISCONNECTED: /* for our example, disconnect = done */
		lws_default_loop_exit(lws_ss_cx_from_user(g));
		break;
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("minpost", http_post_t)
	.tx		= http_post_tx,
	.rx		= http_post_rx,
	.state		= http_post_state,
};
