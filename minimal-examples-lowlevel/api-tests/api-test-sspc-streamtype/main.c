/*
 * lws-api-test-sspc-streamtype
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fence for the serialized client (sspc) streamtype length cap: the
 * streamtype is serialized to the proxy inside a fixed-size frame, and the
 * proxy-side parser can only accept streamtypes up to a fixed maximum
 * length.  Applications passing an over-long streamtype must be refused at
 * creation time, before any serialization is attempted, rather than
 * silently composing a frame that claims more than was written into it.
 */

#include <libwebsockets.h>
#include <string.h>

/* streamtype long enough to overrun the sspc tx scratch if it were copied */
#define OVERLONG_LEN	60

static lws_ss_state_return_t
myss_state(void *userobj, void *sh, lws_ss_constate_t state,
	   lws_ss_tx_ordinal_t ack)
{
	return LWSSSSRET_OK;
}

typedef struct myss {
	struct lws_ss_handle	*ss;
	void			*opaque_data;
} myss_t;

static int
try_create(struct lws_context *cx, const char *streamtype)
{
	lws_ss_info_t ssi;

	memset(&ssi, 0, sizeof(ssi));
	ssi.handle_offset		= offsetof(myss_t, ss);
	ssi.opaque_user_data_offset	= offsetof(myss_t, opaque_data);
	ssi.state			= myss_state;
	ssi.user_alloc			= sizeof(myss_t);
	ssi.streamtype			= streamtype;

	return !!lws_sspc_create(cx, 0, &ssi, NULL, NULL, NULL, NULL);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	char name[LWS_SS_SER_STREAMTYPE_MAX_LEN + 2];
	char overlong[OVERLONG_LEN + 1];
	size_t n;
	int fails = 0;
	struct lws_sspc_handle *h_boundary = NULL;
	lws_ss_info_t ssi;

	(void)argc;
	(void)argv;

	lws_context_info_defaults(&info, NULL);

	/*
	 * We don't need a live proxy for this test: the length cap fires at
	 * creation time, before any connection attempt.  Point at a UDS path
	 * that doesn't exist so nothing accidental can succeed either.
	 */

	info.ss_proxy_bind	= "/tmp/lws-api-test-sspc-streamtype";
	info.ss_proxy_address	= "/tmp/lws-api-test-sspc-streamtype";
	info.port		= CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * Legs that must be refused: one over the cap, and one long enough
	 * to overrun the client-side tx composition scratch
	 */

	for (n = 0; n < sizeof(name) - 1; n++)
		name[n] = (char)('a' + (n % 26));
	name[sizeof(name) - 1] = '\0';

	if (!try_create(cx, name)) {
		lwsl_err("%s: %u-char streamtype not refused\n", __func__,
			 (unsigned int)(sizeof(name) - 1));
		fails++;
	}

	memset(overlong, 'z', sizeof(overlong) - 1);
	overlong[sizeof(overlong) - 1] = '\0';

	if (!try_create(cx, overlong)) {
		lwsl_err("%s: %u-char streamtype not refused\n", __func__,
			 (unsigned int)(sizeof(overlong) - 1));
		fails++;
	}

	/*
	 * Boundary leg: the longest streamtype the serialization can carry
	 * must still be accepted.  No proxy is up, so nothing further can
	 * happen; we destroy the handle immediately.
	 */

	memset(&ssi, 0, sizeof(ssi));
	ssi.handle_offset		= offsetof(myss_t, ss);
	ssi.opaque_user_data_offset	= offsetof(myss_t, opaque_data);
	ssi.state			= myss_state;
	ssi.user_alloc			= sizeof(myss_t);
	memset(name, 'y', LWS_SS_SER_STREAMTYPE_MAX_LEN);
	name[LWS_SS_SER_STREAMTYPE_MAX_LEN] = '\0';
	ssi.streamtype			= name;

	if (lws_sspc_create(cx, 0, &ssi, NULL, &h_boundary, NULL, NULL)) {
		lwsl_err("%s: boundary-length streamtype refused\n", __func__);
		fails++;
	}

	if (h_boundary)
		lws_sspc_destroy(&h_boundary);

	lws_context_destroy(cx);

	if (fails) {
		lwsl_user("Completed: failed\n");
		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
