/*
 * lws-minimal-secure-streams-custom-proxy-transport
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *                         Kutoga <kutoga@user.github.invalid>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This is a version of minimal-secure-streams-binance that uses a custom
 * SS Serialization transport.
 *
 * Lws provides a wsi-based SS serialization transport, so you can connect to
 * SS proxy over tcp or Unix Domain Sockets.  This example shows how to create
 * SS proxy clients with no dependency on libwebsockets library.
 *
 * libwebsockets header is used, but the application does not have an
 * lws_context and does not link against libwebsockets, instead using a much
 * smaller SSPC-only library liblws-sspc (built during lws build).
 */

#define LWS_SS_USE_SSPC

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>

static int interrupted;
extern const struct lws_protocols lws_sspc_protocols[2];

typedef struct range {
	uint64_t		sum;
	uint64_t		lowest;
	uint64_t		highest;

	unsigned int		samples;
} range_t;

typedef struct binance {
	struct lws_ss_handle 	*ss;
	void			*opaque_data;

	lws_sorted_usec_list_t	sul_hz;	     /* 1hz summary dump */

	range_t			e_lat_range;
	range_t			price_range;
} binance_t;

/****** Part 1 / 6: define missing references from lws_sspc library */

void
lws_sul_schedule(struct lws_context_standalone *ctx, int tsi, lws_sorted_usec_list_t *sul,
		 sul_cb_t _cb, lws_usec_t _us)
{

}

void
lws_sul_cancel(lws_sorted_usec_list_t *sul)
{

}

lws_usec_t
lws_now_usecs(void)
{
#if defined(LWS_HAVE_CLOCK_GETTIME)
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;

	return (((lws_usec_t)ts.tv_sec) * LWS_US_PER_SEC) +
			((lws_usec_t)ts.tv_nsec / LWS_NS_PER_US);
#else
	struct timeval now;

	gettimeofday(&now, NULL);
	return (((lws_usec_t)now.tv_sec) * LWS_US_PER_SEC) +
			(lws_usec_t)now.tv_usec;
#endif
}
void
__lws_logv(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
	   int filter, const char *_fun, const char *format, va_list ap)
{
	char logbuf[100];
	int n;

	n = vsnprintf(logbuf, sizeof(logbuf), format, ap);
	fprintf(stderr, logbuf, n);
}

/****** Part 2 / 6: bring in lws apis needed by user code */

const char *
lws_nstrstr(const char *buf, size_t len, const char *name, size_t nl)
{
	const char *end = buf + len - nl + 1;
	size_t n;

	if (nl > len)
		/* it cannot be found if the needle is longer than the haystack */
		return NULL;

	while (buf < end) {
		if (*buf != name[0]) {
			buf++;
			continue;
		}

		if (nl == 1)
			/* single char match, we are done */
			return buf;

		if (buf[nl - 1] == name[nl - 1]) {
			/*
			 * This is looking interesting then... the first
			 * and last chars match, let's check the insides
			 */
			n = 1;
			while (n < nl && buf[n] == name[n])
				n++;

			if (n == nl)
				/* it's a hit */
				return buf;
		}

		buf++;
	}

	return NULL;
}


const char *
lws_json_simple_find(const char *buf, size_t len, const char *name, size_t *alen)
{
	size_t nl = strlen(name);
	const char *np = lws_nstrstr(buf, len, name, nl),
		   *end = buf + len, *as;
	int qu = 0;

	if (!np)
		return NULL;

	np += nl;

	while (np < end && (*np == ' ' || *np == '\t'))
		np++;

	if (np >= end)
		return NULL;

	/*
	 * The arg could be lots of things after "name": with JSON, commonly a
	 * string like "mystring", true, false, null, [...] or {...} ... we want
	 * to handle common, simple cases cheaply with this; the user can choose
	 * a full JSON parser like lejp if it's complicated.  So if no opening
	 * quote, return until a terminator like , ] }.  If there's an opening
	 * quote, return until closing quote, handling escaped quotes.
	 */

	if (*np == '\"') {
		qu = 1;
		np++;
	}

	as = np;
	while (np < end &&
	       (!qu || *np != '\"') && /* end quote is EOT if quoted */
	       (qu || (*np != '}' && *np != ']' && *np != ',')) /* delimiters */
	) {
		if (qu && *np == '\\') /* skip next char if quoted escape */
			np++;
		np++;
	}

	*alen = (unsigned int)lws_ptr_diff(np, as);

	return as;
}

/****** Part 3 / 6: application data processing (unchanged from original) */

static void
range_reset(range_t *r)
{
	r->sum = r->highest = 0;
	r->lowest = 999999999999ull;
	r->samples = 0;
}

static uint64_t
get_us_timeofday(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (uint64_t)((lws_usec_t)tv.tv_sec * LWS_US_PER_SEC) +
			  (uint64_t)tv.tv_usec;
}

static uint64_t
pennies(const char *s)
{
	uint64_t price = (uint64_t)atoll(s) * 100;

	s = strchr(s, '.');

	if (s && isdigit(s[1]) && isdigit(s[2]))
		price = price + (uint64_t)((10 * (s[1] - '0')) + (s[2] - '0'));

	return price;
}

static void
sul_hz_cb(lws_sorted_usec_list_t *sul)
{
	binance_t *bin = lws_container_of(sul, binance_t, sul_hz);

	/*
	 * We are called once a second to dump statistics on the connection
	 */

	lws_sul_schedule(lws_ss_get_context(bin->ss), 0, &bin->sul_hz,
			 sul_hz_cb, LWS_US_PER_SEC);

	if (bin->price_range.samples)
		lwsl_notice("%s: price: min: %llu¢, max: %llu¢, avg: %llu¢, "
			    "(%d prices/s)\n", __func__,
			    (unsigned long long)bin->price_range.lowest,
			    (unsigned long long)bin->price_range.highest,
			    (unsigned long long)(bin->price_range.sum /
						    bin->price_range.samples),
			    bin->price_range.samples);
	if (bin->e_lat_range.samples)
		lwsl_notice("%s: elatency: min: %llums, max: %llums, "
			    "avg: %llums, (%d msg/s)\n", __func__,
			    (unsigned long long)bin->e_lat_range.lowest / 1000,
			    (unsigned long long)bin->e_lat_range.highest / 1000,
			    (unsigned long long)(bin->e_lat_range.sum /
					   bin->e_lat_range.samples) / 1000,
			    bin->e_lat_range.samples);

	range_reset(&bin->e_lat_range);
	range_reset(&bin->price_range);
}

/****** Part 4 / 6: SS communication (unchanged from original) */

static lws_ss_state_return_t
binance_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	binance_t *bin = (binance_t *)userobj;
	uint64_t latency_us, now_us;
	char numbuf[16];
	uint64_t price;
	const char *p;
	size_t alen;

	now_us = (uint64_t)get_us_timeofday();

	p = lws_json_simple_find((const char *)in, len, "\"depthUpdate\"",
				 &alen);
	if (!p)
		return LWSSSSRET_OK;

	p = lws_json_simple_find((const char *)in, len, "\"E\":", &alen);
	if (!p) {
		lwsl_err("%s: no E JSON\n", __func__);
		return LWSSSSRET_OK;
	}

	lws_strnncpy(numbuf, p, alen, sizeof(numbuf));
	latency_us = now_us - ((uint64_t)atoll(numbuf) * LWS_US_PER_MS);

	if (latency_us < bin->e_lat_range.lowest)
		bin->e_lat_range.lowest = latency_us;
	if (latency_us > bin->e_lat_range.highest)
		bin->e_lat_range.highest = latency_us;

	bin->e_lat_range.sum += latency_us;
	bin->e_lat_range.samples++;

	p = lws_json_simple_find((const char *)in, len, "\"a\":[[\"", &alen);
	if (!p)
		return LWSSSSRET_OK;

	lws_strnncpy(numbuf, p, alen, sizeof(numbuf));
	price = pennies(numbuf);

	if (price < bin->price_range.lowest)
		bin->price_range.lowest = price;
	if (price > bin->price_range.highest)
		bin->price_range.highest = price;

	bin->price_range.sum += price;
	bin->price_range.samples++;

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
binance_state(void *userobj, void *h_src, lws_ss_constate_t state,
	      lws_ss_tx_ordinal_t ack)
{
	binance_t *bin = (binance_t *)userobj;

	lwsl_ss_info(bin->ss, "%s (%d), ord 0x%x",
		     lws_ss_state_name((int)state), state, (unsigned int)ack);

	switch (state) {

	case LWSSSCS_CONNECTED:
		lws_sul_schedule(lws_ss_get_context(bin->ss), 0, &bin->sul_hz,
				 sul_hz_cb, LWS_US_PER_SEC);
		range_reset(&bin->e_lat_range);
		range_reset(&bin->price_range);

		return LWSSSSRET_OK;

	case LWSSSCS_DISCONNECTED:
		lws_sul_cancel(&bin->sul_hz);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static const lws_ss_info_t ssi_binance = {
	.handle_offset		  = offsetof(binance_t, ss),
	.opaque_user_data_offset  = offsetof(binance_t, opaque_data),
	.rx			  = binance_rx,
	.state			  = binance_state,
	.user_alloc		  = sizeof(binance_t),
	.streamtype		  = "binance", /* bind to corresponding policy */
};

/****** Part 5 / 6: custom transport to proxy */

/* client custom transport */

static int
lws_sss_transport_loopback_retry_connect(struct lws_sspc_handle *h)
{
#if 0
	/* loopback: create a channel directly at the proxy */

	if (lws_ssproxy_transport_new_conn(lws_sspc_get_context(h),
					   NULL, &pss->conn,
					   (lws_sss_priv_t)wsi)) {
		lwsl_err("%s: hangup from new_conn\n", __func__);
		return -1;
	}
#endif
	return 0;
}

static void
lws_sss_transport_loopback_req_write(lws_sss_priv_t *priv)
{
	/* for loopback, just immediately do the write to proxy side */

//	lws_sspc_transport_tx()
}

static int
lws_sss_transport_loopback_write(lws_sss_priv_t *priv, uint8_t *buf, size_t len)
{
#if 0
	struct lws *wsi = (struct lws *)*priv;

	if (lws_write(wsi, buf, len, LWS_WRITE_RAW) != (ssize_t)len) {
		lwsl_wsi_notice(wsi, "failed");

		return -1;
	}
#endif
	return 0;
}

static void
lws_sss_transport_loopback_close(lws_sss_priv_t *priv)
{
#if 0
	struct lws *wsi = (struct lws *)*priv;

	if (!wsi)
		return;

	lws_set_opaque_user_data(wsi, NULL);
	lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
	*priv = NULL;
#endif
}

static void
lws_sss_transport_loopback_stream_up(lws_sss_priv_t *priv)
{
//	struct lws *wsi = (struct lws *)*priv;

//	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
}

static const lws_sss_ops_client_t lws_sss_ops_client_loopback = {
	.retry_connect		= lws_sss_transport_loopback_retry_connect,
	.req_write		= lws_sss_transport_loopback_req_write,
	.write			= lws_sss_transport_loopback_write,
	.close			= lws_sss_transport_loopback_close,
	.stream_up		= lws_sss_transport_loopback_stream_up
};

/****** Part 6 / 6: init and custom event loop */

static struct lws_context_standalone cx = {
	.sss_ops_client		= &lws_sss_ops_client_loopback,
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{

	signal(SIGINT, sigint_handler);


	printf("LWS minimal Secure Streams binance client / custom SS proxy transport\n");
	if (lws_ss_create(&cx, 0, &ssi_binance, NULL, NULL, NULL, NULL)) {
		printf("failed to create secure stream\n");
		interrupted = 1;
	}


	printf("Completed\n");

	return 0;
}
