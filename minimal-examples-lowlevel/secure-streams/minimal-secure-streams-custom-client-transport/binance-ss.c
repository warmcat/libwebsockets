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
 * Because this links against the cut-down liblws-sspc instead of libwebsockets,
 */

#define LWS_SS_USE_SSPC

/* We use the lws headers, but we link against liblws-sspc, not libwebsockets */
#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>

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
	char			msgbuf[10240];
	size_t			msg_len;

	range_t			e_lat_range;
	range_t			price_range;
} binance_t;

/*
 * Since we don't link to libwebsockets library, we need to bring in our own
 * copies of any lws apis we use in the user Binance SS code
 */

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

/*
 * Rest of the file is Binance application SS processing (UNCHANGED from
 * minimal-secure-streams-binance)
 */

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
		lwsl_user("%s: price: min: %llu¢, max: %llu¢, avg: %llu¢, "
			    "(%d prices/s)\n", __func__,
			    (unsigned long long)bin->price_range.lowest,
			    (unsigned long long)bin->price_range.highest,
			    (unsigned long long)(bin->price_range.sum /
						    bin->price_range.samples),
			    bin->price_range.samples);
	if (bin->e_lat_range.samples)
		lwsl_user("%s: elatency: min: %llums, max: %llums, "
			    "avg: %llums, (%d msg/s)\n", __func__,
			    (unsigned long long)bin->e_lat_range.lowest / 1000,
			    (unsigned long long)bin->e_lat_range.highest / 1000,
			    (unsigned long long)(bin->e_lat_range.sum /
					   bin->e_lat_range.samples) / 1000,
			    bin->e_lat_range.samples);

	range_reset(&bin->e_lat_range);
	range_reset(&bin->price_range);
}

static lws_ss_state_return_t
binance_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	binance_t *bin = (binance_t *)userobj;
	uint64_t latency_us, now_us;
	char numbuf[16];
	uint64_t price;
	const char *p;
	size_t alen;

	if (flags & LWSSS_FLAG_SOM)
		bin->msg_len = 0;

	if (bin->msg_len + len < sizeof(bin->msgbuf)) {
		memcpy(bin->msgbuf + bin->msg_len, in, len);
		bin->msg_len += len;
	}

	/* assemble a full message */
	if (!(flags & LWSSS_FLAG_EOM))
		return LWSSSSRET_OK;

	//lwsl_notice("%s: chunk len %d\n", __func__, (int)len);

	now_us = (uint64_t)get_us_timeofday();

	p = lws_json_simple_find(bin->msgbuf, bin->msg_len, "\"depthUpdate\"",
				 &alen);
	if (!p)
		return LWSSSSRET_OK;

	p = lws_json_simple_find(bin->msgbuf, bin->msg_len, "\"E\":", &alen);
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

	p = lws_json_simple_find(bin->msgbuf, bin->msg_len, "\"a\":[[\"", &alen);
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

	lwsl_ss_info(bin->ss, "%s, ord 0x%x",
		     lws_ss_state_name(state), (unsigned int)ack);

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

const lws_ss_info_t ssi_binance = {
	.handle_offset		  = offsetof(binance_t, ss),
	.opaque_user_data_offset  = offsetof(binance_t, opaque_data),
	.rx			  = binance_rx,
	.state			  = binance_state,
	.user_alloc		  = sizeof(binance_t),
	.streamtype		  = "binance", /* bind to corresponding policy */
};
