/*
 * rt595-sspc-binance
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
 */

#include "private.h"
#include <string.h>
#include <signal.h>
#include <ctype.h>

extern uint64_t
get_us_timeofday(void);

typedef struct range {
	uint64_t		sum;
	uint64_t		lowest;
	uint64_t		highest;

	unsigned int		samples;
} range_t;

LWS_SS_USER_TYPEDEF
	uint64_t		data_in;
	uint64_t		data_in_last_sec;

	lws_sorted_usec_list_t	sul_hz;	     /* 1hz summary dump */
	char			msgbuf[8192];
	size_t			msg_len;

	range_t			e_lat_range;
	range_t			price_range;
} binance_t;


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
		lwsl_user("%s: elatency: min: %lums, max: %lums, "
			    "avg: %lums, (%d msg/s, %lu KiBytes/s SS RX)\n",
			    __func__,
			    (unsigned long)(bin->e_lat_range.lowest / 1000),
			    (unsigned long)(bin->e_lat_range.highest / 1000),
			    (unsigned long)((bin->e_lat_range.sum /
					   bin->e_lat_range.samples) / 1000),
			    bin->e_lat_range.samples,
			    (unsigned long)((bin->data_in -
					     bin->data_in_last_sec) / 1024));

	range_reset(&bin->e_lat_range);
	range_reset(&bin->price_range);

	bin->data_in_last_sec = bin->data_in;
}

static lws_ss_state_return_t
binance_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	binance_t *bin = (binance_t *)userobj;
	uint64_t latency_us, now_us, l1;
	const uint8_t *msg;
	char numbuf[20];
	uint64_t price;
	const char *p;
	size_t alen;

	bin->data_in += len;

	msg = bin->msgbuf;
	if (flags & LWSSS_FLAG_SOM) {
		bin->msg_len = 0;
		if (flags & LWSSS_FLAG_EOM) {
			msg = in;
			bin->msg_len = len;
			goto handle;
		}
	}

	if (bin->msg_len + len < sizeof(bin->msgbuf)) {
		memcpy(bin->msgbuf + bin->msg_len, in, len);
		bin->msg_len += len;
	}

	/* assemble a full message */
	if (!(flags & LWSSS_FLAG_EOM))
		return LWSSSSRET_OK;


handle:
	//lwsl_notice("%s: chunk len %d\n", __func__, (int)len);

	now_us = (uint64_t)get_us_timeofday();

	p = lws_json_simple_find(msg, bin->msg_len, "\"depthUpdate\"",
				 &alen);
	if (!p)
		return LWSSSSRET_OK;

	p = lws_json_simple_find(msg, bin->msg_len, "\"E\":", &alen);
	if (!p) {
		lwsl_err("%s: no E JSON\n", __func__);
		return LWSSSSRET_OK;
	}

	lws_strnncpy(numbuf, p, alen, sizeof(numbuf));
	l1 = ((uint64_t)atoll(numbuf) * LWS_US_PER_MS);
	latency_us = now_us - l1;

//	lwsl_notice("%s: now_us adjusted %llu, %llu, %llu, %s\n", __func__, tm->us_unixtime_peer, now_us, l1, numbuf);


	if (latency_us < bin->e_lat_range.lowest)
		bin->e_lat_range.lowest = latency_us;
	if (latency_us > bin->e_lat_range.highest)
		bin->e_lat_range.highest = latency_us;

	bin->e_lat_range.sum += latency_us;
	bin->e_lat_range.samples++;

	p = lws_json_simple_find(msg, bin->msg_len, "\"a\":[[\"", &alen);
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

LWS_SS_INFO("binance", binance_t)
	.rx			  = binance_rx,
	.state			  = binance_state,
};
