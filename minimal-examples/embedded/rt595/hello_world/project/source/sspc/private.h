/*
 * rt595-sspc-binance
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

/* boilerplate for LWS_ONLY_SSPC Secure Streams
 * LWS_SS_USE_SSPC should be defined by cmake
 */

#define lws_context lws_context_standalone
#undef LWS_SS_USE_SSPC
#define LWS_SS_USE_SSPC
#undef STANDALONE
#define STANDALONE
#include <libwebsockets.h>

typedef struct vcring {
	uint8_t log_ring[4096];
	unsigned int lrh, lrt;
} vcring_t;

extern vcring_t vcr_log, vcr_txp_out, vcr_txp_in;

long long
atoll(const char *s);

size_t
space_available(vcring_t *v);
int
append_vcring(vcring_t *v, const uint8_t *b, size_t l);
size_t
next_chonk(vcring_t *v, const uint8_t ** pp);
void
consume_chonk(vcring_t *v, size_t n);

extern lws_dll2_owner_t scheduler;
extern lws_transport_mux_t *tm;

/* our transport related apis */

extern const lws_transport_client_ops_t lws_sss_ops_client_serial;
void serial_handle_events(lws_transport_mux_t *tm);

/* our SS bindings */

extern const lws_ss_info_t ssi_binance_t,  /* binance-ss.c */
			   ssi_get_t;	 /* get-ss.c */
