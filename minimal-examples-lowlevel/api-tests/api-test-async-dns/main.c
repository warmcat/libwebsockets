/*
 * lws-api-test-async-dns
 *
 * Written in 2019-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This api test confirms various kinds of async dns apis
 */

#include <libwebsockets.h>
#include <signal.h>

static int interrupted, dtest, ok, fail, _exp = 30;
struct lws_context *context;

/*
 * These are used to test the apis to parse and print ipv4 / ipv6 literal
 * address strings for various cases.
 *
 * Expected error cases are not used to test the ip data -> string api.
 */

static const struct ipparser_tests {
	const char	*test;
	int		rlen;
	const char	*emit_test;
	int		emit_len;
	uint8_t		b[16];
} ipt[] = {
	{ "2001:db8:85a3:0:0:8a2e:370:7334", 16,
	  "2001:db8:85a3::8a2e:370:7334", 28,
		{ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
		  0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 } },

	{ "2001:db8:85a3::8a2e:370:7334", 16,
	  "2001:db8:85a3::8a2e:370:7334", 28,
		{ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
		  0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 } },

	{ "::1", 16, "::1", 3,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "::",  16, "::", 2,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },

	{ "::ffff:192.0.2.128", 16,  "::ffff:192.0.2.128", 18,
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x80 } },

	{ "cats", -1, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "onevalid.bogus.warmcat.com", -1, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "1.cat.dog.com", -1, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ ":::1", -8, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "0:0::0:1", 16, "::1", 3,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "1.2.3.4", 4, "1.2.3.4", 7, { 1, 2, 3, 4 } },
};

#define TEST_FLAG_NOCHECK_RESULT_IP 0x100000

static struct async_dns_tests {
	const char *dns_name;
	int recordtype;
	int addrlen;
	uint8_t ads[16];
} adt[] = {
	{ "warmcat.com", LWS_ADNS_RECORD_A, 4,
		{ 46, 105, 127, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
		/* test coming from cache */
	{ "warmcat.com", LWS_ADNS_RECORD_A, 4,
		{ 46, 105, 127, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "libwebsockets.org", LWS_ADNS_RECORD_A, 4,
		{ 46, 105, 127, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "doesntexist", LWS_ADNS_RECORD_A, 0,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "localhost", LWS_ADNS_RECORD_A, 4,
		{ 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "ipv4only.warmcat.com", LWS_ADNS_RECORD_A, 4,
		{ 212, 83, 179, 61, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "onevalid.bogus.warmcat.com", LWS_ADNS_RECORD_A, 4,
		{ 212, 83, 179, 61, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
#if defined(LWS_WITH_IPV6)
	{ "mail.warmcat.com", LWS_ADNS_RECORD_AAAA, 16, /* check ipv6 */
		{ 0x20, 0x01, 0x0b, 0xc8, 0x60, 0x10, 0x02, 0x13,
				0x02, 0x08, 0xa2, 0xff, 0xfe, 0x0c, 0x72, 0xce, } },
	{ "ipv6only.warmcat.com", LWS_ADNS_RECORD_AAAA, 16, /* check ipv6 */
		{ 0x20, 0x01, 0x0b, 0xc8, 0x60, 0x10, 0x02, 0x13,
				0x02, 0x08, 0xa2, 0xff, 0xfe, 0x0c, 0x72, 0xce, } },
#endif
//	{ "c.msn.com", TEST_FLAG_NOCHECK_RESULT_IP |
//		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A, 4,
//		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "assets.msn.com", TEST_FLAG_NOCHECK_RESULT_IP |
		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A, 4,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "e28578.d.akamaiedge.net", TEST_FLAG_NOCHECK_RESULT_IP |
		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A, 0,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "a-0003.a-msedge.net", TEST_FLAG_NOCHECK_RESULT_IP |
		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A, 0,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
//	{ "c-msn-com-europe-vip.trafficmanager.net", TEST_FLAG_NOCHECK_RESULT_IP |
//		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A, 0,
//		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
//	{ "c-msn-com-europe-vip.trafficmanager.net", TEST_FLAG_NOCHECK_RESULT_IP |
//		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A, 0,
//		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
};

static uint8_t canned_c_msn_com[] = {
	0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02,
	0x00, 0x01, 0x00, 0x00, 0x01, 0x63, 0x03, 0x6D,
	0x73, 0x6E, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00,
	0x1C, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x05, 0x00,
	0x01, 0x00, 0x00, 0x54, 0x5E, 0x00, 0x24, 0x0F,
	0x63, 0x2D, 0x6D, 0x73, 0x6E, 0x2D, 0x63, 0x6F,
	0x6D, 0x2D, 0x6E, 0x73, 0x61, 0x74, 0x63, 0x0E,
	0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x6D,
	0x61, 0x6E, 0x61, 0x67, 0x65, 0x72, 0x03, 0x6E,
	0x65, 0x74, 0x00, 0xC0, 0x27, 0x00, 0x05, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x17, 0x14,
	0x63, 0x2D, 0x6D, 0x73, 0x6E, 0x2D, 0x63, 0x6F,
	0x6D, 0x2D, 0x65, 0x75, 0x72, 0x6F, 0x70, 0x65,
	0x2D, 0x76, 0x69, 0x70, 0xC0, 0x37, 0xC0, 0x37,
	0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1C,
	0x00, 0x2E, 0x03, 0x74, 0x6D, 0x31, 0x06, 0x64,
	0x6E, 0x73, 0x2D, 0x74, 0x6D, 0xC0, 0x12, 0x0A,
	0x68, 0x6F, 0x73, 0x74, 0x6D, 0x61, 0x73, 0x74,
	0x65, 0x72, 0xC0, 0x37, 0x77, 0x64, 0x96, 0x60,
	0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x01, 0x2C,
	0x00, 0x24, 0xEA, 0x00, 0x00, 0x00, 0x00, 0x1E,
}, canned_assets_msn_com[] = {
	219,29,129,128,0,1,0,2,0,1,0,0,6,97,115,115,101,116,115,3,109,115,
	110,3,99,111,109,0,0,28,0,1,192,12,0,5,0,1,0,0,81,199,0,28,6,97,115,
	115,101,116,115,3,109,115,110,3,99,111,109,7,101,100,103,101,107,101,
	121,3,110,101,116,0,192,44,0,5,0,1,0,0,0,235,0,22,6,101,50,56,53,55,
	56,1,100,10,97,107,97,109,97,105,101,100,103,101,192,67,192,91,0,6,
	0,1,0,0,1,79,0,46,3,110,48,100,192,93,10,104,111,115,116,109,97,115,
	116,101,114,6,97,107,97,109,97,105,192,23,97,106,246,231,0,0,3,232,0,
	0,3,232,0,0,3,232,0,0,7,8,
}, canned_e28578_d_akamaiedge_net[] = {
	20,191,129,128,0,1,0,0,0,1,0,0,6,101,50,56,53,55,56,1,100,10,97,107,97,
	109,97,105,101,100,103,101,3,110,101,116,0,0,28,0,1,192,19,0,6,0,1,0,0,
	1,17,0,49,3,110,48,100,192,21,10,104,111,115,116,109,97,115,116,101,114,
	6,97,107,97,109,97,105,3,99,111,109,0,97,107,217,31,0,0,3,232,0,0,3,232,
	0,0,3,232,0,0,7,8
}, canned_a_0003_a_msedge_net[] = {
	126,215,129,128,0,1,0,0,0,1,0,0,6,97,45,48,48,48,51,8,97,45,109,115,101,
	100,103,101,3,110,101,116,0,0,28,0,1,192,19,0,6,0,1,0,0,0,172,0,48,3,
	110,115,49,192,19,6,109,115,110,104,115,116,9,109,105,99,114,111,115,
	111,102,116,3,99,111,109,0,120,43,34,229,0,0,7,8,0,0,3,132,0,36,234,0,
	0,0,0,240
}, canned_c_msn_com_europe_vip_trafficmanager_net[] = {
	73,87,129,128,0,1,0,0,0,1,0,0,20,99,45,109,115,110,45,99,111,109,45,101,
	117,114,111,112,101,45,118,105,112,14,116,114,97,102,102,105,99,109,97,
	110,97,103,101,114,3,110,101,116,0,0,28,0,1,192,33,0,6,0,1,0,0,0,30,0,
	49,3,116,109,49,6,100,110,115,45,116,109,3,99,111,109,0,10,104,111,115,
	116,109,97,115,116,101,114,192,33,7,11,234,133,0,0,3,132,0,0,1,44,0,36,
	234,0,0,0,0,30,
};

static lws_sorted_usec_list_t sul, sul_timeout;

struct lws *
cb1(struct lws *wsi_unused, const char *ads, const struct addrinfo *a, int n,
    void *opaque);

static int first = 1;

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	interrupted = 1;
	lws_cancel_service(context);
}

static void
next_test_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_adns_q *q;
	int m;

	lwsl_notice("%s: querying %s\n", __func__, adt[dtest].dns_name);

	m = lws_async_dns_query(context, 0,
				adt[dtest].dns_name,
				(adns_query_type_t)adt[dtest].recordtype, cb1, NULL,
				context, &q);
	if (m != LADNS_RET_CONTINUING && m != LADNS_RET_FOUND && m != LADNS_RET_FAILED_WSI_CLOSED) {
		lwsl_err("%s: adns 1: %s failed: %d\n", __func__, adt[dtest].dns_name, m);
		interrupted = 1;
	}

	if (adt[dtest].recordtype & LWS_ADNS_SYNTHETIC) {

		lwsl_notice("%s: injecting result\n", __func__);

		if (!strcmp(adt[dtest].dns_name, "c.msn.com")) {
			canned_c_msn_com[0] = (uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_c_msn_com[1] = (uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
					   canned_c_msn_com,
					   sizeof(canned_c_msn_com));
		}

		if (!strcmp(adt[dtest].dns_name, "assets.msn.com")) {
			canned_assets_msn_com[0] = (uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_assets_msn_com[1] = (uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
					   canned_assets_msn_com,
					   sizeof(canned_assets_msn_com));
		}

		if (!strcmp(adt[dtest].dns_name, "e28578.d.akamaiedge.net")) {
			canned_e28578_d_akamaiedge_net[0] = (uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_e28578_d_akamaiedge_net[1] = (uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
					canned_e28578_d_akamaiedge_net,
					   sizeof(canned_e28578_d_akamaiedge_net));
		}
		if (!strcmp(adt[dtest].dns_name, "a-0003.a-msedge.net")) {
			canned_a_0003_a_msedge_net[0] = (uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_a_0003_a_msedge_net[1] = (uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
					canned_a_0003_a_msedge_net,
					   sizeof(canned_a_0003_a_msedge_net));
		}
		if (first &&
		    !strcmp(adt[dtest].dns_name, "c-msn-com-europe-vip.trafficmanager.net")) {
			first = 0;
			canned_c_msn_com_europe_vip_trafficmanager_net[0] =
					(uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_c_msn_com_europe_vip_trafficmanager_net[1] =
					(uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
				canned_c_msn_com_europe_vip_trafficmanager_net,
				sizeof(canned_c_msn_com_europe_vip_trafficmanager_net));
		}
	}
}

struct lws *
cb1(struct lws *wsi_unused, const char *ads, const struct addrinfo *a, int n,
    void *opaque)
{
	const struct addrinfo *ac = a;
	int ctr = 0, alen;
	uint8_t *addr;
	char buf[64];

	dtest++;

	if (!ac)
		lwsl_warn("%s: no results\n", __func__);

	/* dump the results */

	while (ac) {
		if (ac->ai_family == AF_INET) {
			addr = (uint8_t *)&(((struct sockaddr_in *)
					ac->ai_addr)->sin_addr.s_addr);
			alen = 4;
		} else {
			addr = (uint8_t *)&(((struct sockaddr_in6 *)
					ac->ai_addr)->sin6_addr.s6_addr);
			alen = 16;
		}
		strcpy(buf, "unknown");
		lws_write_numeric_address(addr, alen, buf, sizeof(buf));

		lwsl_warn("%s: %d: %s %d %s\n", __func__, ctr++, ads, alen, buf);

		ac = ac->ai_next;
	}

	ac = a;
	while (ac) {
		if (ac->ai_family == AF_INET) {
			addr = (uint8_t *)&(((struct sockaddr_in *)
					ac->ai_addr)->sin_addr.s_addr);
			alen = 4;
		} else {
#if defined(LWS_WITH_IPV6)
			addr = (uint8_t *)&(((struct sockaddr_in6 *)
					ac->ai_addr)->sin6_addr.s6_addr);
			alen = 16;
#else
			goto again;
#endif
		}
		if ((adt[dtest - 1].recordtype & TEST_FLAG_NOCHECK_RESULT_IP) ||
		    (alen == adt[dtest - 1].addrlen &&
		    !memcmp(adt[dtest - 1].ads, addr, (unsigned int)alen))) {
			ok++;
			goto next;
		}
#if !defined(LWS_WITH_IPV6)
again:
#endif
		ac = ac->ai_next;
	}

	/* testing for NXDOMAIN? */

	if (!a && !adt[dtest - 1].addrlen) {
		ok++;
		goto next;
	}

	lwsl_err("%s: dns test %d: no match\n", __func__, dtest);
	fail++;

next:
	lws_async_dns_freeaddrinfo(&a);
	if (dtest == (int)LWS_ARRAY_SIZE(adt)) {
		interrupted = 1;
		lws_cancel_service(context);
	} else
		lws_sul_schedule(context, 0, &sul, next_test_cb, 1);

	return NULL;
}

static lws_sorted_usec_list_t sul_l;

struct lws *
cb_loop(struct lws *wsi_unused, const char *ads, const struct addrinfo *a, int n,
		void *opaque)
{
	if (!a) {
		lwsl_err("%s: no results\n", __func__);
		return NULL;
	}

	lwsl_notice("%s: addrinfo %p\n", __func__, a);\
	lws_async_dns_freeaddrinfo(&a);

	return NULL;
}


static void
sul_retry_l(struct lws_sorted_usec_list *sul)
{
	int m;

	lwsl_user("%s: starting new query\n", __func__);

	m = lws_async_dns_query(context, 0, "warmcat.com",
				    (adns_query_type_t)LWS_ADNS_RECORD_A,
				    cb_loop, NULL, context, NULL);
	switch (m) {
	case LADNS_RET_FAILED_WSI_CLOSED:
		lwsl_warn("%s: LADNS_RET_FAILED_WSI_CLOSED "
			  "(== from cache / success in this test)\n", __func__);
		break;
	case LADNS_RET_NXDOMAIN:
		lwsl_warn("%s: LADNS_RET_NXDOMAIN\n", __func__);
		break;
	case LADNS_RET_TIMEDOUT:
		lwsl_warn("%s: LADNS_RET_TIMEDOUT\n", __func__);
		break;
	case LADNS_RET_FAILED:
		lwsl_warn("%s: LADNS_RET_FAILED\n", __func__);
		break;
	case LADNS_RET_FOUND:
		lwsl_warn("%s: LADNS_RET_FOUND\n", __func__);
		break;
	case LADNS_RET_CONTINUING:
		lwsl_warn("%s: LADNS_RET_CONTINUING\n", __func__);
		break;
	}

	lws_sul_schedule(context, 0, &sul_l, sul_retry_l, 5 * LWS_US_PER_SEC);
}

void sigint_handler(int sig)
{
	interrupted = 1;
}

int
fixup(int idx)
{
	struct addrinfo hints, *ai;
	int m;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	m = getaddrinfo(adt[idx].dns_name, "80", &hints, &ai);
	if (m) {
		lwsl_err("Unable to look up %s: %s", adt[0].dns_name,
				gai_strerror(m));
		return 1;
	}
	adt[idx].ads[0] = (uint8_t)((struct sockaddr *)ai->ai_addr)->sa_data[2];
	adt[idx].ads[1] = (uint8_t)((struct sockaddr *)ai->ai_addr)->sa_data[3];
	adt[idx].ads[2] = (uint8_t)((struct sockaddr *)ai->ai_addr)->sa_data[4];
	adt[idx].ads[3] = (uint8_t)((struct sockaddr *)ai->ai_addr)->sa_data[5];

	freeaddrinfo(ai);

	lwsl_notice("%s: %u.%u.%u.%u\n", __func__,
		adt[idx].ads[0], adt[idx].ads[1], adt[idx].ads[2], adt[idx].ads[3]);

	return 0;
}

int
main(int argc, const char **argv)
{
	int n = 1, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	uint8_t mac[6];
	const char *p;

	/* fixup dynamic target addresses we're testing against */

	fixup(0);
	fixup(1);
	fixup(2);
	fixup(5);
	fixup(6);

	/* the normal lws init */

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: Async DNS\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (lws_cmdline_option(argc, argv, "-l")) {
		lws_sul_schedule(context, 0, &sul_l, sul_retry_l, LWS_US_PER_SEC);
		goto evloop;
	}


	/* ip address parser tests */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(ipt); n++) {
		uint8_t u[16];
		int m = lws_parse_numeric_address(ipt[n].test, u, sizeof(u));

		if (m != ipt[n].rlen) {
			lwsl_err("%s: fail %s ret %d\n",
					__func__, ipt[n].test, m);
			fail++;
			continue;
		}

		if (m > 0) {
			if (memcmp(ipt[n].b, u, (unsigned int)m)) {
				lwsl_err("%s: fail %s compare\n", __func__,
						ipt[n].test);
				lwsl_hexdump_notice(u, (unsigned int)m);
				fail++;
				continue;
			}
		}
		ok++;
	}

	/* ip address formatter tests */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(ipt); n++) {
		char buf[64];
		int m;

		/* don't attempt to reverse the ones that are meant to fail */
		if (ipt[n].rlen < 0)
			continue;

		m = lws_write_numeric_address(ipt[n].b, ipt[n].rlen, buf,
						sizeof(buf));
		if (m != ipt[n].emit_len) {
			lwsl_err("%s: fail %s ret %d\n",
					__func__, ipt[n].emit_test, m);
			fail++;
			continue;
		}

		if (m > 0) {
			if (strcmp(ipt[n].emit_test, buf)) {
				lwsl_err("%s: fail %s compare\n", __func__,
						ipt[n].test);
				lwsl_hexdump_notice(buf, (unsigned int)m);
				fail++;
				continue;
			}
		}
		ok++;
	}

	/* mac address parser tests */

	if (lws_parse_mac("11:ff:ce:CE:22:33", mac)) {
		lwsl_err("%s: mac fail 1\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	} else
		if (mac[0] != 0x11 || mac[1] != 0xff || mac[2] != 0xce ||
		    mac[3] != 0xce || mac[4] != 0x22 || mac[5] != 0x33) {
			lwsl_err("%s: mac fail 2\n", __func__);
			lwsl_hexdump_notice(mac, 6);
			fail++;
		}
	if (!lws_parse_mac("11:ff:ce:CE:22:3", mac)) {
		lwsl_err("%s: mac fail 3\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	}
	if (!lws_parse_mac("11:ff:ce:CE:22", mac)) {
		lwsl_err("%s: mac fail 4\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	}
	if (!lws_parse_mac("11:ff:ce:CE:22:", mac)) {
		lwsl_err("%s: mac fail 5\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	}
	if (!lws_parse_mac("11:ff:ce:CE22", mac)) {
		lwsl_err("%s: mac fail 6\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	}

#if !defined(LWS_WITH_IPV6)
	_exp -= 2;
#endif

	/* kick off the async dns tests */

	lws_sul_schedule(context, 0, &sul, next_test_cb, 1);
	lws_sul_schedule(context, 0, &sul_timeout, timeout_cb, 45 * LWS_USEC_PER_SEC);

evloop:
	/* the usual lws event loop */

	n = 1;
	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	if (fail || ok != _exp)
		lwsl_user("Completed: PASS: %d / %d, FAIL: %d\n", ok, _exp,
				fail);
	else
		lwsl_user("Completed: ALL PASS: %d / %d\n", ok, _exp);

	return !(ok == _exp && !fail);
}
