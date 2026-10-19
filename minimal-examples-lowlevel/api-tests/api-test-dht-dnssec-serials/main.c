/*
 * lws-api-test-dht-dnssec-serials
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The dnssec monitor shows a zone propagating by asking every node in the
 * DHT routing table which serial of it they hold, with the lws-dht-dnssec
 * plugin's query_serials().  Here the plugin, built into this test, is the
 * asking node (P), and a bare DHT node (S) on another vhost, in P's routing
 * table, answers it by hand:
 *
 *  - P's own copy of the zone is reported from inside the call
 *  - a second query for the same opaque replaces the first: S's answer to
 *    the first query's nonce, or to a forged one, is not reported, and S's
 *    answer to the second is, once, then the end of the query
 *  - S saying it holds no copy is reported as such, and so is P holding none
 *  - S not answering is reported when the query times out
 *  - a cancelled query reports nothing more
 *  - P answers S's SOA_REQ with the serial it holds, or that it holds none,
 *    echoing S's nonce
 *  - a bootstrap seed on loopback is recognised as this node, a
 *    documentation address is not
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define SERT_STORE	"./serials-store"
#define SERT_DOMAIN	"serials.example"
#define SERT_NONE	"none.example"
#define SERT_SERIAL_P	2026101901u
#define SERT_SERIAL_S	2026101903u
#define SERT_NONCE_LEN	DHT_DNSSEC_SERIAL_NONCE_LEN

static struct lws_context *context;
static struct lws_vhost *vh_p, *vh_s;
static struct lws_dht_ctx *dht_s;
static struct sockaddr_in sa_s, sa_p;
static lws_sorted_usec_list_t sul_step;
static lws_usec_t t_start, t_step;
static int step, fails;

static char hex_domain[65], hex_none[65];

/* what P's queries reported */

struct sert_reports {
	int		self, peer, end;
	uint8_t		self_state, peer_state;
	uint32_t	self_serial, peer_serial;
};

/* each query's opaque: what it was told */
static struct sert_reports rq[4];

/* the SOA_REQs and SOA_RSPs S saw from P */

static uint8_t s_req_nonce[2][SERT_NONCE_LEN];
static char s_req_hash[2][65];
static int s_reqs;

static struct lws_dht_msg s_rsp;
static uint8_t s_rsp_nonce[SERT_NONCE_LEN];
static int s_rsps;

static int
sert_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);
		fails++;

		return 1;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);

	return 0;
}

static void
sert_cb(void *opaque, const char *domain,
	const struct lws_dht_dnssec_serial_report *r)
{
	struct sert_reports *sr = (struct sert_reports *)opaque;

	if (!r) {
		sr->end++;
		return;
	}

	if (!r->sa) {
		sr->self++;
		sr->self_state = r->state;
		sr->self_serial = r->serial;
		return;
	}

	if (r->sa->sa_family != AF_INET ||
	    ((const struct sockaddr_in *)r->sa)->sin_port != sa_s.sin_port) {
		lwsl_err("%s: report from a node we don't know\n", __func__);
		fails++;
		return;
	}

	sr->peer++;
	sr->peer_state = r->state;
	sr->peer_serial = r->serial;
}

static int
sert_query(const char *domain, struct sert_reports *sr, int cancel)
{
	struct lws_dht_dnssec_query_serials_args a;

	memset(&a, 0, sizeof(a));
	a.vhost		= vh_p;
	a.domain	= domain;
	a.cb		= sert_cb;
	a.opaque	= sr;
	a.is_cancel	= cancel;

	return do_query_serials(context, &a);
}

/* S sends P a verb, with an 8-byte nonce as its payload */

static int
sert_s_send(const char *verb, const char *hex, unsigned long long offset,
	    unsigned long long len, const uint8_t *nonce)
{
	char buf[160];
	int n;

	n = lws_dht_msg_gen(buf, sizeof(buf) - SERT_NONCE_LEN, verb, hex,
			    offset, len);
	if (n <= 0 || (size_t)n >= sizeof(buf) - SERT_NONCE_LEN)
		return 1;
	memcpy(buf + n, nonce, SERT_NONCE_LEN);

	return lws_dht_send_data(dht_s, (const struct sockaddr *)&sa_p, buf,
				 (size_t)n + SERT_NONCE_LEN);
}

/* S registers no verbs, so what P sends comes to it whole */

static void
sert_s_cb(void *closure, int event, const lws_dht_hash_t *info_hash,
	  const void *data, size_t data_len, const struct sockaddr *from,
	  size_t fromlen)
{
	struct lws_dht_msg m;

	if (event != LWS_DHT_EVENT_DATA ||
	    lws_dht_msg_parse((const char *)data, data_len, &m) ||
	    m.payload_len != SERT_NONCE_LEN)
		return;

	if (!strcmp(m.verb, "SOA_REQ") && s_reqs < 2) {
		memcpy(s_req_nonce[s_reqs], m.payload, SERT_NONCE_LEN);
		lws_strncpy(s_req_hash[s_reqs], m.hash, sizeof(s_req_hash[0]));
		s_reqs++;
	}

	if (!strcmp(m.verb, "SOA_RSP")) {
		s_rsp = m;
		memcpy(s_rsp_nonce, m.payload, SERT_NONCE_LEN);
		s_rsp.payload = NULL;
		s_rsps++;
	}
}

/* P holds the zone at SERT_SERIAL_P, as a validated PUT would leave it */

static int
sert_store_zone(const char *hex)
{
	char dir[256], path[384];
	int fd;

	lws_snprintf(dir, sizeof(dir), "%s/%.2s", SERT_STORE, hex);
	if (mkdir(dir, 0700) && errno != EEXIST)
		return 1;
	lws_snprintf(dir, sizeof(dir), "%s/%.2s/%.2s", SERT_STORE, hex, hex + 2);
	if (mkdir(dir, 0700) && errno != EEXIST)
		return 1;

	lws_snprintf(path, sizeof(path), "%s/%s_%llu_%llu_%u.payload", dir, hex,
		     (unsigned long long)time(NULL) + 3600,
		     (unsigned long long)time(NULL) + 86400, SERT_SERIAL_P);
	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd < 0)
		return 1;
	close(fd);

	return 0;
}

static void
sert_step_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_dht_dnssec *vhd = get_dnssec_vhd(context, vh_p);
	lws_usec_t now = lws_now_usecs();
	int good = 0, dubious = 0;
	uint8_t nonce[SERT_NONCE_LEN];

	switch (step) {
	case 0:
		if (!vhd || !vhd->dht)
			break;
		lws_dht_nodes(vhd->dht, AF_INET, &good, &dubious, NULL, NULL);
		if (!good && !dubious) {
			if (now - t_start > 5 * LWS_US_PER_SEC) {
				sert_expect(0, "S is in P's routing table");
				goto done;
			}
			break;
		}
		sert_expect(1, "S is in P's routing table");

		{
			lws_sockaddr46 sa46;

			memset(&sa46, 0, sizeof(sa46));
			sa46.sa4.sin_family = AF_INET;
			sa46.sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			sert_expect(dht_dnssec_seed_is_self(vhd, &sa46),
				    "a loopback seed is this node");
			/* 192.0.2.1, TEST-NET-1 */
			sa46.sa4.sin_addr.s_addr = htonl(0xc0000201);
			sert_expect(!dht_dnssec_seed_is_self(vhd, &sa46),
				    "a documentation address seed is not");
		}

		/* the first query, replaced at once by the second */
		if (sert_expect(!sert_query(SERT_DOMAIN, &rq[0], 0),
				"first query started"))
			goto done;
		if (sert_expect(rq[0].self == 1 &&
				rq[0].self_state == LWS_DHT_DNSSEC_SERIAL_HELD &&
				rq[0].self_serial == SERT_SERIAL_P,
				"P's own copy is reported in the call")) {
			lwsl_err("%s: reported %d times, state %d, serial %u\n",
				 __func__, rq[0].self, rq[0].self_state,
				 (unsigned int)rq[0].self_serial);
			goto done;
		}
		if (sert_expect(!sert_query(SERT_DOMAIN, &rq[0], 0),
				"second query, same opaque, started"))
			goto done;

		step++;
		t_step = now;
		break;

	case 1:
		/* S has both queries' SOA_REQ */
		if (s_reqs < 2) {
			if (now - t_step > 3 * LWS_US_PER_SEC) {
				sert_expect(0, "S is asked by both queries");
				goto done;
			}
			break;
		}
		sert_expect(!strcmp(s_req_hash[0], hex_domain) &&
			    !strcmp(s_req_hash[1], hex_domain),
			    "S is asked about the zone's hash");
		sert_expect(memcmp(s_req_nonce[0], s_req_nonce[1],
				   SERT_NONCE_LEN),
			    "each query has its own nonce");

		/* to the replaced query, a forged nonce, then the right one */
		sert_s_send("SOA_RSP", hex_domain, 1, 1, s_req_nonce[0]);
		memset(nonce, 0xa5, sizeof(nonce));
		sert_s_send("SOA_RSP", hex_domain, 2, 1, nonce);
		sert_s_send("SOA_RSP", hex_domain, SERT_SERIAL_S, 1,
			    s_req_nonce[1]);
		step++;
		t_step = now;
		break;

	case 2:
		if (!rq[0].end) {
			if (now - t_step > 3 * LWS_US_PER_SEC) {
				sert_expect(0, "the query ends on S's answer");
				goto done;
			}
			break;
		}
		sert_expect(rq[0].end == 1 && rq[0].self == 2,
			    "the query ends once, after P's own copy");
		sert_expect(rq[0].peer == 1 &&
			    rq[0].peer_state == LWS_DHT_DNSSEC_SERIAL_HELD &&
			    rq[0].peer_serial == SERT_SERIAL_S,
			    "only S's answer to the live nonce is reported");

		/* a zone neither of them holds */
		s_reqs = 0;
		if (sert_expect(!sert_query(SERT_NONE, &rq[1], 0),
				"query for a zone nobody holds started"))
			goto done;
		sert_expect(rq[1].self == 1 &&
			    rq[1].self_state == LWS_DHT_DNSSEC_SERIAL_NONE,
			    "P holding no copy is reported");
		step++;
		t_step = now;
		break;

	case 3:
		if (s_reqs < 1) {
			if (now - t_step > 3 * LWS_US_PER_SEC) {
				sert_expect(0, "S is asked about the other zone");
				goto done;
			}
			break;
		}
		sert_expect(!strcmp(s_req_hash[0], hex_none),
			    "S is asked about the other zone's hash");
		sert_s_send("SOA_RSP", hex_none, 0, 0, s_req_nonce[0]);
		step++;
		t_step = now;
		break;

	case 4:
		if (!rq[1].end) {
			if (now - t_step > 3 * LWS_US_PER_SEC) {
				sert_expect(0, "S holding none ends the query");
				goto done;
			}
			break;
		}
		sert_expect(rq[1].peer == 1 &&
			    rq[1].peer_state == LWS_DHT_DNSSEC_SERIAL_NONE,
			    "S holding no copy is reported");

		/* S won't answer this one */
		s_reqs = 0;
		if (sert_expect(!sert_query(SERT_DOMAIN, &rq[2], 0),
				"query S won't answer started"))
			goto done;
		step++;
		t_step = now;
		break;

	case 5:
		if (!rq[2].end) {
			if (now - t_step > (LWS_DHT_DNSSEC_SERIAL_QUERY_SECS + 3) *
							LWS_US_PER_SEC) {
				sert_expect(0, "the unanswered query times out");
				goto done;
			}
			break;
		}
		sert_expect(rq[2].peer == 1 &&
			    rq[2].peer_state == LWS_DHT_DNSSEC_SERIAL_NO_ANSWER,
			    "S not answering is reported at the timeout");
		sert_expect(now - t_step >= (LWS_DHT_DNSSEC_SERIAL_QUERY_SECS - 1) *
							LWS_US_PER_SEC,
			    "...and not before");

		/* a query cancelled before S answers it */
		s_reqs = 0;
		if (sert_expect(!sert_query(SERT_DOMAIN, &rq[3], 0),
				"query to cancel started"))
			goto done;
		step++;
		t_step = now;
		break;

	case 6:
		if (s_reqs < 1) {
			if (now - t_step > 3 * LWS_US_PER_SEC) {
				sert_expect(0, "S is asked by the query to cancel");
				goto done;
			}
			break;
		}
		sert_query(NULL, &rq[3], 1);
		sert_expect(lws_dll2_is_empty(&serial_queries),
			    "the cancel drops the query");
		sert_s_send("SOA_RSP", hex_domain, SERT_SERIAL_S, 1,
			    s_req_nonce[0]);
		step++;
		t_step = now;
		break;

	case 7:
		if (now - t_step < 700 * LWS_US_PER_MS)
			break;
		sert_expect(!rq[3].peer && !rq[3].end,
			    "a cancelled query reports nothing more");

		/* now S asks P */
		memset(nonce, 0x3c, sizeof(nonce));
		sert_s_send("SOA_REQ", hex_domain, 0, 0, nonce);
		step++;
		t_step = now;
		break;

	case 8:
		if (!s_rsps) {
			if (now - t_step > 3 * LWS_US_PER_SEC) {
				sert_expect(0, "P answers S's SOA_REQ");
				goto done;
			}
			break;
		}
		memset(nonce, 0x3c, sizeof(nonce));
		sert_expect(!strcmp(s_rsp.hash, hex_domain) &&
			    s_rsp.offset == SERT_SERIAL_P && s_rsp.len == 1 &&
			    !memcmp(s_rsp_nonce, nonce, sizeof(nonce)),
			    "P answers with its serial and S's nonce");

		s_rsps = 0;
		memset(nonce, 0x4b, sizeof(nonce));
		sert_s_send("SOA_REQ", hex_none, 0, 0, nonce);
		step++;
		t_step = now;
		break;

	case 9:
		if (!s_rsps) {
			if (now - t_step > 3 * LWS_US_PER_SEC) {
				sert_expect(0, "P answers for a zone it lacks");
				goto done;
			}
			break;
		}
		memset(nonce, 0x4b, sizeof(nonce));
		sert_expect(!strcmp(s_rsp.hash, hex_none) && !s_rsp.offset &&
			    !s_rsp.len && !memcmp(s_rsp_nonce, nonce,
						  sizeof(nonce)),
			    "P answers that it holds no copy");
		step++;
		goto done;
	}

	if (now - t_start > 30 * LWS_US_PER_SEC) {
		sert_expect(0, "finished in time");
		goto done;
	}

	lws_sul_schedule(context, 0, &sul_step, sert_step_cb,
			 100 * LWS_US_PER_MS);

	return;

done:
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	static const struct lws_protocols *pprotocols[] = {
		&lws_dht_dnssec_protocols[0], NULL
	};
	struct lws_protocol_vhost_options pvo[5], pvo_wrap;
	struct lws_context_creation_info info;
	const char *p, *port_p = NULL;
	uint8_t idata[LWS_GENHASH_LARGEST];
	lws_dht_info_t di;
	int port_s = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: dht-dnssec zone serial queries\n");

	if ((p = lws_cmdline_option(argc, argv, "--port-p")))
		port_p = p;
	if ((p = lws_cmdline_option(argc, argv, "--port-s")))
		port_s = atoi(p);
	if (!port_p || port_s <= 0 || port_s > 65535) {
		lwsl_err("%s: --port-p and --port-s <udp port> are required\n",
			 __func__);

		return 1;
	}

	if (dht_dnssec_domain_hash(SERT_DOMAIN, idata, hex_domain,
				   sizeof(hex_domain)) ||
	    dht_dnssec_domain_hash(SERT_NONE, idata, hex_none,
				   sizeof(hex_none))) {
		lwsl_err("%s: unable to hash the domains\n", __func__);

		return 1;
	}

	lws_dir(SERT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(SERT_STORE);
	if (mkdir(SERT_STORE, 0700) || sert_store_zone(hex_domain)) {
		lwsl_err("%s: unable to create %s\n", __func__, SERT_STORE);

		return 1;
	}

	memset(&sa_s, 0, sizeof(sa_s));
	sa_s.sin_family = AF_INET;
	sa_s.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa_s.sin_port = htons((uint16_t)port_s);
	sa_p = sa_s;
	sa_p.sin_port = htons((uint16_t)atoi(port_p));

	/* P: the plugin, on the default vhost, bootstrapping from S */

	memset(pvo, 0, sizeof(pvo));
	pvo[0].name = "dht-storage-path";
	pvo[0].value = SERT_STORE;
	pvo[0].next = &pvo[1];
	pvo[1].name = "dht-port";
	pvo[1].value = port_p;
	pvo[1].next = &pvo[2];
	pvo[2].name = "dht-allow-private";
	pvo[2].value = "1";
	pvo[2].next = &pvo[3];
	pvo[3].name = "target-ip";
	pvo[3].value = "127.0.0.1";
	pvo[3].next = &pvo[4];
	pvo[4].name = "target-port";
	pvo[4].value = lws_cmdline_option(argc, argv, "--port-s");

	memset(&pvo_wrap, 0, sizeof(pvo_wrap));
	pvo_wrap.name = "lws-dht-dnssec";
	pvo_wrap.value = "";
	pvo_wrap.options = pvo;

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.pprotocols = pprotocols;
	info.pvo = &pvo_wrap;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: lws init failed\n", __func__);

		return 1;
	}

	vh_p = lws_get_vhost_by_name(context, "default");

	/* S: a bare DHT node that answers by hand, on its own vhost */

	info.pvo = NULL;
	info.vhost_name = "holder";
	vh_s = lws_create_vhost(context, &info);

	memset(&di, 0, sizeof(di));
	di.vhost		= vh_s;
	di.cb			= sert_s_cb;
	di.name			= "holder";
	di.port			= port_s;
	di.allow_private_ads	= 1; /* both nodes are on loopback */
	{
		lws_dht_hash_t *id;

		memset(idata, 0x33, 20);
		id = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idata);
		di.id = id;
		if (vh_s && id)
			dht_s = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}

	if (!vh_p || !vh_s || !dht_s) {
		lwsl_err("%s: setup failed\n", __func__);
		fails++;
		goto bail;
	}

	t_start = lws_now_usecs();
	lws_sul_schedule(context, 0, &sul_step, sert_step_cb,
			 300 * LWS_US_PER_MS);

	while (lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_step);
	lws_context_destroy(context);

	lws_dir(SERT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(SERT_STORE);

	lwsl_user("Completed: %s\n", fails || step != 10 ? "FAIL" : "PASS");

	return fails || step != 10;
}
