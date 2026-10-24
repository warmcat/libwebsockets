/*
 * lws-api-test-dht-dnssec-fetch-fanout
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Every host a dht-dnssec zone fetch sends its GET to takes one of the DHT's
 * 64 transport sequencers until it acknowledges, and uploads, other fetches
 * and serial queries need them too.  A fetch used to send its GET to every
 * node in the routing table at once, up to 64 and the bootstrap target, and
 * counted a host the DHT had no sequencer for as asked (G-508).  With the
 * lws-dht-dnssec plugin built in, and a routing table of many more nodes than
 * a round may ask, none of which answer, this checks
 *
 *  - when every sequencer is in use, a fetch's sends are refused: no host
 *    counts as asked, and the fetch tries again early, rather than at its
 *    next retry
 *  - once sequencers are free again, that early round asks them, no more
 *    than LWS_DHT_DNSSEC_FETCH_FANOUT nodes and the target
 *  - another fetch also asks only LWS_DHT_DNSSEC_FETCH_FANOUT routing table
 *    nodes and the bootstrap target at first
 *  - its retries ask the next ones, never one it asked already
 *  - an early round only asks what its full round has left to ask, so the
 *    hosts a fetch asks over its life fit the list it keeps of them (G-534)
 *  - and once that list is full, no new host is asked, rather than one asked
 *    before being forgotten, and so refused when it answers
 *  - on the node the bootstrap target names, a fetch doesn't ask the target,
 *    which is itself
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define FFO_STORE	"./fetch-fanout-store"
/* routing table nodes offered: the table keeps what its buckets have room for */
#define FFO_NODES	64
/* zone keys to fetch, "dht-hash-" and 64 hex */
#define FFO_HASH_A	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01"
#define FFO_HASH_B	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02"
#define FFO_HASH_C	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03"
/* how many sends to dead endpoints it may take to fill the sequencer table */
#define FFO_FILL_MAX	256

static int fails, completions;
static lws_sorted_usec_list_t sul_tick;
static struct lws_context *ffo_cx;

static int
ffo_expect(int cond, const char *what)
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
ffo_fetch_cb(void *opaque, const char *domain, int status)
{
	(void)opaque;
	(void)domain;
	(void)status;

	completions++;
}

static int
ffo_fetch(const struct lws_dht_dnssec_ops *ops, struct lws_context *cx,
	  struct lws_vhost *vh, const char *domain)
{
	struct lws_dht_dnssec_fetch_zone_args args;

	memset(&args, 0, sizeof(args));
	args.vhost		= vh;
	args.domain		= domain;
	args.cb			= ffo_fetch_cb;
	args.force_network	= 1;

	return ops->fetch_zone(cx, &args);
}

static int
ffo_count_cb(void *user, const lws_dht_node_info_t *ni)
{
	(void)ni;
	(*(int *)user)++;

	return 0;
}

/* lws_service() only returns when something wakes the loop: wake it */

static void
ffo_tick_cb(lws_sorted_usec_list_t *sul)
{
	lws_sul_schedule(ffo_cx, 0, sul, ffo_tick_cb, 100 * LWS_US_PER_MS);
}

static void
ffo_sa(lws_sockaddr46 *sa46, uint8_t third, uint8_t last, int port)
{
	memset(sa46, 0, sizeof(*sa46));
	sa46->sa4.sin_family = AF_INET;
	sa46->sa4.sin_addr.s_addr = htonl(0x7f000000u | ((uint32_t)third << 8) |
					  last);
	sa46->sa4.sin_port = htons((uint16_t)port);
}

int
main(int argc, const char **argv)
{
	static const struct lws_protocols *pprotocols[] = {
		&lws_dht_dnssec_protocols[0], NULL
	};
	struct lws_protocol_vhost_options pvo[5], pvo_wrap;
	const struct lws_dht_dnssec_ops *ops = NULL;
	struct lws_dht_dnssec_fetch_req *req;
	struct lws_context_creation_info info;
	const char *port, *tport, *dport;
	const struct lws_protocols *pcol;
	struct vhd_dht_dnssec *vhd;
	struct lws_vhost *vh = NULL;
	const lws_dht_hash_t *myid;
	int n, nodes = 0, r, dead;
	struct lws_context *cx;
	lws_sockaddr46 sa46;
	lws_usec_t t_start;
	uint8_t idb[64];

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: dht-dnssec fetch fan-out\n");

	port = lws_cmdline_option(argc, argv, "--port");
	tport = lws_cmdline_option(argc, argv, "--target-port");
	dport = lws_cmdline_option(argc, argv, "--dead-port");
	if (!port || !tport || !dport ||
	    atoi(port) <= 0 || atoi(port) > 65535 ||
	    atoi(tport) <= 0 || atoi(tport) > 65535 ||
	    atoi(dport) <= 0 || atoi(dport) > 65535) {
		lwsl_err("%s: --port, --target-port and --dead-port <udp port> "
			 "are required\n", __func__);

		return 1;
	}
	dead = atoi(dport);

	lws_dir(FFO_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(FFO_STORE);
	if (mkdir(FFO_STORE, 0700) && errno != EEXIST) {
		lwsl_err("%s: unable to create %s\n", __func__, FFO_STORE);

		return 1;
	}

	memset(pvo, 0, sizeof(pvo));
	pvo[0].name = "dht-storage-path";
	pvo[0].value = FFO_STORE;
	pvo[0].next = &pvo[1];
	pvo[1].name = "dht-port";
	pvo[1].value = port;
	pvo[1].next = &pvo[2];
	pvo[2].name = "dht-allow-private";
	pvo[2].value = "1";
	pvo[2].next = &pvo[3];
	pvo[3].name = "target-ip";
	pvo[3].value = "127.0.0.1";
	pvo[3].next = &pvo[4];
	pvo[4].name = "target-port";
	pvo[4].value = tport;

	memset(&pvo_wrap, 0, sizeof(pvo_wrap));
	pvo_wrap.name = "lws-dht-dnssec";
	pvo_wrap.value = "";
	pvo_wrap.options = pvo;

	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: lws init failed\n", __func__);

		return 1;
	}

	info.vhost_name = "fetcher";
	info.pprotocols = pprotocols;
	info.pvo = &pvo_wrap;
	vh = lws_create_vhost(cx, &info);
	pcol = vh ? lws_vhost_name_to_protocol(vh, "lws-dht-dnssec") : NULL;
	if (pcol)
		ops = (const struct lws_dht_dnssec_ops *)pcol->user;

	/* the vhost's protocols are initialized once the loop runs */
	t_start = lws_now_usecs();
	while (ops && !lws_protocol_vh_priv_get(vh, pcol) &&
	       lws_now_usecs() - t_start < 5 * LWS_US_PER_SEC)
		if (lws_service(cx, 0) < 0)
			break;

	if (ffo_expect(ops && ops->fetch_zone &&
		       lws_protocol_vh_priv_get(vh, pcol),
		       "plugin instantiated"))
		goto bail;

	/* ...and it creates its DHT after the context is up */
	vhd = (struct vhd_dht_dnssec *)lws_protocol_vh_priv_get(vh, pcol);
	t_start = lws_now_usecs();
	while (!vhd->dht && lws_now_usecs() - t_start < 10 * LWS_US_PER_SEC)
		if (lws_service(cx, 0) < 0)
			break;
	if (ffo_expect(!!vhd->dht, "plugin has its DHT"))
		goto bail;

	/* a routing table of nodes on loopback that never answer */

	myid = lws_dht_get_myid(vhd->dht);
	if (ffo_expect(myid && myid->len <= sizeof(idb), "our node id"))
		goto bail;

	for (n = 0; n < FFO_NODES; n++) {
		lws_dht_hash_t *id;

		if (lws_get_random(cx, idb, myid->len) != myid->len)
			break;
		id = lws_dht_hash_create(myid->type, myid->len, idb);
		if (!id)
			break;
		ffo_sa(&sa46, 1, (uint8_t)(1 + n), dead);
		lws_dht_insert_node(vhd->dht, id, (struct sockaddr *)&sa46,
				    sizeof(struct sockaddr_in));
		lws_dht_hash_destroy(&id);
	}

	lws_dht_foreach_node(vhd->dht, AF_INET, ffo_count_cb, &nodes);
	lwsl_user("%s: routing table holds %d nodes\n", __func__, nodes);
	/*
	 * Nodes that never answered are dubious, so the table only splits its
	 * first bucket, and holds two buckets' worth: as many as two rounds ask
	 */
	if (ffo_expect(nodes >= 2 * LWS_DHT_DNSSEC_FETCH_FANOUT,
		       "routing table has as many nodes as two rounds ask"))
		goto bail;

	/*
	 * Fill the DHT's sequencer table with sends to endpoints that never
	 * answer, until it refuses one: every sequencer holds unacked data
	 */

	r = LWS_DHT_SEND_QUEUED;
	for (n = 0; n < FFO_FILL_MAX && r != LWS_DHT_SEND_REFUSED; n++) {
		ffo_sa(&sa46, 2, (uint8_t)(1 + n), dead);
		r = lws_dht_send_data(vhd->dht, (struct sockaddr *)&sa46,
				      "fill", 4);
	}
	lwsl_user("%s: sequencer table full after %d sends\n", __func__, n);
	if (ffo_expect(r == LWS_DHT_SEND_REFUSED, "sequencer table full"))
		goto bail;

	/* now a fetch can ask nobody: it is not fooled, and tries again soon */

	n = ffo_fetch(ops, cx, vh, "dht-hash-" FFO_HASH_B);
	req = dht_dnssec_find_fetch_req(vhd, FFO_HASH_B);
	if (ffo_expect(!n && req, "fetch pending with no sequencers"))
		goto bail;
	lwsl_user("%s: with no sequencers, %d hosts asked\n", __func__,
		  req->asked_count);
	ffo_expect(!req->asked_count,
		   "hosts refused a sequencer are not counted as asked");
	ffo_expect(req->early_rounds == 1 &&
		   req->sul_timeout.us - lws_now_usecs() <=
				LWS_DHT_DNSSEC_FETCH_REFUSED_US,
		   "the fetch tries again early");

	/*
	 * The fill's sequencers fail as nobody answers, and the early round
	 * asks a round's worth then
	 */

	ffo_cx = cx;
	lws_sul_schedule(cx, 0, &sul_tick, ffo_tick_cb, 0);
	t_start = lws_now_usecs();
	while ((req = dht_dnssec_find_fetch_req(vhd, FFO_HASH_B)) &&
	       !req->asked_count &&
	       lws_now_usecs() - t_start < LWS_DHT_DNSSEC_FETCH_REFUSED_US +
					   3 * LWS_US_PER_SEC)
		if (lws_service(cx, 0) < 0)
			break;

	if (ffo_expect(!!req, "fetch still pending"))
		goto bail;
	lwsl_user("%s: early round asked %d hosts\n", __func__,
		  req->asked_count);
	ffo_expect(req->asked_count == LWS_DHT_DNSSEC_FETCH_FANOUT + 1,
		   "the early round asks the fan-out's worth of nodes and "
		   "the target");

	/* another fetch asks a round's worth of nodes, and the target */

	n = ffo_fetch(ops, cx, vh, "dht-hash-" FFO_HASH_A);
	req = dht_dnssec_find_fetch_req(vhd, FFO_HASH_A);
	if (ffo_expect(!n && req, "another fetch pending"))
		goto bail;
	lwsl_user("%s: first round asked %d hosts\n", __func__,
		  req->asked_count);
	ffo_expect(req->asked_count == LWS_DHT_DNSSEC_FETCH_FANOUT + 1,
		   "first round asks the fan-out's worth of nodes and the "
		   "target");

	/*
	 * an early round before its retry is due asks nobody new: the round
	 * already asked its fan-out's worth (G-534)
	 */
	n = req->asked_count;
	dht_dnssec_sul_fetch_req_timeout(&req->sul_timeout);
	lwsl_user("%s: after an early round, %d hosts asked\n", __func__,
		  req->asked_count);
	ffo_expect(!req->retries && req->asked_count == n,
		   "an early round asks no more than its full round left");

	/* its retry asks the next ones */

	req->next_retry = 0;
	dht_dnssec_sul_fetch_req_timeout(&req->sul_timeout);
	lwsl_user("%s: after the retry, %d hosts asked\n", __func__,
		  req->asked_count);
	ffo_expect(req->retries == 1 &&
		   req->asked_count == 2 * LWS_DHT_DNSSEC_FETCH_FANOUT + 1,
		   "the retry asks as many again, none asked before");

	/* ...and once all were asked, the next retry asks only the target */

	req->next_retry = 0;
	dht_dnssec_sul_fetch_req_timeout(&req->sul_timeout);
	ffo_expect(req->retries == 2 &&
		   req->asked_count == (nodes > 2 * LWS_DHT_DNSSEC_FETCH_FANOUT ?
				3 * LWS_DHT_DNSSEC_FETCH_FANOUT : nodes) + 1,
		   "a node asked before is not asked again");

	/*
	 * Fill the first fetch's list of hosts asked to the brim with others:
	 * its next round must not ask anyone new, so every host it asked
	 * before stays able to answer (G-534)
	 */
	req = dht_dnssec_find_fetch_req(vhd, FFO_HASH_B);
	if (ffo_expect(req && req->asked_count, "first fetch still pending"))
		goto bail;
	{
		lws_sockaddr46 was[LWS_DHT_DNSSEC_FETCH_MAX_ASKED];
		int had = req->asked_count, ok = 1;

		memcpy(was, req->asked, sizeof(was));
		while (req->asked_count < LWS_DHT_DNSSEC_FETCH_MAX_ASKED) {
			ffo_sa(&req->asked[req->asked_count], 3,
			       (uint8_t)(1 + req->asked_count), dead);
			req->asked_count++;
		}

		req->next_retry = 0;
		dht_dnssec_sul_fetch_req_timeout(&req->sul_timeout);

		for (n = 0; n < had; n++)
			if (!dht_dnssec_fetch_asked(vhd, FFO_HASH_B,
					(const struct sockaddr *)&was[n]))
				ok = 0;
		lwsl_user("%s: full list, after the retry: %d hosts asked\n",
			  __func__, req->asked_count);
		ffo_expect(req->retries == 1 && ok &&
			   req->asked_count == LWS_DHT_DNSSEC_FETCH_MAX_ASKED,
			   "with its list of hosts asked full, a fetch asks no "
			   "new one, and forgets none it asked");
	}

	/* the target names this node, as the policy's seed does on the seed */

	vhd->target_port = vhd->dht_port;
	n = ffo_fetch(ops, cx, vh, "dht-hash-" FFO_HASH_C);
	req = dht_dnssec_find_fetch_req(vhd, FFO_HASH_C);
	ffo_sa(&sa46, 0, 1, vhd->dht_port);
	ffo_expect(!n && req && req->asked_count &&
		   !dht_dnssec_fetch_asked(vhd, FFO_HASH_C,
					   (const struct sockaddr *)&sa46),
		   "on the node the target names, a fetch doesn't ask itself");

bail:
	lws_sul_cancel(&sul_tick);
	lws_context_destroy(cx);

	/* nobody answered: the fetches completed once each, at destroy */
	ffo_expect(completions == 3, "the fetches completed once each");

	lws_dir(FFO_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(FFO_STORE);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
