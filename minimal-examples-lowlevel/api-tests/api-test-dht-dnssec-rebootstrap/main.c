/*
 * lws-api-test-dht-dnssec-rebootstrap
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A node bootstraps from its seed once, at startup.  If later nobody
 * answers it any more, eg, its own link was down for a few minutes, the DHT
 * drops every node it has after a few unanswered requests, and the peers
 * drop it the same way: nobody contacts anybody again, least of all it at a
 * new external address, and it never learns that address either.  It has to
 * go back to the seed.
 *
 * Here the lws-dht-dnssec plugin, built into this test, is that node (P), and
 * a bare DHT node on another vhost is its seed (S):
 *
 *  - P bootstraps from S
 *  - S goes away, and a plain UDP socket listens where it was, answering
 *    nothing: P's requests go unanswered until it has no good node left
 *  - P must then ping the seed again, which its routine maintenance never
 *    does (that sends find_node)
 *  - S comes back, with another id, and P must have it as a good node again,
 *    and ask it what our external address is
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define RBT_STORE	"./rebootstrap-store"

static struct lws_context *context;
static struct lws_vhost *vh_p, *vh_s;
static struct lws_dht_ctx *dht_s;
static struct lws *wsi_listen;
static lws_sorted_usec_list_t sul_step;
static lws_usec_t t_start, t_step;
static int step, fails, port_s, seed_pings;

static int
rbt_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);
		fails++;

		return 1;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);

	return 0;
}

/*
 * Where S was, while it is away: count the pings P sends the seed.  Those
 * have a 4-byte "pn" tid, unlike the external address probes' "ip" ones.
 */

static int
callback_seed_listen(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	static const char ping[] = "1:q4:ping1:t4:pn";

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (in && lws_nstrstr((const char *)in, len, ping,
				      sizeof(ping) - 1)) {
			seed_pings++;
			lwsl_user("%s: P pinged the seed\n", __func__);
		}
		break;
	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_seed[] = {
	{ "rbt-seed-listen", callback_seed_listen, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_dht_ctx *
rbt_create_s(uint8_t id_byte)
{
	struct lws_dht_ctx *dht;
	uint8_t idata[20];
	lws_dht_hash_t *id;
	lws_dht_info_t di;

	memset(idata, id_byte, sizeof(idata));
	id = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idata);
	if (!id)
		return NULL;

	memset(&di, 0, sizeof(di));
	di.vhost		= vh_s;
	di.name			= "seed";
	di.port			= port_s;
	di.id			= id;
	di.allow_private_ads	= 1; /* both nodes are on loopback */

	dht = lws_dht_create(&di);
	lws_dht_hash_destroy(&id);

	return dht;
}

static int
rbt_p_good(struct vhd_dht_dnssec *vhd)
{
	int good = 0;

	lws_dht_nodes(vhd->dht, AF_INET, &good, NULL, NULL, NULL);

	return good;
}

static void
rbt_step_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_dht_dnssec *vhd = get_dnssec_vhd(context, vh_p);
	lws_usec_t now = lws_now_usecs();

	if (!vhd || !vhd->dht) {
		rbt_expect(0, "plugin instantiated");
		goto done;
	}

	switch (step) {
	case 0:
		if (rbt_p_good(vhd) && vhd->initial_search_done) {
			rbt_expect(1, "P bootstrapped from the seed");
			/* S goes away: its socket closes on the next service */
			lws_dht_destroy(&dht_s);
			step++;
			t_step = now;
			break;
		}
		if (now - t_step > 10 * LWS_US_PER_SEC) {
			rbt_expect(0, "P bootstraps from the seed");
			goto done;
		}
		break;

	case 1:
		if (now - t_step < LWS_US_PER_SEC)
			break;
		wsi_listen = lws_create_adopt_udp(vh_s, "127.0.0.1", port_s,
						  LWS_CAUDP_BIND,
						  protocols_seed[0].name, NULL,
						  NULL, NULL, NULL,
						  "rbt-seed-listen");
		if (rbt_expect(!!wsi_listen, "a silent socket is where the "
					     "seed was"))
			goto done;
		step++;
		t_step = now;
		break;

	case 2:
		if (!rbt_p_good(vhd)) {
			rbt_expect(1, "nobody answering, P has no good node");
			step++;
			t_step = now;
			break;
		}
		if (now - t_step > 120 * LWS_US_PER_SEC) {
			rbt_expect(0, "P's requests go unanswered");
			goto done;
		}
		break;

	case 3:
		if (seed_pings) {
			rbt_expect(vhd->bootstrap_lost, "P knows it lost its "
				   "peers");
			rbt_expect(1, "P pings the seed again");
			lws_set_timeout(wsi_listen, 1, LWS_TO_KILL_ASYNC);
			wsi_listen = NULL;
			step++;
			t_step = now;
			break;
		}
		if (now - t_step > 20 * LWS_US_PER_SEC) {
			rbt_expect(0, "P pings the seed again");
			goto done;
		}
		break;

	case 4:
		if (now - t_step < LWS_US_PER_SEC)
			break;
		dht_s = rbt_create_s(0x44);
		if (rbt_expect(!!dht_s, "the seed is back, with another id"))
			goto done;
		step++;
		t_step = now;
		break;

	case 5:
		if (rbt_p_good(vhd) && !vhd->bootstrap_lost &&
		    !vhd->bootstrap_reprobe) {
			rbt_expect(1, "P has the seed again and asked it our "
				      "address");
			step++;
			goto done;
		}
		if (now - t_step > 30 * LWS_US_PER_SEC) {
			rbt_expect(0, "P gets its peers back");
			goto done;
		}
		break;
	}

	if (now - t_start > 170 * LWS_US_PER_SEC) {
		rbt_expect(0, "finished in time");
		goto done;
	}

	lws_sul_schedule(context, 0, &sul_step, rbt_step_cb,
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
	const char *p, *port_p = NULL, *port_s_str = NULL;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: dht-dnssec bootstraps again when it "
		  "loses its peers\n");

	if ((p = lws_cmdline_option(argc, argv, "--port-p")))
		port_p = p;
	if ((p = lws_cmdline_option(argc, argv, "--port-s"))) {
		port_s_str = p;
		port_s = atoi(p);
	}
	if (!port_p || port_s <= 0 || port_s > 65535) {
		lwsl_err("%s: --port-p and --port-s <udp port> are required\n",
			 __func__);

		return 1;
	}

	lws_dir(RBT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(RBT_STORE);
	if (mkdir(RBT_STORE, 0700) && errno != EEXIST) {
		lwsl_err("%s: unable to create %s\n", __func__, RBT_STORE);

		return 1;
	}

	/* P: the plugin, on the default vhost, with S as its seed */

	memset(pvo, 0, sizeof(pvo));
	pvo[0].name = "dht-storage-path";
	pvo[0].value = RBT_STORE;
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
	pvo[4].value = port_s_str;

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

	/* S: a bare DHT node, on its own vhost */

	info.pprotocols = NULL;
	info.protocols = protocols_seed;
	info.pvo = NULL;
	info.vhost_name = "seed";
	vh_s = lws_create_vhost(context, &info);
	if (vh_s)
		dht_s = rbt_create_s(0x33);

	if (!vh_p || !vh_s || !dht_s) {
		lwsl_err("%s: setup failed\n", __func__);
		fails++;
		goto bail;
	}

	t_start = t_step = lws_now_usecs();
	lws_sul_schedule(context, 0, &sul_step, rbt_step_cb,
			 300 * LWS_US_PER_MS);

	while (lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_step);
	if (dht_s)
		lws_dht_destroy(&dht_s);
	lws_context_destroy(context);

	lws_dir(RBT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(RBT_STORE);

	lwsl_user("Completed: %s\n", fails || step != 6 ? "FAIL" : "PASS");

	return fails || step != 6;
}
