/*
 * lws-api-test-dht-dnssec-subscribe
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An authoritative node serving a zone from the DHT subscribes to it with
 * the node it fetched it from, so it hears of a new version at once rather
 * than when its own copy expires.  Here the lws-dht-dnssec plugin, built
 * into this test, is that node (P), and a bare DHT node (S) on another
 * vhost holds the zone:
 *
 *  - P subscribes with S as it does when a fetch from S completes; S's
 *    token comes back naming the zone's hash, P confirms it, and S then
 *    has P as a subscriber
 *  - P's subscribe for a hash it does not serve is answered with a token
 *    too, but P does not confirm that one
 *  - S notifying its subscribers of a new serial makes P fetch the zone
 *  - a second new serial right after is not dropped by P's rate limit: P
 *    defers it to a fetch when the limit ends
 *  - a newer serial from S once the minimum interval has passed is fetched
 *    at once, which also covers the deferred one
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define SUBT_STORE	"./subscribe-store"
#define SUBT_DOMAIN	"sub.example"
#define SUBT_SERIAL1	2026100501ull
#define SUBT_SERIAL2	2026100502ull
#define SUBT_SERIAL3	2026100503ull

static struct lws_context *context;
static struct lws_vhost *vh_p, *vh_s;
static struct lws_dht_ctx *dht_s;
static struct sockaddr_in sa_s;
static lws_sorted_usec_list_t sul_step;
static lws_usec_t t_start, t_step, t_first_notify;
static int step, fails;
static lws_dht_hash_t *zone_hash, *other_hash;

static int
subt_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);
		fails++;

		return 1;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);

	return 0;
}

/* S tells its subscribers the zone has a new serial, as a holder does */

static int
subt_notify(const lws_dht_hash_t *h, uint64_t serial)
{
	uint8_t pl[8 + sizeof(SUBT_DOMAIN)], sha[32];
	int n;

	for (n = 0; n < 8; n++)
		pl[n] = (uint8_t)(serial >> (56 - (8 * n)));
	memcpy(pl + 8, SUBT_DOMAIN, sizeof(SUBT_DOMAIN));

	/* stands in for the new payload's hash: it differs per serial */
	memset(sha, 0, sizeof(sha));
	memcpy(sha, pl, 8);

	return lws_dht_notify_subscribers(dht_s, h, sha, pl, sizeof(pl));
}

static void
subt_step_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_dht_dnssec *vhd = get_dnssec_vhd(context, vh_p);
	struct lws_dht_dnssec_subscribed_domain *sub = NULL;
	lws_usec_t now = lws_now_usecs();

	if (vhd && zone_hash)
		sub = dht_dnssec_find_sub(vhd, zone_hash->id, zone_hash->len);

	switch (step) {
	case 0:
		if (subt_expect(vhd && vhd->dht, "plugin instantiated") ||
		    subt_expect(!do_subscribe_zone(vh_p, SUBT_DOMAIN),
				"zone subscribed"))
			goto done;

		/* the plugin's own record of the zone gives us its hash */
		sub = lws_container_of(lws_dll2_get_tail(
				&vhd->subscribed_domains),
				struct lws_dht_dnssec_subscribed_domain, list);
		zone_hash = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA256, 32,
						sub->hash);
		if (subt_expect(!!zone_hash, "zone hash"))
			goto done;

		/* as when a fetch from S completed */
		dht_dnssec_sub_subscribe(vhd, sub, (struct sockaddr *)&sa_s,
					 sizeof(sa_s));

		/* and a subscribe for a hash P serves no zone for */
		lws_dht_send_subscribe(vhd->dht, (struct sockaddr *)&sa_s,
				       sizeof(sa_s), other_hash, 0, 0);
		step++;
		t_step = now;
		break;

	case 1:
		/* S only has a subscriber once P confirmed S's token */
		if (subt_notify(zone_hash, SUBT_SERIAL1) == 1) {
			subt_expect(1, "S holds P's subscription");
			t_first_notify = now;
			step++;
			t_step = now;
			break;
		}
		if (now - t_step > 5 * LWS_US_PER_SEC) {
			subt_expect(0, "S holds P's subscription");
			goto done;
		}
		break;

	case 2:
		if (sub && sub->last_notify_soa == SUBT_SERIAL1) {
			subt_expect(sub->last_notify_fetch != 0,
				    "the NOTIFY made P fetch the zone");
			/* straight away: inside P's rate limit */
			subt_notify(zone_hash, SUBT_SERIAL2);
			step++;
			t_step = now;
			break;
		}
		if (now - t_step > 3 * LWS_US_PER_SEC) {
			subt_expect(0, "the NOTIFY made P fetch the zone");
			goto done;
		}
		break;

	case 3:
		if (now - t_step < 500 * LWS_US_PER_MS)
			break;
		subt_expect(sub && sub->last_notify_soa == SUBT_SERIAL1 &&
			    !lws_dll2_is_detached(&sub->sul_refetch.list),
			    "a rate-limited NOTIFY is deferred, not dropped");
		subt_expect(!subt_notify(other_hash, SUBT_SERIAL1),
			    "no subscription for a hash P doesn't serve");
		step++;
		break;

	case 4:
		if (now - t_first_notify < (DHT_DNSSEC_NOTIFY_FETCH_MIN_SECS *
					    LWS_US_PER_SEC) + 500 * LWS_US_PER_MS)
			break;
		subt_notify(zone_hash, SUBT_SERIAL3);
		step++;
		t_step = now;
		break;

	case 5:
		if (sub && sub->last_notify_soa == SUBT_SERIAL3) {
			subt_expect(lws_dll2_is_detached(&sub->sul_refetch.list),
				    "a newer serial from the holder is fetched "
				    "at once, covering the deferred one");
			goto done;
		}
		if (now - t_step > 3 * LWS_US_PER_SEC) {
			subt_expect(0, "a newer serial from the holder is "
				       "fetched at once");
			goto done;
		}
		break;
	}

	if (now - t_start > 30 * LWS_US_PER_SEC) {
		subt_expect(0, "finished in time");
		goto done;
	}

	lws_sul_schedule(context, 0, &sul_step, subt_step_cb,
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
	uint8_t idata[32];
	lws_dht_info_t di;
	int port_s = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: dht-dnssec zone subscription\n");

	if ((p = lws_cmdline_option(argc, argv, "--port-p")))
		port_p = p;
	if ((p = lws_cmdline_option(argc, argv, "--port-s")))
		port_s = atoi(p);
	if (!port_p || port_s <= 0 || port_s > 65535) {
		lwsl_err("%s: --port-p and --port-s <udp port> are required\n",
			 __func__);

		return 1;
	}

	lws_dir(SUBT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(SUBT_STORE);
	if (mkdir(SUBT_STORE, 0700) && errno != EEXIST) {
		lwsl_err("%s: unable to create %s\n", __func__, SUBT_STORE);

		return 1;
	}

	memset(&sa_s, 0, sizeof(sa_s));
	sa_s.sin_family = AF_INET;
	sa_s.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa_s.sin_port = htons((uint16_t)port_s);

	/* P: the plugin, on the default vhost, bootstrapping from S */

	memset(pvo, 0, sizeof(pvo));
	pvo[0].name = "dht-storage-path";
	pvo[0].value = SUBT_STORE;
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

	/* S: a bare DHT node holding the zone, on its own vhost */

	info.pvo = NULL;
	info.vhost_name = "holder";
	vh_s = lws_create_vhost(context, &info);

	memset(idata, 0x5a, sizeof(idata));
	other_hash = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA256, 32, idata);

	memset(&di, 0, sizeof(di));
	di.vhost		= vh_s;
	di.name			= "holder";
	di.port			= port_s;
	di.allow_private_ads	= 1; /* both nodes are on loopback */
	{
		lws_dht_hash_t *id;

		memset(idata, 0x33, 20);
		id = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idata);
		di.id = id;
		if (vh_s)
			dht_s = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}

	if (!vh_p || !vh_s || !dht_s || !other_hash) {
		lwsl_err("%s: setup failed\n", __func__);
		fails++;
		goto bail;
	}

	t_start = lws_now_usecs();
	lws_sul_schedule(context, 0, &sul_step, subt_step_cb,
			 300 * LWS_US_PER_MS);

	while (lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_step);
	lws_context_destroy(context);

	if (zone_hash)
		lws_dht_hash_destroy(&zone_hash);
	if (other_hash)
		lws_dht_hash_destroy(&other_hash);

	lws_dir(SUBT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(SUBT_STORE);

	lwsl_user("Completed: %s\n", fails || step != 5 ? "FAIL" : "PASS");

	return fails || step != 5;
}
