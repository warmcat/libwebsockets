/*
 * lws-api-test-dht-dnssec-sponge
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A node running the lws-dht-dnssec plugin also keeps copies of zones it
 * doesn't serve, the sponge, so it can bridge them to parts of the DHT that
 * would not otherwise find one.  The plugin is built into this test, and its
 * NOTIFY intake and sponge sweep are driven directly:
 *
 *  - a NOTIFY naming a zone we don't serve takes it into the sponge, with a
 *    fetch that asks only the node that sent it, since a NOTIFY's source is
 *    not verified
 *  - new zones are taken in a burst at a time, then one a second, none
 *    whose hash isn't the named domain's, and none while the sponge is full
 *  - NOTIFYs about zones we don't track are limited per address, those about
 *    a zone we track are not: a fetch they ask for is deferred, not lost
 *  - a sponge copy is not handed to auth-dns, unless auth-dns asks us to
 *    fetch the zone, and auth-dns subscribing to a zone the sponge holds
 *    makes it one served here
 *  - while the sponge holds more than its budget, its copies stored longest
 *    ago are evicted, but never a zone auth-dns serves, nor the high-water
 *    mark that keeps refusing older versions of an evicted zone
 *  - a zone taken in whose copy never came is forgotten
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define SPT_STORE	"./sponge-store"

static struct lws_context *context;
static lws_sorted_usec_list_t sul_wait;
static lws_usec_t t_start;
static int fails;

static int
spt_expect(int cond, const char *what)
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
spt_v4(lws_sockaddr46 *sa46, uint8_t last)
{
	memset(sa46, 0, sizeof(*sa46));
	sa46->sa4.sin_family = AF_INET;
	/* TEST-NET-3: never routed, so what the plugin sends goes nowhere */
	sa46->sa4.sin_addr.s_addr = htonl(0xcb007100u | last);
	sa46->sa4.sin_port = htons(49100);
}

static void
spt_hex(const char *domain, char *hex)
{
	uint8_t hash[LWS_GENHASH_LARGEST];

	dht_dnssec_domain_hash(domain, hash, hex, 65);
}

/*
 * A NOTIFY as the DHT core hands one up: the zone's hash, the serial, then the
 * domain it names, from the host numbered from
 */

static void
spt_notify(struct vhd_dht_dnssec *vhd, const char *domain,
	   const char *hash_domain, uint8_t from)
{
	uint8_t hash[LWS_GENHASH_LARGEST], pl[8 + 256];
	size_t dl = strlen(domain) + 1;
	lws_dht_hash_t *id;
	lws_sockaddr46 sa;
	char hex[65];

	dht_dnssec_domain_hash(hash_domain, hash, hex, sizeof(hex));
	memset(pl, 0, 8);
	pl[7] = 5; /* serial */
	memcpy(pl + 8, domain, dl);

	id = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA256, 32, hash);
	if (!id)
		return;
	spt_v4(&sa, from);
	cb_dht(vhd, LWS_DHT_EVENT_NOTIFY, id, pl, 8 + dl,
	       sa46_sockaddr(&sa), sizeof(sa.sa4));
	lws_dht_hash_destroy(&id);
}

static struct lws_dht_dnssec_subscribed_domain *
spt_sub(struct vhd_dht_dnssec *vhd, const char *domain)
{
	uint8_t hash[LWS_GENHASH_LARGEST];
	char hex[65];

	dht_dnssec_domain_hash(domain, hash, hex, sizeof(hex));

	return dht_dnssec_find_sub(vhd, hash, 32);
}

static struct lws_dht_dnssec_fetch_req *
spt_req(struct vhd_dht_dnssec *vhd, const char *domain)
{
	char hex[65];

	spt_hex(domain, hex);

	return dht_dnssec_find_fetch_req(vhd, hex);
}

/* a file of len bytes in the zone's directory, last written age secs ago */

static int
spt_file(const char *domain, const char *suffix, size_t len, time_t age)
{
	char hex[65], path[512], buf[256];
	struct timespec ts[2];
	size_t n;
	int fd, r;

	spt_hex(domain, hex);
	lws_snprintf(path, sizeof(path), SPT_STORE "/%.2s", hex);
	if (mkdir(path, 0700) && errno != EEXIST)
		return 1;
	lws_snprintf(path, sizeof(path), SPT_STORE "/%.2s/%.2s", hex, hex + 2);
	if (mkdir(path, 0700) && errno != EEXIST)
		return 1;
	lws_snprintf(path, sizeof(path), SPT_STORE "/%.2s/%.2s/%s%s", hex,
		     hex + 2, hex, suffix);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return 1;

	memset(buf, 'z', sizeof(buf));
	for (n = 0; n < len; n += sizeof(buf))
		if (write(fd, buf, len - n < sizeof(buf) ? len - n :
							   sizeof(buf)) < 0) {
			close(fd);
			return 1;
		}

	ts[0].tv_sec = ts[1].tv_sec = time(NULL) - age;
	ts[0].tv_nsec = ts[1].tv_nsec = 0;
	r = futimens(fd, ts);
	close(fd);

	return !!r;
}

/* a stored copy of the zone: its JWS and its payload, len bytes in all */

static int
spt_copy(const char *domain, size_t len, time_t age)
{
	char suffix[64];

	lws_snprintf(suffix, sizeof(suffix), "_%llu_%llu_5.payload",
		     (unsigned long long)time(NULL) + 3600,
		     (unsigned long long)time(NULL) + 86400);

	return spt_file(domain, "", len / 2, age) ||
	       spt_file(domain, suffix, len - len / 2, age);
}

static int
spt_has(const char *domain, const char *suffix)
{
	char hex[65], path[512];

	spt_hex(domain, hex);
	lws_snprintf(path, sizeof(path), SPT_STORE "/%.2s/%.2s/%s%s", hex,
		     hex + 2, hex, suffix);

	return !access(path, F_OK);
}

static void
spt_sweep(struct vhd_dht_dnssec *vhd)
{
	dht_dnssec_sponge_sweep_cb(&vhd->sul_sponge);
}

static void
spt_run(struct vhd_dht_dnssec *vhd)
{
	struct lws_dht_dnssec_subscribed_domain *sub;
	struct lws_dht_dnssec_fetch_zone_args args;
	struct lws_dht_dnssec_fetch_req *req;
	lws_sockaddr46 notifier;
	char hex[65], name[32];
	int n;

	/* what this filesystem has free is no part of the test */
	vhd->sponge_min_free_pct = 0;

	/* taken in, fetched only from the notifier */

	spt_notify(vhd, "a.example", "a.example", 1);
	sub = spt_sub(vhd, "a.example");
	req = spt_req(vhd, "a.example");
	spt_v4(&notifier, 1);
	spt_expect(sub && sub->sponge && req && req->internal &&
		   req->only_set && req->asked_count == 1 &&
		   !lws_sa46_compare_ads(&req->only, &notifier) &&
		   lws_dht_same_host(sa46_sockaddr(&req->asked[0]),
				     sa46_sockaddr(&notifier)),
		   "a zone a NOTIFY names is taken in, asking only the notifier");

	for (n = 1; n < LWS_DHT_DNSSEC_SPONGE_INTAKE_BURST; n++) {
		lws_snprintf(name, sizeof(name), "burst%d.example", n);
		spt_notify(vhd, name, name, (uint8_t)(10 + n));
		if (!spt_sub(vhd, name))
			break;
	}
	spt_notify(vhd, "b.example", "b.example", 2);
	spt_expect(n == LWS_DHT_DNSSEC_SPONGE_INTAKE_BURST &&
		   !spt_sub(vhd, "b.example") && !spt_req(vhd, "b.example"),
		   "new zones are taken in a burst at a time, then no faster "
		   "than one a second");

	dht_dnssec_bucket_init(&vhd->sponge_intake,
			       LWS_DHT_DNSSEC_SPONGE_INTAKE_BURST);
	spt_notify(vhd, "c.example", "d.example", 3);
	spt_expect(!spt_sub(vhd, "c.example") && !spt_sub(vhd, "d.example") &&
		   !spt_req(vhd, "c.example"),
		   "none whose hash isn't the named domain's");

	vhd->sponge_full = 1;
	spt_notify(vhd, "e.example", "e.example", 4);
	spt_expect(!spt_sub(vhd, "e.example"), "none while the sponge is full");
	vhd->sponge_full = 0;

	/*
	 * The limit per address: c.example's NOTIFY, whose hash isn't its
	 * domain's, is about a zone we don't track
	 */

	for (n = 0; n < LWS_DHT_DNSSEC_NOTIFY_BURST; n++)
		spt_notify(vhd, "c.example", "d.example", 100);
	spt_notify(vhd, "j.example", "j.example", 100);
	spt_expect(!spt_sub(vhd, "j.example"),
		   "NOTIFYs about untracked zones are limited per address");

	spt_notify(vhd, "k.example", "k.example", 101);
	spt_expect(spt_sub(vhd, "k.example") != NULL,
		   "other addresses aren't held to that address's limit");

	sub = spt_sub(vhd, "k.example");
	if (sub)
		sub->last_notify_fetch = time(NULL);
	spt_notify(vhd, "k.example", "k.example", 100);
	spt_expect(sub && !lws_dll2_is_detached(&sub->sul_refetch.list),
		   "a NOTIFY about a zone we track isn't held to it, and the "
		   "fetch it asks for while that is limited is deferred");

	/* who auth-dns hears of */

	spt_notify(vhd, "f.example", "f.example", 5);
	spt_hex("f.example", hex);
	spt_expect(spt_sub(vhd, "f.example") && !dht_dnssec_for_auth(vhd, hex),
		   "a sponge copy is not handed to auth-dns");

	memset(&args, 0, sizeof(args));
	args.vhost = vhd->vhost;
	args.domain = "f.example";
	args.opaque = &args;
	do_fetch_zone(context, &args);
	spt_expect(dht_dnssec_for_auth(vhd, hex),
		   "unless auth-dns asks us to fetch it");
	args.is_cancel = 1;
	do_fetch_zone(context, &args);

	spt_hex("a.example", hex);
	spt_expect(!do_subscribe_zone(vhd->vhost, "a.example") &&
		   (sub = spt_sub(vhd, "a.example")) && !sub->sponge &&
		   dht_dnssec_for_auth(vhd, hex),
		   "auth-dns subscribing to a sponge zone makes it served here");

	/*
	 * The sweep: a.example is served here and stored longest ago, then
	 * the sponge's g, h and i, 1000 bytes each
	 */

	if (spt_expect(!spt_copy("a.example", 2000, 1000) &&
		       !spt_copy("g.example", 1000, 300) &&
		       !spt_file("g.example", ".hwm", 20, 300) &&
		       !spt_copy("h.example", 1000, 200) &&
		       !spt_copy("i.example", 1000, 100), "stored copies"))
		return;

	vhd->sponge_max_bytes = 2500;
	spt_sweep(vhd);
	spt_expect(!spt_has("g.example", "") && spt_has("g.example", ".hwm") &&
		   spt_has("h.example", "") && spt_has("i.example", "") &&
		   spt_has("a.example", "") && vhd->sponge_bytes == 2000 &&
		   !vhd->sponge_full,
		   "over budget, the copy stored longest ago goes, its mark stays");

	vhd->sponge_max_bytes = 1000;
	spt_sweep(vhd);
	spt_expect(!spt_has("h.example", "") && spt_has("i.example", "") &&
		   spt_has("a.example", "") && vhd->sponge_bytes == 1000 &&
		   vhd->sponge_full,
		   "the next goes, never a served zone, and the sponge is full");

	/* f.example's copy never came: its fetch gives up, it is forgotten */

	memset(&args, 0, sizeof(args));
	args.vhost = vhd->vhost;
	args.domain = "f.example";
	args.is_cancel = 1;
	do_fetch_zone(context, &args);
	sub = spt_sub(vhd, "f.example");
	if (sub)
		sub->created = time(NULL) - LWS_DHT_DNSSEC_SPONGE_ORPHAN_SECS - 1;
	spt_sweep(vhd);
	spt_expect(sub && !spt_sub(vhd, "f.example") &&
		   spt_sub(vhd, "a.example"),
		   "a zone taken in whose copy never came is forgotten");
}

/* the plugin makes its DHT once the system is up: wait for that */

static void
spt_wait_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_dht_dnssec *vhd = get_dnssec_vhd(context,
			lws_get_vhost_by_name(context, "default"));

	if (!vhd || !vhd->dht) {
		if (lws_now_usecs() - t_start < 10 * LWS_US_PER_SEC) {
			lws_sul_schedule(context, 0, &sul_wait, spt_wait_cb,
					 50 * LWS_US_PER_MS);
			return;
		}
		spt_expect(0, "plugin instantiated");
	} else
		spt_run(vhd);

	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	static const struct lws_protocols *pprotocols[] = {
		&lws_dht_dnssec_protocols[0], NULL
	};
	struct lws_protocol_vhost_options pvo[3], pvo_wrap;
	struct lws_context_creation_info info;
	const char *port;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: dht-dnssec sponge\n");

	port = lws_cmdline_option(argc, argv, "--port");
	if (!port || atoi(port) <= 0 || atoi(port) > 65535) {
		lwsl_err("%s: --port <udp port> is required\n", __func__);

		return 1;
	}

	lws_dir(SPT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(SPT_STORE);
	if (mkdir(SPT_STORE, 0700) && errno != EEXIST) {
		lwsl_err("%s: unable to create %s\n", __func__, SPT_STORE);

		return 1;
	}

	memset(pvo, 0, sizeof(pvo));
	pvo[0].name = "dht-storage-path";
	pvo[0].value = SPT_STORE;
	pvo[0].next = &pvo[1];
	pvo[1].name = "dht-port";
	pvo[1].value = port;
	pvo[1].next = &pvo[2];
	pvo[2].name = "dht-allow-private";
	pvo[2].value = "1";

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

	t_start = lws_now_usecs();
	lws_sul_schedule(context, 0, &sul_wait, spt_wait_cb,
			 50 * LWS_US_PER_MS);

	while (lws_service(context, 0) >= 0)
		;

	lws_sul_cancel(&sul_wait);
	lws_context_destroy(context);

	lws_dir(SPT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(SPT_STORE);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
