/*
 * lws-api-test-netdev-creds
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Stores wifi credentials for several APs, in a settings store kept in
 * memory, and checks
 *
 *  - with none stored, there are none, and that isn't an error
 *
 *  - credentials for several APs can be added, and come back from the
 *    settings as they went in, including passphrases and SSIDs with
 *    characters JSON has to escape, and an open AP's empty passphrase
 *
 *  - adding them for an AP again replaces its passphrase, not adds another
 *
 *  - they are stored for any BSS of the AP
 *
 *  - they can be removed, one AP at a time, including the first, and all
 *    of them at once
 *
 *  - too long SSIDs or passphrases are refused
 *
 *  - many APs, with the longest passphrases, all of whose characters have to
 *    be escaped, can be stored
 *
 *  - once nothing holds them, they are freed, and the heap all comes back
 *
 * and for the hostname, that
 *
 *  - with none stored, and no netdev that knows its MAC, there is none
 *
 *  - with none stored, it's "lws-" and the end of the first netdev's MAC
 *
 *  - one set is stored in lower case, comes back, and the netdevs are told
 *
 *  - hostnames that aren't a single DNS label of a-z, 0-9 and '-' are
 *    refused, and so is one that is too long, changing nothing, and one in
 *    the settings that isn't a hostname is ignored for the default
 *
 *  - setting "" forgets it, back to the default
 *
 * and that a wifi netdev's rssi is asked of it, and other netdevs have none.
 *
 * For each AP's history kept with its credentials, that
 *
 *  - it starts unknown, and failing to join is recorded, as a refusal if the
 *    AP refused us, but losing a link that was made isn't
 *
 *  - with SMD, getting an address on the AP records it as joined, and
 *    captive portal detection passing then records it reached the internet
 *
 *  - it's only stored again when it changed
 *
 *  - storing a different passphrase forgets how joining went, but the same
 *    one doesn't
 *
 * and that the AP authentication types have names.
 */

#include <libwebsockets.h>
#include <string.h>

#define BLOBS		4

/* the settings store, in memory */

static struct {
	char		name[32];
	uint8_t		*data;
	size_t		len;
} blobs[BLOBS];

static int fail;
/* how many times the credentials were stored */
static int creds_writes;

/* a netdev, as far as the hostname and rssi go */

static char told[LWS_NETDEV_HOSTNAME_MAX + 1];
static int told_count;

static int
fake_hostname(struct lws_netdev_instance *nd, const char *name)
{
	lws_strncpy(told, name, sizeof(told));
	told_count++;

	return 0;
}

static int
fake_rssi(struct lws_netdev_instance *nd, int *rssi)
{
	*rssi = -55;

	return 0;
}

static int
fake_event(struct lws_netdev_instance *nd, lws_usec_t timestamp, void *buf,
	   size_t len)
{
	return 0;
}

static const lws_netdev_ops_t fake_ops = {
	.event		= fake_event,
	.hostname	= fake_hostname,
	.rssi		= fake_rssi,
};

static int
mem_get(lws_settings_instance_t *si, const char *name, uint8_t *dest,
	size_t *max_actual)
{
	int n;

	for (n = 0; n < BLOBS; n++)
		if (blobs[n].data && !strcmp(blobs[n].name, name)) {
			if (dest)
				memcpy(dest, blobs[n].data,
				       *max_actual < blobs[n].len ?
						*max_actual : blobs[n].len);
			*max_actual = blobs[n].len;

			return 0;
		}

	return 1;
}

static int
mem_set(lws_settings_instance_t *si, const char *name, const uint8_t *src,
	size_t len)
{
	int n, f = -1;

	for (n = 0; n < BLOBS; n++) {
		if (blobs[n].data && !strcmp(blobs[n].name, name)) {
			f = n;
			break;
		}
		if (!blobs[n].data && f < 0)
			f = n;
	}
	if (f < 0)
		return 1;

	if (!strcmp(name, "netdev.creds"))
		creds_writes++;

	free(blobs[f].data);
	blobs[f].data = malloc(len);
	if (!blobs[f].data)
		return 1;
	memcpy(blobs[f].data, src, len);
	blobs[f].len = len;
	lws_strncpy(blobs[f].name, name, sizeof(blobs[f].name));

	return 0;
}

static const lws_settings_ops_t mem_ops = {
	.get		= mem_get,
	.set		= mem_set,
};

static void
expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("FAIL: %s\n", what);
		fail = 1;
	}
}

/*
 * How many are stored, and the passphrase for ssid, which must be stored for
 * any BSS of it; or, if it isn't stored, -1 - how many are
 */

static int
stored(lws_netdevs_t *nds, const char *ssid, char *pp, size_t pp_len)
{
	static const uint8_t any[LWS_ETH_ALEN];
	int n, found = 0;

	lws_netdev_credentials_hold(nds);
	n = (int)lws_dll2_count(&nds->owner_creds);
	*pp = '\0';

	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&nds->owner_creds)) {
		lws_wifi_creds_t *c = lws_container_of(p, lws_wifi_creds_t,
						       list);

		if (!strcmp(c->ssid, ssid)) {
			expect(!memcmp(c->bssid, any, sizeof(any)),
			       "stored for any BSS");
			lws_strncpy(pp, c->passphrase, pp_len);
			found = 1;
		}
	} lws_end_foreach_dll(p);

	lws_netdev_credentials_release(nds);

	return found ? n : -n - 1;
}

/* how joining ssid went, as stored: returns nonzero if it isn't stored */

static int
history(lws_netdevs_t *nds, const char *ssid, int *join, int *internet)
{
	int r = 1;

	lws_netdev_credentials_hold(nds);

	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&nds->owner_creds)) {
		lws_wifi_creds_t *c = lws_container_of(p, lws_wifi_creds_t,
						       list);

		if (!strcmp(c->ssid, ssid)) {
			*join = c->last_join;
			*internet = c->internet;
			r = 0;
		}
	} lws_end_foreach_dll(p);

	lws_netdev_credentials_release(nds);

	return r;
}

/* the AP history kept with the credentials, using a wifi netdev */

static void
test_history(struct lws_context *cx, lws_netdevs_t *nds)
{
	static lws_netdev_instance_wifi_t wnd;
	int join, inet, w;

	memset(&wnd, 0, sizeof(wnd));
	wnd.inst.type = LWSNDTYP_WIFI;
	wnd.inst.ops = &fake_ops;
	wnd.inst.name = "wl0";
	lws_dll2_add_tail(&wnd.inst.list, &nds->owner);

	expect(!lws_netdev_credentials_add(nds, "home", "newpassphrase") &&
	       !history(nds, "home", &join, &inet) &&
	       join == LWS_WIFI_JOIN_UNKNOWN && !inet, "history unknown");

	/* failing to join it */

	lws_strncpy(wnd.current_attempt_ssid, "home",
		    sizeof(wnd.current_attempt_ssid));
	w = creds_writes;
	lws_netdev_wifi_link_lost(&wnd, 1);
	expect(!history(nds, "home", &join, &inet) &&
	       join == LWS_WIFI_JOIN_AUTH_FAILED && creds_writes == w + 1,
	       "auth failure recorded");
	lws_netdev_wifi_link_lost(&wnd, 1);
	expect(creds_writes == w + 1, "unchanged history not stored");
	lws_netdev_wifi_link_lost(&wnd, 0);
	expect(!history(nds, "home", &join, &inet) &&
	       join == LWS_WIFI_JOIN_FAILED, "failure recorded");

	/* an AP we have no credentials for has no history */

	lws_strncpy(wnd.current_attempt_ssid, "elsewhere",
		    sizeof(wnd.current_attempt_ssid));
	w = creds_writes;
	lws_netdev_wifi_link_lost(&wnd, 1);
	expect(creds_writes == w && history(nds, "elsewhere", &join, &inet),
	       "no history without credentials");

#if defined(LWS_WITH_SYS_SMD)
	{
		lws_usec_t until = lws_now_usecs() + 5 * LWS_US_PER_SEC;

		/*
		 * An address on it: joined.  Captive portal detection is
		 * bypassed, so it passes at once, and it reached the internet
		 */

		lws_strncpy(wnd.current_attempt_ssid, "home",
			    sizeof(wnd.current_attempt_ssid));
		lws_smd_msg_printf(cx, LWSSMDCL_NETWORK,
				   "{\"type\":\"ipacq\",\"if\":\"wl0\","
				   "\"ipv4\":\"192.168.1.2\"}");

		do {
			lws_service(cx, 0);
			if (!history(nds, "home", &join, &inet) &&
			    join == LWS_WIFI_JOIN_OK && inet)
				break;
		} while (lws_now_usecs() < until);

		expect(join == LWS_WIFI_JOIN_OK && inet && wnd.joined,
		       "joined and reached internet");

		/* losing a link that was made is nothing against them */

		w = creds_writes;
		lws_netdev_wifi_link_lost(&wnd, 0);
		expect(!history(nds, "home", &join, &inet) &&
		       join == LWS_WIFI_JOIN_OK && !wnd.joined &&
		       creds_writes == w, "link lost after joining");

		/* the same passphrase keeps it, a new one forgets the join */

		expect(!lws_netdev_credentials_add(nds, "home", "newpassphrase") &&
		       !history(nds, "home", &join, &inet) &&
		       join == LWS_WIFI_JOIN_OK && inet, "same passphrase");
		expect(!lws_netdev_credentials_add(nds, "home", "another1") &&
		       !history(nds, "home", &join, &inet) &&
		       join == LWS_WIFI_JOIN_UNKNOWN && inet, "new passphrase");
	}
#endif

	lws_dll2_remove(&wnd.inst.list);

	expect(!strcmp(lws_wifi_auth_name(LWS_WIFI_AUTH_OPEN), "Open") &&
	       !strcmp(lws_wifi_auth_name(LWS_WIFI_AUTH_WPA2), "WPA2") &&
	       !strcmp(lws_wifi_auth_name(LWS_WIFI_AUTH_OTHER), "?") &&
	       !strcmp(lws_wifi_auth_name((lws_wifi_auth_t)200), "?"),
	       "auth names");
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char pp[64], ssid[33], big[64], toolong[65];
	struct lws_context *cx;
	lws_netdevs_t *nds;
	size_t heap;
	int n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	/* the AP history test has captive portal detection pass at once */
	info.options |= LWS_SERVER_OPTION_CPD_BYPASS;

	lwsl_user("LWS API Test - netdev credentials\n");

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	nds = lws_netdevs_from_ctx(cx);
	nds->si = lws_settings_init(&mem_ops, NULL);
	if (!nds->si) {
		lws_context_destroy(cx);
		return 1;
	}

	heap = lws_get_allocated_heap();

	/* none stored */

	expect(!lws_netdev_credentials_has(nds, "home"), "none: has");
	expect(stored(nds, "home", pp, sizeof(pp)) == -1, "none: empty");
	expect(lws_netdev_credentials_remove(nds, "home"), "none: remove");

	/* several APs, with characters JSON escapes */

	expect(!lws_netdev_credentials_add(nds, "home", "passphrase1"),
	       "add home");
	expect(!lws_netdev_credentials_add(nds, "office \"2\"",
					   "p\\w\"2\t</x>"), "add office");
	expect(!lws_netdev_credentials_add(nds, "caf\xc3\xa9", ""),
	       "add open cafe");

	expect(lws_netdev_credentials_has(nds, "home") &&
	       lws_netdev_credentials_has(nds, "office \"2\"") &&
	       lws_netdev_credentials_has(nds, "caf\xc3\xa9") &&
	       !lws_netdev_credentials_has(nds, "hom"), "has");

	expect(stored(nds, "home", pp, sizeof(pp)) == 3 &&
	       !strcmp(pp, "passphrase1"), "home passphrase");
	expect(stored(nds, "office \"2\"", pp, sizeof(pp)) == 3 &&
	       !strcmp(pp, "p\\w\"2\t</x>"), "office passphrase");
	expect(stored(nds, "caf\xc3\xa9", pp, sizeof(pp)) == 3 && !pp[0],
	       "cafe passphrase");

	/* again for the same AP replaces it */

	expect(!lws_netdev_credentials_add(nds, "home", "newpassphrase"),
	       "replace home");
	expect(stored(nds, "home", pp, sizeof(pp)) == 3 &&
	       !strcmp(pp, "newpassphrase"), "home replaced");

	/* removing one leaves the others */

	expect(!lws_netdev_credentials_remove(nds, "office \"2\""),
	       "remove office");
	expect(lws_netdev_credentials_remove(nds, "office \"2\""),
	       "remove office again");
	expect(!lws_netdev_credentials_has(nds, "office \"2\"") &&
	       stored(nds, "home", pp, sizeof(pp)) == 2 &&
	       !strcmp(pp, "newpassphrase"), "office removed");

	/* the first of them too, as they come back from the settings */

	expect(!lws_netdev_credentials_remove(nds, "home") &&
	       !lws_netdev_credentials_has(nds, "home") &&
	       stored(nds, "caf\xc3\xa9", pp, sizeof(pp)) == 1,
	       "first removed");
	expect(!lws_netdev_credentials_add(nds, "home", "newpassphrase"),
	       "add home again");

	/* too long */

	/* one character longer than an SSID can be */
	memset(big, 'a', sizeof(ssid));
	big[sizeof(ssid)] = '\0';
	expect(lws_netdev_credentials_add(nds, big, "x") &&
	       lws_netdev_credentials_add(nds, NULL, "x") &&
	       lws_netdev_credentials_add(nds, "", "x"), "bad ssid refused");
	/* one character longer than a passphrase can be */
	memset(toolong, 'b', sizeof(toolong) - 1);
	toolong[sizeof(toolong) - 1] = '\0';
	expect(lws_netdev_credentials_add(nds, "home", toolong) &&
	       lws_netdev_credentials_add(nds, "home", NULL),
	       "bad passphrase refused");
	expect(stored(nds, "home", pp, sizeof(pp)) == 2 &&
	       !strcmp(pp, "newpassphrase"), "refused changed nothing");

	/* many APs, whose passphrases are all escaped characters */

	memset(big, '"', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	for (n = 0; n < 20; n++) {
		memset(ssid, '\\', sizeof(ssid) - 1);
		lws_snprintf(ssid, 8, "ap%02d", n);
		ssid[strlen(ssid)] = '\\';
		ssid[sizeof(ssid) - 1] = '\0';
		if (lws_netdev_credentials_add(nds, ssid, big)) {
			expect(0, "add many");
			break;
		}
	}
	expect(stored(nds, ssid, pp, sizeof(pp)) == 22 && !strcmp(pp, big),
	       "many stored");

	/* forgetting all of them, eg, for a factory reset */

	expect(!lws_netdev_credentials_clear(nds) &&
	       stored(nds, "home", pp, sizeof(pp)) == -1 &&
	       !lws_netdev_credentials_clear(nds), "cleared");

	/* the hostname, with no netdev yet, so no default */

	{
		static lws_netdev_instance_t ni;
		char hn[LWS_NETDEV_HOSTNAME_MAX + 1];
		int r;

		expect(lws_netdev_hostname_get(nds, hn, sizeof(hn)) == -1 &&
		       !hn[0], "no hostname");
		expect(lws_netdev_hostname_get(nds, hn, 8) == -1,
		       "hostname buffer too small");

		/* a netdev that knows its MAC gives the default */

		memset(&ni, 0, sizeof(ni));
		ni.type = LWSNDTYP_WIFI;
		ni.mac[3] = 0xa1;
		ni.mac[4] = 0xb2;
		ni.mac[5] = 0xc3;
		ni.ops = &fake_ops;
		ni.name = "fake";
		lws_dll2_add_tail(&ni.list, &nds->owner);

		r = lws_netdev_hostname_get(nds, hn, sizeof(hn));
		expect(r == 1 && !strcmp(hn, "lws-a1b2c3"), "default hostname");

		expect(!lws_netdev_hostname_set(nds, "Kitchen-Display2"),
		       "set hostname");
		r = lws_netdev_hostname_get(nds, hn, sizeof(hn));
		expect(r == 0 && !strcmp(hn, "kitchen-display2"),
		       "stored hostname");
		expect(told_count == 1 && !strcmp(told, "kitchen-display2"),
		       "netdev told hostname");

		/* not a hostname, or too long: refused, nothing changed */

		memset(big, 'a', LWS_NETDEV_HOSTNAME_MAX + 1);
		big[LWS_NETDEV_HOSTNAME_MAX + 1] = '\0';
		expect(lws_netdev_hostname_set(nds, "-front") &&
		       lws_netdev_hostname_set(nds, "back-") &&
		       lws_netdev_hostname_set(nds, "a_b") &&
		       lws_netdev_hostname_set(nds, "a.b") &&
		       lws_netdev_hostname_set(nds, "a b") &&
		       lws_netdev_hostname_set(nds, "caf\xc3\xa9") &&
		       lws_netdev_hostname_set(nds, big), "bad hostname refused");
		big[LWS_NETDEV_HOSTNAME_MAX] = '\0';
		r = lws_netdev_hostname_get(nds, hn, sizeof(hn));
		expect(r == 0 && !strcmp(hn, "kitchen-display2") &&
		       told_count == 1, "refused changed nothing");

		/* the longest there can be */

		expect(!lws_netdev_hostname_set(nds, big) &&
		       !lws_netdev_hostname_get(nds, hn, sizeof(hn)) &&
		       !strcmp(hn, big), "longest hostname");

		/* what is in the settings is untrusted */

		mem_set(nds->si, "netdev.hostname", (const uint8_t *)"a<b>", 5);
		r = lws_netdev_hostname_get(nds, hn, sizeof(hn));
		expect(r == 1 && !strcmp(hn, "lws-a1b2c3"),
		       "bad stored hostname ignored");
		mem_set(nds->si, "netdev.hostname", (const uint8_t *)"abc", 3);
		r = lws_netdev_hostname_get(nds, hn, sizeof(hn));
		expect(r == 1, "unterminated stored hostname ignored");

		/* forgetting it */

		expect(!lws_netdev_hostname_set(nds, "x") &&
		       !lws_netdev_hostname_set(nds, ""), "forget hostname");
		r = lws_netdev_hostname_get(nds, hn, sizeof(hn));
		expect(r == 1 && !strcmp(hn, "lws-a1b2c3") &&
		       !strcmp(told, "lws-a1b2c3"), "forgotten hostname");

		/* rssi */

		expect(!lws_netdev_wifi_rssi(&ni, &r) && r == -55, "rssi");
		ni.type = LWSNDTYP_ETH;
		expect(lws_netdev_wifi_rssi(&ni, &r) &&
		       lws_netdev_wifi_rssi(NULL, &r), "no rssi");

		lws_dll2_remove(&ni.list);
	}

	/* nothing holds them now */

	expect(!nds->ac_creds && !nds->refcount_creds &&
	       !lws_dll2_get_head(&nds->owner_creds), "freed");
	expect(lws_get_allocated_heap() == heap, "heap");

	/*
	 * Last, since the context acts on the address the netdev gets too,
	 * eg, it starts captive portal detection, which holds some heap
	 */
	test_history(cx, nds);
	expect(!nds->ac_creds && !nds->refcount_creds &&
	       !lws_dll2_get_head(&nds->owner_creds), "history: freed");

	lws_settings_deinit(&nds->si);
	lws_context_destroy(cx);

	for (n = 0; n < BLOBS; n++)
		free(blobs[n].data);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
