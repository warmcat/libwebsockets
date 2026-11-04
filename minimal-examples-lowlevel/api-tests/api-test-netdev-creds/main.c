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
 *  - they can be removed, one AP at a time
 *
 *  - too long SSIDs or passphrases are refused
 *
 *  - many APs, with the longest passphrases, all of whose characters have to
 *    be escaped, can be stored
 *
 *  - once nothing holds them, they are freed, and the heap all comes back
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

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char pp[64], ssid[33], big[64];
	struct lws_context *cx;
	lws_netdevs_t *nds;
	size_t heap;
	int n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;

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

	/* too long */

	memset(ssid, 'a', sizeof(ssid));
	expect(lws_netdev_credentials_add(nds, ssid, "x") &&
	       lws_netdev_credentials_add(nds, NULL, "x") &&
	       lws_netdev_credentials_add(nds, "", "x"), "bad ssid refused");
	memset(big, 'b', sizeof(big));
	expect(lws_netdev_credentials_add(nds, "home", big) &&
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

	/* nothing holds them now */

	expect(!nds->ac_creds && !nds->refcount_creds &&
	       !lws_dll2_get_head(&nds->owner_creds), "freed");
	expect(lws_get_allocated_heap() == heap, "heap");

	lws_settings_deinit(&nds->si);
	lws_context_destroy(cx);

	for (n = 0; n < BLOBS; n++)
		free(blobs[n].data);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
