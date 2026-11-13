/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <private-lib-core.h>

static const lws_struct_map_t lsm_wifi_creds[] = {
	LSM_CARRAY	(lws_wifi_creds_t, ssid,		"ssid"),
	LSM_CARRAY	(lws_wifi_creds_t, passphrase,		"passphrase"),
	LSM_UNSIGNED	(lws_wifi_creds_t, alg,			"alg"),
	LSM_CARRAY	(lws_wifi_creds_t, bssid_hex,		"bssid"),
	LSM_UNSIGNED	(lws_wifi_creds_t, last_join,		"last_join"),
	LSM_UNSIGNED	(lws_wifi_creds_t, internet,		"internet"),
};

static const lws_struct_map_t lsm_netdev_credentials[] = {
	LSM_LIST	(lws_netdevs_t, owner_creds, lws_wifi_creds_t, list,
			 NULL, lsm_wifi_creds,			"credentials"),
};

static const lws_struct_map_t lsm_netdev_schema[] = {
        LSM_SCHEMA      (lws_netdevs_t, NULL, lsm_netdev_credentials,
                                              "lws-netdev-creds"),
};


//LSM_CHILD_PTR	(lws_netdev_instance_wifi_t, ap_cred, lws_wifi_creds_t,
//		 NULL, lsm_wifi_creds,			"ap_cred"),
//LSM_STRING_PTR	(lws_netdev_instance_wifi_t, ap_ip,	"ap_ip"),

int
lws_netdev_credentials_settings_set(lws_netdevs_t *nds)
{
	lws_struct_serialize_t *js;
	size_t w = 0, max;
	int n, r = 1;
	uint8_t *buf;

	/*
	 * Each one, if every character of its ssid and passphrase had to be
	 * escaped as \uXXXX, and its names, alg, bssid and history
	 */
	max = 64 + lws_dll2_count(&nds->owner_creds) *
		(6 * (sizeof(((lws_wifi_creds_t *)0)->ssid) +
		      sizeof(((lws_wifi_creds_t *)0)->passphrase)) + 128);

	buf = lws_malloc(max, __func__);
	if (!buf)
		return 1;

	/* bring the serializable hex form of each bssid up to date */

	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&nds->owner_creds)) {
		lws_wifi_creds_t *cr = lws_container_of(p, lws_wifi_creds_t, list);

		lws_hex_from_byte_array(cr->bssid, sizeof(cr->bssid),
					cr->bssid_hex, sizeof(cr->bssid_hex));

	} lws_end_foreach_dll(p);

	js = lws_struct_json_serialize_create(lsm_netdev_schema,
			LWS_ARRAY_SIZE(lsm_netdev_schema), 0, nds);
	if (!js)
		goto bail;

	n = lws_struct_json_serialize(js, buf, max, &w);
	lws_struct_json_serialize_destroy(&js);
	if (n != LSJS_RESULT_FINISH)
		goto bail;

	/*
	 * The serialized blob contains the passphrases... it must not be
	 * logged, only counted
	 */

	lwsl_notice("%s: storing %u credential(s)\n", __func__,
		    (unsigned int)lws_dll2_count(&nds->owner_creds));

	if (nds->si && !nds->si->so->set(nds->si, "netdev.creds", buf, w))
		r = 0;

bail:
	if (r)
		lwsl_err("%s: failed\n", __func__);
	/* it held the passphrases */
	lws_explicit_bzero(buf, max);
	lws_free(buf);

	return r;
}

int
lws_netdev_credentials_settings_get(lws_netdevs_t *nds)
{
	struct lejp_ctx ctx;
	lws_struct_args_t a;
	size_t l = 0;
	uint8_t *buf;
	int m;

	memset(&a, 0, sizeof(a));

	if (!nds->si ||
	    nds->si->so->get(nds->si, "netdev.creds", NULL, &l)) {
		lwsl_notice("%s: not in settings\n", __func__);
		return 1;
	}

	buf = lws_malloc(l, __func__);
	if (!buf)
		return 1;

	if (nds->si->so->get(nds->si, "netdev.creds", buf, &l)) {
		lwsl_err("%s: unexpected settings get fail\n", __func__);
		goto bail;
	}

	a.map_st[0] = lsm_netdev_schema;
	a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_netdev_schema);
	a.ac_block_size = 512;

	lws_struct_json_init_parse(&ctx, NULL, &a);
	m = lejp_parse(&ctx, (uint8_t *)buf, (int)l);
	lws_explicit_bzero(buf, l);
	lws_free(buf);
	if (m < 0 || !a.dest) {
		lwsl_notice("%s: JSON decode failed '%s'\n",
			    __func__, lejp_error_to_string(m));
		goto bail1;
	}

	/*
	 * Move the credentials to our list from the one synthesized in the
	 * ac: each knows the owner it's on, so the list can't just be copied,
	 * or removing one later would change the ac's list, not ours.  Keep
	 * the ac for as long as we keep the creds out.
	 */
	lws_dll2_owner_clear(&nds->owner_creds);
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1, lws_dll2_get_head(
			&((lws_netdevs_t *)a.dest)->owner_creds)) {
		lws_dll2_remove(p);
		lws_dll2_add_tail(p, &nds->owner_creds);
	} lws_end_foreach_dll_safe(p, p1);
	nds->ac_creds = a.ac;

	/*
	 * Recover the binary bssid from the (untrusted, settings-provided)
	 * hex form... anything that isn't exactly LWS_ETH_ALEN bytes of hex
	 * leaves the bssid zeroed rather than half-filled
	 */

	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&nds->owner_creds)) {
		lws_wifi_creds_t *cr = lws_container_of(p, lws_wifi_creds_t, list);

		if (lws_hex_len_to_byte_array(cr->bssid_hex,
					      strlen(cr->bssid_hex), cr->bssid,
					      (int)sizeof(cr->bssid)) !=
							(int)sizeof(cr->bssid))
			memset(cr->bssid, 0, sizeof(cr->bssid));

	} lws_end_foreach_dll(p);

	return 0;

bail:
	lws_free(buf);
bail1:
	lwsac_free(&a.ac);

	return 1;
}

void
lws_netdev_credentials_hold(lws_netdevs_t *nds)
{
	/* none stored is not an error: there are just none in the list */
	if (!nds->refcount_creds && !nds->ac_creds &&
	    lws_netdev_credentials_settings_get(nds))
		lws_dll2_owner_clear(&nds->owner_creds);

	nds->refcount_creds++;
}

void
lws_netdev_credentials_release(lws_netdevs_t *nds)
{
	if (!nds->refcount_creds || --nds->refcount_creds)
		return;

	/* the passphrases are secrets: don't leave them in the heap */

	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&nds->owner_creds)) {
		lws_wifi_creds_t *w = lws_container_of(p, lws_wifi_creds_t,
						       list);

		lws_explicit_bzero(w->passphrase, sizeof(w->passphrase));
	} lws_end_foreach_dll(p);

	lws_dll2_owner_clear(&nds->owner_creds);
	lwsac_free(&nds->ac_creds);
}

/* the held credentials for ssid, if any */

static lws_wifi_creds_t *
creds_by_ssid(lws_netdevs_t *nds, const char *ssid)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&nds->owner_creds)) {
		lws_wifi_creds_t *w = lws_container_of(p, lws_wifi_creds_t,
						       list);

		if (!strcmp(w->ssid, ssid))
			return w;
	} lws_end_foreach_dll(p);

	return NULL;
}

int
lws_netdev_credentials_add(lws_netdevs_t *nds, const char *ssid,
			   const char *passphrase)
{
	lws_wifi_creds_t *c;
	int r = 1;

	if (!ssid || !*ssid || strlen(ssid) >= sizeof(c->ssid) || !passphrase ||
	    strlen(passphrase) >= sizeof(c->passphrase))
		return 1;

	/* the ones already stored, if any, are kept alongside it */

	lws_netdev_credentials_hold(nds);

	c = creds_by_ssid(nds, ssid);
	if (!c) {
		c = lwsac_use_zero(&nds->ac_creds, sizeof(*c), 512);
		if (!c)
			goto bail;
		lws_strncpy(c->ssid, ssid, sizeof(c->ssid));
		lws_dll2_add_tail(&c->list, &nds->owner_creds);
	}

	/* any BSS of it */
	memset(c->bssid, 0, sizeof(c->bssid));
	/* a different passphrase hasn't been tried yet */
	if (strcmp(c->passphrase, passphrase))
		c->last_join = LWS_WIFI_JOIN_UNKNOWN;
	lws_strncpy(c->passphrase, passphrase, sizeof(c->passphrase));

	r = lws_netdev_credentials_settings_set(nds);

bail:
	lws_netdev_credentials_release(nds);

	return r;
}

int
lws_netdev_credentials_remove(lws_netdevs_t *nds, const char *ssid)
{
	lws_wifi_creds_t *c;
	int r = 1;

	if (!ssid)
		return 1;

	lws_netdev_credentials_hold(nds);

	c = creds_by_ssid(nds, ssid);
	if (c) {
		/* its memory goes with the lwsac */
		lws_explicit_bzero(c->passphrase, sizeof(c->passphrase));
		lws_dll2_remove(&c->list);
		r = lws_netdev_credentials_settings_set(nds);
	}

	lws_netdev_credentials_release(nds);

	return r;
}

/*
 * Record how joining the AP went with its credentials, if there are any for
 * it.  They're only stored again if that changed what was stored, so the
 * flash isn't written each time we join.  join is lws_wifi_join_t, or -1 to
 * leave it, and internet is nonzero once it reached the internet.
 */

static void
creds_note(lws_netdevs_t *nds, const char *ssid, int join, int internet)
{
	lws_wifi_creds_t *c;

	if (!ssid[0])
		return;

	lws_netdev_credentials_hold(nds);

	c = creds_by_ssid(nds, ssid);
	if (c && ((join >= 0 && c->last_join != (uint8_t)join) ||
		  (internet && !c->internet))) {
		if (join >= 0)
			c->last_join = (uint8_t)join;
		if (internet)
			c->internet = 1;
		lws_netdev_credentials_settings_set(nds);
	}

	lws_netdev_credentials_release(nds);
}

void
lws_netdev_wifi_link_lost(lws_netdev_instance_wifi_t *wnd, int auth_failed)
{
	lws_netdevs_t *nds = lws_netdevs_from_ndi(&wnd->inst);

	/* losing a link we had made is nothing against its credentials */
	if (auth_failed || !wnd->joined)
		creds_note(nds, wnd->current_attempt_ssid,
			   auth_failed ? LWS_WIFI_JOIN_AUTH_FAILED :
					 LWS_WIFI_JOIN_FAILED, 0);

	wnd->joined = 0;
}

const char *
lws_wifi_auth_name(lws_wifi_auth_t auth)
{
	static const char * const names[] = {
		"Open", "WEP", "WPA", "WPA2", "WPA/2", "WPA3", "WPA2/3",
		"802.1X"
	};

	if ((unsigned int)auth >= LWS_ARRAY_SIZE(names))
		return "?";

	return names[auth];
}

int
lws_netdev_credentials_has(lws_netdevs_t *nds, const char *ssid)
{
	int r;

	if (!ssid)
		return 0;

	lws_netdev_credentials_hold(nds);
	r = !!creds_by_ssid(nds, ssid);
	lws_netdev_credentials_release(nds);

	return r;
}

lws_wifi_creds_t *
lws_netdev_credentials_find(lws_netdevs_t *netdevs, const char *ssid,
			    const uint8_t *bssid)
{
	static const uint8_t any[LWS_ETH_ALEN];

	lws_start_foreach_dll(struct lws_dll2 *, p, lws_dll2_get_head(
	                                               &netdevs->owner_creds)) {
		lws_wifi_creds_t *w = lws_container_of(p, lws_wifi_creds_t, list);

		/*
		 * Unlike lws_wifi_sta_t, lws_wifi_creds_t is not
		 * overallocated with the ssid after it, it has its own
		 * .ssid member
		 */

		/* credentials with no bssid are for any BSS of the SSID */
		if (!strcmp(ssid, w->ssid) &&
		    (!memcmp(bssid, w->bssid, sizeof(w->bssid)) ||
		     !memcmp(any, w->bssid, sizeof(w->bssid))))
			return w;

	} lws_end_foreach_dll(p);

	return NULL;
}

/*
 * The hostname is stored in the settings as it is, with its NUL, so that
 * forgetting it stores something: it can only be made of characters that need
 * nothing escaping.  The name is short enough to be an esp32 nvs key
 */

#define LWS_NETDEV_HOSTNAME_SETTING	"netdev.hostname"

/* a single DNS label of a-z, 0-9 and '-', not starting or ending with '-' */

static int
hostname_valid(const char *name, size_t len)
{
	size_t n;

	if (!len || len > LWS_NETDEV_HOSTNAME_MAX || name[0] == '-' ||
	    name[len - 1] == '-')
		return 0;

	for (n = 0; n < len; n++)
		if (!((name[n] >= 'a' && name[n] <= 'z') ||
		      (name[n] >= '0' && name[n] <= '9') || name[n] == '-'))
			return 0;

	return 1;
}

int
lws_netdev_hostname_get(lws_netdevs_t *nds, char *buf, size_t len)
{
	static const uint8_t none[LWS_ETH_ALEN];
	size_t l = len;

	if (len < LWS_NETDEV_HOSTNAME_MAX + 1)
		return -1;

	/* what is stored is untrusted until we see it is a hostname */

	if (nds->si && !nds->si->so->get(nds->si, LWS_NETDEV_HOSTNAME_SETTING,
					 (uint8_t *)buf, &l) &&
	    l >= 2 && l <= len && !buf[l - 1] && hostname_valid(buf, l - 1))
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&nds->owner)) {
		lws_netdev_instance_t *ni = lws_container_of(p,
						lws_netdev_instance_t, list);

		if (memcmp(ni->mac, none, sizeof(none))) {
			lws_snprintf(buf, len, "lws-%02x%02x%02x", ni->mac[3],
				     ni->mac[4], ni->mac[5]);
			return 1;
		}
	} lws_end_foreach_dll(p);

	buf[0] = '\0';

	return -1;
}

int
lws_netdev_hostname_set(lws_netdevs_t *nds, const char *name)
{
	char h[LWS_NETDEV_HOSTNAME_MAX + 1];
	size_t n, len = name ? strlen(name) : 0;

	if (len > LWS_NETDEV_HOSTNAME_MAX || !nds->si)
		return 1;

	for (n = 0; n < len; n++)
		h[n] = (char)tolower((unsigned char)name[n]);
	h[len] = '\0';

	if (len && !hostname_valid(h, len))
		return 1;

	/* nothing stored, just the NUL, is the default */

	if (nds->si->so->set(nds->si, LWS_NETDEV_HOSTNAME_SETTING,
			     (const uint8_t *)h, len + 1))
		return 1;

	if (lws_netdev_hostname_get(nds, h, sizeof(h)) < 0)
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&nds->owner)) {
		lws_netdev_instance_t *ni = lws_container_of(p,
						lws_netdev_instance_t, list);

		if (ni->ops->hostname)
			ni->ops->hostname(ni, h);
	} lws_end_foreach_dll(p);

	return 0;
}

int
lws_netdev_wifi_rssi(lws_netdev_instance_t *nd, int *rssi)
{
	if (!nd || nd->type != LWSNDTYP_WIFI || !nd->ops->rssi)
		return 1;

	return nd->ops->rssi(nd, rssi);
}

lws_netdev_instance_t *
lws_netdev_find(lws_netdevs_t *netdevs, const char *ifname)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, lws_dll2_get_head(
	                                               &netdevs->owner)) {
		lws_netdev_instance_t *ni = lws_container_of(p,
						lws_netdev_instance_t, list);

		if (!strcmp(ifname, ni->name))
			return ni;

	} lws_end_foreach_dll(p);

	return NULL;
}

/*
 * Context forwards NETWORK related smd here, in lws thread context
 */

int
lws_netdev_smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
		  void *buf, size_t len)
{
	struct lws_context *ctx = (struct lws_context *)opaque;
	char pure_ssid[(sizeof(((lws_netdev_instance_wifi_t *)0)->
					current_attempt_ssid) * 6) + 1];
	const char *iface;
	char setname[16];
	size_t al = 0;

	/* deal with anything from whole-network perspective */

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "cpd") &&
	    !lws_json_simple_strcmp(buf, len, "\"result\":", "OK")) {
		/* the AP we're joined to reaches the internet */
		lws_start_foreach_dll(struct lws_dll2 *, p, lws_dll2_get_head(
						&ctx->netdevs.owner)) {
			lws_netdev_instance_t *ni = lws_container_of(p,
						lws_netdev_instance_t, list);
			lws_netdev_instance_wifi_t *wnd =
					(lws_netdev_instance_wifi_t *)ni;

			if (ni->type == LWSNDTYP_WIFI && wnd->joined)
				creds_note(&ctx->netdevs,
					   wnd->current_attempt_ssid, -1, 1);
		} lws_end_foreach_dll(p);

		return 0;
	}

	/* pass through netdev-specific messages to correct platform handler */

	iface = lws_json_simple_find(buf, len, "\"if\":", &al);
	if (!iface)
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, p, lws_dll2_get_head(
	                                                 &ctx->netdevs.owner)) {
		lws_netdev_instance_t *ni = lws_container_of(
						p, lws_netdev_instance_t, list);

		if (!strncmp(ni->name, iface, al)) {

			/*
			 * IP assignment on our netif?  We can deal with marking
			 * the last successful association generically...
			 */

			if (ni->type == LWSNDTYP_WIFI &&
			    !lws_json_simple_strcmp(buf, len, "\"type\":",
							"ipacq")) {
				const char *ev = lws_json_simple_find(buf, len,
							"\"ipv4\":", &al);
				lws_netdev_instance_wifi_t *wnd =
					       (lws_netdev_instance_wifi_t *)ni;

				if (!ev)
					ev = lws_json_simple_find(buf, len,
							"\"ipv6\":", &al);
				if (!ev)
					return 0;

				/* its credentials work */
				wnd->joined = 1;
				creds_note(&ctx->netdevs,
					   wnd->current_attempt_ssid,
					   LWS_WIFI_JOIN_OK, 0);

				lws_snprintf(setname, sizeof(setname),
						"netdev.last.%s", iface);

				/*
				 * An 802.11 SSID is 0 - 32 arbitrary octets
				 * chosen by the AP, it must be escaped before
				 * it can go into a JSON document
				 */

				lws_json_purify(pure_ssid,
						wnd->current_attempt_ssid,
						(int)sizeof(pure_ssid), NULL);

				lws_settings_plat_printf(ctx->netdevs.si,
					setname, "{\"ssid\":\"%s\",\"bssid\":"
					"\"%02X%02X%02X%02X%02X%02X\"}",
					pure_ssid,
					wnd->current_attempt_bssid[0],
					wnd->current_attempt_bssid[1],
					wnd->current_attempt_bssid[2],
					wnd->current_attempt_bssid[3],
					wnd->current_attempt_bssid[4],
					wnd->current_attempt_bssid[5]);
			}

			/*
			 * Pass it through to related netdev instance for
			 * private actions
			 */

			return ni->ops->event(ni, timestamp, buf, len);
		}

	} lws_end_foreach_dll(p);

	return 0;
}

/*
 * This is the generic part of the netdev instance initialization that's always
 * the same, regardless of the netdev type
 */

void
lws_netdev_instance_create(lws_netdev_instance_t *ni, struct lws_context *ctx,
			   const lws_netdev_ops_t *ops, const char *name,
			   void *platinfo)
{
	ni->ops		= ops;
	ni->name	= name;
	ni->platinfo	= platinfo;

	/* add us to the list of active netdevs */

	lws_dll2_add_tail(&ni->list, &ctx->netdevs.owner);
}

void
lws_netdev_instance_remove_destroy(struct lws_netdev_instance *ni)
{
	lws_dll2_remove(&ni->list);
	lws_free(ni);
}

lws_netdevs_t *
lws_netdevs_from_ctx(struct lws_context *ctx)
{
	return &ctx->netdevs;
}
