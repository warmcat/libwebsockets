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
	size_t w = 0, max = 2048;
	int n, r = 1;
	uint8_t *buf;

	buf = lws_malloc(max, __func__); /* length should be computed */
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

	if (!lws_settings_plat_set(nds->si, "netdev.creds", buf, w))
		r = 0;

bail:
	if (r)
		lwsl_err("%s: failed\n", __func__);
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

	if (lws_settings_plat_get(nds->si, "netdev.creds", NULL, &l)) {
		lwsl_notice("%s: not in settings\n", __func__);
		return 1;
	}

	buf = lws_malloc(l, __func__);
	if (!buf)
		return 1;

	if (lws_settings_plat_get(nds->si, "netdev.creds", buf, &l)) {
		lwsl_err("%s: unexpected settings get fail\n", __func__);
		goto bail;
	}

	a.map_st[0] = lsm_netdev_schema;
	a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_netdev_schema);
	a.ac_block_size = 512;

	lws_struct_json_init_parse(&ctx, NULL, &a);
	m = lejp_parse(&ctx, (uint8_t *)buf, l);
	lws_free(buf);
	if (m < 0 || !a.dest) {
		lwsl_notice("%s: JSON decode failed '%s'\n",
			    __func__, lejp_error_to_string(m));
		goto bail1;
	}

	/*
	 * Forcibly set the state of the nds creds owner to the synthesized
	 * one in the ac, and keep the ac for as long as we keep the creds out
	 */
	nds->owner_creds = ((lws_netdevs_t *)a.dest)->owner_creds;
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

lws_wifi_creds_t *
lws_netdev_credentials_find(lws_netdevs_t *netdevs, const char *ssid,
			    const uint8_t *bssid)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, lws_dll2_get_head(
	                                               &netdevs->owner_creds)) {
		lws_wifi_creds_t *w = lws_container_of(p, lws_wifi_creds_t, list);

		/*
		 * Unlike lws_wifi_sta_t, lws_wifi_creds_t is not
		 * overallocated with the ssid after it, it has its own
		 * .ssid member
		 */

		if (!strcmp(ssid, w->ssid) &&
		    !memcmp(bssid, w->bssid, sizeof(w->bssid)))
			return w;

	} lws_end_foreach_dll(p);

	return NULL;
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
					return 0;

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
