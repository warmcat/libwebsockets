/*
 * libwebsockets - esp32 wifi -> lws_netdev_wifi
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
 *
 *
 * These are the esp platform wifi-specific netdev pieces.  Nothing else should
 * know any esp-specific apis.
 *
 * Operations happen via the generic lws_detdev instantiation for the platform
 * wifi device, which point in here for operations.  We also set up native OS
 * event hooks per device for wifi and IP stack events, and post them as lws_smd
 * NETWORK events on the if in the "platform private" namespace.  We then
 * service the events in the lws event loop thread context, which may again
 * generate lws_smd NETWORK events in the public namespace depending on what
 * happened.
 *
 * Scan requests go through a sul to make sure we don't get "piling on" from
 * scheduled, timed scans.  Scan results go through the lws_smd "washing" and
 * are actually parsed in lws thread context, where they are converted to lws
 * netdev scan results and processed by generic code.
 */

#include "private-lib-core.h"

#include "esp_system.h"
#include "spi_flash_mmap.h"
#include "esp_wifi.h"
#include <nvs_flash.h>
#include <esp_netif.h>
#include "lwip/stats.h"

/*
 * While associated, how often we log the link's health at NOTICE: rssi and
 * channel, and the lwIP counters if CONFIG_LWIP_STATS is enabled.  Gaps and
 * stalls in tcp traffic over wifi are usually loss and retransmit backoff,
 * these give something to correlate them with.
 */
#define LWS_ESP32_LINK_STATS_INTERVAL_US	(15 * LWS_US_PER_SEC)

/*
 * lws_netdev_instance_t:
 *   lws_netdev_instance_wifi_t:
 *     lws_netdev_instance_wifi_esp32_t
 */

typedef struct lws_netdev_instance_wifi_esp32 {
	lws_netdev_instance_wifi_t		wnd;
	esp_event_handler_instance_t		instance_any_id;
	esp_event_handler_instance_t		instance_got_ip;
	esp_netif_t				*netif;
	wifi_config_t				sta_config;
	lws_sorted_usec_list_t			sul_link_stats;
} lws_netdev_instance_wifi_esp32_t;

/*
static wifi_config_t config = {
	.ap = {
	    .channel = 6,
	    .authmode = WIFI_AUTH_OPEN,
	    .max_connection = 1,
	} };
	*/

/*
 * Platform-specific connect / associate
 */

int
lws_netdev_wifi_connect_plat(lws_netdev_instance_t *nd, const char *ssid,
			     const char *passphrase, uint8_t *bssid)
{
	lws_netdev_instance_wifi_esp32_t *wnde32 =
					(lws_netdev_instance_wifi_esp32_t *)nd;

	wnde32->wnd.inst.ops->up(&wnde32->wnd.inst);

	wnde32->wnd.flags |= LNDIW_MODE_STA;
	esp_wifi_set_mode(WIFI_MODE_STA);
	esp_wifi_set_ps(WIFI_PS_NONE);

#if 0
	/* we will do our own dhcp */
	tcpip_adapter_dhcpc_stop(TCPIP_ADAPTER_IF_STA);
#endif

	lws_strncpy((char *)wnde32->sta_config.sta.ssid, ssid,
		    sizeof(wnde32->sta_config.sta.ssid));
	lws_strncpy((char *)wnde32->sta_config.sta.password, passphrase,
		    sizeof(wnde32->sta_config.sta.password));

	if (bssid) {
		wnde32->sta_config.sta.bssid_set = 1;
		memcpy(wnde32->sta_config.sta.bssid, bssid, 6);
	} else {
		wnde32->sta_config.sta.bssid_set = 0;
	}

	esp_wifi_set_config(WIFI_IF_STA, &wnde32->sta_config);
	esp_wifi_connect();

	return 0;
}

/*
 * This is called from the SMD / lws thread context, after we heard there were
 * scan results on this netdev
 */

static void
lws_esp32_scan_update(lws_netdev_instance_wifi_t *wnd)
{
//	lws_netdevs_t *netdevs = lws_netdevs_from_ndi(&wnd->inst);
	wifi_ap_record_t ap_records[LWS_WIFI_MAX_SCAN_TRACK], *ar;
	uint32_t now = lws_now_secs();
	uint16_t count_ap_records;
	int n;

	count_ap_records = LWS_ARRAY_SIZE(ap_records);
	if (esp_wifi_scan_get_ap_records(&count_ap_records, ap_records)) {
		lwsl_err("%s: failed\n", __func__);
		return;
	}

	if (!count_ap_records)
		return;

	if (wnd->state != LWSNDVWIFI_STATE_SCAN)
		return;

	/*
	 * ... let's collect the OS-specific scan results, and convert then to
	 * lws_netdev sorted by rssi.  If we already have it in the scan list,
	 * keep it and keep a little ringbuffer of its rssi along with an
	 * averaging.  If it's new, add it into the linked-list sorted by rssi.
	 */

	ar = &ap_records[0];
	for (n = 0; n < count_ap_records; n++) {
		lws_wifi_sta_t *w;
		int m;

		m = strlen((const char *)ar->ssid);
		if (!m)
			goto next;

		/*
		 * We know this guy from before?
		 */

		w = lws_netdev_wifi_scan_find(wnd, (const char *)ar->ssid,
						ar->bssid);
		if (!w) {
			w = lws_zalloc(sizeof(*w) + m + 1, __func__);
			if (!w)
				goto next;

			w->ssid = (char *)&w[1];
			memcpy(w->ssid, ar->ssid, m + 1);
			w->ssid_len = m;

			memcpy(w->bssid, ar->bssid, 6);
		} else {
			/* we will update the rssi and re-insert it */
			lws_dll2_remove(&w->list);
		}

		if (w->rssi_count == LWS_ARRAY_SIZE(w->rssi))
			w->rssi_avg -= w->rssi[w->rssi_next];
		else
			w->rssi_count++;
		w->rssi[w->rssi_next] = ar->rssi;
		w->rssi_avg += w->rssi[w->rssi_next++];
		w->rssi_next = w->rssi_next & (LWS_ARRAY_SIZE(w->rssi) - 1);

		lws_dll2_add_sorted(&w->list, &wnd->scan,
				    lws_netdev_wifi_rssi_sort_compare);

		w->ch = ar->primary;
		w->authmode = ar->authmode;
		w->last_seen = now;

next:
		ar++;
	}

	/*
	 * We can do the rest of it using the generic scan list and credentials
	 */

	lws_netdev_wifi_scan_select(wnd);
}

static wifi_scan_config_t scan_config = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,
        .show_hidden = true
};

void
lws_netdev_wifi_scan_plat(lws_netdev_instance_t *nd)
{
	lws_netdev_instance_wifi_t *wnd = (lws_netdev_instance_wifi_t *)nd;

	if (esp_wifi_scan_start(&scan_config, false))
		lwsl_err("%s: %s scan failed\n", __func__, wnd->inst.name);
}

/*
 * Names for the commoner wifi_err_reason_t disconnect reasons, by number since
 * the esp-idf symbol names for them change between versions.  1 - 66 are the
 * 802.11 reason codes, 200+ are esp-idf's own.
 */

static const char *
lws_esp32_disconnect_reason(unsigned int r)
{
	switch (r) {
	case 1:		return "unspecified";
	case 2:		return "auth expired";
	case 3:		return "deauth, AP leaving";
	case 4:		return "disassoc, inactivity";
	case 5:		return "AP too busy";
	case 6:		return "class 2 frame from unauth sta";
	case 7:		return "class 3 frame from unassoc sta";
	case 8:		return "disassoc, sta leaving";
	case 15:	return "4-way handshake timeout";
	case 16:	return "group key update timeout";
	case 34:	return "too many unacked frames";
	case 200:	return "beacon timeout";
	case 201:	return "no AP found";
	case 202:	return "auth fail";
	case 203:	return "assoc fail";
	case 204:	return "handshake timeout";
	case 205:	return "connection fail";
	default:	return "?";
	}
}

#if defined(LWS_WITH_ROUTING)
/*
 * Reflect an address the IP stack has on our interface, if_idx 0, in the lws
 * routing table, as the source of a default route of its family.
 *
 * If we already have exactly that route, it's left alone, since replacing it
 * closes everything that was using it.  Otherwise any route it supersedes is
 * removed first: for IPv4, whatever default route we had before, since the
 * interface has only one IPv4 address.
 *
 * Returns 1 if the route was added, 0 if we already had it, or -1 if OOM.
 */

static int
lws_esp32_route_set(struct lws_context *ctx, const lws_sockaddr46 *src,
		    const lws_sockaddr46 *gw)
{
	struct lws_context_per_thread *pt = &ctx->pt[0];
	lws_route_t robj, *rou;

	lws_pt_lock(pt, __func__);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ctx->routing_table)) {
		rou = lws_container_of(d, lws_route_t, list);

		if (!rou->if_idx && !lws_sa46_compare_ads(&rou->src, src) &&
		    !lws_sa46_compare_ads(&rou->gateway, gw)) {
			lws_pt_unlock(pt);

			return 0;
		}
	} lws_end_foreach_dll(d);

	/* the default route of src's family is the unspecified address, /0 */

	memset(&robj, 0, sizeof(robj));
	robj.dest.sa4.sin_family = AF_INET;
	_lws_route_remove(pt, &robj, LRR_MATCH_DST | LRR_IGNORE_PRI);

	rou = lws_zalloc(sizeof(*rou), __func__);
	if (!rou) {
		lws_pt_unlock(pt);

		return -1;
	}

	rou->dest = robj.dest;
	rou->src = *src;
	rou->src_len = 32;
	rou->gateway = *gw;
	rou->uidx = _lws_route_get_uidx(ctx);

	lws_dll2_add_tail(&rou->list, &ctx->routing_table);
	lws_pt_unlock(pt);

	_lws_route_pt_close_unroutable(pt);

	return 1;
}
#endif

/*
 * The IP stack acquired an IPv4 address on the interface, update the routing
 * table to match and tell everyone about it
 */

static void
lws_esp32_got_ip4(lws_netdev_instance_wifi_esp32_t *wnde32)
{
	struct lws_context *ctx = netdev_instance_to_ctx(&wnde32->wnd.inst);
	esp_netif_ip_info_t ipi;
	char ip[16];

	if (!wnde32->netif || esp_netif_get_ip_info(wnde32->netif, &ipi) ||
	    !ipi.ip.addr)
		return;

#if defined(LWS_WITH_ROUTING)
	{
		lws_sockaddr46 src, gw;

		memset(&src, 0, sizeof(src));
		src.sa4.sin_family = AF_INET;
		memcpy(&src.sa4.sin_addr, &ipi.ip.addr, 4);

		memset(&gw, 0, sizeof(gw));
		gw.sa4.sin_family = AF_INET;
		memcpy(&gw.sa4.sin_addr, &ipi.gw.addr, 4);

		if (lws_esp32_route_set(ctx, &src, &gw) < 0)
			return;
	}
#endif

	lws_write_numeric_address((void *)&ipi.ip.addr, 4, ip, sizeof(ip));
#if defined(LWS_WITH_SYS_SMD)
	lws_smd_msg_printf(ctx, LWSSMDCL_NETWORK,
			   "{\"type\":\"ipacq\",\"if\":\"%s\","
			   "\"ipv4\":\"%s\"}", wnde32->wnd.inst.name, ip);
#endif
}

static void
lws_esp32_link_stats(lws_netdev_instance_wifi_esp32_t *wnde32)
{
	wifi_ap_record_t ap;
	char s[192];
	size_t n;

	if (esp_wifi_sta_get_ap_info(&ap)) {
		lwsl_notice("%s: %s: not associated\n", __func__,
			    wnde32->wnd.inst.name);
		return;
	}

	/* "+" / "-" is the HT40 secondary channel above / below primary */

	n = (size_t)lws_snprintf(s, sizeof(s), "rssi %d, ch %u%s",
				 (int)ap.rssi, (unsigned int)ap.primary,
				 ap.second == WIFI_SECOND_CHAN_ABOVE ? "+" :
				 (ap.second == WIFI_SECOND_CHAN_BELOW ? "-" : ""));
#if LWIP_STATS && TCP_STATS
	n += (size_t)lws_snprintf(s + n, sizeof(s) - n,
				  ", tcp: tx %u, rx %u, drop %u, err %u, "
				  "memerr %u",
				  (unsigned int)lwip_stats.tcp.xmit,
				  (unsigned int)lwip_stats.tcp.recv,
				  (unsigned int)lwip_stats.tcp.drop,
				  (unsigned int)lwip_stats.tcp.err,
				  (unsigned int)lwip_stats.tcp.memerr);
#endif
#if LWIP_STATS && LINK_STATS
	n += (size_t)lws_snprintf(s + n, sizeof(s) - n,
				  ", link: tx %u, rx %u, drop %u, memerr %u",
				  (unsigned int)lwip_stats.link.xmit,
				  (unsigned int)lwip_stats.link.recv,
				  (unsigned int)lwip_stats.link.drop,
				  (unsigned int)lwip_stats.link.memerr);
#endif
	(void)n;

	lwsl_notice("%s: %s: %s\n", __func__, wnde32->wnd.inst.name, s);
}

static void
lws_esp32_link_stats_cb(lws_sorted_usec_list_t *sul)
{
	lws_netdev_instance_wifi_esp32_t *wnde32 = lws_container_of(sul,
			lws_netdev_instance_wifi_esp32_t, sul_link_stats);
	struct lws_context *ctx = netdev_instance_to_ctx(&wnde32->wnd.inst);

	lws_esp32_link_stats(wnde32);

	lws_sul_schedule(ctx, 0, &wnde32->sul_link_stats,
			 lws_esp32_link_stats_cb,
			 LWS_ESP32_LINK_STATS_INTERVAL_US);
}

/*
 * We lost the association: say why, and take down our route, so nothing
 * believes it can still send via the address we had on it
 */

static void
lws_esp32_link_lost(lws_netdev_instance_wifi_esp32_t *wnde32, void *buf,
		    size_t len)
{
#if defined(LWS_WITH_ROUTING)
	struct lws_context *ctx = netdev_instance_to_ctx(&wnde32->wnd.inst);
	struct lws_context_per_thread *pt = &ctx->pt[0];
#endif
	const char *p;
	unsigned int reason = 0;
	int rssi = 0;
	size_t al;

	p = lws_json_simple_find(buf, len, "\"reason\":", &al);
	if (p)
		reason = (unsigned int)atoi(p);
	p = lws_json_simple_find(buf, len, "\"rssi\":", &al);
	if (p)
		rssi = atoi(p);

	lwsl_notice("%s: %s: disconnected, reason %u (%s), rssi %d\n",
		    __func__, wnde32->wnd.inst.name, reason,
		    lws_esp32_disconnect_reason(reason), rssi);

	lws_sul_cancel(&wnde32->sul_link_stats);

#if defined(LWS_WITH_ROUTING)
	lws_pt_lock(pt, __func__);
	_lws_route_table_ifdown(pt, 0);
	lws_pt_unlock(pt);
#endif
}

/*
 * Platform-private interface events turn up here after going through SMD and
 * passed down by matching network interface name via generic lws_netdev.  All
 * that messing around gets us from an OS-specific thread with an event to back
 * here in lws event loop thread context, with the same event bound to a the
 * netdev it belongs to.
 */

int
lws_netdev_wifi_event_plat(struct lws_netdev_instance *nd, lws_usec_t timestamp,
			   void *buf, size_t len)
{
	lws_netdev_instance_wifi_t *wnd = (lws_netdev_instance_wifi_t *)nd;
	struct lws_context *ctx = netdev_instance_to_ctx(&wnd->inst);
	size_t al;

	/*
	 * netdev-private sync messages?  IP_EVENT ids overlap WIFI_EVENT ones,
	 * so they come with a type of their own
	 */

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "privip")) {
		const char *ev = lws_json_simple_find(buf, len, "\"ev\":", &al);

		if (!ev)
			return 0;

		switch (atoi(ev)) {
		case IP_EVENT_STA_GOT_IP:
			lws_esp32_got_ip4(
				(lws_netdev_instance_wifi_esp32_t *)wnd);
			break;
		default:
			break;
		}

		return 0;
	}

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "priv")) {
		const char *ev = lws_json_simple_find(buf, len, "\"ev\":", &al);

		if (!ev)
			return 0;

		lwsl_notice("%s: smd priv ev %.*s\n", __func__, (int)al, ev);

		switch (atoi(ev)) {
		case WIFI_EVENT_STA_START:
			wnd->state = LWSNDVWIFI_STATE_INITIAL;
			goto scan;

		case WIFI_EVENT_STA_DISCONNECTED:
			lws_esp32_link_lost(
				(lws_netdev_instance_wifi_esp32_t *)wnd,
				buf, len);
scan:
#if defined(LWS_WITH_SYS_SMD)
			lws_smd_msg_printf(ctx, LWSSMDCL_NETWORK,
					   "{\"type\":\"linkdown\","
					   "\"if\":\"%s\"}", wnd->inst.name);
#endif
			wnd->state = LWSNDVWIFI_STATE_SCAN;
			/*
			 * We do it via the sul so we don't get timed scans
			 * on top of each other
			 */
			lws_sul_schedule(ctx, 0, &wnd->sul_scan,
					 lws_netdev_wifi_scan, 1);
			break;

		case WIFI_EVENT_STA_CONNECTED:
#if defined(LWS_WITH_SYS_SMD)
			lws_smd_msg_printf(ctx, LWSSMDCL_NETWORK,
					   "{\"type\":\"linkup\","
					   "\"if\":\"%s\"}", wnd->inst.name);
#endif
			lws_sul_schedule(ctx, 0,
				&((lws_netdev_instance_wifi_esp32_t *)wnd)->
							sul_link_stats,
				lws_esp32_link_stats_cb,
				LWS_ESP32_LINK_STATS_INTERVAL_US);
			break;

		case WIFI_EVENT_SCAN_DONE:
			lws_esp32_scan_update(wnd);
			break;
		default:
			return 0;
		}

		return 0;
	}

	return 0;
}

/*
 * This is coming from a thread context unrelated to lws... the first order is
 * to turn these into lws_smd events synchronized on lws thread, since we want
 * to change correspsonding lws netdev object states without locking.
 */

static void
_event_handler_wifi(void *arg, esp_event_base_t event_base, int32_t event_id,
		   void *event_data)
{
	lws_netdev_instance_wifi_t *wnd = (lws_netdev_instance_wifi_t *)arg;
	struct lws_context *ctx = netdev_instance_to_ctx(&wnd->inst);

	switch (event_id) {
	case WIFI_EVENT_STA_DISCONNECTED:
		/*
		 * Why we lost the association is only available here, so it
		 * must travel with the event
		 */
#if defined(LWS_WITH_SYS_SMD)
		{
			wifi_event_sta_disconnected_t *e =
				(wifi_event_sta_disconnected_t *)event_data;

			lws_smd_msg_printf(ctx, LWSSMDCL_NETWORK,
				   "{\"type\":\"priv\",\"if\":\"%s\",\"ev\":%d,"
				   "\"reason\":%u,\"rssi\":%d}",
				   wnd->inst.name, (int)event_id,
				   (unsigned int)e->reason, (int)e->rssi);
		}
#endif
		break;

	case WIFI_EVENT_STA_START:
	case WIFI_EVENT_SCAN_DONE:
	case WIFI_EVENT_STA_CONNECTED:
		/*
		 * These are events in the platform's private namespace,
		 * interpreted only by the lws_smd handler above, ** in the lws
		 * event thread context **.  The point of this is to requeue the
		 * event in the lws thread context like a bottom-half.
		 *
		 * To save on registrations, the context's NETWORK smd
		 * participant passes messages to lws_netdev, who passes ones
		 * that have if matching the netdev name to that netdev's
		 * (*event) handler.
		 *
		 * The other handler may emit generic network state SMD events
		 * for other things to consume.
		 */

#if defined(LWS_WITH_SYS_SMD)
		lws_smd_msg_printf(ctx, LWSSMDCL_NETWORK,
				   "{\"type\":\"priv\",\"if\":\"%s\",\"ev\":%d}",
				   wnd->inst.name, (int)event_id);
#endif
		break;
	default:
		return;
	}
}

/*
 * This is coming from a thread context unrelated to lws, it must not touch lws
 * state like the routing table.  So like the wifi events, we requeue it to be
 * dealt with in the lws event thread context, where the addresses are read
 * back from the netif.
 */

static void
_event_handler_ip(void *arg, esp_event_base_t event_base, int32_t event_id,
	      void *event_data)
{
	lws_netdev_instance_wifi_t *wnd = (lws_netdev_instance_wifi_t *)arg;
	struct lws_context *ctx = netdev_instance_to_ctx(&wnd->inst);

	switch (event_id) {
	case IP_EVENT_STA_GOT_IP:
#if defined(LWS_WITH_SYS_SMD)
		lws_smd_msg_printf(ctx, LWSSMDCL_NETWORK,
				   "{\"type\":\"privip\",\"if\":\"%s\","
				   "\"ev\":%d}", wnd->inst.name, (int)event_id);
#endif
		break;
	default:
		break;
	}
}

/*
 * This is the platform (esp-idf) init for any kind of networking to be
 * available at all
 */
int
lws_netdev_plat_init(void)
{
        nvs_flash_init();
	esp_netif_init();
	ESP_ERROR_CHECK(esp_event_loop_create_default());

	return 0;
}

/*
 * This is the platform (esp-idf) init for any wifi to be available at all
 */
int
lws_netdev_plat_wifi_init(void)
{
	wifi_init_config_t wic = WIFI_INIT_CONFIG_DEFAULT();
	int n;

	esp_netif_create_default_wifi_sta();

	n = esp_wifi_init(&wic);
	if (n) {
		lwsl_err("%s: wifi init fail: %d\n", __func__, n);
		return 1;
	}

	 ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	esp_wifi_set_ps(WIFI_PS_NONE);

	return 0;
}


struct lws_netdev_instance *
lws_netdev_wifi_create_plat(struct lws_context *ctx,
			    const lws_netdev_ops_t *ops,
			    const char *name, void *platinfo)
{
	lws_netdev_instance_wifi_esp32_t *wnde32 = lws_zalloc(
						sizeof(*wnde32), __func__);

	if (!wnde32)
		return NULL;

	wnde32->wnd.inst.type = LWSNDTYP_WIFI;
	lws_netdev_instance_create(&wnde32->wnd.inst, ctx, ops, name, platinfo);

	return &wnde32->wnd.inst;
}

int
lws_netdev_wifi_configure_plat(struct lws_netdev_instance *nd,
			       lws_netdev_config_t *config)
{
	return 0;
}

int
lws_netdev_wifi_up_plat(struct lws_netdev_instance *nd)
{
	lws_netdev_instance_wifi_esp32_t *wnde32 =
					(lws_netdev_instance_wifi_esp32_t *)nd;
	struct lws_context *ctx = netdev_instance_to_ctx(&wnde32->wnd.inst);

	if (wnde32->wnd.flags & LNDIW_UP)
		return 0;

	/* created by esp_netif_create_default_wifi_sta() at wifi init */
	wnde32->netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");

	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
			  IP_EVENT_STA_GOT_IP, _event_handler_ip, nd,
			  &wnde32->instance_got_ip));

	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
			  ESP_EVENT_ANY_ID, _event_handler_wifi, nd,
			  &wnde32->instance_any_id));

	esp_wifi_start();
	esp_wifi_set_ps(WIFI_PS_NONE);
	wnde32->wnd.flags |= LNDIW_UP;

#if defined(LWS_WITH_SYS_SMD)
	lws_smd_msg_printf(ctx, LWSSMDCL_NETWORK,
			   "{\"type\":\"up\",\"if\":\"%s\"}",
			   wnde32->wnd.inst.name);
#endif

	return 0;
}

int
lws_netdev_wifi_down_plat(struct lws_netdev_instance *nd)
{
	lws_netdev_instance_wifi_esp32_t *wnde32 =
					(lws_netdev_instance_wifi_esp32_t *)nd;
	struct lws_context *ctx = netdev_instance_to_ctx(&wnde32->wnd.inst);

	if (!(wnde32->wnd.flags & LNDIW_UP))
		return 0;

#if defined(LWS_WITH_SYS_SMD)
	lws_smd_msg_printf(ctx, LWSSMDCL_NETWORK,
			   "{\"type\":\"down\",\"if\":\"%s\"}",
			   wnde32->wnd.inst.name);
#endif

	lws_sul_cancel(&wnde32->sul_link_stats);
	esp_wifi_stop();

	esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP,
						&wnde32->instance_got_ip);
	esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID,
						&wnde32->instance_any_id);

	wnde32->wnd.flags &= ~LNDIW_UP;

	return 0;
}

void
lws_netdev_wifi_destroy_plat(struct lws_netdev_instance **pnd)
{
	lws_netdev_instance_wifi_esp32_t *wnde32 =
					(lws_netdev_instance_wifi_esp32_t *)*pnd;

	if (wnde32)
		lws_sul_cancel(&wnde32->sul_link_stats);
	lws_free(*pnd);
	*pnd = NULL;
}
