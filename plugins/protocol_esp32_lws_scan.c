/*
 * Example ESP32 app code using Libwebsockets
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.	So unlike the library itself, they are licensed
 * Public Domain.
 *
 */
#include <string.h>
#include <nvs.h>

typedef enum {
	SCAN_STATE_NONE,
	SCAN_STATE_INITIAL,
	SCAN_STATE_LIST,
	SCAN_STATE_FINAL
} scan_state;

struct store_json {
	const char *j;
	const char *nvs;
};

struct per_session_data__esplws_scan {
	struct per_session_data__esplws_scan *next;
	scan_state scan_state;
	char ap_record;
	unsigned char subsequent:1;
	unsigned char changed_partway:1;
};

struct per_vhost_data__esplws_scan {
	wifi_ap_record_t ap_records[20];
	TimerHandle_t timer;
	struct per_session_data__esplws_scan *live_pss_list;
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	uint16_t count_ap_records;
	char count_live_pss;
	unsigned char scan_ongoing:1;
	unsigned char completed_any_scan:1;
	unsigned char reboot:1;
};

static const struct store_json store_json[] = {
	{ "ssid\":\"", "ssid" },
	{ ",\"pw\":\"", "password" },
	{ ",\"serial\":\"", "serial" },
	{ ",\"region\":\"", "region" },
};

static wifi_scan_config_t scan_config = {
	.ssid = 0,
	.bssid = 0,
	.channel = 0,
        .show_hidden = true
};

extern void (*lws_cb_scan_done)(void *);
extern void *lws_cb_scan_done_arg;


static void
scan_finished(void *v);

static int
esplws_simple_arg(char *dest, int len, const char *in, const char *match)
{
       const char *p = strstr(in, match);
       int n = 0;

       if (!p) {
               lwsl_err("No match %s\n", match);
               return 1;
       }

       p += strlen(match);
       while (*p && *p != '\"' && n < len - 1)
               dest[n++] = *p++;
       dest[n] = '\0';

       return 0;
}

static void
scan_start(struct per_vhost_data__esplws_scan *vhd)
{
	int n;

	if (vhd->reboot)
		esp_restart();

	if (vhd->scan_ongoing)
		return;

	vhd->scan_ongoing = 1;
	lws_cb_scan_done = scan_finished;
	lws_cb_scan_done_arg = vhd;
	n = esp_wifi_scan_start(&scan_config, false);
	if (n != ESP_OK)
		lwsl_err("scan start failed %d\n", n);
}

static void timer_cb(TimerHandle_t t)
{
	struct per_vhost_data__esplws_scan *vhd = pvTimerGetTimerID(t);

	scan_start(vhd);
}

static void
scan_finished(void *v)
{
	struct per_vhost_data__esplws_scan *vhd = v;
	struct per_session_data__esplws_scan *p = vhd->live_pss_list;

	vhd->scan_ongoing = 0;

	vhd->count_ap_records = ARRAY_SIZE(vhd->ap_records);
	if (esp_wifi_scan_get_ap_records(&vhd->count_ap_records, vhd->ap_records) != ESP_OK) {
		lwsl_err("%s: failed\n", __func__);
		return;
	}
	
	while (p) {
		if (p->scan_state != SCAN_STATE_INITIAL && p->scan_state != SCAN_STATE_NONE)
			p->changed_partway = 1;
		else
			p->scan_state = SCAN_STATE_INITIAL;
		p = p->next;
	}

	lws_callback_on_writable_all_protocol(vhd->context, vhd->protocol);
}

static int
callback_esplws_scan(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__esplws_scan *pss =
			(struct per_session_data__esplws_scan *)user;
	struct per_vhost_data__esplws_scan *vhd =
			(struct per_vhost_data__esplws_scan *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	char buf[LWS_PRE + 384], /*ip[24],*/ *start = buf + LWS_PRE - 1, *p = start,
	     *end = buf + sizeof(buf) - 1;
	wifi_ap_record_t *r;
	int n, m;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__esplws_scan));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		vhd->timer = xTimerCreate("x", pdMS_TO_TICKS(10000), 1, vhd,
			  (TimerCallbackFunction_t)timer_cb);
		xTimerStart(vhd->timer, 0);
		vhd->scan_ongoing = 0;
		scan_start(vhd);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
		xTimerStop(vhd->timer, 0);
		xTimerDelete(vhd->timer, 0);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		vhd->count_live_pss++;
		pss->next = vhd->live_pss_list;
		vhd->live_pss_list = pss;
		/* if we have scan results, update them.  Otherwise wait */
		if (vhd->count_ap_records) {
			pss->scan_state = SCAN_STATE_INITIAL;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		switch (pss->scan_state) {
		case SCAN_STATE_INITIAL:
			n = LWS_WRITE_TEXT | LWS_WRITE_NO_FIN;;
			p += snprintf(p, end - p,
				      "{ \"model\":\"%s\","
				      " \"serial\":\"%s\","
				      " \"host\":\"%s-%s\","
				      " \"region\":\"%d\","
				      " \"aps\":[",
				      lws_esp32_model,
				      lws_esp32_serial,
				      lws_esp32_model, lws_esp32_serial,
				      lws_esp32_region);
			pss->scan_state = SCAN_STATE_LIST;
			pss->ap_record = 0;
			pss->subsequent = 0;
			break;
		case SCAN_STATE_LIST:
			n = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
			if (pss->ap_record >= vhd->count_ap_records)
				goto scan_state_final;

			if (pss->subsequent)
				*p++ = ',';
			pss->subsequent = 1;

			r = &vhd->ap_records[(int)pss->ap_record++];
			p += snprintf(p, end - p,
				      "{\"ssid\":\"%s\","
				       "\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
				       "\"rssi\":\"%d\","
				       "\"chan\":\"%d\","
				       "\"auth\":\"%d\"}",
					r->ssid,
					r->bssid[0], r->bssid[1], r->bssid[2],
					r->bssid[3], r->bssid[4], r->bssid[5],
					r->rssi, r->primary, r->authmode);
			if (pss->ap_record >= vhd->count_ap_records)
				pss->scan_state = SCAN_STATE_FINAL;
			break;

		case SCAN_STATE_FINAL:
scan_state_final:
			n = LWS_WRITE_CONTINUATION;
			p += sprintf(p, "]}");
			if (pss->changed_partway) {
				pss->subsequent = 0;
				pss->scan_state = SCAN_STATE_INITIAL;
			} else
				pss->scan_state = SCAN_STATE_NONE;
			break;
		default:
			return 0;
		}

		m = lws_write(wsi, (unsigned char *)start, p - start, n);
		if (m < 0) {
			lwsl_err("ERROR %d writing to di socket\n", m);
			return -1;
		}

		if (pss->scan_state != SCAN_STATE_NONE)
			lws_callback_on_writable(wsi);

		break;

	case LWS_CALLBACK_RECEIVE:
		{
			nvs_handle nvh;
			char p[64];
			int n;

			if (strstr((const char *)in, "identify")) {
				lws_esp32_identify_physical_device();
				break;
			}

			if (nvs_open("lws-station", NVS_READWRITE, &nvh) != ESP_OK) {
				lwsl_err("Unable to open nvs\n");
				break;
			}

			for (n = 0; n < ARRAY_SIZE(store_json); n++) {
				if (esplws_simple_arg(p, sizeof(p),  in, store_json[n].j))
					goto bail_nvs;

				if (nvs_set_str(nvh, store_json[n].nvs, p) != ESP_OK) {
					lwsl_err("Unable to store %s in nvm\n", store_json[n].nvs);
					goto bail_nvs;
				}
			}

			nvs_commit(nvh);
			nvs_close(nvh);

			vhd->reboot = 1;
			break;

bail_nvs:
			nvs_close(nvh);

			return 1;
		}

	case LWS_CALLBACK_CLOSED:
		{
			struct per_session_data__esplws_scan **p = &vhd->live_pss_list;

			while (*p) {
				if ((*p) == pss) {
					*p = pss->next;
					continue;
				}

				p = &((*p)->next);
			}

			vhd->count_live_pss--;
		}
		break;
	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_ESPLWS_SCAN \
	{ \
		"esplws-scan", \
		callback_esplws_scan, \
		sizeof(struct per_session_data__esplws_scan), \
		512, 0, NULL \
	}

