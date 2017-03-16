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
#include <esp_ota_ops.h>

typedef enum {
	SCAN_STATE_NONE,
	SCAN_STATE_INITIAL,
	SCAN_STATE_INITIAL_MANIFEST,
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

	struct lws_spa *spa;
	char filename[32];
	char result[LWS_PRE + 512];
	unsigned char buffer[4096];
	int result_len;
	int filename_length;
	long file_length;
	nvs_handle nvh;

	char ap_record;
	unsigned char subsequent:1;
	unsigned char changed_partway:1;
};

struct per_vhost_data__esplws_scan {
	wifi_ap_record_t ap_records[10];
	TimerHandle_t timer, reboot_timer;
	struct per_session_data__esplws_scan *live_pss_list;
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	const esp_partition_t *part;
	esp_ota_handle_t otahandle;
	long file_length;
	long content_length;

	struct lws *cwsi;
	char json[1024];
	int json_len;

	uint16_t count_ap_records;
	char count_live_pss;
	unsigned char scan_ongoing:1;
	unsigned char completed_any_scan:1;
	unsigned char reboot:1;
	unsigned char changed_settings:1;
	unsigned char checked_updates:1;
	unsigned char autonomous_update:1;
	unsigned char autonomous_update_sampled:1;
};

static const struct store_json store_json[] = {
	{ "ssid\":\"", "ssid" },
	{ ",\"pw\":\"", "password" },
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

const esp_partition_t *
ota_choose_part(void);

static const char * const param_names[] = {
	"text",
	"pub",
	"pri",
	"serial",
};

enum enum_param_names {
	EPN_TEXT,
	EPN_PUB,
	EPN_PRI,
	EPN_SERIAL,
};


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

static void reboot_timer_cb(TimerHandle_t t)
{
	esp_restart();
}

static int
client_connection(struct per_vhost_data__esplws_scan *vhd, const char *file)
{
	static struct lws_client_connect_info i;
	char path[256];

	memset(&i, 0, sizeof i);

	snprintf(path, sizeof(path) - 1, CONFIG_LWS_OTA_SERVER_BASE_URL "/" CONFIG_LWS_MODEL_NAME "/%s", file);

	lwsl_notice("Fetching %s\n", path);

	i.port = 443;
	i.context = vhd->context;
	i.address = CONFIG_LWS_OTA_SERVER_FQDN;
	i.ssl_connection = 1;
	i.host = i.address;
	i.origin = i.host;
	i.vhost = vhd->vhost;
	i.method = "GET";
	i.path = path;
	i.protocol = "esplws-scan";
	i.pwsi = &vhd->cwsi;

	vhd->cwsi = lws_client_connect_via_info(&i);
	if (!vhd->cwsi) {
		lwsl_notice("NULL return\n");
		return 1; /* fail */
	}

	return 0; /* ongoing */
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

	if (lws_esp32.inet && !vhd->cwsi && !vhd->checked_updates)
		client_connection(vhd, "manifest.json");

	if (vhd->changed_settings) {
		lws_esp32_wlan_nvs_get(1);
		vhd->changed_settings = 0;
	} else
               esp_wifi_connect();
}

static const char *ssl_names[] = { "ssl-pub.der", "ssl-pri.der" };

static int
file_upload_cb(void *data, const char *name, const char *filename,
	       char *buf, int len, enum lws_spa_fileupload_states state)
{
	struct per_session_data__esplws_scan *pss =
			(struct per_session_data__esplws_scan *)data;
	int n;

	switch (state) {
	case LWS_UFS_OPEN:
		lwsl_notice("LWS_UFS_OPEN Filename %s\n", filename);
		strncpy(pss->filename, filename, sizeof(pss->filename) - 1);
		if (!strcmp(name, "pub") || !strcmp(name, "pri")) {
			if (nvs_open("lws-station", NVS_READWRITE, &pss->nvh))
				return 1;
		} else
			return 1;
		pss->file_length = 0;
		break;

	case LWS_UFS_FINAL_CONTENT:
	case LWS_UFS_CONTENT:
		if (len) {
			/* if the file length is too big, drop it */
			if (pss->file_length + len > sizeof(pss->buffer))
				return 1;

			memcpy(pss->buffer + pss->file_length, buf, len);
		}
		pss->file_length += len;

		if (state == LWS_UFS_CONTENT)
			break;

		lwsl_notice("LWS_UFS_FINAL_CONTENT\n");
		n = 0;
		if (!strcmp(name, "pri"))
			n = 1;
		n = nvs_set_blob(pss->nvh, ssl_names[n], pss->buffer, pss->file_length);
		if (n == ESP_OK)
			nvs_commit(pss->nvh);
		nvs_close(pss->nvh);
		if (n != ESP_OK)
			return 1;
		break;
	}

	return 0;
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
	unsigned char *start = pss->buffer + LWS_PRE - 1, *p = start,
		      *end = pss->buffer + sizeof(pss->buffer) - 1;
	wifi_ap_record_t *r;
	int n, m;
	nvs_handle nvh;
	size_t s;


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
		strcpy(vhd->json, " { }");
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

		if (vhd->autonomous_update_sampled) {
			p += snprintf((char *)p, end - p,
				      " {\n \"auton\":\"1\",\n \"pos\": \"%ld\",\n"
				      " \"len\":\"%ld\"\n}\n",
					vhd->file_length,
				        vhd->content_length);

			n = LWS_WRITE_TEXT;
			goto issue;
		}

		switch (pss->scan_state) {
			char ssid[32];
			uint8_t mac[6];
			struct lws_esp32_image i;
			char img_factory[512], img_ota[512];

		case SCAN_STATE_INITIAL:

			ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
			n = 0;
			if (nvs_get_blob(nvh, "ssl-pub.der", NULL, &s) == ESP_OK)
				n = 1;
			if (nvs_get_blob(nvh, "ssl-pri.der", NULL, &s) == ESP_OK)
				n |= 2;
			s = sizeof(ssid) - 1;
			ssid[0] = '\0';
			nvs_get_str(nvh, "ssid", ssid, &s);

			nvs_close(nvh);

			esp_efuse_read_mac(mac);
			strcpy(img_factory, " { \"date\": \"Empty\" }");
			strcpy(img_ota, " { \"date\": \"Empty\" }");

			lws_esp32_get_image_info(esp_partition_find_first(ESP_PARTITION_TYPE_APP,
				ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL), &i,
				img_factory, sizeof(img_factory));
			lws_esp32_get_image_info(esp_partition_find_first(ESP_PARTITION_TYPE_APP,
				ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL), &i,
				img_ota, sizeof(img_ota));

			p += snprintf((char *)p, end - p,
				      "{ \"model\":\"%s\",\n"
				      " \"serial\":\"%s\",\n"
				      " \"host\":\"%s-%s\",\n"
				      " \"region\":\"%d\",\n"
				      " \"ssl_pub\":\"%d\",\n"
				      " \"ssl_pri\":\"%d\",\n"
				      " \"mac\":\"%02X%02X%02X%02X%02X%02X\",\n"
				      " \"ssid\":\"%s\",\n"
				      " \"conn_ip\":\"%s\",\n"
				      " \"conn_mask\":\"%s\",\n"
				      " \"conn_gw\":\"%s\",\n"
				      " \"img_factory\": %s,\n"
				      " \"img_ota\": %s,\n",
				      lws_esp32.model,
				      lws_esp32.serial,
				      lws_esp32.model, lws_esp32.serial,
				      lws_esp32.region,
				      n & 1, (n >> 1) & 1,
				      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] | 1,
				      ssid,
				      lws_esp32.sta_ip,
				      lws_esp32.sta_mask,
				      lws_esp32.sta_gw,
					img_factory,
					img_ota
				      );

			n = LWS_WRITE_TEXT | LWS_WRITE_NO_FIN;
			pss->scan_state = SCAN_STATE_INITIAL_MANIFEST;
			pss->ap_record = 0;
			pss->subsequent = 0;
			break;

		case SCAN_STATE_INITIAL_MANIFEST:
			p += snprintf((char *)p, end - p,
				      " \"latest\": %s,\n"
				      " \"inet\":\"%d\",\n",
					vhd->json,
				      lws_esp32.inet
				      );

			p += snprintf((char *)p, end - p,
                                      " \"aps\":[\n");

			n = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
			pss->scan_state = SCAN_STATE_LIST;
			break;

		case SCAN_STATE_LIST:
			for (m = 0; m < 6; m++) {
				n = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
				if (pss->ap_record >= vhd->count_ap_records)
					goto scan_state_final;

				if (pss->subsequent)
					*p++ = ',';
				pss->subsequent = 1;

				r = &vhd->ap_records[(int)pss->ap_record++];
				p += snprintf((char *)p, end - p,
					      "{\"ssid\":\"%s\",\n"
					       "\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\n"
					       "\"rssi\":\"%d\",\n"
					       "\"chan\":\"%d\",\n"
					       "\"auth\":\"%d\"}\n",
						r->ssid,
						r->bssid[0], r->bssid[1], r->bssid[2],
						r->bssid[3], r->bssid[4], r->bssid[5],
						r->rssi, r->primary, r->authmode);
				if (pss->ap_record >= vhd->count_ap_records)
					pss->scan_state = SCAN_STATE_FINAL;
			}
			break;

		case SCAN_STATE_FINAL:
scan_state_final:
			n = LWS_WRITE_CONTINUATION;
			p += sprintf((char *)p, "]\n}\n");
			if (pss->changed_partway) {
				pss->subsequent = 0;
				pss->scan_state = SCAN_STATE_INITIAL;
			} else {
				pss->scan_state = SCAN_STATE_NONE;
				vhd->autonomous_update_sampled = vhd->autonomous_update;
			}
			break;
		default:
			return 0;
		}
issue:
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
			const char *sect = "\"app\": {", *b;
			nvs_handle nvh;
			char p[64];
			int n;

			if (strstr((const char *)in, "identify")) {
				lws_esp32_identify_physical_device();
				break;
			}

			if (vhd->json_len && strstr((const char *)in, "update-factory")) {
				sect = "\"factory\": {";
				goto auton;
			}
			if (vhd->json_len && strstr((const char *)in, "update-ota"))
				goto auton;

			if (strstr((const char *)in, "factory-reset")) {
				ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
				nvs_erase_all(nvh);
				nvs_commit(nvh);
				nvs_close(nvh);

				vhd->reboot_timer = xTimerCreate("x", pdMS_TO_TICKS(1000), 0, vhd,
				  (TimerCallbackFunction_t)reboot_timer_cb);
				xTimerStart(vhd->reboot_timer, 0);
				return 1;
			}
			if (strstr((const char *)in, "reset")) {
				vhd->reboot_timer = xTimerCreate("x", pdMS_TO_TICKS(1000), 0, vhd,
				  (TimerCallbackFunction_t)reboot_timer_cb);
				xTimerStart(vhd->reboot_timer, 0);
				return 1;
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

			if (vhd->scan_ongoing)
				vhd->changed_settings = 1;
			else
				lws_esp32_wlan_nvs_get(1);

			lwsl_notice("set Join AP info\n");
			break;

bail_nvs:
			nvs_close(nvh);

			return 1;

auton:
			lwsl_notice("Autonomous upload\n");
			b = strstr(vhd->json, sect);
			if (!b) {
				lwsl_notice("Can't find %s in JSON\n", sect);
				return 1;
			}
			b = strstr(b, "\"file\": \"");
			if (!b) {
				lwsl_notice("Can't find \"file\": JSON\n");
				return 1;
			}
			vhd->autonomous_update = 1;
			if (pss->scan_state == SCAN_STATE_NONE)
				vhd->autonomous_update_sampled = 1;
			b += 9;
			n = 0;
			while ((*b != '\"') && n < sizeof(p) - 1)
				p[n++] = *b++;

			p[n] = '\0';

			vhd->part = ota_choose_part();
			if (!vhd->part)
				return 1;

			if (client_connection(vhd, p))
				vhd->autonomous_update = 0;

			break;
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

	/* "factory" POST handling */

	case LWS_CALLBACK_HTTP_BODY:
		/* create the POST argument parser if not already existing */
		lwsl_notice("LWS_CALLBACK_HTTP_BODY (scan)\n");
		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
					ARRAY_SIZE(param_names), 1024,
					file_upload_cb, pss);
			if (!pss->spa)
				return -1;

			pss->filename[0] = '\0';
			pss->file_length = 0;
		}

		/* let it parse the POST data */
		if (lws_spa_process(pss->spa, in, len))
			return -1;
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_notice("LWS_CALLBACK_HTTP_BODY_COMPLETION (scan)\n");
		/* call to inform no more payload data coming */
		lws_spa_finalize(pss->spa);

		if (nvs_open("lws-station", NVS_READWRITE, &nvh) != ESP_OK) {
			lwsl_err("Unable to open nvs\n");
			break;
		}

		if (lws_spa_get_string(pss->spa, EPN_SERIAL)) {
			if (nvs_set_str(nvh, "serial", lws_spa_get_string(pss->spa, EPN_SERIAL)) != ESP_OK) {
				lwsl_err("Unable to store serial in nvm\n");
				goto bail_nvs;
			}
	
			nvs_commit(nvh);
		}
		nvs_close(nvh);

		pss->result_len = snprintf(pss->result + LWS_PRE, sizeof(pss->result) - LWS_PRE - 1,
				"<html>Rebooting after storing certs...<br>connect to AP '<b>config-%s-%s</b>' and continue here: "
				"<a href=\"https://192.168.4.1\">https://192.168.4.1</a></html>",
				lws_esp32.model, lws_spa_get_string(pss->spa, EPN_SERIAL));

		if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end))
			goto bail;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"text/html", 9, &p, end))
			goto bail;
		if (lws_add_http_header_content_length(wsi, pss->result_len, &p, end))
			goto bail;
		if (lws_finalize_http_header(wsi, &p, end))
			goto bail;

		n = lws_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS);
		if (n < 0)
			goto bail;

		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		lwsl_debug("LWS_CALLBACK_HTTP_WRITEABLE: sending %d\n",
			   pss->result_len);
		n = lws_write(wsi, (unsigned char *)pss->result + LWS_PRE,
			      pss->result_len, LWS_WRITE_HTTP);
		if (n < 0)
			return 1;

		vhd->reboot_timer = xTimerCreate("x", pdMS_TO_TICKS(3000), 0, vhd,
			  (TimerCallbackFunction_t)reboot_timer_cb);
		xTimerStart(vhd->reboot_timer, 0);

		return 1; // hang up since we will reset

	/* ----- client handling ----- */

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("Client connection error %s\n", (char *)in);
		vhd->cwsi = NULL;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!vhd->autonomous_update)
			break;

		{
			char pp[20];

			if (lws_hdr_copy(wsi, pp, sizeof(pp) - 1, WSI_TOKEN_HTTP_CONTENT_LENGTH) < 0)
				return -1;
	
			vhd->content_length = atoi(pp);
			if (vhd->content_length <= 0 ||
			    vhd->content_length > vhd->part->size)
				return -1;

			if (esp_ota_begin(vhd->part, (long)-1, &vhd->otahandle) != ESP_OK) {
				lwsl_err("OTA: Failed to begin\n");
				return 1;
			}

			vhd->file_length = 0;
			break;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		//lwsl_notice("LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: %ld\n",
		//	    (long)len);

		if (!vhd->autonomous_update) {
			if (sizeof(vhd->json) - vhd->json_len - 1 < len)
				len = sizeof(vhd->json) - vhd->json_len - 1;
			memcpy(vhd->json + vhd->json_len, in, len);
			vhd->json_len += len;
			vhd->json[vhd->json_len] = '\0';
			break;
		}

		/* autonomous download */


		if (vhd->file_length + len > vhd->part->size) {
			lwsl_err("OTA: incoming file too large\n");
			goto abort_ota;
		}

		lwsl_debug("writing 0x%lx... 0x%lx\n",
			   vhd->part->address + vhd->file_length,
			   vhd->part->address + vhd->file_length + len);
		if (esp_ota_write(vhd->otahandle, in, len) != ESP_OK) {
			lwsl_err("OTA: Failed to write\n");
			goto abort_ota;
		}
		vhd->file_length += len;

		lws_callback_on_writable_all_protocol(vhd->context, vhd->protocol);
		break;

abort_ota:
		esp_ota_end(vhd->otahandle);
		vhd->otahandle = 0;
		vhd->autonomous_update = 0;

		return 1;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char *px = (char *)pss->buffer + LWS_PRE;
			int lenx = sizeof(pss->buffer) - LWS_PRE - 1;

			//lwsl_notice("LWS_CALLBACK_RECEIVE_CLIENT_HTTP: %d\n", len);

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_notice("LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n");
		vhd->cwsi = NULL;
		if (!vhd->autonomous_update) {

			vhd->checked_updates = 1;
			puts(vhd->json);
			return -1;
		}

		/* autonomous download */

		lwsl_notice("auton complete\n");

		if (esp_ota_end(vhd->otahandle) != ESP_OK) {
			lwsl_err("OTA: end failed\n");
			return 1;
		}

		if (esp_ota_set_boot_partition(vhd->part) != ESP_OK) {
			lwsl_err("OTA: set boot part failed\n");
			return 1;
		}
		vhd->otahandle = 0;
		vhd->autonomous_update = 0;

		vhd->reboot_timer = xTimerCreate("x", pdMS_TO_TICKS(250), 0, vhd,
			  (TimerCallbackFunction_t)reboot_timer_cb);
			xTimerStart(vhd->reboot_timer, 0);
		return -1;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_notice("LWS_CALLBACK_CLOSED_CLIENT_HTTP\n");
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		/* called when our wsi user_space is going to be destroyed */
		if (pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		break;

	default:
		break;
	}

	return 0;

bail:
	return 1;
}

#define LWS_PLUGIN_PROTOCOL_ESPLWS_SCAN \
	{ \
		"esplws-scan", \
		callback_esplws_scan, \
		sizeof(struct per_session_data__esplws_scan), \
		1024, 0, NULL, 900 \
	}

