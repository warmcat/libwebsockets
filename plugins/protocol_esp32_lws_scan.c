/*
 * ESP32 Scan / Factory protocol handler
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA*
 *
 */
#include <string.h>
#include <nvs.h>
#include <esp_ota_ops.h>

typedef enum {
	SCAN_STATE_NONE,
	SCAN_STATE_INITIAL,
	SCAN_STATE_INITIAL_MANIFEST,
	SCAN_STATE_KNOWN,
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
	struct timeval last_send;

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

#define max_aps 12

struct per_vhost_data__esplws_scan {
	wifi_ap_record_t ap_records[10];
	TimerHandle_t timer, reboot_timer;
	struct per_session_data__esplws_scan *live_pss_list;
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	struct lws_wifi_scan *known_aps_list;

	const esp_partition_t *part;
	esp_ota_handle_t otahandle;
	long file_length;
	long content_length;

	int cert_remaining_days;

	struct lws *cwsi;
	char json[2048];
	int json_len;

	int acme_state;
	char acme_msg[256];

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
	{ "\"ssid0\":\"", "0ssid" },
	{ ",\"pw0\":\"", "0password" },
	{ "\"ssid1\":\"", "1ssid" },
	{ ",\"pw1\":\"", "1password" },
	{ "\"ssid2\":\"", "2ssid" },
	{ ",\"pw2\":\"", "2password" },
	{ "\"ssid3\":\"", "3ssid" },
	{ ",\"pw3\":\"", "3password" },
	{ ",\"access_pw\":\"", "access_pw" },
	{ "{\"group\":\"", "group" },
	{ "{\"role\":\"", "role" },
	{ ",\"region\":\"", "region" },
};

static wifi_scan_config_t scan_config = {
	.ssid = 0,
	.bssid = 0,
	.channel = 0,
        .show_hidden = true
};

const esp_partition_t *
ota_choose_part(void);

static const char * const param_names[] = {
	"text",
	"pub",
	"pri",
	"serial",
	"opts",
	"group",
	"role",
	"updsettings",
};

enum enum_param_names {
	EPN_TEXT,
	EPN_PUB,
	EPN_PRI,
	EPN_SERIAL,
	EPN_OPTS,
	EPN_GROUP,
	EPN_ROLE,
	EPN_UPDSETTINGS,
};


static void
scan_finished(uint16_t count, wifi_ap_record_t *recs, void *v);

static int
esplws_simple_arg(char *dest, int len, const char *in, const char *match)
{
       const char *p = strstr(in, match);
       int n = 0;

       if (!p)
               return 1;

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

	if (lws_esp32.acme)
		return;

	vhd->scan_ongoing = 1;
	lws_esp32.scan_consumer = scan_finished;
	lws_esp32.scan_consumer_arg = vhd;
	n = esp_wifi_scan_start(&scan_config, false);
	if (n != ESP_OK)
		lwsl_err("scan start failed %d\n", n);
}

static char scan_defer;

static void timer_cb(TimerHandle_t t)
{
	struct per_vhost_data__esplws_scan *vhd = pvTimerGetTimerID(t);

	if (!lws_esp32.inet && (scan_defer & 1)) {
		/* if connected in AP mode, wait twice as long between scans */
		return;
	}

	scan_start(vhd);
}

static void reboot_timer_cb(TimerHandle_t t)
{
	esp_restart();
}

static int
client_connection(struct per_vhost_data__esplws_scan *vhd, const char *file)
{
#if CONFIG_LWS_IS_FACTORY_APPLICATION == 'y' && defined(CONFIG_LWS_OTA_SERVER_BASE_URL) && \
    defined(CONFIG_LWS_OTA_SERVER_FQDN)
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
#endif
	return 0; /* ongoing */
}

static int
lws_wifi_scan_rssi(struct lws_wifi_scan *p)
{
	if (!p->count)
		return -127;

	return p->rssi / p->count;
}

/*
 * Insert new lws_wifi_scan into linkedlist in rssi-sorted order, trimming the
 * list if needed to keep it at or below max_aps entries.
 */

static int
lws_wifi_scan_insert_trim(struct lws_wifi_scan **list, struct lws_wifi_scan *ns)
{
	int count = 0, ins = 1, worst;
	struct lws_wifi_scan *newlist, **pworst, *pp1;

	lws_start_foreach_llp(struct lws_wifi_scan **, pp, *list) {
		/* try to find existing match */
		if (!strcmp((*pp)->ssid, ns->ssid) &&
		    !memcmp((*pp)->bssid, ns->bssid, 6)) {
			if ((*pp)->count > 127) {
				(*pp)->count /= 2;
				(*pp)->rssi /= 2;
			}
			(*pp)->rssi += ns->rssi;
			(*pp)->count++;
			ins = 0;
			break;
		}
	} lws_end_foreach_llp(pp, next);

	if (ins) {
		lws_start_foreach_llp(struct lws_wifi_scan **, pp, *list) {
			/* trim any excess guys */
			if (count++ >= max_aps - 1) {
				pp1 = *pp;
				*pp = (*pp)->next;
				free(pp1);
				continue; /* stay where we are */
			}
		} lws_end_foreach_llp(pp, next);

		/* we are inserting... so alloc a copy of him */
		pp1 = malloc(sizeof(*pp1));
		if (!pp1)
			return -1;

		memcpy(pp1, ns, sizeof(*pp1));
		pp1->next = *list;
		*list = pp1;
	}

	/* sort the list ... worst first, but added at the newlist head */

	newlist = NULL;

	/* while anybody left on the old list */
	while (*list) {
		worst = 0;
		pworst = NULL;

		/* who is the worst guy still left on the old list? */
		lws_start_foreach_llp(struct lws_wifi_scan **, pp, *list) {
			if (lws_wifi_scan_rssi(*pp) <= worst) {
				worst = lws_wifi_scan_rssi(*pp);
				pworst = pp;
			}
		} lws_end_foreach_llp(pp, next);

		if (pworst) {
			/* move the worst to the head of the new list */
			pp1 = *pworst;
			*pworst = (*pworst)->next;
			pp1->next = newlist;
			newlist = pp1;
		}
	}

	*list = newlist;

	return 0;
}

static void
scan_finished(uint16_t count, wifi_ap_record_t *recs, void *v)
{
	struct per_vhost_data__esplws_scan *vhd = v;
	struct per_session_data__esplws_scan *p = vhd->live_pss_list;
	struct lws_wifi_scan lws;
	wifi_ap_record_t *r;
	int m;

	lwsl_notice("%s: count %d\n", __func__, count);

	vhd->scan_ongoing = 0;

	if (count < ARRAY_SIZE(vhd->ap_records))
		vhd->count_ap_records = count;
	else
		vhd->count_ap_records = ARRAY_SIZE(vhd->ap_records);

	memcpy(vhd->ap_records, recs, vhd->count_ap_records * sizeof(*recs));
	
	while (p) {
		if (p->scan_state != SCAN_STATE_INITIAL &&
		    p->scan_state != SCAN_STATE_NONE)
			p->changed_partway = 1;
		else
			p->scan_state = SCAN_STATE_INITIAL;
		p = p->next;
	}

	/* convert to generic, cumulative scan results */

	for (m = 0; m < vhd->count_ap_records; m++) {

		r = &vhd->ap_records[m];

		lws.authmode = r->authmode;
		lws.channel = r->primary;
		lws.rssi = r->rssi;
		lws.count = 1;
		memcpy(&lws.bssid, r->bssid, 6);
		strncpy(lws.ssid, (const char *)r->ssid, sizeof(lws.ssid) - 1);
		lws.ssid[sizeof(lws.ssid) - 1] = '\0';

		lws_wifi_scan_insert_trim(&vhd->known_aps_list, &lws);
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

static const char *ssl_names[] = { "ap-cert.pem", "ap-key.pem" };

static int
file_upload_cb(void *data, const char *name, const char *filename,
	       char *buf, int len, enum lws_spa_fileupload_states state)
{
	struct per_session_data__esplws_scan *pss =
			(struct per_session_data__esplws_scan *)data;
	int n;

	switch (state) {
	case LWS_UFS_OPEN:
		if (lws_esp32_get_reboot_type() != LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON)
			return -1;

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
		lwsl_notice("writing %s\n", ssl_names[n]);
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
	union lws_tls_cert_info_results ir;
	struct lws_wifi_scan *lwscan;
	char subject[64];
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
		vhd->scan_ongoing = 0;
		strcpy(vhd->json, " { }");
	//	scan_start(vhd);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
		xTimerStop(vhd->timer, 0);
		xTimerDelete(vhd->timer, 0);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice("%s: ESTABLISHED\n", __func__);
		if (!vhd->live_pss_list) {
		//	scan_start(vhd);
			xTimerStart(vhd->timer, 0);
		}
		vhd->count_live_pss++;
		pss->next = vhd->live_pss_list;
		vhd->live_pss_list = pss;
		/* if we have scan results, update them.  Otherwise wait */
//		if (vhd->count_ap_records) {
			pss->scan_state = SCAN_STATE_INITIAL;
			lws_callback_on_writable(wsi);
//		}
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
			struct timeval t;
			uint8_t mac[6];
			struct lws_esp32_image i;
			char img_factory[384], img_ota[384], group[16], role[16];
			int grt;

		case SCAN_STATE_NONE:

			/* fallthru */

		case SCAN_STATE_INITIAL:

			gettimeofday(&t, NULL);
		//	if (t.tv_sec - pss->last_send.tv_sec < 10)
		//		return 0;

			pss->last_send = t;

			if (nvs_open("lws-station", NVS_READWRITE, &nvh)) {
				lwsl_err("unable to open nvs\n");
				return -1;
			}
			n = 0;
			if (nvs_get_blob(nvh, "ap-cert.pem", NULL, &s) == ESP_OK)
				n = 1;
			if (nvs_get_blob(nvh, "ap-key.pem", NULL, &s) == ESP_OK)
				n |= 2;
			s = sizeof(group) - 1;
			group[0] = '\0';
			role[0] = '\0';
			nvs_get_str(nvh, "group", group, &s);
			nvs_get_str(nvh, "role", role, &s);

			nvs_close(nvh);

			ir.ns.name[0] = '\0';
			subject[0] = '\0';

			if (t.tv_sec > 1464083026 &&
			    !lws_tls_vhost_cert_info(vhd->vhost,
				       LWS_TLS_CERT_INFO_VALIDITY_TO, &ir, 0)) {
				vhd->cert_remaining_days =
					     (ir.time - t.tv_sec) / (24 * 3600);
				ir.ns.name[0] = '\0';
				lws_tls_vhost_cert_info(vhd->vhost,
					LWS_TLS_CERT_INFO_COMMON_NAME, &ir,
						sizeof(ir.ns.name));
				strncpy(subject, ir.ns.name, sizeof(subject) - 1);

				ir.ns.name[0] = '\0';
				lws_tls_vhost_cert_info(vhd->vhost,
					LWS_TLS_CERT_INFO_ISSUER_NAME, &ir,
						sizeof(ir.ns.name));
			}

			/*
			 * this value in the JSON is just
			 * used for UI indication.  Each conditional feature confirms
			 * it itself before it allows itself to be used.
			 */

			grt = lws_esp32_get_reboot_type();

			esp_efuse_mac_get_default(mac);
			strcpy(img_factory, " { \"date\": \"Empty\" }");
			strcpy(img_ota, " { \"date\": \"Empty\" }");

	//		if (grt != LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON) {
				lws_esp32_get_image_info(esp_partition_find_first(ESP_PARTITION_TYPE_APP,
					ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL), &i,
					img_factory, sizeof(img_factory) - 1);
				img_factory[sizeof(img_factory) - 1] = '\0';
				if (img_factory[0] == 0xff || strlen(img_factory) < 8)
					strcpy(img_factory, " { \"date\": \"Empty\" }");

				lws_esp32_get_image_info(esp_partition_find_first(ESP_PARTITION_TYPE_APP,
					ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL), &i,
					img_ota, sizeof(img_ota) - 1);
				img_ota[sizeof(img_ota) - 1] = '\0';
				if (img_ota[0] == 0xff || strlen(img_ota) < 8)
					strcpy(img_ota, " { \"date\": \"Empty\" }");
	//		}

			p += snprintf((char *)p, end - p,
				      "{ \"model\":\"%s\",\n"
				      " \"forced_button\":\"%d\",\n"
				      " \"serial\":\"%s\",\n"
				      " \"opts\":\"%s\",\n"
				      " \"host\":\"%s-%s\",\n"
				      " \"region\":\"%d\",\n"
				      " \"ssl_pub\":\"%d\",\n"
				      " \"ssl_pri\":\"%d\",\n"
				      " \"mac\":\"%02X%02X%02X%02X%02X%02X\",\n"
				      " \"ssid\":\"%s\",\n"
				      " \"conn_ip\":\"%s\",\n"
				      " \"conn_mask\":\"%s\",\n"
				      " \"conn_gw\":\"%s\",\n"
				      " \"certdays\":\"%d\",\n"
				      " \"unixtime\":\"%llu\",\n"
				      " \"certissuer\":\"%s\",\n"
				      " \"certsubject\":\"%s\",\n"
				      " \"le_dns\":\"%s\",\n"
				      " \"le_email\":\"%s\",\n"
				      " \"acme_state\":\"%d\",\n"
				      " \"acme_msg\":\"%s\",\n"
				      " \"button\":\"%d\",\n"
				      " \"group\":\"%s\",\n"
				      " \"role\":\"%s\",\n",
				      lws_esp32.model,
				      grt == LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON, 
				      lws_esp32.serial,
				      lws_esp32.opts,
				      lws_esp32.model, lws_esp32.serial,
				      lws_esp32.region,
				      n & 1, (n >> 1) & 1,
				      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] | 1,
				      lws_esp32.active_ssid,
				      lws_esp32.sta_ip,
				      lws_esp32.sta_mask,
				      lws_esp32.sta_gw,
				      vhd->cert_remaining_days,
				      (unsigned long long)t.tv_sec,
				      ir.ns.name, subject,
				      lws_esp32.le_dns,
				      lws_esp32.le_email,
				      vhd->acme_state,
				      vhd->acme_msg,
				      ((volatile struct lws_esp32 *)(&lws_esp32))->button_is_down,
				      group, role);
			p += snprintf((char *)p, end - p,
				      " \"img_factory\": %s,\n"
				      " \"img_ota\": %s,\n",
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
                                      " \"known\":[\n");

			n = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
			pss->scan_state = SCAN_STATE_KNOWN;
			break;

		case SCAN_STATE_KNOWN:
			if (nvs_open("lws-station", NVS_READONLY, &nvh)) {
				lwsl_notice("unable to open nvh\n");
				return -1;
			}

			for (m = 0; m < 4; m++) {
				char name[10], ssid[32];
				unsigned int pp = 0, use = 0;

				if (m)
					*p++ = ',';

				s = sizeof(ssid) - 1;
				ssid[0] = '\0';
				lws_snprintf(name, sizeof(name) - 1, "%dssid", m);
				nvs_get_str(nvh, name, ssid, &s);
				lws_snprintf(name, sizeof(name) - 1, "%dpassword", m);
				s = 10;
				nvs_get_str(nvh, name, NULL, &s);
				pp = !!s;
				lws_snprintf(name, sizeof(name) - 1, "%duse", m);
				nvs_get_u32(nvh, name, &use);

				p += snprintf((char *)p, end - p,
					"{\"ssid\":\"%s\",\n"
					" \"pp\":\"%u\",\n"
					"\"use\":\"%u\"}\n",
					ssid, pp, use);
			}
			nvs_close(nvh);
			pss->ap_record = 0;

			p += snprintf((char *)p, end - p,
                                      "], \"aps\":[\n");

			n = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
			pss->scan_state = SCAN_STATE_LIST;
			break;

		case SCAN_STATE_LIST:
			lwscan = vhd->known_aps_list;

			n = pss->ap_record;
			while (lwscan && n--)
				lwscan = lwscan->next;

			for (m = 0; m < 6; m++) {
				n = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
				if (!lwscan)
					goto scan_state_final;

				if (pss->subsequent)
					*p++ = ',';
				pss->subsequent = 1;
				pss->ap_record++;

				p += snprintf((char *)p, end - p,
					      "{\"ssid\":\"%s\",\n"
					       "\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\n"
					       "\"rssi\":\"%d\",\n"
					       "\"chan\":\"%d\",\n"
					       "\"auth\":\"%d\"}\n",
					       lwscan->ssid,
					       lwscan->bssid[0], lwscan->bssid[1], lwscan->bssid[2],
					       lwscan->bssid[3], lwscan->bssid[4], lwscan->bssid[5],
					       lws_wifi_scan_rssi(lwscan),
					       lwscan->channel, lwscan->authmode);

				lwscan = lwscan->next;
				if (!lwscan)
					pss->scan_state = SCAN_STATE_FINAL;
			}
			break;

		case SCAN_STATE_FINAL:
scan_state_final:
			n = LWS_WRITE_CONTINUATION;
			p += sprintf((char *)p, "]\n}\n");
			if (pss->changed_partway) {
				pss->changed_partway = 0;
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

	case LWS_CALLBACK_VHOST_CERT_UPDATE:
		lwsl_notice("LWS_CALLBACK_VHOST_CERT_UPDATE: %d\n", (int)len);
		vhd->acme_state = (int)len;
		if (in) {
			strncpy(vhd->acme_msg, in, sizeof(vhd->acme_msg) - 1);
			vhd->acme_msg[sizeof(vhd->acme_msg) - 1] = '\0';
			lwsl_notice("acme_msg: %s\n", (char *)in);
		}
		lws_callback_on_writable_all_protocol_vhost(vhd->vhost, vhd->protocol);
		break;

	case LWS_CALLBACK_RECEIVE:
		{
			const char *sect = "\"app\": {", *b;
			nvs_handle nvh;
			char p[64], use[6];
			int n, si = -1;

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

			if (strstr((const char *)in, "\"reset\""))
				goto sched_reset;

			if (!strncmp((const char *)in, "{\"job\":\"start-le\"", 17))
				goto start_le;


			if (nvs_open("lws-station", NVS_READWRITE, &nvh) != ESP_OK) {
				lwsl_err("Unable to open nvs\n");
				break;
			}

			if (!esplws_simple_arg(p, sizeof(p), in, ",\"slot\":\""))
				si = atoi(p);

			lwsl_notice("si %d\n", si);

			for (n = 0; n < ARRAY_SIZE(store_json); n++) {
				if (esplws_simple_arg(p, sizeof(p), in, store_json[n].j))
					continue;

				/* only change access password if he has physical access to device */
				if (n == 8 && lws_esp32_get_reboot_type() != LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON)
					continue;

				if (lws_nvs_set_str(nvh, store_json[n].nvs, p) != ESP_OK) {
					lwsl_err("Unable to store %s in nvm\n", store_json[n].nvs);
					goto bail_nvs;
				}

				if (si != -1 && n < 8) {
					if (!(n & 1)) {
						strncpy(lws_esp32.ssid[(n >> 1) & 3], p,
								sizeof(lws_esp32.ssid[0]));
						lws_esp32.ssid[(n >> 1) & 3]
							[sizeof(lws_esp32.ssid[0]) - 1] = '\0';
						lws_snprintf(use, sizeof(use) - 1, "%duse", si);
						lwsl_notice("resetting %s to 0\n", use);
						nvs_set_u32(nvh, use, 0);

					} else {
						strncpy(lws_esp32.password[(n >> 1) & 3], p,
								sizeof(lws_esp32.password[0]));
						lws_esp32.password[(n >> 1) & 3]
							[sizeof(lws_esp32.password[0]) - 1] = '\0';
					}
				}

			}

			nvs_commit(nvh);
			nvs_close(nvh);

			if (strstr((const char *)in, "\"factory-reset\"")) {
				if (lws_esp32_get_reboot_type() ==
					LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON) {

					lwsl_notice("Doing factory reset\n");
					ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
					n = nvs_erase_all(nvh);
					if (n)
						lwsl_notice("erase_all failed %d\n", n);
					nvs_commit(nvh);
					nvs_close(nvh);

					goto sched_reset;
				} else
					lwsl_notice("failed on factory button boot\n");
			}

			if (vhd->scan_ongoing)
				vhd->changed_settings = 1;
			else
				lws_esp32_wlan_nvs_get(1);

			lwsl_notice("set Join AP info\n");
			break;

bail_nvs:
			nvs_close(nvh);

			return 1;

sched_reset:
			vhd->reboot_timer = xTimerCreate("x", pdMS_TO_TICKS(250), 0, vhd,
						(TimerCallbackFunction_t)reboot_timer_cb);
			xTimerStart(vhd->reboot_timer, 0);

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

start_le:
			lws_esp32.acme = 1; /* hold off scanning */
			puts(in);
			/*
			 * {"job":"start-le","cn":"home.warmcat.com",
			 * "email":"andy@warmcat.com", "staging":"true"}
			 */

			if (nvs_open("lws-station", NVS_READWRITE, &nvh) != ESP_OK) {
				lwsl_err("Unable to open nvs\n");
				break;
			}

			n = 0;
			b = strstr(in, ",\"cn\":\"");
			if (b) {
				b += 7;
				while (*b && *b != '\"' && n < sizeof(lws_esp32.le_dns) - 1)
					lws_esp32.le_dns[n++] = *b++;
			}
			lws_esp32.le_dns[n] = '\0';

			lws_nvs_set_str(nvh, "acme-cn", lws_esp32.le_dns);
			n = 0;
			b = strstr(in, ",\"email\":\"");
			if (b) {
				b += 10;
				while (*b && *b != '\"' && n < sizeof(lws_esp32.le_email) - 1)
					lws_esp32.le_email[n++] = *b++;
			}
			lws_esp32.le_email[n] = '\0';
			lws_nvs_set_str(nvh, "acme-email", lws_esp32.le_email);
			nvs_commit(nvh);

			nvs_close(nvh);

			n = 1;
			b = strstr(in, ",\"staging\":\"");
			if (b)
				lwsl_notice("staging: %s\n", b);
			if (b && b[12] == 'f')
				n = 0;

			lwsl_notice("cn: %s, email: %s, staging: %d\n", lws_esp32.le_dns, lws_esp32.le_email, n);

			{
				struct lws_acme_cert_aging_args caa;

				memset(&caa, 0, sizeof(caa));
				caa.vh = vhd->vhost;

				caa.element_overrides[LWS_TLS_REQ_ELEMENT_COMMON_NAME] = lws_esp32.le_dns;
				caa.element_overrides[LWS_TLS_REQ_ELEMENT_EMAIL] = lws_esp32.le_email;

				if (n)
					caa.element_overrides[LWS_TLS_SET_DIR_URL] =
							"https://acme-staging.api.letsencrypt.org/directory"; /* staging */
				else
					caa.element_overrides[LWS_TLS_SET_DIR_URL] =
						"https://acme-v01.api.letsencrypt.org/directory"; /* real */

				lws_callback_vhost_protocols_vhost(vhd->vhost,
						LWS_CALLBACK_VHOST_CERT_AGING,
							(void *)&caa, 0);
			}

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
		if (!vhd->live_pss_list)
			xTimerStop(vhd->timer, 0);
		break;

	/* "factory" POST handling */

	case LWS_CALLBACK_HTTP_BODY:
		/* create the POST argument parser if not already existing */
		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
					ARRAY_SIZE(param_names), 1024,
					file_upload_cb, pss);
			if (!pss->spa)
				return -1;

			pss->filename[0] = '\0';
			pss->file_length = 0;
		}
		//puts((const char *)in);
		/* let it parse the POST data */
		if (lws_spa_process(pss->spa, in, len))
			return -1;
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_notice("LWS_CALLBACK_HTTP_BODY_COMPLETION (scan)\n");
		/* call to inform no more payload data coming */
		lws_spa_finalize(pss->spa);

		for (n = 0; n < ARRAY_SIZE(param_names); n++)
			if (lws_spa_get_string(pss->spa, n))
				lwsl_notice(" Param %s: %s\n", param_names[n],
					    lws_spa_get_string(pss->spa, n));
			else
				lwsl_notice(" Param %s: (none)\n",
					    param_names[n]);

		if (nvs_open("lws-station", NVS_READWRITE, &nvh) != ESP_OK) {
			lwsl_err("Unable to open nvs\n");
			break;
		}

		if (lws_esp32_get_reboot_type() == LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON) {

			if (lws_spa_get_string(pss->spa, EPN_SERIAL)) {
				if (lws_nvs_set_str(nvh, "serial", lws_spa_get_string(pss->spa, EPN_SERIAL)) != ESP_OK) {
					lwsl_err("Unable to store serial in nvm\n");
					goto bail_nvs;
				}
		
				nvs_commit(nvh);
			}

			if (lws_spa_get_string(pss->spa, EPN_OPTS)) {
				if (lws_nvs_set_str(nvh, "opts", lws_spa_get_string(pss->spa, EPN_OPTS)) != ESP_OK) {
					lwsl_err("Unable to store options in nvm\n");
					goto bail_nvs;
				}
		
				nvs_commit(nvh);
			}
		}

		if (lws_spa_get_string(pss->spa, EPN_GROUP)) {
			if (lws_nvs_set_str(nvh, "group", lws_spa_get_string(pss->spa, EPN_GROUP)) != ESP_OK) {
				lwsl_err("Unable to store group in nvm\n");
				goto bail_nvs;
			}

			nvs_commit(nvh);
		}

		if (lws_spa_get_string(pss->spa, EPN_ROLE)) {
			if (lws_nvs_set_str(nvh, "role", lws_spa_get_string(pss->spa, EPN_ROLE)) != ESP_OK) {
				lwsl_err("Unable to store group in nvm\n");
				goto bail_nvs;
			}

			nvs_commit(nvh);
		}

		nvs_close(nvh);

		pss->result_len = snprintf(pss->result + LWS_PRE, sizeof(pss->result) - LWS_PRE - 1,
				"<html>OK</html>");

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
		goto bail;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		lwsl_debug("LWS_CALLBACK_HTTP_WRITEABLE: sending %d\n",
			   pss->result_len);
		if (!pss->result_len)
			break;
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

