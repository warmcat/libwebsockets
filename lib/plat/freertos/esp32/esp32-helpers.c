/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"

#include "romfs.h"
#include <esp_ota_ops.h>
#include <tcpip_adapter.h>
#include <esp_image_format.h>
#include <esp_task_wdt.h>
#include "soc/ledc_reg.h"
#include "driver/ledc.h"

struct lws_esp32 lws_esp32 = {
	.model = CONFIG_LWS_MODEL_NAME,
	.serial = "unknown",
};

/*
 * Group AP / Station State
 */

enum lws_gapss {
	LWS_GAPSS_INITIAL,	/* just started up, init and move to
				 * LWS_GAPSS_SCAN */
	LWS_GAPSS_SCAN,		/*
				 * Unconnected, scanning: AP known in one of the
				 * config slots -> configure it, start timeout +
				 * LWS_GAPSS_STAT, if no AP already up in same
				 * group with lower MAC, after a random period
				 * start up our AP (LWS_GAPSS_AP)
				 */
	LWS_GAPSS_AP,		/*
				 * Trying to be the group AP... periodically do
				 * a scan LWS_GAPSS_AP_SCAN, faster and then
				 * slower
       				 */
	LWS_GAPSS_AP_SCAN,	/*
				 * doing a scan while trying to be the group
				 * AP... if we see a lower MAC being the AP for
				 * the same group AP, abandon being an AP and
				 * join that AP as a station
				 */
	LWS_GAPSS_STAT_GRP_AP,	/*
				 * We have decided to join another group member
				 * who is being the AP, as its MAC is lower than
				 * ours.  This is a stable state, but we still
				 * do periodic scans LWS_GAPSS_STAT_GRP_AP_SCAN
				 * and will always prefer an AP configured in a
				 * slot.
				 */
	LWS_GAPSS_STAT_GRP_AP_SCAN,
				/*
				 * We have joined a group member who is doing
				 * the AP job... we want to check every now and
				 * then if a configured AP has appeared that we
				 * should better use instead.  Otherwise stay in
				 * LWS_GAPSS_STAT_GRP_AP
				 */
	LWS_GAPSS_STAT,		/*
				 * trying to connect to another non-group AP.
				 * If we don't get an IP within a timeout and
				 * retries, blacklist it and go back
				 */
	LWS_GAPSS_STAT_HAPPY,
};

static const char *gapss_str[] = {
	"LWS_GAPSS_INITIAL",
        "LWS_GAPSS_SCAN",
        "LWS_GAPSS_AP",
        "LWS_GAPSS_AP_SCAN",
        "LWS_GAPSS_STAT_GRP_AP",
        "LWS_GAPSS_STAT_GRP_AP_SCAN",
        "LWS_GAPSS_STAT",
	"LWS_GAPSS_STAT_HAPPY",
};

static romfs_t lws_esp32_romfs;
static TimerHandle_t leds_timer, scan_timer, debounce_timer, association_timer
#if !defined(CONFIG_LWS_IS_FACTORY_APPLICATION)
, mdns_timer
#endif
;
static enum lws_gapss gapss = LWS_GAPSS_INITIAL;
#if !defined(CONFIG_LWS_IS_FACTORY_APPLICATION)
static mdns_result_t *mdns_results_head;
#endif

#define GPIO_SW 14

struct esp32_file {
	const struct inode *i;
};

static void lws_gapss_to(enum lws_gapss to)
{
	lwsl_notice("gapss from %s to %s\n", gapss_str[gapss], gapss_str[to]);
	gapss = to;
}

uint32_t lws_esp32_get_reboot_type(void)
{
	uint32_t *p = (uint32_t *)LWS_MAGIC_REBOOT_TYPE_ADS, val = *p;
	nvs_handle nvh;
	size_t s = 0;
	int n = 0;

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
	if (nvs_get_blob(nvh, "ssl-pub.pem", NULL, &s) == ESP_OK)
		n = 1;
	if (nvs_get_blob(nvh, "ssl-pri.pem", NULL, &s) == ESP_OK)
		n |= 2;
	nvs_close(nvh);

	/*
	 * in the case the SSL certs are not there, don't require
	 * the button to be down to access all features.
	 */
	if (n != 3)
		val = LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON;

	return val;
}

static void render_ip(char *dest, int len, uint8_t *ip)
{
	snprintf(dest, len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void lws_esp32_restart_guided(uint32_t type)
{
        uint32_t *p_force_factory_magic = (uint32_t *)LWS_MAGIC_REBOOT_TYPE_ADS;

	lwsl_notice("%s: %x\n", __func__, type);
        *p_force_factory_magic = type;

	esp_restart();
}

/*
 * esp-idf goes crazy with zero length str nvs.  Use this as a workaround
 * to delete the key in that case.
 */

esp_err_t lws_nvs_set_str(nvs_handle handle, const char* key, const char* value)
{
	if (*value)
		return nvs_set_str(handle, key, value);

	return nvs_erase_key(handle, key);
}

static wifi_scan_config_t scan_config = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,
        .show_hidden = true
};

static char scan_ongoing = 0, scan_timer_exists = 0;
static int try_slot = -1;

static wifi_config_t config = {
	.ap = {
	    .channel = 6,
	    .authmode = WIFI_AUTH_OPEN,
	    .max_connection = 1,
	} }, sta_config = {
	.sta = {
		.bssid_set = 0,
	} };

static void lws_esp32_scan_timer_cb(TimerHandle_t th)
{
	int n;

	lwsl_notice("%s\n", __func__);
	scan_ongoing = 0;
	n = esp_wifi_scan_start(&scan_config, false);
	if (n != ESP_OK)
		lwsl_err("scan start failed %d\n", n);
}

static void lws_esp32_assoc_timer_cb(TimerHandle_t th)
{
	int n;

	xTimerStop(association_timer, 0);

	if (gapss == LWS_GAPSS_STAT_HAPPY) {
		lwsl_debug("%s: saw we were happy\n", __func__);

		return;
	}

	lwsl_notice("%s: forcing rescan\n", __func__);

	lws_gapss_to(LWS_GAPSS_SCAN);
	scan_ongoing = 0;
	n = esp_wifi_scan_start(&scan_config, false);
	if (n != ESP_OK)
		lwsl_err("scan start failed %d\n", n);
}


#if !defined(CONFIG_LWS_IS_FACTORY_APPLICATION)

void __attribute__(( weak ))
lws_group_member_event(int e, void *p)
{
}

void __attribute__(( weak ))
lws_get_iframe_size(int *w, int *h)
{
	*w = 320;
	*h = 160;
}

void lws_group_member_event_call(int e, void *p)
{
	lws_group_member_event(e, p);
}

static int
get_txt_param(const mdns_result_t *mr, const char *param, char *result, int len)
{
	const char *p;

	*result = '\0';

	p = strstr(mr->txt->key, param);
	if (!p) {
		*result = '\0';
		return 1;
	}

	lws_strncpy(result, mr->txt->value, len);

	return 0;
}

static void lws_esp32_mdns_timer_cb(TimerHandle_t th)
{
	uint64_t now = lws_now_usecs();
	struct lws_group_member *p, **p1;
	const mdns_result_t *r = mdns_results_head;

	while (r) {
		char ch = 0, group[16];

		get_txt_param(r, "group", group, sizeof(group));
		if (strcmp(group, lws_esp32.group)) /* not our group */ {
			lwsl_notice("group %s vs %s  %s\n",
					group, lws_esp32.group, r->txt->value);
			continue;
		}

		p = lws_esp32.first;
		while (p) {
			if (strcmp(r->hostname, p->host))
				goto next;
			if (memcmp(&r->addr, &p->addr, sizeof(r->addr)))
				goto next;

			p->last_seen = now;
			break;
next:
			p = p->next;
		}
		if (!p) { /* did not find */
			char temp[8];

			p = lws_malloc(sizeof(*p), "group");
			if (!p)
				continue;
			lws_strncpy(p->host, r->hostname, sizeof(p->host));

			get_txt_param(r, "model", p->model, sizeof(p->model));
			get_txt_param(r, "role", p->role, sizeof(p->role));
			get_txt_param(r, "mac", p->mac, sizeof(p->mac));
			get_txt_param(r, "width", temp, sizeof(temp));
			p->width = atoi(temp);
			get_txt_param(r, "height", temp, sizeof(temp));
			p->height = atoi(temp);

			memcpy(&p->addr, &r->addr, sizeof(p->addr));
//			memcpy(&p->addrv6, &r->addrv6, sizeof(p->addrv6));
			p->last_seen = now;
			p->flags = 0;
			p->next = lws_esp32.first;
			lws_esp32.first = p;
			lws_esp32.extant_group_members++;

			lws_group_member_event_call(LWS_SYSTEM_GROUP_MEMBER_ADD, p);
		} else {
			if (memcmp(&p->addr, &r->addr, sizeof(p->addr))) {
				memcpy(&p->addr, &r->addr, sizeof(p->addr));
				ch = 1;
			}
/*			if (memcmp(&p->addrv6, &r->addrv6, sizeof(p->addrv6))) {
				memcpy(&p->addrv6, &r->addrv6, sizeof(p->addrv6));
				ch = 1;
			} */
			if (ch)
				lws_group_member_event_call(LWS_SYSTEM_GROUP_MEMBER_CHANGE, p);
		}
	}

	mdns_query_results_free(mdns_results_head);

	/* garbage-collect group members not seen for too long */
	p1 = &lws_esp32.first;
	while (*p1) {
		p = *p1;
		if (!(p->flags & LWS_GROUP_FLAG_SELF) &&
				now - p->last_seen > 60000000) {
			lws_esp32.extant_group_members--;
			*p1 = p->next;

			lws_group_member_event_call(LWS_SYSTEM_GROUP_MEMBER_REMOVE, p);
			lws_free(p);
			continue;
		}
		p1 = &(*p1)->next;
	}

	mdns_query_txt(lws_esp32.group, "_lwsgrmem", "_tcp", 0,
			       &mdns_results_head);
	xTimerStart(mdns_timer, 0);
}
#endif

void __attribute__(( weak ))
lws_esp32_button(int down)
{
}

void IRAM_ATTR
gpio_irq(void *arg)
{
	gpio_set_intr_type(GPIO_SW, GPIO_INTR_DISABLE);
	xTimerStart(debounce_timer, 0);
}

static void lws_esp32_debounce_timer_cb(TimerHandle_t th)
{
	if (lws_esp32.button_is_down)
		gpio_set_intr_type(GPIO_SW, GPIO_INTR_POSEDGE);
	else
		gpio_set_intr_type(GPIO_SW, GPIO_INTR_NEGEDGE);

	lws_esp32.button_is_down = gpio_get_level(GPIO_SW);

	lws_esp32_button(lws_esp32.button_is_down);
}


static int
start_scan()
{
	/* if no APs configured, no point... */

	if (!lws_esp32.ssid[0][0] &&
	    !lws_esp32.ssid[1][0] &&
	    !lws_esp32.ssid[2][0] &&
	    !lws_esp32.ssid[3][0])
		return 0;

	if (scan_timer_exists && !scan_ongoing) {
		// lwsl_notice("Starting scan timer...\n");
		scan_ongoing = 1;
		xTimerStart(scan_timer, 0);
	}

	return 0;
}



static void
end_scan()
{
	wifi_ap_record_t ap_records[10];
	uint16_t count_ap_records;
	int n, m;

	count_ap_records = LWS_ARRAY_SIZE(ap_records);
	if (esp_wifi_scan_get_ap_records(&count_ap_records, ap_records)) {
		lwsl_err("%s: failed\n", __func__);
		return;
	}

	if (!count_ap_records)
		goto passthru;

	if (gapss != LWS_GAPSS_SCAN) {
		lwsl_info("ignoring scan as gapss %s\n", gapss_str[gapss]);
		goto passthru;
	}

	/* no point if no APs set up */
	if (!lws_esp32.ssid[0][0] &&
	    !lws_esp32.ssid[1][0] &&
	    !lws_esp32.ssid[2][0] &&
	    !lws_esp32.ssid[3][0])
		goto passthru;

	lwsl_info("checking %d scan records\n", count_ap_records);

	for (n = 0; n < 4; n++) {

		if (!lws_esp32.ssid[(n + try_slot + 1) & 3][0])
			continue;

		lwsl_debug("looking for %s\n",
			    lws_esp32.ssid[(n + try_slot + 1) & 3]);

		/* this ssid appears in scan results? */

		for (m = 0; m < count_ap_records; m++) {
			// lwsl_notice("  %s\n", ap_records[m].ssid);
			if (!strcmp((char *)ap_records[m].ssid,
				    lws_esp32.ssid[(n + try_slot + 1) & 3]))
				goto hit;
		}

		continue;

hit:
		m = (n + try_slot + 1) & 3;
		try_slot = m;
		lwsl_info("Attempting connection with slot %d: %s:\n", m,
				lws_esp32.ssid[m]);
		/* set the ssid we last tried to connect to */
		lws_strncpy(lws_esp32.active_ssid, lws_esp32.ssid[m],
				sizeof(lws_esp32.active_ssid));

		lws_strncpy((char *)sta_config.sta.ssid, lws_esp32.ssid[m],
			sizeof(sta_config.sta.ssid));
		lws_strncpy((char *)sta_config.sta.password, lws_esp32.password[m],
			sizeof(sta_config.sta.password));

		tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA,
					   (const char *)&config.ap.ssid[7]);
		lws_gapss_to(LWS_GAPSS_STAT);
		xTimerStop(association_timer, 0);
		xTimerStart(association_timer, 0);

		esp_wifi_set_config(WIFI_IF_STA, &sta_config);
		esp_wifi_connect();
		break;
	}

	if (n == 4)
		start_scan();

passthru:
	if (lws_esp32.scan_consumer)
		lws_esp32.scan_consumer(count_ap_records, ap_records,
					lws_esp32.scan_consumer_arg);

}

static void
lws_set_genled(int n)
{
	lws_esp32.genled_t = lws_now_usecs();
	lws_esp32.genled = n;
}

int
lws_esp32_leds_network_indication(void)
{
	uint64_t us, r;
	int n, fadein = 100, speed = 1199, div = 1, base = 0;

	r = lws_now_usecs();
	us = r - lws_esp32.genled_t;

	switch (lws_esp32.genled) {
	case LWSESP32_GENLED__INIT:
		lws_esp32.genled = LWSESP32_GENLED__LOST_NETWORK;
		/* fallthru */
	case LWSESP32_GENLED__LOST_NETWORK:
		fadein = us / 10000; /* 100 steps in 1s */
		if (fadein > 100) {
			fadein = 100;
			lws_esp32.genled = LWSESP32_GENLED__NO_NETWORK;
		}
		/* fallthru */
	case LWSESP32_GENLED__NO_NETWORK:
		break;
	case LWSESP32_GENLED__CONN_AP:
		base = 4096;
		speed = 933;
		div = 2;
		break;
	case LWSESP32_GENLED__GOT_IP:
		fadein = us / 10000; /* 100 steps in 1s */
		if (fadein > 100) {
			fadein = 100;
			lws_esp32.genled = LWSESP32_GENLED__OK;
		}
		fadein = 100 - fadein; /* we are fading out */
		/* fallthru */
	case LWSESP32_GENLED__OK:
		if (lws_esp32.genled == LWSESP32_GENLED__OK)
			return 0;

		base = 4096;
		speed = 766;
		div = 3;
		break;
	}

	n = base + (lws_esp32_sine_interp(r / speed) / div);
	return (n * fadein) / 100;
}

esp_err_t lws_esp32_event_passthru(void *ctx, system_event_t *event)
{
#if !defined(CONFIG_LWS_IS_FACTORY_APPLICATION)
	struct lws_group_member *mem;
	int n;
#endif
	nvs_handle nvh;
	uint32_t use;

	switch((int)event->event_id) {
	case SYSTEM_EVENT_STA_START:
		//esp_wifi_connect();
//		break;
		/* fallthru */
	case SYSTEM_EVENT_STA_DISCONNECTED:
		lwsl_notice("SYSTEM_EVENT_STA_DISCONNECTED\n");
		if (sntp_enabled())
			sntp_stop();
		lws_esp32.conn_ap = 0;
		lws_esp32.inet = 0;
		lws_esp32.sta_ip[0] = '\0';
		lws_esp32.sta_mask[0] = '\0';
		lws_esp32.sta_gw[0] = '\0';
		lws_gapss_to(LWS_GAPSS_SCAN);
		mdns_free();
		lws_set_genled(LWSESP32_GENLED__LOST_NETWORK);
		start_scan();
		esp_wifi_connect();
		break;

	case SYSTEM_EVENT_STA_CONNECTED:
		lws_esp32.conn_ap = 1;
		lws_set_genled(LWSESP32_GENLED__CONN_AP);
		break;

	case SYSTEM_EVENT_STA_GOT_IP:
		lwsl_notice("SYSTEM_EVENT_STA_GOT_IP\n");

		lws_esp32.inet = 1;
		lws_set_genled(LWSESP32_GENLED__GOT_IP);

		render_ip(lws_esp32.sta_ip, sizeof(lws_esp32.sta_ip) - 1,
				(uint8_t *)&event->event_info.got_ip.ip_info.ip);
		render_ip(lws_esp32.sta_mask, sizeof(lws_esp32.sta_mask) - 1,
				(uint8_t *)&event->event_info.got_ip.ip_info.netmask);
		render_ip(lws_esp32.sta_gw, sizeof(lws_esp32.sta_gw) - 1,
				(uint8_t *)&event->event_info.got_ip.ip_info.gw);

		if (!nvs_open("lws-station", NVS_READWRITE, &nvh)) {
			char slot[8];

			lws_snprintf(slot, sizeof(slot) - 1, "%duse", try_slot);
			use = 0;
			nvs_get_u32(nvh, slot, &use);
			nvs_set_u32(nvh, slot, use + 1);
			nvs_commit(nvh);
			nvs_close(nvh);
		}

		lws_gapss_to(LWS_GAPSS_STAT_HAPPY);

#if !defined(CONFIG_LWS_IS_FACTORY_APPLICATION)
		n = mdns_init();
		if (!n) {
			static mdns_txt_item_t txta[6];
			static char wh[2][6];
			int w, h;

			mdns_hostname_set(lws_esp32.hostname);
			mdns_instance_name_set(lws_esp32.group);

			lws_get_iframe_size(&w, &h);

			txta[0].key = "model";
			txta[1].key = "group";
			txta[2].key = "role";
			txta[3].key = "mac";
			txta[4].key = "width";
			txta[5].key = "height";

			txta[0].value = lws_esp32.model;
			txta[1].value = lws_esp32.group;
			txta[2].value = lws_esp32.role;
			txta[3].value = lws_esp32.mac;
			txta[4].value = wh[0];
			txta[5].value = wh[1];

			lws_snprintf(wh[0], 6, "%d", w);
			lws_snprintf(wh[1], 6, "%d", h);

			mdns_service_add(lws_esp32.group,
					 "_lwsgrmem", "_tcp", 443, txta,
					 LWS_ARRAY_SIZE(txta));

			mem = lws_esp32.first;
			while (mem) {
				if (mem->flags & 1)
					break;
				mem = mem->next;
			}

			if (!mem) {
				struct lws_group_member *mem =
					      lws_malloc(sizeof(*mem), "group");
				if (mem) {
					mem->last_seen = ~(uint64_t)0;
					strcpy(mem->model, lws_esp32.model);
					strcpy(mem->role, lws_esp32.role);
					strcpy(mem->host, lws_esp32.hostname);
					strcpy(mem->mac, lws_esp32.mac);
					mem->flags = LWS_GROUP_FLAG_SELF;
					lws_get_iframe_size(&mem->width,
							    &mem->height);
					memcpy(&mem->addr,
					       &event->event_info.got_ip.ip_info.ip,
					       sizeof(mem->addr));
					memcpy(&mem->addrv6,
					       &event->event_info.got_ip6.ip6_info.ip,
					       sizeof(mem->addrv6));
					mem->next = lws_esp32.first;
					lws_esp32.first = mem;
					lws_esp32.extant_group_members++;

					lws_group_member_event_call(
					      LWS_SYSTEM_GROUP_MEMBER_ADD, mem);
				}
			} else { /* update our IP */
				memcpy(&mem->addr,
				       &event->event_info.got_ip.ip_info.ip,
				       sizeof(mem->addr));
				memcpy(&mem->addrv6,
				       &event->event_info.got_ip6.ip6_info.ip,
				       sizeof(mem->addrv6));
				lws_group_member_event_call(
					   LWS_SYSTEM_GROUP_MEMBER_CHANGE, mem);
			}

		} else
			lwsl_err("unable to init mdns on STA: %d\n", n);

		mdns_query_txt(lws_esp32.group, "_lwsgrmem", "_tcp", 0,
			       &mdns_results_head);
		xTimerStart(mdns_timer, 0);
#endif

		lwsl_notice(" --- Got IP %s\n", lws_esp32.sta_ip);
		if (!sntp_enabled()) {
			sntp_setoperatingmode(SNTP_OPMODE_POLL);
			sntp_setservername(0, "pool.ntp.org");
			sntp_init();
		}
		break;

	case SYSTEM_EVENT_SCAN_DONE:
		lwsl_notice("SYSTEM_EVENT_SCAN_DONE\n");
		end_scan();
		break;

	default:
		break;
	}

	return ESP_OK;
}

#if defined(LWS_WITH_FILE_OPS)
static lws_fop_fd_t IRAM_ATTR
esp32_lws_fops_open(const struct lws_plat_file_ops *fops, const char *filename,
                    const char *vfs_path, lws_fop_flags_t *flags)
{
	struct esp32_file *f = malloc(sizeof(*f));
	lws_fop_fd_t fop_fd;
	size_t len, csum;

	lwsl_notice("%s: %s\n", __func__, filename);

	if (!f)
		return NULL;
	f->i = romfs_get_info(lws_esp32_romfs, filename, &len, &csum);
	if (!f->i)
		goto bail;

        fop_fd = malloc(sizeof(*fop_fd));
        if (!fop_fd)
                goto bail;

        fop_fd->fops = fops;
        fop_fd->filesystem_priv = f;
	fop_fd->mod_time = csum;
	*flags |= LWS_FOP_FLAG_MOD_TIME_VALID;
	fop_fd->flags = *flags;

	fop_fd->len = len;
	fop_fd->pos = 0;

	return fop_fd;

bail:
	free(f);

	return NULL;
}

static int IRAM_ATTR
esp32_lws_fops_close(lws_fop_fd_t *fop_fd)
{
	free((*fop_fd)->filesystem_priv);
	free(*fop_fd);

	*fop_fd = NULL;

	return 0;
}
static lws_fileofs_t IRAM_ATTR
esp32_lws_fops_seek_cur(lws_fop_fd_t fop_fd, lws_fileofs_t offset_from_cur_pos)
{
	fop_fd->pos += offset_from_cur_pos;

	if (fop_fd->pos > fop_fd->len)
		fop_fd->pos = fop_fd->len;

       return 0;
}

static int IRAM_ATTR
esp32_lws_fops_read(lws_fop_fd_t fop_fd, lws_filepos_t *amount, uint8_t *buf,
                   lws_filepos_t len)
{
       struct esp32_file *f = fop_fd->filesystem_priv;
#if 0
       if ((long)buf & 3) {
               lwsl_err("misaligned buf\n");

               return -1;
       }
#endif
       if (fop_fd->pos >= fop_fd->len)
               return 0;

       if (len > fop_fd->len - fop_fd->pos)
               len = fop_fd->len - fop_fd->pos;

       spi_flash_read((uint32_t)(char *)f->i + fop_fd->pos, buf, len);

       *amount = len;
       fop_fd->pos += len;

       return 0;
}

static const struct lws_plat_file_ops fops = {
	.next = &fops_zip,
	.LWS_FOP_OPEN = esp32_lws_fops_open,
	.LWS_FOP_CLOSE = esp32_lws_fops_close,
	.LWS_FOP_READ = esp32_lws_fops_read,
	.LWS_FOP_SEEK_CUR = esp32_lws_fops_seek_cur,
};
#endif

int
lws_esp32_wlan_nvs_get(int retry)
{
	nvs_handle nvh;
	char lws_esp32_force_ap = 0, slot[12];
	size_t s;
	uint8_t mac[6];
	int n;

	esp_efuse_mac_get_default(mac);
	mac[5] |= 1; /* match the AP MAC */
	snprintf(lws_esp32.serial, sizeof(lws_esp32.serial) - 1,
		 "%02X%02X%02X", mac[3], mac[4], mac[5]);
	snprintf(lws_esp32.mac, sizeof(lws_esp32.mac) - 1,
		 "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3],
		 mac[4], mac[5]);

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));

	config.sta.ssid[0] = '\0';
	config.sta.password[0] = '\0';

	for (n = 0; n < 4; n++) {
		lws_snprintf(slot, sizeof(slot) - 1, "%dssid", n);
		s = sizeof(lws_esp32.ssid[0]) - 1;
		lws_esp32.ssid[n][0] = '\0';
		nvs_get_str(nvh, slot, lws_esp32.ssid[n], &s);

		lws_snprintf(slot, sizeof(slot) - 1, "%dpassword", n);
		s = sizeof(lws_esp32.password[0]) - 1;
		lws_esp32.password[n][0] = '\0';
		nvs_get_str(nvh, slot, lws_esp32.password[n], &s);
	}

	s = sizeof(lws_esp32.serial) - 1;
	if (nvs_get_str(nvh, "serial", lws_esp32.serial, &s) != ESP_OK)
		lws_esp32_force_ap = 1;
	else
		snprintf((char *)config.ap.ssid, sizeof(config.ap.ssid) - 1,
			 "config-%s-%s", lws_esp32.model, lws_esp32.serial);
	s = sizeof(lws_esp32.opts) - 1;
	if (nvs_get_str(nvh, "opts", lws_esp32.opts, &s) != ESP_OK)
		lws_esp32_force_ap = 1;

	lws_esp32.access_pw[0] = '\0';
	nvs_get_str(nvh, "access_pw", lws_esp32.access_pw, &s);

	lws_esp32.group[0] = '\0';
	s = sizeof(lws_esp32.group);
	nvs_get_str(nvh, "group", lws_esp32.group, &s);

	lws_esp32.role[0] = '\0';
	s = sizeof(lws_esp32.role);
	nvs_get_str(nvh, "role", lws_esp32.role, &s);

	/* if group and role defined: group-role */
	if (lws_esp32.group[0] && lws_esp32.role[0])
		lws_snprintf(lws_esp32.hostname, sizeof(lws_esp32.hostname) - 1,
				"%s-%s", lws_esp32.group, lws_esp32.role);
	else /* otherwise model-serial */
		lws_snprintf(lws_esp32.hostname, sizeof(lws_esp32.hostname) - 1,
				"%s-%s", lws_esp32.model, lws_esp32.serial);

	nvs_close(nvh);

	lws_gapss_to(LWS_GAPSS_SCAN);
	start_scan();

	return lws_esp32_force_ap;
}


void
lws_esp32_wlan_config(void)
{
	ledc_timer_config_t ledc_timer = {
	        .bit_num = LEDC_TIMER_13_BIT,
	        .freq_hz = 5000,
	        .speed_mode = LEDC_HIGH_SPEED_MODE,
	        .timer_num = LEDC_TIMER_0
	};
	int n;

	lwsl_debug("%s\n", __func__);

	ledc_timer_config(&ledc_timer);

	lws_set_genled(LWSESP32_GENLED__INIT);

	/* user code needs to provide lws_esp32_leds_timer_cb */

        leds_timer = xTimerCreate("lws_leds", pdMS_TO_TICKS(25), 1, NULL,
                          (TimerCallbackFunction_t)lws_esp32_leds_timer_cb);
        scan_timer = xTimerCreate("lws_scan", pdMS_TO_TICKS(10000), 0, NULL,
                          (TimerCallbackFunction_t)lws_esp32_scan_timer_cb);
        debounce_timer = xTimerCreate("lws_db", pdMS_TO_TICKS(100), 0, NULL,
                          (TimerCallbackFunction_t)lws_esp32_debounce_timer_cb);
        association_timer = xTimerCreate("lws_assoc", pdMS_TO_TICKS(10000), 0, NULL,
                          (TimerCallbackFunction_t)lws_esp32_assoc_timer_cb);

#if !defined(CONFIG_LWS_IS_FACTORY_APPLICATION)
        mdns_timer = xTimerCreate("lws_mdns", pdMS_TO_TICKS(5000), 0, NULL,
                          (TimerCallbackFunction_t)lws_esp32_mdns_timer_cb);
#endif
	scan_timer_exists = 1;
        xTimerStart(leds_timer, 0);

	*(volatile uint32_t *)PERIPHS_IO_MUX_MTMS_U = FUNC_MTMS_GPIO14;

	gpio_output_set(0, 0, 0, (1 << GPIO_SW));

	n = gpio_install_isr_service(0);
	if (!n) {
		gpio_config_t c;

		c.intr_type = GPIO_INTR_NEGEDGE;
		c.mode = GPIO_MODE_INPUT;
		c.pin_bit_mask = 1 << GPIO_SW;
		c.pull_down_en = 0;
		c.pull_up_en = 0;
		gpio_config(&c);

		if (gpio_isr_handler_add(GPIO_SW, gpio_irq, NULL))
			lwsl_notice("isr handler add for 14 failed\n");
	} else
		lwsl_notice("failed to install gpio isr service: %d\n", n);

	lws_esp32_wlan_nvs_get(0);
	tcpip_adapter_init();
}

void
lws_esp32_wlan_start_ap(void)
{
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

	ESP_ERROR_CHECK( esp_wifi_init(&cfg));
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM));

	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_APSTA) );
	ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_AP, &config) );
	ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &sta_config));
	ESP_ERROR_CHECK( esp_wifi_start());

	esp_wifi_scan_start(&scan_config, false);

	if (sta_config.sta.ssid[0]) {
		tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA,
					   (const char *)&config.ap.ssid[7]);
		// esp_wifi_set_auto_connect(1);
		ESP_ERROR_CHECK( esp_wifi_connect());
		ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &sta_config));
		ESP_ERROR_CHECK( esp_wifi_connect());
	}
}

void
lws_esp32_wlan_start_station(void)
{
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

	ESP_ERROR_CHECK( esp_wifi_init(&cfg));
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM));

	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &sta_config));

	ESP_ERROR_CHECK( esp_wifi_start());

	tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA,
				   (const char *)&config.ap.ssid[7]);
	//esp_wifi_set_auto_connect(1);
	//ESP_ERROR_CHECK( esp_wifi_connect());

	lws_esp32_scan_timer_cb(NULL);
}

const esp_partition_t *
lws_esp_ota_get_boot_partition(void)
{
	const esp_partition_t *part = esp_ota_get_boot_partition(),
			      *factory_part, *ota;
	esp_image_header_t eih, ota_eih;
	uint32_t *p_force_factory_magic = (uint32_t *)LWS_MAGIC_REBOOT_TYPE_ADS;

	/* confirm what we are told is the boot part is sane */
	spi_flash_read(part->address , &eih, sizeof(eih));
	factory_part = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
			ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
 	ota = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
			ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL);
	spi_flash_read(ota->address , &ota_eih, sizeof(ota_eih));

	if (eih.spi_mode == 0xff ||
	    *p_force_factory_magic == LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY ||
	    *p_force_factory_magic == LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON
	) {
		/*
		 * we believed we were going to boot OTA, but we fell
		 * back to FACTORY in the bootloader when we saw it
		 * had been erased.  esp_ota_get_boot_partition() still
		 * says the OTA partition then even if we are in the
		 * factory partition right now.
		 */
		part = factory_part;
	}

#ifdef CONFIG_LWS_IS_FACTORY_APPLICATION
	else
		if (ota_eih.spi_mode != 0xff &&
		    part->address != factory_part->address) {
			uint8_t buf[4096];
			uint32_t n;
			/*
			 * we are a FACTORY image running in an OTA slot...
			 * it means we were just written and need to copy
			 * ourselves into the FACTORY slot.
			 */
			lwsl_notice("Copying FACTORY update into place "
				    "0x%x len 0x%x\n", factory_part->address,
				    factory_part->size);
			esp_task_wdt_reset();
			if (spi_flash_erase_range(factory_part->address,
						  factory_part->size)) {
	               	        lwsl_err("spi: Failed to erase\n");
	               	        goto retry;
	               	}

			for (n = 0; n < factory_part->size; n += sizeof(buf)) {
				esp_task_wdt_reset();
				spi_flash_read(part->address + n , buf,
					       sizeof(buf));
				if (spi_flash_write(factory_part->address + n,
						    buf, sizeof(buf))) {
	                	        lwsl_err("spi: Failed to write\n");
	                	        goto retry;
	                	}
			}

			/*
			 * We send a message to the bootloader to erase the OTA header, we will come back up in
			 * factory where the user can reload the OTA image
			 */
			lwsl_notice("  FACTORY copy successful, rebooting\n");
			lws_esp32_restart_guided(LWS_MAGIC_REBOOT_TYPE_REQ_FACTORY_ERASE_OTA);
retry:
			esp_restart();
		}
#endif

	return part;
}


void
lws_esp32_set_creation_defaults(struct lws_context_creation_info *info)
{
	const esp_partition_t *part;

	memset(info, 0, sizeof(*info));

	lws_set_log_level(63, lwsl_emit_syslog);

	part = lws_esp_ota_get_boot_partition();
	(void)part;

	info->vhost_name = "default";
	info->port = 443;
	info->fd_limit_per_thread = 16;
	info->max_http_header_pool = 5;
	info->max_http_header_data = 1024;
	info->pt_serv_buf_size = 4096;
	info->keepalive_timeout = 30;
	info->timeout_secs = 30;
	info->simultaneous_ssl_restriction = 2;
	info->options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		        LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
}

int
lws_esp32_get_image_info(const esp_partition_t *part, struct lws_esp32_image *i,
			 char *json, int json_len)
{
	esp_image_segment_header_t eis;
	esp_image_header_t eih;
	uint32_t hdr;

	spi_flash_read(part->address , &eih, sizeof(eih));
	hdr = part->address + sizeof(eih);

	if (eih.magic != ESP_IMAGE_HEADER_MAGIC) {
		lwsl_notice("%s: bad image header magic\n", __func__);
		return 1;
	}

	eis.data_len = 0;
	while (eih.segment_count-- && eis.data_len != 0xffffffff) {
		spi_flash_read(hdr, &eis, sizeof(eis));
		hdr += sizeof(eis) + eis.data_len;
	}
	hdr += (~hdr & 15) + 1;

	if (eih.hash_appended)
		hdr += 0x20;

//	lwsl_notice("romfs estimated at 0x%x\n", hdr);

	i->romfs = hdr + 0x4;
	spi_flash_read(hdr, &i->romfs_len, sizeof(i->romfs_len));
	i->json = i->romfs + i->romfs_len + 4;
	spi_flash_read(i->json - 4, &i->json_len, sizeof(i->json_len));

	if (i->json_len < json_len - 1)
		json_len = i->json_len;
	spi_flash_read(i->json, json, json_len);
	json[json_len] = '\0';

	return 0;
}

static int
_rngf(void *context, unsigned char *buf, size_t len)
{
	if (lws_get_random(context, buf, len) == len)
		return 0;

	return -1;
}

int
lws_esp32_selfsigned(struct lws_vhost *vhost)
{
	mbedtls_x509write_cert crt;
	char subject[200];
	mbedtls_pk_context mpk;
	int buf_size = 4096, n;
	uint8_t *buf = malloc(buf_size); /* malloc because given to user code */
	mbedtls_mpi mpi;
	nvs_handle nvh;
	size_t s;

	lwsl_notice("%s: %s\n", __func__, vhost->name);

	if (!buf)
		return -1;

	if (nvs_open("lws-station", NVS_READWRITE, &nvh)) {
		lwsl_notice("%s: can't open nvs\n", __func__);
		free(buf);
		return 1;
	}

	n = 0;
	if (!nvs_get_blob(nvh, vhost->tls.alloc_cert_path, NULL, &s))
		n |= 1;
	if (!nvs_get_blob(nvh, vhost->tls.key_path, NULL, &s))
		n |= 2;

	nvs_close(nvh);
	if (n == 3) {
		lwsl_notice("%s: certs exist\n", __func__);
		free(buf);
		return 0; /* certs already exist */
	}

	lwsl_notice("%s: creating selfsigned initial certs\n", __func__);

	mbedtls_x509write_crt_init(&crt);

	mbedtls_pk_init(&mpk);
	if (mbedtls_pk_setup(&mpk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) {
		lwsl_notice("%s: pk_setup failed\n", __func__);
		goto fail;
	}
	lwsl_notice("%s: generating 2048-bit RSA keypair... "
		    "this may take a minute or so...\n", __func__);
	n = mbedtls_rsa_gen_key(mbedtls_pk_rsa(mpk), _rngf, vhost->context,
				2048, 65537);
	if (n) {
		lwsl_notice("%s: failed to generate keys\n", __func__);
		goto fail1;
	}
	lwsl_notice("%s: keys done\n", __func__);

	/* subject must be formatted like "C=TW,O=warmcat,CN=myserver" */

	lws_snprintf(subject, sizeof(subject) - 1,
		     "C=TW,ST=New Taipei City,L=Taipei,O=warmcat,CN=%s",
		     lws_esp32.hostname);

	if (mbedtls_x509write_crt_set_subject_name(&crt, subject)) {
		lwsl_notice("set SN failed\n");
		goto fail1;
	}
	mbedtls_x509write_crt_set_subject_key(&crt, &mpk);
	if (mbedtls_x509write_crt_set_issuer_name(&crt, subject)) {
		lwsl_notice("set IN failed\n");
		goto fail1;
	}
	mbedtls_x509write_crt_set_issuer_key(&crt, &mpk);

	lws_get_random(vhost->context, &n, sizeof(n));
	lws_snprintf(subject, sizeof(subject), "%d", n);

	mbedtls_mpi_init(&mpi);
	mbedtls_mpi_read_string(&mpi, 10, subject);
	mbedtls_x509write_crt_set_serial(&crt, &mpi);
	mbedtls_mpi_free(&mpi);

	mbedtls_x509write_crt_set_validity(&crt, "20171105235959",
					   "20491231235959");

	mbedtls_x509write_crt_set_key_usage(&crt,
					    MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
					    MBEDTLS_X509_KU_KEY_ENCIPHERMENT);


	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

	n = mbedtls_x509write_crt_pem(&crt, buf, buf_size, _rngf,
				      vhost->context);
	if (n < 0) {
		lwsl_notice("%s: write crt der failed\n", __func__);
		goto fail1;
	}

	lws_plat_write_cert(vhost, 0, 0, buf, strlen((const char *)buf));

	if (mbedtls_pk_write_key_pem(&mpk, buf, buf_size)) {
		lwsl_notice("write key pem failed\n");
		goto fail1;
	}

	lws_plat_write_cert(vhost, 1, 0, buf, strlen((const char *)buf));

	mbedtls_pk_free(&mpk);
	mbedtls_x509write_crt_free(&crt);

	lwsl_notice("%s: cert creation complete\n", __func__);

	return n;

fail1:
	mbedtls_pk_free(&mpk);
fail:
	mbedtls_x509write_crt_free(&crt);
	free(buf);

	nvs_close(nvh);

	return -1;
}

void
lws_esp32_update_acme_info(void)
{
        int n;

	n = lws_plat_read_file("acme-email", lws_esp32.le_email,
			       sizeof(lws_esp32.le_email) - 1);
	if (n >= 0)
		lws_esp32.le_email[n] = '\0';

	n = lws_plat_read_file("acme-cn", lws_esp32.le_dns,
			       sizeof(lws_esp32.le_dns) - 1);
	if (n >= 0)
		lws_esp32.le_dns[n] = '\0';
}

struct lws_context *
lws_esp32_init(struct lws_context_creation_info *info, struct lws_vhost **pvh)
{
	const esp_partition_t *part = lws_esp_ota_get_boot_partition();
	struct lws_context *context;
	struct lws_esp32_image i;
	struct lws_vhost *vhost;
	struct lws wsi;
	char buf[512];

	context = lws_create_context(info);
	if (context == NULL) {
		lwsl_err("Failed to create context\n");
		return NULL;
	}

	lws_esp32_get_image_info(part, &i, buf, sizeof(buf) - 1);

	lws_esp32_romfs = (romfs_t)i.romfs;
	if (!romfs_mount_check(lws_esp32_romfs)) {
		lwsl_err("mount error on ROMFS at %p 0x%x\n", lws_esp32_romfs,
			 i.romfs);
		return NULL;
	}

	lwsl_notice("ROMFS length %uKiB\n", i.romfs_len >> 10);

	puts(buf);

	/* set the lws vfs to use our romfs */
#if defined(LWS_WITH_FILE_OPS)
	lws_set_fops(context, &fops);
#endif

	info->options |= LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX |
			 LWS_SERVER_OPTION_IGNORE_MISSING_CERT;

	vhost = lws_create_vhost(context, info);
	if (!vhost) {
		lwsl_err("Failed to create vhost\n");
		return NULL;
	}

	lws_esp32_update_acme_info();

	lws_esp32_selfsigned(vhost);
	wsi.context = vhost->context;
	wsi.vhost = vhost;

	lws_tls_server_certs_load(vhost, &wsi, info->ssl_cert_filepath,
			info->ssl_private_key_filepath, NULL, 0, NULL, 0);

	lws_init_vhost_client_ssl(info, vhost);

	if (pvh)
		*pvh = vhost;

	if (lws_protocol_init(context))
		return NULL;

	return context;
}

static const uint16_t sineq16[] = {
        0x0000, 0x0191, 0x031e, 0x04a4, 0x061e, 0x0789, 0x08e2, 0x0a24,
        0x0b4e, 0x0c5c, 0x0d4b, 0x0e1a, 0x0ec6, 0x0f4d, 0x0faf, 0x0fea,
};

static uint16_t sine_lu(int n)
{
        switch ((n >> 4) & 3) {
        case 1:
                return 4096 + sineq16[n & 15];
        case 2:
                return 4096 + sineq16[15 - (n & 15)];
        case 3:
                return 4096 - sineq16[n & 15];
        default:
                return  4096 - sineq16[15 - (n & 15)];
        }
}

/* useful for sine led fade patterns */

uint16_t lws_esp32_sine_interp(int n)
{
        /*
         * 2: quadrant
         * 4: table entry in quadrant
         * 4: interp (LSB)
         *
         * total 10 bits / 1024 steps per cycle
	 *
	 * +   0: 0
	 * + 256: 4096
	 * + 512: 8192
	 * + 768: 4096
	 * +1023: 0
         */

        return (sine_lu(n >> 4) * (15 - (n & 15)) +
                sine_lu((n >> 4) + 1) * (n & 15)) / 15;
}
