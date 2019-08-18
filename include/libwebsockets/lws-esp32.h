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
 *
 * This is only included from libwebsockets.h if LWS_WITH_ESP32
 */

/* ESP32 helper declarations */

#include <mdns.h>
#include <esp_partition.h>

#define LWS_PLUGIN_STATIC
#define LWS_MAGIC_REBOOT_TYPE_ADS 0x50001ffc
#define LWS_MAGIC_REBOOT_TYPE_REQ_FACTORY 0xb00bcafe
#define LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY 0xfaceb00b
#define LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON 0xf0cedfac
#define LWS_MAGIC_REBOOT_TYPE_REQ_FACTORY_ERASE_OTA 0xfac0eeee

/* user code provides these */

extern void
lws_esp32_identify_physical_device(void);

/* lws-plat-esp32 provides these */

typedef void (*lws_cb_scan_done)(uint16_t count, wifi_ap_record_t *recs, void *arg);

enum genled_state {
	LWSESP32_GENLED__INIT,
	LWSESP32_GENLED__LOST_NETWORK,
	LWSESP32_GENLED__NO_NETWORK,
	LWSESP32_GENLED__CONN_AP,
	LWSESP32_GENLED__GOT_IP,
	LWSESP32_GENLED__OK,
};

struct lws_group_member {
	struct lws_group_member *next;
	uint64_t last_seen;
	char model[16];
	char role[16];
	char host[32];
	char mac[20];
	int width, height;
	struct ip4_addr addr;
	struct ip6_addr addrv6;
	uint8_t	flags;
};

#define LWS_SYSTEM_GROUP_MEMBER_ADD		1
#define LWS_SYSTEM_GROUP_MEMBER_CHANGE		2
#define LWS_SYSTEM_GROUP_MEMBER_REMOVE		3

#define LWS_GROUP_FLAG_SELF 1

struct lws_esp32 {
	char sta_ip[16];
	char sta_mask[16];
	char sta_gw[16];
	char serial[16];
	char opts[16];
	char model[16];
	char group[16];
	char role[16];
	char ssid[4][64];
	char password[4][64];
	char active_ssid[64];
	char access_pw[16];
	char hostname[32];
	char mac[20];
	char le_dns[64];
	char le_email[64];
       	char region;
       	char inet;
	char conn_ap;

	enum genled_state genled;
	uint64_t genled_t;

	lws_cb_scan_done scan_consumer;
	void *scan_consumer_arg;
	struct lws_group_member *first;
	int extant_group_members;

	char acme;
	char upload;

	volatile char button_is_down;
};

struct lws_esp32_image {
	uint32_t romfs;
	uint32_t romfs_len;
	uint32_t json;
	uint32_t json_len;
};

extern struct lws_esp32 lws_esp32;
struct lws_vhost;

extern esp_err_t
lws_esp32_event_passthru(void *ctx, system_event_t *event);
extern void
lws_esp32_wlan_config(void);
extern void
lws_esp32_wlan_start_ap(void);
extern void
lws_esp32_wlan_start_station(void);
struct lws_context_creation_info;
extern void
lws_esp32_set_creation_defaults(struct lws_context_creation_info *info);
extern struct lws_context *
lws_esp32_init(struct lws_context_creation_info *, struct lws_vhost **pvh);
extern int
lws_esp32_wlan_nvs_get(int retry);
extern esp_err_t
lws_nvs_set_str(nvs_handle handle, const char* key, const char* value);
extern void
lws_esp32_restart_guided(uint32_t type);
extern const esp_partition_t *
lws_esp_ota_get_boot_partition(void);
extern int
lws_esp32_get_image_info(const esp_partition_t *part, struct lws_esp32_image *i, char *json, int json_len);
extern int
lws_esp32_leds_network_indication(void);

extern uint32_t lws_esp32_get_reboot_type(void);
extern uint16_t lws_esp32_sine_interp(int n);

/* required in external code by esp32 plat (may just return if no leds) */
extern void lws_esp32_leds_timer_cb(TimerHandle_t th);

#endif /* LWS_AMAZON_RTOS */
