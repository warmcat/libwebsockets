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

#include "private-lib-core.h"

#include "esp_system.h"
#include "esp_spi_flash.h"
#include "esp_wifi.h"
#include <nvs_flash.h>
#include <esp_netif.h>

/*
static wifi_config_t config = {
	.ap = {
	    .channel = 6,
	    .authmode = WIFI_AUTH_OPEN,
	    .max_connection = 1,
	} };
	*/
static wifi_config_t sta_config = {
	.sta = {
		.bssid_set = 0,
	} };

static void
event_handler_wifi(void *arg, esp_event_base_t event_base, int32_t event_id,
		   void *event_data)
{
	lws_netdev_instance_wifi_t *wnd = (lws_netdev_instance_wifi_t *)arg;

	switch (event_id) {
	case WIFI_EVENT_STA_START:
		esp_wifi_connect();
		break;
	case WIFI_EVENT_STA_DISCONNECTED:
		lwsl_err("%s: %s: disconnect -> wifi connect\n", __func__,
			 wnd->inst.name);
		// !!! should only retry for a given amount of times
		esp_wifi_connect();
		break;
	}
}

static void
event_handler_ip(void *arg, esp_event_base_t event_base, int32_t event_id,
	      void *event_data)
{
	lws_netdev_instance_wifi_t *wnd = (lws_netdev_instance_wifi_t *)arg;

	if (event_id == IP_EVENT_STA_GOT_IP) {
		ip_event_got_ip_t *e = (ip_event_got_ip_t *)event_data;
		char ip[16];
		lws_write_numeric_address((void *)&e->ip_info.ip, 4, ip,
				sizeof(ip));
		lws_smd_msg_printf(wnd->inst.ctx, LWSSMDCL_NETWORK,
				   "{\"type\":\"ip\",\"if\":\"%s\","
				   "\"ipv4\":\"%s\"}", wnd->inst.name, ip);
	}
}


esp_event_handler_instance_t instance_any_id;
esp_event_handler_instance_t instance_got_ip;

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

	return 0;
}


struct lws_netdev_instance *
lws_netdev_wifi_create_plat(struct lws_context *ctx,
			    const lws_netdev_ops_t *ops,
			    const char *name, void *platinfo)
{
	lws_netdev_instance_wifi_t *wnd = lws_zalloc(sizeof(*wnd), __func__);

	if (!wnd)
		return NULL;

	wnd->inst.ops = ops;
	wnd->inst.name = name;
	wnd->inst.platinfo = platinfo;
	wnd->inst.ctx = ctx;

	return &wnd->inst;
}

int
lws_netdev_wifi_configure_plat(struct lws_netdev_instance *nd,
			       lws_netdev_config_t *config)
{
	lws_netdev_instance_wifi_t *wnd = (lws_netdev_instance_wifi_t *)nd;

	esp_wifi_set_mode(WIFI_MODE_STA);

	lws_strncpy((char *)sta_config.sta.ssid, wnd->sta.creds.ssid,
		    sizeof(sta_config.sta.ssid));
	lws_strncpy((char *)sta_config.sta.password, wnd->sta.creds.passphrase,
		    sizeof(sta_config.sta.password));

	esp_wifi_set_config(WIFI_IF_STA, &sta_config);

	return 0;
}

int
lws_netdev_wifi_up_plat(struct lws_netdev_instance *nd)
{
	lws_netdev_instance_wifi_t *wnd = (lws_netdev_instance_wifi_t *)nd;

	if (wnd->flags & LNDIW_UP)
		return 0;

	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
							    IP_EVENT_STA_GOT_IP,
							    &event_handler_ip,
							    nd,
							    &instance_got_ip));

	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
							    ESP_EVENT_ANY_ID,
							    &event_handler_wifi,
							    nd,
							    &instance_any_id));

	esp_wifi_start();
	wnd->flags |= LNDIW_UP;

	lws_smd_msg_printf(wnd->inst.ctx, LWSSMDCL_NETWORK,
			   "{\"type\":\"up\",\"if\":\"%s\"}", wnd->inst.name);

	return 0;
}

int
lws_netdev_wifi_down_plat(struct lws_netdev_instance *nd)
{
	lws_netdev_instance_wifi_t *wnd = (lws_netdev_instance_wifi_t *)nd;

	if (!(wnd->flags & LNDIW_UP))
		return 0;

	lws_smd_msg_printf(wnd->inst.ctx, LWSSMDCL_NETWORK,
			   "{\"type\":\"down\",\"if\":\"%s\"}", wnd->inst.name);

	esp_wifi_stop();

	esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP,
						&instance_got_ip);
	esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID,
						&instance_any_id);

	wnd->flags &= ~LNDIW_UP;

	return 0;
}

void
lws_netdev_wifi_destroy_plat(struct lws_netdev_instance **pnd)
{
	lws_free(*pnd);
	*pnd = NULL;
}
