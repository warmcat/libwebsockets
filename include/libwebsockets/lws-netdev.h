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

#define LWS_WIFI_MAX_SCAN_TRACK 16

typedef uint8_t	lws_wifi_ch_t;
struct lws_netdev_instance;

/*
 * Base class for netdev configuration
 */

typedef struct lws_netdev_config {
	void				*plat_config;
} lws_netdev_config_t;

/*
 * Const Logical generic network interface ops
 */

typedef struct lws_netdev_ops {
	struct lws_netdev_instance * (*create)(struct lws_context *ctx,
					       const struct lws_netdev_ops *ops,
					       const char *name, void *platinfo);
	int (*configure)(struct lws_netdev_instance *nd,
			 lws_netdev_config_t *config);
	int (*up)(struct lws_netdev_instance *nd);
	int (*down)(struct lws_netdev_instance *nd);
	void (*destroy)(struct lws_netdev_instance **pnd);
} lws_netdev_ops_t;

/*
 * Base class for an allocated instantiated derived object using lws_netdev_ops,
 * ie, a specific ethernet device
 */

typedef struct lws_netdev_instance {
	const char			*name;
	const lws_netdev_ops_t		*ops;
	struct lws_context		*ctx;
	void				*platinfo;
	lws_dll2_t			list;
} lws_netdev_instance_t;

enum {
	LNDIW_ALG_OPEN,
	LNDIW_ALG_WPA2,

	LNDIW_MODE_STA			= (1 << 0),
	LNDIW_MODE_AP			= (1 << 1),
	LNDIW_UP			= (1 << 7),

	LNDIW_ACQ_IPv4			= (1 << 0),
	LNDIW_ACQ_IPv6			= (1 << 1),
};

typedef struct lws_wifi_credentials {
	uint8_t				bssid[6];
	char				passphrase[64];
	char				ssid[33];
	uint8_t				alg;
} lws_wifi_credentials_t;

typedef struct lws_netdev_instance_wifi {
	lws_netdev_instance_t		inst;
	lws_dll2_owner_t		scan;

	struct {
		lws_wifi_credentials_t	creds;
		lws_sockaddr46		sa46[2];
		uint8_t			flags;
	} ap;
	struct {
		lws_wifi_credentials_t	creds;
		lws_sockaddr46		sa46[2];
		uint8_t			flags;
	} sta;

	uint8_t				flags;
} lws_netdev_instance_wifi_t;

/*
 * Logical scan results sorted list item
 */

typedef struct lws_wifi_sta {
	lws_dll2_t			list;

	uint8_t				bssid[6];
	uint8_t				ssid_len;
	lws_wifi_ch_t			ch;
	int8_t				rssi[4];
	uint8_t				authmode;

	uint8_t				rssi_count;
	uint8_t				rssi_next;

	/* ssid overallocated afterwards */
} lws_wifi_sta_t;

typedef struct lws_wifi_credentials_setting {
	lws_dll2_t			list;

	lws_wifi_credentials_t		creds;
} lws_wifi_credentials_setting_t;

LWS_VISIBLE LWS_EXTERN struct lws_netdev_instance *
lws_netdev_wifi_create_plat(struct lws_context *ctx,
			    const lws_netdev_ops_t *ops, const char *name,
			    void *platinfo);
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_configure_plat(struct lws_netdev_instance *nd,
			       lws_netdev_config_t *config);
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_up_plat(struct lws_netdev_instance *nd);
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_down_plat(struct lws_netdev_instance *nd);
LWS_VISIBLE LWS_EXTERN void
lws_netdev_wifi_destroy_plat(struct lws_netdev_instance **pnd);

#define lws_netdev_wifi_plat_ops \
	.create				= lws_netdev_wifi_create_plat, \
	.configure			= lws_netdev_wifi_configure_plat, \
	.up				= lws_netdev_wifi_up_plat, \
	.down				= lws_netdev_wifi_down_plat, \
	.destroy			= lws_netdev_wifi_destroy_plat

/*
 * This is for plat / OS level init that is necessary to be able to use
 * networking or wifi at all, without mentioning any specific device
 */

LWS_VISIBLE LWS_EXTERN int
lws_netdev_plat_init(void);

LWS_VISIBLE LWS_EXTERN int
lws_netdev_plat_wifi_init(void);
