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
#define LWS_ETH_ALEN 6

typedef uint8_t	lws_wifi_ch_t;
typedef int8_t lws_wifi_rssi_t;
struct lws_netdev_instance;

typedef enum {
	LWSNDTYP_UNKNOWN,
	LWSNDTYP_WIFI,
	LWSNDTYP_ETH,
} lws_netdev_type_t;

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
	int (*event)(struct lws_netdev_instance *nd, lws_usec_t timestamp,
		     void *buf, size_t len);
	/**< these are SMD events coming from lws event loop thread context */
	void (*destroy)(struct lws_netdev_instance **pnd);
	int (*connect)(struct lws_netdev_instance *wnd, const char *ssid,
			    const char *passphrase, uint8_t *bssid);
	void (*scan)(struct lws_netdev_instance *nd);
	int (*rssi)(struct lws_netdev_instance *nd, int *rssi);
	/**< NULL, or if associated, set *rssi to the signal strength of the
	 * AP, in dBm, and return 0, else nonzero */
	int (*hostname)(struct lws_netdev_instance *nd, const char *name);
	/**< NULL, or use name, see lws_netdev_hostname_get(), as the
	 * hostname the netdev gives when it acquires or renews an address,
	 * eg, by DHCP, from now on */
} lws_netdev_ops_t;

/*
 * Network devices on this platform
 *
 * We also hold a list of all known network credentials (when they are needed
 * because there is a network interface without anything to connect to) and
 * the lws_settings instance they are stored in
 */

typedef struct lws_netdevs {
	lws_dll2_owner_t		owner;
	/**< list of netdevs / lws_netdev_instance_t -based objects */

	lws_dll2_owner_t		owner_creds;
	/**< list of known credentials */
	struct lwsac			*ac_creds;
	/**< lwsac holding retreived credentials settings, or NULL */
	lws_settings_instance_t		*si;

	lws_sockaddr46			sa46_dns_resolver;

	uint8_t				refcount_creds;
	/**< when there are multiple netdevs, must refcount creds in mem */
} lws_netdevs_t;

/*
 * Base class for an allocated instantiated derived object using lws_netdev_ops,
 * ie, a specific ethernet device
 */

typedef struct lws_netdev_instance {
	const char			*name;
	const lws_netdev_ops_t		*ops;
	void				*platinfo;
	lws_dll2_t			list;
	uint8_t				mac[LWS_ETH_ALEN];
	uint8_t				type; /* lws_netdev_type_t */
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

/*
 * Group AP / Station State
 */

typedef enum {
	LWSNDVWIFI_STATE_INITIAL,
		/*
		 * We should gratuitously try whatever last worked for us, then
		 * if that fails, worry about the rest of the logic
		 */
	LWSNDVWIFI_STATE_SCAN,
		/*
		 * Unconnected, scanning: AP known in one of the config slots ->
		 * configure it, start timeout + LWSNDVWIFI_STATE_STAT, if no AP
		 * already up in same group with lower MAC, after a random
		 * period start up our AP (LWSNDVWIFI_STATE_AP)
		 */
	LWSNDVWIFI_STATE_AP,
		/* Trying to be the group AP... periodically do a scan
		 * LWSNDVWIFI_STATE_AP_SCAN, faster and then slower
       		 */
	LWSNDVWIFI_STATE_AP_SCAN,
		/*
		 * doing a scan while trying to be the group AP... if we see a
		 * lower MAC being the AP for the same group AP, abandon being
		 * an AP and join that AP as a station
		 */
	LWSNDVWIFI_STATE_STAT_GRP_AP,
		/*
		 * We have decided to join another group member who is being the
		 * AP, as its MAC is lower than ours.  This is a stable state,
		 * but we still do periodic scans
		 * LWSNDVWIFI_STATE_STAT_GRP_AP_SCAN and will always prefer an
		 * AP configured in a slot.
		 */
	LWSNDVWIFI_STATE_STAT_GRP_AP_SCAN,
		/*
		 * We have joined a group member who is doing the AP job... we
		 * want to check every now and then if a configured AP has
		 * appeared that we should better use instead.  Otherwise stay
		 * in LWSNDVWIFI_STATE_STAT_GRP_AP
		 */
	LWSNDVWIFI_STATE_STAT,
		/*
		 * trying to connect to another non-group AP. If we don't get an
		 * IP within a timeout and retries, mark it as unusable it and go back
		 */
	LWSNDVWIFI_STATE_STAT_HAPPY,
} lws_netdev_wifi_state_t;

/*
 * Generic WIFI credentials
 */

/* how the last attempt to join an AP with its credentials went */

typedef enum {
	LWS_WIFI_JOIN_UNKNOWN,		/* not tried since they were stored */
	LWS_WIFI_JOIN_OK,		/* joined it and got an address */
	LWS_WIFI_JOIN_AUTH_FAILED,	/* it refused us, eg, wrong passphrase */
	LWS_WIFI_JOIN_FAILED,		/* couldn't join it for another reason */
} lws_wifi_join_t;

typedef struct lws_wifi_creds {
	lws_dll2_t			list;

	uint8_t				bssid[LWS_ETH_ALEN];
	/**< binary form of the AP MAC, this is what the netdev ops use */
	char				bssid_hex[(LWS_ETH_ALEN * 2) + 1];
	/**< ascii hex form of .bssid... an in-struct byte array cannot be
	 * described to lws_struct, so this is the member that is actually
	 * serialized to and from settings as "bssid".  lws keeps the two in
	 * step when it stores or restores the credentials.
	 */
	char				passphrase[64];
	char				ssid[33];
	uint8_t				alg;
	uint8_t				last_join;
	/**< lws_wifi_join_t: how the last attempt to join the AP went.  It
	 * goes back to LWS_WIFI_JOIN_UNKNOWN when the passphrase changes */
	uint8_t				internet;
	/**< nonzero once captive portal detection passed while joined to it */
} lws_wifi_creds_t;

/*
 * Generic WIFI Network Device Instance
 */

typedef struct lws_netdev_instance_wifi {
	lws_netdev_instance_t		inst;
	lws_dll2_owner_t		scan; /* sorted scan results */
	lws_sorted_usec_list_t		sul_scan;

	lws_wifi_creds_t		*ap_cred;
	const char			*ap_ip;

	const char			*sta_ads;

	char				current_attempt_ssid[33];
	uint8_t				current_attempt_bssid[LWS_ETH_ALEN];

	uint8_t				flags;
	uint8_t				state; /* lws_netdev_wifi_state_t */
	uint8_t				joined;
	/**< current_attempt_ssid was joined and gave us an address */
} lws_netdev_instance_wifi_t;

/*
 * Logical scan results sorted list item
 */

/* how an AP authenticates, as the scan saw it */

typedef enum {
	LWS_WIFI_AUTH_OPEN,		/* no passphrase */
	LWS_WIFI_AUTH_WEP,
	LWS_WIFI_AUTH_WPA,
	LWS_WIFI_AUTH_WPA2,
	LWS_WIFI_AUTH_WPA_WPA2,
	LWS_WIFI_AUTH_WPA3,
	LWS_WIFI_AUTH_WPA2_WPA3,
	LWS_WIFI_AUTH_ENTERPRISE,	/* 802.1X, not a passphrase */
	LWS_WIFI_AUTH_OTHER,		/* none of those, or unknown */
} lws_wifi_auth_t;

typedef struct lws_wifi_sta {
	lws_dll2_t			list;

	uint32_t			last_seen; /* unix time */
	uint32_t			last_tried; /* unix time */

	uint8_t				bssid[LWS_ETH_ALEN];
	char				*ssid; /* points to overallocation */
	uint8_t				ssid_len;
	lws_wifi_ch_t			ch;
	lws_wifi_rssi_t			rssi[8];
	int16_t				rssi_avg;
	uint8_t				authmode;
	/**< lws_wifi_auth_t */

	uint8_t				rssi_count;
	uint8_t				rssi_next;

	/* ssid overallocated afterwards */
} lws_wifi_sta_t;

#define rssi_averaged(_x) (_x->rssi_count ? \
		((int)_x->rssi_avg / (int)_x->rssi_count) : \
			-200)

LWS_VISIBLE LWS_EXTERN lws_netdevs_t *
lws_netdevs_from_ctx(struct lws_context *ctx);

LWS_VISIBLE LWS_EXTERN int
lws_netdev_credentials_settings_set(lws_netdevs_t *nds);

LWS_VISIBLE LWS_EXTERN int
lws_netdev_credentials_settings_get(lws_netdevs_t *nds);

/**
 * lws_netdev_credentials_add() - store credentials for an AP
 *
 * \param nds: the netdevs
 * \param ssid: the AP's SSID
 * \param passphrase: its passphrase, "" for an open AP
 *
 * Adds the credentials to those stored in the settings, replacing any for
 * the same SSID, and stores them all again.  If the passphrase changed, how
 * the last attempt to join went is forgotten.  Credentials for any number of
 * APs can be stored: the wifi netdev joins the strongest AP it sees that it
 * has credentials for, trying the others in turn if that fails.  It scans
 * every few seconds while it is not joined, so it finds the AP by itself.
 *
 * Returns 0 if they were stored, else nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_netdev_credentials_add(lws_netdevs_t *nds, const char *ssid,
			   const char *passphrase);

/**
 * lws_netdev_credentials_remove() - forget the credentials for an AP
 *
 * \param nds: the netdevs
 * \param ssid: the AP's SSID
 *
 * Returns 0 if there were credentials for it, and the rest were stored
 * again without them, else nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_netdev_credentials_remove(lws_netdevs_t *nds, const char *ssid);

/**
 * lws_netdev_credentials_has() - are credentials stored for an AP
 *
 * \param nds: the netdevs
 * \param ssid: the AP's SSID
 *
 * Returns 1 if they are, else 0.  The passphrase isn't given out.
 */
LWS_VISIBLE LWS_EXTERN int
lws_netdev_credentials_has(lws_netdevs_t *nds, const char *ssid);

/**
 * lws_netdev_credentials_hold() - bring the stored credentials into memory
 *
 * \param nds: the netdevs
 *
 * Reads the credentials from the settings into nds->owner_creds, a list of
 * lws_wifi_creds_t, if nothing is holding them already, and holds them
 * until lws_netdev_credentials_release().  If none are stored, the list is
 * empty.
 */
LWS_VISIBLE LWS_EXTERN void
lws_netdev_credentials_hold(lws_netdevs_t *nds);

/**
 * lws_netdev_credentials_release() - let go of the credentials
 *
 * \param nds: the netdevs
 *
 * When nothing else holds them, the passphrases are cleared and the
 * credentials are freed.
 */
LWS_VISIBLE LWS_EXTERN void
lws_netdev_credentials_release(lws_netdevs_t *nds);

/**
 * lws_wifi_auth_name() - a short name for how an AP authenticates
 *
 * \param auth: lws_wifi_auth_t
 *
 * Returns eg, "WPA2", or "Open", for showing to the user.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_wifi_auth_name(lws_wifi_auth_t auth);

/**
 * lws_netdev_wifi_link_lost() - the platform lost, or failed to make, the link
 *
 * \param wnd: the wifi netdev
 * \param auth_failed: nonzero if the AP refused us, eg, the passphrase is wrong
 *
 * The platform calls this when it loses the association to the AP it was
 * trying, current_attempt_ssid, or fails to make it.  If the AP refused us, or
 * we never got an address from it this time, it's recorded with its
 * credentials, see lws_wifi_creds_t .last_join.
 */
LWS_VISIBLE LWS_EXTERN void
lws_netdev_wifi_link_lost(lws_netdev_instance_wifi_t *wnd, int auth_failed);

/*
 * The hostname, at most this many characters
 */

#define LWS_NETDEV_HOSTNAME_MAX		32

/**
 * lws_netdev_hostname_get() - the hostname the device gives eg, DHCP
 *
 * \param nds: the netdevs
 * \param buf: where to put it
 * \param len: the size of buf, at least LWS_NETDEV_HOSTNAME_MAX + 1
 *
 * The hostname stored with lws_netdev_hostname_set(), or if there isn't one,
 * "lws-" and the last three bytes of the first netdev's MAC address in hex,
 * eg, "lws-a1b2c3", so devices are told apart, eg, in a DHCP server's local
 * DNS.  Netdevs use it when they acquire an address.
 *
 * Returns 0 if a stored hostname was given, 1 if the default was, or -1 if
 * neither can be, eg, no netdev knows its MAC address yet.
 */
LWS_VISIBLE LWS_EXTERN int
lws_netdev_hostname_get(lws_netdevs_t *nds, char *buf, size_t len);

/**
 * lws_netdev_hostname_set() - store the hostname
 *
 * \param nds: the netdevs
 * \param name: the hostname, or NULL or "" to forget it, and use the default
 *
 * The hostname must be a single DNS label, 1 to LWS_NETDEV_HOSTNAME_MAX of
 * a-z, 0-9 and '-', not starting or ending with '-'.  Upper case letters are
 * stored as lower case.  It's stored in the settings, and each netdev that can
 * is told, so it is given when it next acquires or renews an address.
 *
 * Returns 0 if it was stored, or nonzero if it isn't a valid hostname or it
 * couldn't be stored.
 */
LWS_VISIBLE LWS_EXTERN int
lws_netdev_hostname_set(lws_netdevs_t *nds, const char *name);

/**
 * lws_netdev_wifi_rssi() - how strong the associated AP's signal is
 *
 * \param nd: the netdev
 * \param rssi: set to the signal strength, in dBm
 *
 * Returns 0 if *rssi was set, or nonzero if the netdev isn't associated, or
 * can't say.
 */
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_rssi(lws_netdev_instance_t *nd, int *rssi);

LWS_VISIBLE LWS_EXTERN struct lws_netdev_instance *
lws_netdev_wifi_create_plat(struct lws_context *ctx,
			    const lws_netdev_ops_t *ops, const char *name,
			    void *platinfo);
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_configure_plat(struct lws_netdev_instance *nd,
			       lws_netdev_config_t *config);
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_event_plat(struct lws_netdev_instance *nd, lws_usec_t timestamp,
			   void *buf, size_t len);
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_up_plat(struct lws_netdev_instance *nd);
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_down_plat(struct lws_netdev_instance *nd);
LWS_VISIBLE LWS_EXTERN void
lws_netdev_wifi_destroy_plat(struct lws_netdev_instance **pnd);
LWS_VISIBLE LWS_EXTERN void
lws_netdev_wifi_scan_plat(lws_netdev_instance_t *nd);
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_rssi_plat(lws_netdev_instance_t *nd, int *rssi);
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_hostname_plat(lws_netdev_instance_t *nd, const char *name);

LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_connect_plat(lws_netdev_instance_t *wnd, const char *ssid,
			     const char *passphrase, uint8_t *bssid);

LWS_VISIBLE LWS_EXTERN lws_netdev_instance_t *
lws_netdev_find(lws_netdevs_t *netdevs, const char *ifname);

#define lws_netdev_wifi_plat_ops \
	.create				= lws_netdev_wifi_create_plat, \
	.configure			= lws_netdev_wifi_configure_plat, \
	.event				= lws_netdev_wifi_event_plat, \
	.up				= lws_netdev_wifi_up_plat, \
	.down				= lws_netdev_wifi_down_plat, \
	.connect			= lws_netdev_wifi_connect_plat, \
	.scan				= lws_netdev_wifi_scan_plat, \
	.rssi				= lws_netdev_wifi_rssi_plat, \
	.hostname			= lws_netdev_wifi_hostname_plat, \
	.destroy			= lws_netdev_wifi_destroy_plat

/*
 * This is for plat / OS level init that is necessary to be able to use
 * networking or wifi at all, without mentioning any specific device
 */

LWS_VISIBLE LWS_EXTERN int
lws_netdev_plat_init(void);

LWS_VISIBLE LWS_EXTERN int
lws_netdev_plat_wifi_init(void);
