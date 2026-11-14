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
	int (*ap)(struct lws_netdev_instance *nd, const char *ssid,
		  const char *passphrase);
	/**< NULL, or be an AP called ssid alongside being a station, or if
	 * ssid is NULL, stop being one: see lws_netdev_wifi_ap() */
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
	char				ap_ipv4[16];
	/**< while we are an AP (LNDIW_MODE_AP), our address on it, eg,
	 * "192.168.4.1", else "" */

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
 * lws_netdev_credentials_clear() - forget the credentials for every AP
 *
 * \param nds: the netdevs
 *
 * Eg, for a "factory reset".  Returns 0 if they were all forgotten, or there
 * were none, else nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_netdev_credentials_clear(lws_netdevs_t *nds);

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

/**
 * lws_netdev_wifi_ap() - be an AP, as well as a station
 *
 * \param nd: the wifi netdev
 * \param ssid: the SSID of our AP, 1 to 32 characters, or NULL to stop it
 * \param passphrase: NULL or "" for an open AP, else 8 to 63 characters
 *
 * Starts our own AP alongside the station, which goes on scanning and
 * joining APs it has credentials for, eg, so a phone can join our AP and be
 * served a page to give us credentials.  Our AP has an address of its own,
 * eg, 192.168.4.1, given in wnd->ap_ipv4, and gives the stations that join it
 * addresses by DHCP.  Its subnet is in the routing table, so what talks to
 * us over it isn't closed as unroutable when the station's routes change.
 *
 * While we are an AP, the station scans less often, since it has to leave
 * our AP's channel to do it.
 *
 * SMD NETWORK messages {"type":"apup","if":"<name>","ipv4":"<address>"} and
 * {"type":"apdown","if":"<name>"} say when it started and stopped.
 *
 * Returns 0 if it was started or stopped, else nonzero, eg, the netdev can't
 * be an AP.
 */
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_ap(lws_netdev_instance_t *nd, const char *ssid,
		   const char *passphrase);

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
lws_netdev_wifi_ap_plat(lws_netdev_instance_t *nd, const char *ssid,
			const char *passphrase);

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
	.ap				= lws_netdev_wifi_ap_plat, \
	.destroy			= lws_netdev_wifi_destroy_plat

/*
 * The wifi settings, as html
 *
 * What we know of the APs around us and those we have credentials for, and the
 * hostname, written as html that is the same whether it is shown on the
 * device's own display, eg, as a dialog of the strip ui (lws-dlo-ui.h), or
 * served to a browser by the device, see lws_wifi_provision_create().  Its
 * links say what to do in the same way for both, see
 * lws_wifi_settings_href().
 */

/*
 * The icons the html uses, by name: whatever shows it provides them, eg, from
 * contrib/assets/settings and contrib/assets/boot-status.  The signal's are
 * LWS_WIFI_SETTINGS_ICON_SIG "0.svg" to "4.svg", for none to four bars lit.
 */
#define LWS_WIFI_SETTINGS_ICON_KEY	"set-key.svg"	/* we have its passphrase */
#define LWS_WIFI_SETTINGS_ICON_NET	"set-net.svg"	/* internet was reached */
#define LWS_WIFI_SETTINGS_ICON_COG	"set-cog.svg"	/* set its passphrase */
#define LWS_WIFI_SETTINGS_ICON_FORGET	"set-bin.svg"	/* forget it */
#define LWS_WIFI_SETTINGS_ICON_OK	"set-ok.svg"	/* last join went ok */
#define LWS_WIFI_SETTINGS_ICON_REFUSED	"set-no.svg"	/* passphrase refused */
#define LWS_WIFI_SETTINGS_ICON_FAILED	"set-fail.svg"	/* join failed */
#define LWS_WIFI_SETTINGS_ICON_SIG	"set-sig"

/* what we know of an AP, see lws_netdev_wifi_ap_list() */

typedef struct lws_wifi_ap_info {
	char				ssid[33];
	uint8_t				auth;	/* lws_wifi_auth_t, if seen */
	uint8_t				last_join; /* lws_wifi_join_t */
	uint8_t				open;	/* needs no passphrase */
	uint8_t				stored;	/* we have credentials for it */
	uint8_t				seen;	/* in the scan results */
	uint8_t				internet; /* was reached through it */
	uint8_t				bars;	/* signal, 0 if not seen, else
						 * lws_wifi_rssi_bars() */
} lws_wifi_ap_info_t;

/* what a link in the settings' html asks for, see lws_wifi_settings_href() */

typedef enum {
	LWS_WIFI_SETTINGS_ACT_NONE,	/* not one of ours */
	LWS_WIFI_SETTINGS_ACT_SET,	/* set the passphrase of an AP */
	LWS_WIFI_SETTINGS_ACT_FORGET,	/* forget an AP's credentials */
	LWS_WIFI_SETTINGS_ACT_HOSTNAME,	/* edit the hostname */
} lws_wifi_settings_act_t;

/**
 * lws_wifi_rssi_bars() - how many of four signal bars an rssi is
 *
 * \param rssi: the signal strength in dBm
 *
 * Returns 1 to 4: strong enough for anything at -55dBm, barely usable below
 * -75dBm, so everything showing a signal agrees.
 */
LWS_VISIBLE LWS_EXTERN int
lws_wifi_rssi_bars(int rssi);

/**
 * lws_netdev_wifi_scan_sig() - a signature of the scan results
 *
 * \param wnd: the wifi netdev, or NULL
 *
 * Changes when the APs scanned, or the bars of their signal, change, but not
 * their order, or their rssi within the same bars, so a list of them only
 * needs showing again when it does.
 */
LWS_VISIBLE LWS_EXTERN uint32_t
lws_netdev_wifi_scan_sig(const lws_netdev_instance_wifi_t *wnd);

/**
 * lws_netdev_wifi_ap_list() - the APs we know of
 *
 * \param nds: the netdevs
 * \param wnd: the wifi netdev whose scan results to use, or NULL for none
 * \param aps: filled with up to max APs
 * \param max: the most to list
 *
 * Lists the networks in the scan results, one per SSID, strongest first, then
 * those we have credentials for that weren't seen.  Hidden networks can't be
 * picked, so aren't listed.  Returns how many were listed.
 */
LWS_VISIBLE LWS_EXTERN int
lws_netdev_wifi_ap_list(lws_netdevs_t *nds,
			const lws_netdev_instance_wifi_t *wnd,
			lws_wifi_ap_info_t *aps, int max);

/**
 * lws_wifi_settings_html() - write the wifi settings as html
 *
 * \param w: the html writer
 * \param aps: the APs, from lws_netdev_wifi_ap_list()
 * \param count: how many
 * \param have_wlan: nonzero if there is a wifi netdev, to say it's scanning
 *		     when there are no APs to show yet
 * \param hostname: the hostname, from lws_netdev_hostname_get(), or NULL
 *
 * A section titled "WLAN", a table of the APs, a row each: its signal, its
 * SSID over what we know of it, and the links to set its passphrase and to
 * forget it, and a section titled "Hostname", the hostname as a link to edit
 * it.  The links' hrefs are relative urls with an argument, eg,
 * "?set=<ssid>", so a browser asks the page's own url with it, and a dialog
 * on the device is told them, for lws_wifi_settings_href() to say what they
 * ask for.  Style it with lws_wifi_settings_css(); it uses the
 * LWS_WIFI_SETTINGS_ICON_ icons.
 */
LWS_VISIBLE LWS_EXTERN void
lws_wifi_settings_html(lws_html_w_t *w, const lws_wifi_ap_info_t *aps,
		       int count, int have_wlan, const char *hostname);

/**
 * lws_wifi_settings_href() - what a link in the settings' html asks for
 *
 * \param href: the link's href, eg, "?set=My%20AP"
 * \param ssid: set to the SSID it's for, if any
 * \param ssid_len: the size of ssid, at least 33
 *
 * Returns what it asks for, or LWS_WIFI_SETTINGS_ACT_NONE if it's not one of
 * the settings' links, or what it says isn't a usable SSID.
 */
LWS_VISIBLE LWS_EXTERN lws_wifi_settings_act_t
lws_wifi_settings_href(const char *href, char *ssid, size_t ssid_len);

/* the css for the settings' html */
LWS_VISIBLE LWS_EXTERN const char *
lws_wifi_settings_css(void);

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_SYS_SMD)

/*
 * Giving a device wifi credentials when it has none it can use
 *
 * If it has none, or none it can use, the device becomes an AP of its own,
 * named for its hostname, eg, "lws-a1b2c3", open by default, with the station
 * still scanning alongside it.  Whoever joins it can browse to it, eg,
 * http://192.168.4.1/, and is served the same wifi settings the device shows on
 * its own display, if it has one (lws_wifi_settings_html()), to pick an AP and
 * type its passphrase.  When credentials are stored, the device restarts to
 * join it, with the system's reboot op.  A led the caller names, if any, gives
 * two short flashes over and over meanwhile, so a device without a display can
 * be seen to be waiting to be set up.
 *
 * It decides at lws_wifi_provision_create():
 *
 *  - no credentials are stored, or every AP refused its passphrase the last
 *    time it was tried: it becomes an AP at once
 *
 *  - credentials are stored, but none worked yet: if the station hasn't
 *    joined one after .join_wait_s, it becomes an AP then
 *
 *  - credentials are stored that worked before: it never does, the station
 *    finds the AP again by itself when it's back
 *
 * If the station joins an AP after all while it's an AP, it stops being one.
 *
 * Built with LWS_WITH_SYS_CAPTIVE_DNS, it's a captive portal while it's an AP:
 * lws_captive_dns_start() makes every name our address to whoever joins, and
 * a request for any other host is redirected to the settings.  So the phone
 * or laptop that joins finds its check for internet answered by us, and
 * offers to "sign in to the network", which shows the settings, without
 * anybody having to know our address.  Without it, they have to browse to
 * our address themselves, which not every browser does: in testing, Firefox
 * on Android never connected to it, where Chrome did.
 *
 * A "factory reset": if the button named .reset_button is pressed within
 * .reset_window_s of lws_wifi_provision_create() and held for .reset_hold_s,
 * the credentials for every AP are forgotten, the led flashes fast for a
 * couple of seconds, and the device restarts, to come up as an AP.  Given
 * .buttons, the button can already be held when we're created, so it can be
 * pressed as soon as the device starts and held until it resets.
 *
 * The device's own settings can be used at the same time, eg, on its display:
 * when they store credentials, the caller tells us with
 * lws_wifi_provision_stored(), and the device restarts to join it the same
 * way.
 *
 * The pages are served by plain http/1.1, since browsers only use h2 over TLS,
 * and a certificate for an address on the device's own AP can't be trusted by
 * them: so anyone near enough to join the AP can see the passphrase typed in.
 * Give .ap_passphrase, eg, printed on the device, to have the AP use WPA2.
 */

typedef enum {
	LWS_WIFI_PROV_IDLE,	/* the station uses the credentials we have */
	LWS_WIFI_PROV_AP,	/* we're an AP, serving the settings */
	LWS_WIFI_PROV_RESET,	/* the reset button forgot the credentials */
	LWS_WIFI_PROV_REBOOT,	/* about to restart, eg, to join an AP */
} lws_wifi_provision_state_t;

/* told when the state changes, from the lws event loop */
typedef void (*lws_wifi_provision_cb_t)(void *opaque,
					lws_wifi_provision_state_t state);

/* a file served beside the settings, eg, the icons they use */

typedef struct lws_wifi_provision_file {
	const char			*name;	/* eg, "set-cog.svg", served
						 * at /set-cog.svg */
	const void			*data;
	size_t				len;
	const char			*mimetype; /* eg, "image/svg+xml" */
} lws_wifi_provision_file_t;

typedef struct lws_wifi_provision_info {
	struct lws_context		*cx;
	lws_netdev_instance_wifi_t	*wnd;
	/**< the wifi netdev, which must be able to be an AP as well */
	struct lws_led_state		*lls;
	/**< NULL, or the leds, one of which is named by .led */
	const char			*led;
	/**< NULL, or the name of the led to flash */
	const char			*reset_button;
	/**< NULL, or the name of the button, eg, "user", whose SMD
	 * interaction events, eg, from "bc/user", mean a factory reset when
	 * it's held, see above */
	struct lws_button_state		*buttons;
	/**< NULL, or the button controller .reset_button is on.  Given it, a
	 * button already held when we're created counts as pressed then, eg,
	 * one pressed while the device was starting, and one released without
	 * an "up" event we saw isn't taken as still held */
	const lws_wifi_provision_file_t	*files;
	/**< NULL, or files to serve beside the settings, eg, the
	 * LWS_WIFI_SETTINGS_ICON_ ones they use: they must exist for as long
	 * as this does.  Without them, the settings work but show no icons */
	size_t				count_files;
	const char			*ap_passphrase;
	/**< NULL for our AP to be open, else 8 to 63 characters for WPA2 */
	lws_wifi_provision_cb_t		cb;
	/**< NULL, or told when the state changes */
	void				*opaque;
	/**< passed to cb */
	uint16_t			port;
	/**< 0 for 80, the port the settings are served on */
	uint16_t			join_wait_s;
	/**< 0 for 60, how long credentials that never worked are given */
	uint16_t			reset_window_s;
	/**< 0 for 10, how long after starting the reset button can be
	 * pressed to begin a reset */
	uint16_t			reset_hold_s;
	/**< 0 for 5, how long it has to be held */
	uint16_t			dns_port;
	/**< 0 for 53, the port the captive dns answers on, with
	 * LWS_WITH_SYS_CAPTIVE_DNS */
} lws_wifi_provision_info_t;

struct lws_wifi_provision;

/**
 * lws_wifi_provision_create() - become an AP to be given credentials, if needed
 *
 * \param i: what to use: copied
 *
 * Decides if we need to be an AP to be given credentials, now or after a
 * while, and watches the reset button, see above.  Call it once the wifi
 * netdev is up, and the context's system ops have reboot.
 *
 * Returns the provisioning object, or NULL if it failed.
 */
LWS_VISIBLE LWS_EXTERN struct lws_wifi_provision *
lws_wifi_provision_create(const lws_wifi_provision_info_t *i);

/* stop serving the settings and being an AP, and free it */
LWS_VISIBLE LWS_EXTERN void
lws_wifi_provision_destroy(struct lws_wifi_provision **p);

/* the state, eg, LWS_WIFI_PROV_AP while we're an AP */
LWS_VISIBLE LWS_EXTERN lws_wifi_provision_state_t
lws_wifi_provision_state(const struct lws_wifi_provision *p);

/* the SSID of our AP while we're one, else NULL, eg, to show it */
LWS_VISIBLE LWS_EXTERN const char *
lws_wifi_provision_ap_ssid(const struct lws_wifi_provision *p);

/* the url of the settings while we're an AP, else NULL, eg, to show it */
LWS_VISIBLE LWS_EXTERN const char *
lws_wifi_provision_url(const struct lws_wifi_provision *p);

/**
 * lws_wifi_provision_stored() - credentials were stored some other way
 *
 * \param p: the provisioning object, or NULL
 *
 * Eg, on the device's own display.  While we're an AP, the device restarts
 * after a few seconds to join it, as when they're stored by the served
 * settings.  Otherwise there's nothing to do: the station joins it by itself.
 */
LWS_VISIBLE LWS_EXTERN void
lws_wifi_provision_stored(struct lws_wifi_provision *p);

#endif

/*
 * This is for plat / OS level init that is necessary to be able to use
 * networking or wifi at all, without mentioning any specific device
 */

LWS_VISIBLE LWS_EXTERN int
lws_netdev_plat_init(void);

LWS_VISIBLE LWS_EXTERN int
lws_netdev_plat_wifi_init(void);
