/*
 * lhp boot status overlay
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The boot overlay is the list of a strip ui (lws-dlo-ui.h) titled "Boot": a
 * row per boot stage, with its icon and what we know about it, eg, the AP we
 * are looking for or the addresses we got.  The stages reached are shown
 * normally and the others dimmed, with the row of the stage being worked on
 * highlighted and kept in the middle of the list: as that moves on, the list
 * scrolls with it.
 *
 * Nothing here is platform-specific: the caller tells us which stages were
 * reached and what it knows about them, and we say what each row shows.
 */

#if !defined(__LHP_BOOT_UI_H__)
#define __LHP_BOOT_UI_H__

#include <libwebsockets.h>

/* in the order they are shown, matching contrib/assets/boot-status */

typedef enum {
	LHP_BOOT_SETUP,		/* wifi credentials are stored, see .ap */
	LHP_BOOT_WLAN,		/* associated to the AP */
	LHP_BOOT_IPV4,		/* have an IPv4 address */
	LHP_BOOT_IPV6,		/* have an IPv6 address (optional) */
	LHP_BOOT_INTERNET,	/* captive portal detection passed */
	LHP_BOOT_DATE,		/* the time is known */
	LHP_BOOT_OTA,		/* we are on the latest firmware */
	LHP_BOOT_AUTH,		/* the server recognizes us */

	LHP_BOOT_COUNT
} lhp_boot_stage_t;

/* what the update check, if any, said */

typedef enum {
	LHP_BOOT_OTA_UNKNOWN,
	LHP_BOOT_OTA_CHECKING,
	LHP_BOOT_OTA_UP_TO_DATE,
	LHP_BOOT_OTA_UPDATE,
	LHP_BOOT_OTA_FAILED,
	LHP_BOOT_OTA_DISABLED,
} lhp_boot_ota_t;

typedef struct lhp_boot {
	struct lws_context		*cx;
	lws_netdev_instance_wifi_t	*wnd;	/* NULL, or wifi, for the APs */

	char				ap[33];	 /* the first stored AP's SSID */
	char				own_ap[33]; /* while we're an AP to be
						     * set up, its SSID */
	char				own_ip[16]; /* and our address on it */
	char				ipv4[16];
	char				ipv6[48];

	uint8_t				aps;	 /* how many APs are stored */

	uint16_t			reached; /* 1 << lhp_boot_stage_t */
	uint8_t				ota;	 /* lhp_boot_ota_t */
} lhp_boot_t;

/*
 * Prepare b, and register the stages' icons in the dlo filesystem, where the
 * rows refer to them
 */
int
lhp_boot_init(struct lws_context *cx, lhp_boot_t *b,
	      lws_netdev_instance_wifi_t *wnd);

/* the overlay is finished with: unregister its icons */
void
lhp_boot_deinit(lhp_boot_t *b);

/*
 * Mark stage s reached (reached = 1) or no longer reached (eg, the link went
 * down).  Returns nonzero if that changed anything.
 */
int
lhp_boot_set(lhp_boot_t *b, lhp_boot_stage_t s, int reached);

/*
 * The stage being worked on: the first not reached, apart from IPv6, which
 * we may never get, or LHP_BOOT_COUNT if all have been
 */
lhp_boot_stage_t
lhp_boot_focus(const lhp_boot_t *b);

/*
 * Fill in the strip ui row for stage idx, as it is now.  Returns nonzero if
 * there is no such stage.
 */
int
lhp_boot_row(const lhp_boot_t *b, int idx, lws_dlo_ui_row_t *row);

#endif
