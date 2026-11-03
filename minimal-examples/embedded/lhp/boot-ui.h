/*
 * lhp boot status overlay
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The boot overlay is html, laid out and rendered by lhp like any other page.
 * It shows the boot stages as a table at the top left of the display, a row
 * per stage with its icon, and next to it what we know about it, eg, the AP
 * we are looking for or the addresses we got.  The stages reached are at full
 * opacity and the others dimmed, with the row of the stage being worked on
 * highlighted.  When the display is too short for the whole table, it's shown
 * through a window as tall as the display, offset so the row being worked on
 * is in the middle: as that moves on, the table moves with it.
 *
 * Nothing here is platform-specific: the caller tells us which stages were
 * reached and what it knows about them, and we make the html.
 */

#if !defined(__LHP_BOOT_UI_H__)
#define __LHP_BOOT_UI_H__

#include <libwebsockets.h>

/* in the order they are shown, matching contrib/assets/boot-status */

typedef enum {
	LHP_BOOT_SETUP,		/* wifi credentials are stored */
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
	const lws_surface_info_t	*ic;	/* the display */
	lws_netdev_instance_wifi_t	*wnd;	/* NULL, or wifi, for the APs */

	char				ipv4[16];
	char				ipv6[48];

	uint16_t			reached; /* 1 << lhp_boot_stage_t */
	uint8_t				ota;	 /* lhp_boot_ota_t */
} lhp_boot_t;

/*
 * Prepare b for the display described by ic, and register the overlay's css
 * and icons in the dlo filesystem, where the overlay html refers to them
 */
int
lhp_boot_init(struct lws_context *cx, lhp_boot_t *b,
	      const lws_surface_info_t *ic, lws_netdev_instance_wifi_t *wnd);

/* the overlay is finished with: unregister its css and icons */
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
 * Write the overlay html for the current state into buf, returns its length,
 * or -1 if it didn't fit
 */
int
lhp_boot_html(const lhp_boot_t *b, char *buf, size_t len);

#endif
