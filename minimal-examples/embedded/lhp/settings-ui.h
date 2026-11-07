/*
 * lhp settings pages
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The settings of the system the application runs on, shown as pages of the
 * strip ui (lws-dlo-ui.h):
 *
 *  - "Settings": the WLAN, and the hostname, which pressing changes
 *
 *  - "WLAN": the APs, the ones scanned strongest first, then any we have
 *    credentials for that aren't in range, dimmed.  Those we have credentials
 *    for are highlighted.  Pressing one we have none for asks for its
 *    passphrase, unless it's open; pressing one we have them for goes to
 *
 *  - the AP's page, titled with its SSID: "Change passphrase" or "Forget"
 *
 * A passphrase is typed in from empty, even if one is stored: what is stored
 * is never shown, not even its length.  The hostname starts as it is, to be
 * changed, see lws_netdev_hostname_set().  Pressing the title goes back a
 * page, and from "Settings", out of the settings.
 *
 * Nothing here is platform-specific: the caller gives us the strip ui and the
 * wifi netdev, and passes on the ui's callbacks while the settings are shown.
 */

#if !defined(__LHP_SETTINGS_UI_H__)
#define __LHP_SETTINGS_UI_H__

#include <libwebsockets.h>

typedef enum {
	LHP_SET_NONE,		/* the settings aren't shown */
	LHP_SET_TOP,		/* "Settings" */
	LHP_SET_WLAN,		/* the APs */
	LHP_SET_AP,		/* one AP we have credentials for */
} lhp_settings_page_t;

typedef enum {
	LHP_SET_EDIT_NONE,
	LHP_SET_EDIT_PASSPHRASE,	/* of the AP picked */
	LHP_SET_EDIT_HOSTNAME,
} lhp_settings_edit_t;

/* the most APs listed */
#define LHP_SET_AP_MAX			16

/*
 * The settings are finished with, eg, the title of "Settings" was pressed.
 * It's called from inside the ui's callbacks: it may show something else on
 * the ui, but not destroy it.
 */
typedef void (*lhp_settings_exit_cb_t)(void *opaque);

typedef struct lhp_settings_ap {
	char				ssid[33];
	uint8_t				open;	/* needs no passphrase */
	uint8_t				stored;	/* we have credentials for it */
	uint8_t				seen;	/* in the scan results */
} lhp_settings_ap_t;

typedef struct lhp_settings {
	struct lws_context		*cx;
	struct lws_dlo_ui		*ui;
	lws_netdev_instance_wifi_t	*wnd;
	lhp_settings_exit_cb_t		exit_cb;
	void				*opaque;

	/*
	 * A copy of the APs as they were when the list was last set, so a row
	 * pressed is the AP that was shown there
	 */
	lhp_settings_ap_t		aps[LHP_SET_AP_MAX];
	int				ap_count;
	uint32_t			scan_sig;

	char				ssid[33]; /* the AP picked */
	uint8_t				ssid_open; /* ...needs no passphrase */

	uint8_t				page;	/* lhp_settings_page_t */
	uint8_t				editing; /* lhp_settings_edit_t */
	uint8_t				flags;	/* LHP_SET_FL_* */
} lhp_settings_t;

/* lhp_settings_open() flags */

#define LHP_SET_FL_EXIT_ON_STORE	(1 << 0)
/**< once credentials are stored for an AP, the settings are finished with,
 * eg, they were opened because there were none */

/**
 * lhp_settings_init() - prepare the settings
 *
 * \param s: the settings
 * \param cx: the lws context
 * \param wnd: the wifi netdev, for its scan results, or NULL
 * \param exit_cb: told when the settings are finished with
 * \param opaque: passed to exit_cb
 */
void
lhp_settings_init(lhp_settings_t *s, struct lws_context *cx,
		  lws_netdev_instance_wifi_t *wnd,
		  lhp_settings_exit_cb_t exit_cb, void *opaque);

/**
 * lhp_settings_open() - show the settings
 *
 * \param s: the settings
 * \param ui: the strip ui to show them on
 * \param page: LHP_SET_TOP, or LHP_SET_WLAN to start at the APs
 * \param flags: LHP_SET_FL_*
 *
 * While they are shown, the caller passes the ui's row, pick, title and done
 * callbacks on to lhp_settings_row() and the others.
 */
void
lhp_settings_open(lhp_settings_t *s, struct lws_dlo_ui *ui,
		  lhp_settings_page_t page, unsigned int flags);

/*
 * Stop showing the settings, without the exit callback, eg, because something
 * else takes the display.  An edit in progress is the ui's to abandon.
 */
void
lhp_settings_close(lhp_settings_t *s);

/* are the settings being shown */
int
lhp_settings_shown(const lhp_settings_t *s);

/* the scan results changed: the APs are shown again if they are different */
void
lhp_settings_scan(lhp_settings_t *s);

/* the strip ui's callbacks, while the settings are shown */

int
lhp_settings_row(lhp_settings_t *s, int idx, lws_dlo_ui_row_t *row);
void
lhp_settings_pick(lhp_settings_t *s, int idx);
void
lhp_settings_title(lhp_settings_t *s);
int
lhp_settings_done(lhp_settings_t *s, const char *text);

#endif
