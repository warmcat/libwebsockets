/*
 * lhp settings dialog
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The settings of the system the application runs on, shown as a dialog of
 * the strip ui (lws-dlo-ui.h), titled "Settings".  It's an example of a
 * dialog of the application's own: html, and what to do when its links are
 * pressed.  It has
 *
 *  - "WLAN": a table of the APs, kept up to date while it's shown: the ones
 *    scanned, strongest first, then any we have credentials for that aren't
 *    in range, dimmed.  Each row is its SSID, over a line of what we know
 *    about it, then the icons to press:
 *
 *     - a key, if we have its passphrase
 *     - how it authenticates, eg, "WPA2", if it's in range
 *     - how the last try to join it went: a check, a cross if its
 *       passphrase was refused, or a warning if it failed some other way
 *     - a globe, if the internet was ever reached through it
 *     - a cog, to type its passphrase (or for an open AP, to add it)
 *     - a bin, to forget it, if we have credentials for it
 *
 *  - "Hostname": the hostname, shaded like an editbox, which pressing edits
 *
 * A passphrase is typed in from empty, even if one is stored: what is stored
 * is never shown, not even its length.  It's only stored when Done is pressed
 * on it.  The hostname starts as it is, to be changed, and is stored however
 * its edit is left, if it's valid, see lws_netdev_hostname_set().
 *
 * Pressing the title closes the settings, as does the caller, eg, when the
 * status capsule is pressed again.
 *
 * Nothing here is platform-specific: the caller gives us the strip ui and the
 * wifi netdev, and passes on the ui's title and done callbacks while the
 * settings are shown.
 */

#if !defined(__LHP_SETTINGS_UI_H__)
#define __LHP_SETTINGS_UI_H__

#include <libwebsockets.h>

typedef enum {
	LHP_SET_EDIT_NONE,
	LHP_SET_EDIT_PASSPHRASE,	/* of the AP picked */
	LHP_SET_EDIT_HOSTNAME,
} lhp_settings_edit_t;

/*
 * The most APs listed.  Each has up to two links, and the hostname one more:
 * 2 * LHP_SET_AP_MAX + 1 must be no more than the 32 links the ui finds on a
 * dialog
 */
#define LHP_SET_AP_MAX			12

/*
 * The settings were closed by the user, eg, the title was pressed.  It's
 * called from inside the ui's callbacks: it may show something else on the
 * ui, but not destroy it.
 */
typedef void (*lhp_settings_exit_cb_t)(void *opaque);

typedef struct lhp_settings_ap {
	char				ssid[33];
	uint8_t				auth;	/* lws_wifi_auth_t, if seen */
	uint8_t				last_join; /* lws_wifi_join_t */
	uint8_t				open;	/* needs no passphrase */
	uint8_t				stored;	/* we have credentials for it */
	uint8_t				seen;	/* in the scan results */
	uint8_t				internet; /* was reached through it */
	uint8_t				bars;	/* signal, 0 if not seen, else
						 * lhp_rssi_bars() */
} lhp_settings_ap_t;

typedef struct lhp_settings {
	struct lws_context		*cx;
	struct lws_dlo_ui		*ui;
	lws_netdev_instance_wifi_t	*wnd;
	lhp_settings_exit_cb_t		exit_cb;
	void				*opaque;

	/*
	 * The APs as they were when the dialog's html was last written: the
	 * links on it say which by their index here
	 */
	lhp_settings_ap_t		aps[LHP_SET_AP_MAX];
	int				ap_count;
	uint32_t			scan_sig;

	char				ssid[33]; /* the AP being edited */

	uint8_t				shown;
	uint8_t				editing; /* lhp_settings_edit_t */
	uint8_t				flags;	/* LHP_SET_FL_* */
} lhp_settings_t;

/**
 * lhp_rssi_bars() - how many of four signal bars an rssi is
 *
 * \param rssi: the signal strength in dBm
 *
 * Returns 1 to 4: strong enough for anything at -55dBm, barely usable below
 * -75dBm.  The status capsule's wlan icon and the settings' list of APs both
 * show it, so they agree.
 */
int
lhp_rssi_bars(int rssi);

/* lhp_settings_open() flags */

#define LHP_SET_FL_EXIT_ON_STORE	(1 << 0)
/**< once credentials are stored for an AP, the settings are closed, eg,
 * they were opened because there were none */

/**
 * lhp_settings_init() - prepare the settings
 *
 * \param s: the settings
 * \param cx: the lws context
 * \param wnd: the wifi netdev, for its scan results, or NULL
 * \param exit_cb: told when the user closes the settings
 * \param opaque: passed to exit_cb
 *
 * Registers the icons the dialog uses in the dlo filesystem.  Returns 0, or
 * nonzero if it couldn't, after which lhp_settings_deinit() is still called.
 */
int
lhp_settings_init(lhp_settings_t *s, struct lws_context *cx,
		  lws_netdev_instance_wifi_t *wnd,
		  lhp_settings_exit_cb_t exit_cb, void *opaque);

/* the settings are finished with: closes them, and unregisters the icons */
void
lhp_settings_deinit(lhp_settings_t *s);

/**
 * lhp_settings_open() - show the settings
 *
 * \param s: the settings
 * \param ui: the strip ui to show them on
 * \param flags: LHP_SET_FL_*
 *
 * While they are shown, the caller passes the ui's title and done callbacks
 * on to lhp_settings_title() and lhp_settings_done().
 */
void
lhp_settings_open(lhp_settings_t *s, struct lws_dlo_ui *ui,
		  unsigned int flags);

/*
 * Stop showing the settings, without the exit callback, eg, because something
 * else takes the display.  An edit in progress ends as if its title had been
 * pressed, so the hostname being edited is kept, and the ui is left showing
 * the dialog, for the caller to show something else.
 */
void
lhp_settings_close(lhp_settings_t *s);

/*
 * Close the settings as the user would, eg, the status capsule was pressed
 * again: as lhp_settings_close(), then the exit callback is called.
 */
void
lhp_settings_exit(lhp_settings_t *s);

/* are the settings being shown */
int
lhp_settings_shown(const lhp_settings_t *s);

/* the scan results changed: the APs are shown again if they are different */
void
lhp_settings_scan(lhp_settings_t *s);

/*
 * Something the APs' rows show may have changed, eg, an AP was joined, or the
 * internet was reached: they're shown again
 */
void
lhp_settings_changed(lhp_settings_t *s);

/* the strip ui's callbacks, while the settings are shown */

void
lhp_settings_title(lhp_settings_t *s);
int
lhp_settings_done(lhp_settings_t *s, const char *text);

#endif
