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
 * pressed.  The html is lws_wifi_settings_html(), the same the device serves
 * to a browser while it's an AP of its own to be given credentials, see
 * lws_wifi_provision_create(), and its links are understood the same way,
 * by lws_wifi_settings_href().  It has
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
 * The caller can give a note to show above them, eg, that the device is an
 * AP to be set up from a browser too.
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

/*
 * Credentials were stored for an AP.  As for the exit callback, it's called
 * from inside the ui's callbacks.
 */
typedef void (*lhp_settings_stored_cb_t)(void *opaque);

typedef struct lhp_settings {
	struct lws_context		*cx;
	struct lws_dlo_ui		*ui;
	lws_netdev_instance_wifi_t	*wnd;
	lhp_settings_exit_cb_t		exit_cb;
	lhp_settings_stored_cb_t	stored_cb;
	void				*opaque;

	/* the APs as they were when the dialog's html was last written */
	lws_wifi_ap_info_t		aps[LHP_SET_AP_MAX];
	int				ap_count;
	uint32_t			scan_sig;

	char				ssid[33]; /* the AP being edited */
	char				note[96]; /* shown above them, if any */

	uint8_t				shown;
	uint8_t				editing; /* lhp_settings_edit_t */
	uint8_t				flags;	/* LHP_SET_FL_* */
} lhp_settings_t;

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
 * \param stored_cb: NULL, or told when credentials were stored for an AP
 * \param opaque: passed to the callbacks
 *
 * Registers the icons the dialog uses in the dlo filesystem.  Returns 0, or
 * nonzero if it couldn't, after which lhp_settings_deinit() is still called.
 */
int
lhp_settings_init(lhp_settings_t *s, struct lws_context *cx,
		  lws_netdev_instance_wifi_t *wnd,
		  lhp_settings_exit_cb_t exit_cb,
		  lhp_settings_stored_cb_t stored_cb, void *opaque);

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

/*
 * A note to show above the settings, or NULL for none, eg, that the device
 * can be set up from a browser too.  If they're shown, they're shown again.
 */
void
lhp_settings_note(lhp_settings_t *s, const char *note);

/*
 * The icons the settings use, the LWS_WIFI_SETTINGS_ICON_ ones, eg, for the
 * settings served to a browser, see lws_wifi_provision_info_t .files
 */
const lws_wifi_provision_file_t *
lhp_settings_icons(size_t *count);

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
