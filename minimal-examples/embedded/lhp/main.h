#define LWIP_PROVIDE_ERRNO 1
#define _ESP_PLATFORM_ERRNO_H_

#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <esp_task_wdt.h>
#include <driver/gpio.h>

#include <libwebsockets.h>

enum {
	LWS_LHPCD_PHASE_IDLE,
	LWS_LHPCD_PHASE_FETCHING,
	LWS_LHPCD_PHASE_RENDERING,
};

extern struct lws_led_state *lls;
extern lws_display_state_t lds;
extern struct lws_button_state *bcs;
extern struct lws_touch_state *tcs; /* set by boards with a touch panel */
extern lws_netdev_instance_wifi_t *wnd;
extern struct lws_context *cx;
/* the strip ui, if it exists: the boot overlay, settings, and the frame */
extern struct lws_dlo_ui *sui;

/*
 * A board with a battery sets this in init_plat_devices(), to say how charged
 * it is, 0 to 100 percent, and if it's being charged.  It returns 0 if it set
 * them.  It's NULL on boards without one, and the status capsule doesn't show
 * a battery.
 */
typedef int (*lhp_battery_cb_t)(int *percent, int *charging);
extern lhp_battery_cb_t plat_battery;

/*
 * A board sets these in init_plat_devices() to the name of a led in its led
 * controller, flashed while the device is an AP waiting to be given wifi
 * credentials, and of a button in its button controller, which held soon
 * after starting forgets the wifi credentials, see lws_wifi_provision_create().
 * They're NULL on boards without them.
 */
extern const char *plat_status_led, *plat_reset_button;

extern int
init_plat_devices(struct lws_context *);
extern void
deinit_plat_devices(struct lws_context *);
extern int
display_completion_cb(lws_display_state_t *lds, int a);
/*
 * The board shows the demo's phase on its led, see show_demo_phase() in its
 * devices.c; lhp_demo_phase() is how the rest of the example asks for it, so
 * the led is left alone while it's flashing for being an AP to be set up
 */
extern void
show_demo_phase(int phase);
extern void
lhp_demo_phase(int phase);
extern void
next_carousel(lws_sorted_usec_list_t *sul);
/*
 * frame: lay the page out below the strip ui's title strip, see sui.  ids:
 * NULL, or a NULL-terminated list of the ids of elements that are changed in
 * place once it's laid out, see redraw_damage()
 */
extern int
init_browse(struct lws_context *cx, lws_display_render_state_t *rs,
	    const char *url, int frame, const char * const *ids);
extern int
redraw_page(lws_display_render_state_t *rs);
extern int
redraw_damage(lws_display_render_state_t *rs);

