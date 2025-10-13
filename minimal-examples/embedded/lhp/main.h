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
extern lws_netdev_instance_wifi_t *wnd;
extern struct lws_context *cx;

extern int
init_plat_devices(struct lws_context *);
extern int
display_completion_cb(lws_display_state_t *lds, int a);
extern void
show_demo_phase(int phase);
extern void
next_carousel(lws_sorted_usec_list_t *sul);
extern int
init_browse(struct lws_context *cx, lws_display_render_state_t *rs, const char *url);

