/*
 * lws-minimal-esp32
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Based on espressif Public Domain sample
 */

#define LWIP_PROVIDE_ERRNO 1
#define _ESP_PLATFORM_ERRNO_H_

#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <driver/gpio.h>

#include <libwebsockets.h>

struct lws_context *context;
extern struct lws_led_state *lls;
extern lws_display_state_t lds;
extern lws_netdev_instance_wifi_t *wnd;

extern int init_plat_devices(struct lws_context *);

#include "policy.h"

static uint8_t flip;

typedef struct myss {
	struct lws_ss_handle 		*ss;
	void				*opaque_data;
	/* ... application specific state ... */

	size_t				amount;

} myss_t;

static int
myss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	myss_t *m = (myss_t *)userobj;

	lwsl_user("%s: len %d, flags: %d\n", __func__, (int)len, flags);
//	lwsl_hexdump_info(buf, len);
	m->amount += len;

	if (flags & LWSSS_FLAG_EOM) {

		/*
		 * If we received the whole message, for our example it means
		 * we are done.
		 */

		lwsl_notice("%s: received %u bytes\n", __func__,
			    (unsigned int)m->amount);

		/*
		 * In CI, we use sai-expect to look for this
		 * string for success
		 */

		lwsl_notice("Completed: PASS\n");
	}

	return 0;
}

static int
myss_state(void *userobj, void *sh, lws_ss_constate_t state,
	   lws_ss_tx_ordinal_t ack)
{
	myss_t *m = (myss_t *)userobj;

	lwsl_user("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name(state),
		  (unsigned int)ack);

	switch (state) {
	case LWSSSCS_CREATING:
		if (lws_ss_client_connect(m->ss))
			lwsl_err("%s: connection failed\n", __func__);
		break;
	default:
		break;
	}

	return 0;
}

static const lws_ss_info_t ssi = {
	.handle_offset			= offsetof(myss_t, ss),
	.opaque_user_data_offset	= offsetof(myss_t, opaque_data),
	.rx				= myss_rx,
	.state				= myss_state,
	.user_alloc			= sizeof(myss_t),
	.streamtype			= "test_stream",
};

static const lws_led_sequence_def_t *seqs[] = {
	&lws_pwmseq_static_on,
	&lws_pwmseq_static_off,
	&lws_pwmseq_sine_endless_slow,
	&lws_pwmseq_sine_endless_fast,
};

static int
smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp, void *buf,
       size_t len)
{

	if (!lws_json_simple_strcmp(buf, len, "\"src\":", "bc/user") &&
	    !lws_json_simple_strcmp(buf, len, "\"event\":", "click")) {
		lws_led_transition(lls, "alert", seqs[flip & 3],
				   &lws_pwmseq_linear_wipe);
		flip++;
	}

	lwsl_hexdump_notice(buf, len);

	if ((_class & LWSSMDCL_SYSTEM_STATE) &&
	    !lws_json_simple_strcmp(buf, len, "\"state\":", "OPERATIONAL")) {

		/* create the secure stream */

		lwsl_notice("%s: creating test secure stream\n", __func__);

		if (lws_ss_create(context, 0, &ssi, NULL, NULL, NULL, NULL)) {
			lwsl_err("%s: failed to create secure stream\n",
				 __func__);
			return -1;
		}
	}

	if (_class & LWSSMDCL_INTERACTION)
		/*
		 * Any kind of user interaction brings the display back up and
		 * resets the dimming / blanking timers
		 */
		lws_display_state_active(&lds);

	return 0;
}

void 
app_main(void)
{
	struct lws_context_creation_info *info;

	lws_set_log_level(1024 | 7, NULL);

        lws_netdev_plat_init();
        lws_netdev_plat_wifi_init();

        info = malloc(sizeof(*info));
        if (!info)
        	goto spin;

	memset(info, 0, sizeof(*info));

	lwsl_notice("LWS test for ESP32-C3 Dev Board\n");

	info->pss_policies_json		= ss_policy;
	info->options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
					  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info->port			= CONTEXT_PORT_NO_LISTEN;
	info->early_smd_cb		= smd_cb;
	info->early_smd_class_filter	= LWSSMDCL_INTERACTION |
					  LWSSMDCL_SYSTEM_STATE |
					  LWSSMDCL_NETWORK;

	context = lws_create_context(info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return;
	}

	/*
	 * We don't need this after context creation... things it pointed to
	 * still need to exist though since the context copied the pointers.
	 */

	free(info);

	/* devices and init are in devices.c */

	if (init_plat_devices(context))
		goto spin;


	/* the lws event loop */

	do {
		taskYIELD();
	} while (lws_service(context, 0) >= 0);


spin:
	vTaskDelay(10);
	taskYIELD();
	goto spin;
}
