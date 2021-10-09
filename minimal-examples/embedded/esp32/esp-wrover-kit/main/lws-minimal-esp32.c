/*
 * lws-minimal-esp32
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Configured for ESP32 WROVER KIT
 *
 * What should be notable about this is there are no esp-idf apis used here or
 * any related files, despite we are running on top of stock esp-idf.
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
extern struct lws_button_state *bcs;
extern lws_netdev_instance_wifi_t *wnd;

lws_sorted_usec_list_t		sul_pass;

extern int init_plat_devices(struct lws_context *);

static const uint8_t logo[] = {
#include "cat-565.h"
};

#if defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
#include "static-policy.h"
#else
#include "policy.h"
#endif

static uint8_t flip;


typedef struct myss {
	struct lws_ss_handle 		*ss;
	void				*opaque_data;
	/* ... application specific state ... */

	size_t				amount;

} myss_t;

/*
 * When we're actually happy we passed, we schedule the actual pass
 * string to happen a few seconds later, so we can observe what the
 * code did after the pass.
 */

static void
completion_sul_cb(lws_sorted_usec_list_t *sul)
{
	/*
	 * In CI, we use sai-expect to look for this
	 * string for success
	 */

	lwsl_notice("Completed: PASS\n");
}

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
		 *
		 * Howevere we want to record what happened after we received
		 * the last bit so we can see anything unexpected coming.  So
		 * wait 5s before sending the PASS magic.
		 */

		lwsl_notice("%s: received %u bytes, passing in 10s\n",
			    __func__, (unsigned int)m->amount);

		lws_sul_schedule(context, 0, &sul_pass, completion_sul_cb,
				 5 * LWS_US_PER_SEC);

		return LWSSSSRET_DESTROY_ME;
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
		lws_ss_client_connect(m->ss);
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
		lws_led_transition(lls, "blue", seqs[flip & 3],
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

	lws_set_log_level(1024 | 15, NULL);

        lws_netdev_plat_init();
        lws_netdev_plat_wifi_init();

        info = malloc(sizeof(*info));
        if (!info)
        	goto spin;

	memset(info, 0, sizeof(*info));

	lwsl_notice("LWS test for Espressif ESP32 WROVER KIT\n");

#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
	info->pss_policies_json		= ss_policy;
#else
	info->pss_policies		= &_ss_static_policy_entry;
#endif
	info->options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
					  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info->port			= CONTEXT_PORT_NO_LISTEN;
	info->early_smd_cb		= smd_cb;
	info->early_smd_class_filter	= LWSSMDCL_INTERACTION |
					  LWSSMDCL_SYSTEM_STATE |
					  LWSSMDCL_NETWORK;
	info->smd_ttl_us		= 20 * LWS_USEC_PER_SEC; /* we can spend a long time in display */

	context = lws_create_context(info);
	if (!context) {
		lwsl_err("lws init failed\n");
		goto spin;
	}

	/*
	 * We don't need this after context creation... things it pointed to
	 * still need to exist though since the context copied the pointers.
	 */

	free(info);

	/* devices and init are in devices.c */

	if (init_plat_devices(context))
		goto spin;

	/* put the cat picture up there and enable the backlight */

	lds.disp->blit(lds.disp, logo, 0, 0, 320, 240);
	lws_display_state_active(&lds);

	/* the lws event loop */

	do {
		taskYIELD();
		lws_service(context, 0);
	} while (1);

	lwsl_notice("%s: exited event loop\n", __func__);


spin:
	vTaskDelay(10);
	taskYIELD();
	goto spin;
}
