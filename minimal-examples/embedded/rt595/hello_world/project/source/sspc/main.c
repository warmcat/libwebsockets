/*
 * rt595-sspc-binance
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_class.h"
#include "usb_device_cdc_acm.h"
#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"
#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "composite.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"

#include "private.h"

void USB_DeviceApplicationInit(void);

extern const lws_ss_info_t ssi_binance_t,  /* binance-ss.c */
			   ssi_get_t;	 /* get-ss.c */
extern const lws_transport_client_ops_t lws_sss_ops_client_serial;

static struct lws_context_standalone cx = {
	.txp_cpath.ops_onw		= &lws_transport_mux_client_ops,
};

lws_transport_mux_t *tm;

/*
 * Describes how the lws_transport path goes through the transport_mux
 */

lws_transport_info_t info_serial = {
	.ping_interval_us		= LWS_US_PER_SEC * 10,
	.pong_grace_us			= LWS_US_PER_SEC * 2,
	.flags				= 0,
}, info_mux = {
	.ping_interval_us		= LWS_US_PER_SEC * 10,
	.pong_grace_us			= LWS_US_PER_SEC * 2,
	.txp_cpath = {
		.ops_onw		= &lws_sss_ops_client_serial,
		/**< onward transport for mux is serial */
		.ops_in			= &lws_transport_mux_client_ops,
	},
	.onward_txp_info		= &info_serial,
	.flags				= 0,
};

extern usb_cdc_acm_info_t s_usbCdcAcmInfo[USB_DEVICE_CONFIG_CDC_ACM];

#if defined(__CC_ARM) || (defined(__ARMCC_VERSION)) || defined(__GNUC__)
int main(void)
#else
void main(void)
#endif
{
	unsigned int f = 0, din = 0;

    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    *((volatile uint32_t*)0xE0001000) = 0x40000001;

    USB_DeviceApplicationInit();

	/* create the ss transport mux object itself... only one of these */

	tm = lws_transport_mux_create(&cx, &info_mux, NULL);
	if (!tm) {
		lwsl_err("%s: unable to create client mux\n", __func__);
		return 1;
	}
	tm->info.txp_cpath.priv_in = tm;
	cx.txp_cpath.mux = tm;


    while (1) {

    	/*
    	 * When the host link ttyACM is hooked up, create the SS.  They could be
    	 * created before the link, but delaying it like this means we will be
    	 * able to hook up the log ttyACM and see the related logs for this.
    	 */

    	if (!din && (s_usbCdcAcmInfo[1].uartState & USB_DEVICE_CDC_UART_STATE_RX_CARRIER)) {
    		din = 1;

    		if (lws_ss_create(&cx, 0, &ssi_binance_t, NULL, NULL, NULL, NULL)) {
    			lwsl_err("failed to create binance secure stream\n");
    			f = 1;
    		}

    		if (lws_ss_create(&cx, 0, &ssi_get_t, NULL, NULL, NULL, NULL)) {
    			lwsl_err("failed to create get secure stream\n");
    			f = 2;
    		}
    	}

        USB_DeviceCdcVcomTask();
        lws_now_usecs();
        serial_handle_events(tm);

		/* check the scheduler */

		while (scheduler.head) {
			lws_sorted_usec_list_t *sul = lws_container_of(
					scheduler.head, lws_sorted_usec_list_t, list);

			if (sul->us > lws_now_usecs())
				break;
			lws_dll2_remove(&sul->list);

			sul->cb(sul);
		}
    }
}
