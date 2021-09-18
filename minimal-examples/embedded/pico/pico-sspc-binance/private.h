/*
 * pico-sspc-binance
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

/* boilerplate for using PICO_SDK */

#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/types.h"
#include "hardware/uart.h"
#include "hardware/irq.h"

/* boilerplate for LWS_ONLY_SSPC Secure Streams
 * LWS_SS_USE_SSPC should be defined by cmake
 */

#undef STANDALONE
#define STANDALONE
#include <libwebsockets.h>

#define RXBUF_SIZE 2048

extern lws_dll2_owner_t scheduler;
extern uint16_t rxh, rxt;
extern uint8_t rxbuf[RXBUF_SIZE];
extern int rx_overflowed;
extern unsigned int actual_baud;
extern lws_transport_mux_t *tm;

/* our transport related apis */

extern int pico_example_open_serial_port(uart_inst_t * const  port);
extern const lws_transport_client_ops_t lws_sss_ops_client_serial;
void serial_handle_events(lws_transport_mux_t *tm);

/* our SS bindings */

extern const lws_ss_info_t ssi_binance_t,  /* binance-ss.c */
			   ssi_get_t;	 /* get-ss.c */
