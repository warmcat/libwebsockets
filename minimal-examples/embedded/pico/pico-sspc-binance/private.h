/* */
#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/types.h"
#include "hardware/uart.h"
#include "hardware/irq.h"

/* boilerplate for liblws-sspc Secure Streams */
#define LWS_SS_USE_SSPC
#undef STANDALONE
#define STANDALONE
#include <libwebsockets.h>

#define RXBUF_SIZE 32768

extern lws_dll2_owner_t scheduler;
extern uint16_t rxh, rxt;
extern uint8_t rxbuf[RXBUF_SIZE];
extern int rx_overflowed;
extern unsigned int actual_baud;
extern lws_transport_mux_t *tm;

extern int open_serial_port(uart_inst_t * const  port);
extern const lws_ss_info_t ssi_binance;
extern const lws_transport_client_ops_t lws_sss_ops_client_serial;
void
serial_handle_events(lws_transport_mux_t *tm);

