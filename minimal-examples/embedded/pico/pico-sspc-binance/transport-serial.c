/*
 * pico-sspc-binance
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * The serial port based custom transport, and helpers used by lws_transport
 */

#include "private.h"

int uart_irq, irqc, need_pollout, rx_overflowed;
uint8_t rxbuf[RXBUF_SIZE], txbuf[RXBUF_SIZE];
uint16_t rxh, rxt, txh, txt;
unsigned int actual_baud;
uart_inst_t * uid;

static void
on_uart_rx(void)
{
	int budget = 64;
	irqc++;

	while (uart_is_readable(uid) && budget--) {
        	rxbuf[rxh] = uart_getc(uid);
		rxh = (rxh + 1) & (sizeof(rxbuf) - 1);
		if (rxt == rxh)
			rx_overflowed++;
	}
}

/*
 * Open and configure the serial transport
 *
 * This had to be somewhat handrolled to use IRQ rx via the UART FIFOs, we
 * get triggered by irq to dump the rx fifo when it starts getting full, but
 * if there are only a few bytes coming, we don't get an irq and have to also
 * drain the fifo from the foreground.
 */

int
pico_example_open_serial_port(uart_inst_t * const port)
{
	uid = port;

	uart_init(port, 2400);

	gpio_set_function(0, GPIO_FUNC_UART);
	gpio_set_function(1, GPIO_FUNC_UART);

	actual_baud = uart_set_baudrate(port, 2000000); // 921600);
	uart_set_hw_flow(port, false, false);
	uart_set_format(port, 8, 1, UART_PARITY_NONE);
	uart_set_fifo_enabled(port, true);

	uart_irq = port == uart0 ? UART0_IRQ : UART1_IRQ;

	irq_set_exclusive_handler(uart_irq, on_uart_rx);
	irq_set_enabled(uart_irq, true);
	uart_set_irq_enables(port, true, false);
}

/* incoming parsed channel cbs */

static int
ltm_ch_payload(lws_transport_mux_ch_t *tmc, const uint8_t *buf, size_t len)
{
	lwsl_notice("%s\n", __func__);
	return 0;
}

static int
ltm_ch_opens_serial(lws_transport_mux_ch_t *tmc, int determination)
{
	lws_transport_mux_t *tm = lws_container_of(tmc->list.owner,
						   lws_transport_mux_t, owner);
	struct lws_sspc_handle *h = (struct lws_sspc_handle *)tmc->priv;

	assert_is_tm(tm);

	lwsl_sspc_err(h, "%d", determination);

       	if (tm->info.txp_cpath.ops_in->event_connect_disposition(h, determination))
        		return -1;

	return 0;
}

static int
ltm_ch_closes(lws_transport_mux_ch_t *tmc)
{
	lwsl_notice("%s\n", __func__);
	return 0;
}

static void
ltm_txp_req_write(lws_transport_mux_t *tm)
{
	tm->info.txp_cpath.ops_onw->req_write(tm->info.txp_cpath.priv_onw);
}

static int
ltm_txp_can_write(lws_transport_mux_ch_t *tmc)
{
	assert_is_tmch(tmc);
	return lws_txp_inside_sspc.event_can_write(
			(struct lws_sspc_handle *)tmc->priv, 2048);
}

/*
 * So that we can use the same mux framing parser for both sides, we pass into
 * the parser an "ops struct" that gets called back to customize response to
 * mux parser framing.
 */

static const lws_txp_mux_parse_cbs_t cbs = {
	.payload		= ltm_ch_payload,
	.ch_opens		= ltm_ch_opens_serial,
	.ch_closes		= ltm_ch_closes,
	.txp_req_write		= ltm_txp_req_write,
	.txp_can_write		= ltm_txp_can_write,
};

void
serial_handle_events(lws_transport_mux_t *tm)
{
	int tbudget = 32, rbudget = 1024, pbudget = 32;
	uint8_t chonk[256];
	size_t cl = 0;

	/*
	 * UART rx fifo doesn't interrupt until it's full, so drain anything we
	 * see lying around in there from the foreground loop as well as the
	 * fifo full interrupt
	 */

	irq_set_enabled(uart_irq, false);
	while (uart_is_readable(uid) && pbudget--) {
        	rxbuf[rxh] = uart_getc(uid);
		rxh = (rxh + 1) & (sizeof(rxbuf) - 1);
		if (rxt == rxh)
			rx_overflowed++;
	}
	irq_set_enabled(uart_irq, true);

	/* for POLLIN
	 *
	 * rxt (rx tail) and rxh (head) are offsets in a ringbuffer, the rx
	 * is harvested in one or two chunks depending on if it has wrapped in
	 * the ringbuffer yet or not.
	 */

	if (rxt > rxh) {
		cl = sizeof(rxbuf) - rxt;
		if (cl > rbudget)
			cl = rbudget;
		//lwsl_hexdump_level(LLL_NOTICE, rxbuf + rxt, cl);
		if (tm->info.txp_cpath.ops_in->event_read(
				tm->info.txp_cpath.priv_in, rxbuf + rxt, cl)) {
			/*
			 * The SSS parser can identify the framing is broken,
			 * in that case the transport needs to re-link up
			 */
			tm->info.txp_cpath.ops_in->lost_coherence(
					tm->info.txp_cpath.priv_in);
			rxt = rxh;
			txt = txh;
			return;
		}
		rbudget -= cl;
		rxt = (rxt + cl) & (sizeof(rxbuf) - 1);
	}

	if (rbudget && rxt < rxh) {
		cl = rxh - rxt;
		if (cl > rbudget)
			cl = rbudget;
		//lwsl_hexdump_level(LLL_NOTICE, rxbuf + rxt, cl);
		if (tm->info.txp_cpath.priv_in) {
			/* may have been zapped by lost_coherence already */
			if (tm->info.txp_cpath.ops_in->event_read(
				tm->info.txp_cpath.priv_in, rxbuf + rxt, cl)) {
				/*
				 * The SSS parser can identify the framing is broken,
				 * in that case the transport needs to re-link up
				 */
				tm->info.txp_cpath.ops_in->lost_coherence(
						tm->info.txp_cpath.priv_in);
				rxt = rxh;
				txt = txh;
				return;
			}
		}
		rxt = (rxt + cl) & (sizeof(rxbuf) - 1);
	}

	/* for serial write drain */

	while (txh != txt && uart_is_writable(uid) && tbudget--) {
		uart_putc(uid, txbuf[txt]);
		txt = (txt + 1) & (sizeof(txbuf) - 1);
	}

	/* for "POLLOUT" */

	if (need_pollout && txh == txt) {
		need_pollout = 0;
		cl = sizeof(chonk);

		if (lws_transport_mux_pending(tm, chonk, &cl, &cbs)) {
#if defined(_DEBUG)
			lws_transport_path_client_dump(&tm->info.txp_cpath, "cpath");
#endif
			tm->info.txp_cpath.ops_onw->_write(
				tm->info.txp_cpath.priv_onw, chonk, cl);

			return;
		}
	}
}

/*
 * We get called while an individual SS is trying to connect to the proxy to
 * be recognized as operational.  It's the equivalent of trying to bring up the
 * Unix Domain socket
 */

static int
txp_serial_retry_connect(lws_txp_path_client_t *path,
				       struct lws_sspc_handle *h)
{
	lwsl_user("%s\n", __func__);

	if (!path)
		return 0;

	if (path->ops_onw->event_connect_disposition(h,
				path->mux->link_state != LWSTM_OPERATIONAL))
	        return -1;

	return 0;
}

static void
txp_serial_req_write(lws_transport_priv_t priv)
{
	need_pollout = 1;
}

static int
txp_serial_write(lws_transport_priv_t priv, uint8_t *buf, size_t len)
{
	lwsl_notice("%s: writing %u\n", __func__, (unsigned int)len);

	lwsl_hexdump_level(LLL_WARN, buf, len);

	while (len--) {
		txbuf[txh] = *buf++;
		txh = (txh + 1) & (sizeof(txbuf) - 1);
	}

	return 0;
}

static void
txp_serial_close(lws_transport_priv_t priv)
{
#if 0
	struct lws *wsi = (struct lws *)priv;

	if (!wsi)
		return;

	lws_set_opaque_user_data(wsi, NULL);
	lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
	*priv = NULL;
#endif
}

static void
txp_serial_stream_up(lws_transport_priv_t priv)
{
//	struct lws *wsi = (struct lws *)priv;

//	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
}

/*
 * This is the lws_transport export for our custom serial transport
 */

const lws_transport_client_ops_t lws_sss_ops_client_serial = {
	.name			= "txpserial",
	.event_retry_connect	= txp_serial_retry_connect,
	.req_write		= txp_serial_req_write,
	._write			= txp_serial_write,
	._close			= txp_serial_close,
	.event_stream_up	= txp_serial_stream_up,
	.flags			= LWS_DSHFLAG_ENABLE_COALESCE,
	.dsh_splitat		= 0,
};
