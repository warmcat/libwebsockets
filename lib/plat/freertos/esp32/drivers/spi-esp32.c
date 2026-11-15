/*
 * esp32 / esp-idf SPI
 *
 * Copyright (C) 2019 - 2022 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <libwebsockets.h>

#include <driver/spi_master.h>
#include <esp_heap_caps.h>

typedef struct {
	uint32_t		*dma_stash;
	size_t			dma_stash_len;
	spi_transaction_t	esp_txn;
} lws_spi_async_txn_t;

/* the most the bus is set up to send in one transaction with DMA */
#define LWS_ESP32_SPI_MAX_XFER	4092

static spi_device_handle_t sdh[4][4]; /* [unit][cs index] */
static volatile lws_spi_async_txn_t sat[7];

void *
lws_esp32_spi_alloc_dma(const struct lws_spi_ops *ctx, size_t size)
{
	 return heap_caps_malloc(size, MALLOC_CAP_32BIT | MALLOC_CAP_DMA);
}

void
lws_esp32_spi_free_dma(const struct lws_spi_ops *ctx, void **p)
{
	if (*p) {
		heap_caps_free(*p);
		*p = NULL;
	}
}

static void IRAM_ATTR
lcd_spi_pre_transfer_callback(spi_transaction_t *t)
{
	int n = (int)(intptr_t)((volatile spi_transaction_t *)t)->user;

	gpio_set_level((n >> 8) & 0xff, n & 1);
}

static void IRAM_ATTR
lcd_spi_post_transfer_callback(spi_transaction_t *t)
{
	((volatile spi_transaction_t *)t)->user = NULL;
}

static lws_spi_async_txn_t *
find_idle_sat(void)
{
	size_t n = 0;

	for (n = 0; n < LWS_ARRAY_SIZE(sat); n++)
		if (!sat[n].esp_txn.user) {
			memset((void *)&sat[n].esp_txn, 0, sizeof(sat[0].esp_txn));
			return (lws_spi_async_txn_t *)&sat[n];
		}

	return NULL;
}

int
lws_esp32_spi_in_flight(const struct lws_spi_ops *ctx)
{
	size_t n = 0;
	int inf = 0;

	for (n = 0; n < LWS_ARRAY_SIZE(sat); n++)
		if (sat[n].esp_txn.user)
			inf++;

	return inf;
}

/*
 * Point the transaction at the data to send: directly if the caller says it
 * is somewhere the DMA can read, otherwise copied into a DMA-capable bounce
 * buffer the txn slot keeps, eg, for data in flash
 */

static int
stage_data(lws_spi_async_txn_t *at, const uint8_t *d, size_t len, uint8_t flags)
{
	uint32_t u = 0;
	size_t i;

	if (flags & LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED) {
		at->esp_txn.tx_buffer = d;

		return 0;
	}

	if (at->dma_stash && at->dma_stash_len != len) {
		/* we lazily free these to avoid heap apis in IRQ ctx */
		lws_esp32_spi_free_dma(NULL, (void **)&at->dma_stash);
		at->dma_stash_len = 0;
	}

	if (!at->dma_stash) {
		/* it's filled a whole u32 at a time */
		at->dma_stash = lws_esp32_spi_alloc_dma(NULL, (len + 3) & ~3u);
		if (!at->dma_stash) {
			lwsl_err("%s: OOM getting DMA bounce\n", __func__);
			return 1;
		}
		at->dma_stash_len = len;
	}

	for (i = 0; i < len; i++) {
		((uint8_t *)&u)[i & 3] = *d++;
		at->dma_stash[i >> 2] = u;
	}

	at->esp_txn.tx_buffer = at->dma_stash;

	return 0;
}

/*
 * A quad bus has no D/C line: each desc is one transaction, under one nCS, of
 * an 8-bit opcode and a 24-bit address on one line, then the data, on four
 * lines if the desc says so.  The data can't be split into more than one
 * transaction, since the device would see nCS go up in the middle of it.
 */

static int
lws_esp32_spi_queue_quad(spi_device_handle_t h, const lws_spi_desc_t *desc)
{
	lws_spi_async_txn_t *at = NULL;
	esp_err_t e;

	if (desc->count_cmd != 4 || desc->count_read ||
	    desc->count_write > LWS_ESP32_SPI_MAX_XFER) {
		lwsl_err("%s: unusable desc: cmd %u, write %u, read %u\n",
			 __func__, desc->count_cmd, desc->count_write,
			 desc->count_read);
		return 1;
	}

	while (!at)
		at = find_idle_sat();

	at->esp_txn.cmd = desc->src[0];
	at->esp_txn.addr = (uint64_t)((desc->src[1] << 16) |
				      (desc->src[2] << 8) | desc->src[3]);
	at->esp_txn.flags = desc->flags & LWS_SPI_FLAG_DATA_QUAD ?
						SPI_TRANS_MODE_QIO : 0;
	at->esp_txn.length = (size_t)desc->count_write * 8;
	at->esp_txn.rx_buffer = NULL;
	at->esp_txn.rxlength = 0;
	at->esp_txn.tx_buffer = NULL;

	if (desc->count_write &&
	    stage_data(at, desc->data, desc->count_write, desc->flags))
		return -1;

	/* nonzero marks the slot as in flight until the post callback */
	at->esp_txn.user = (void *)1;

	e = spi_device_queue_trans(h, &at->esp_txn, 50);
	if (e != ESP_OK) {
		at->esp_txn.user = NULL;
		lwsl_err("%s: failed to queue trans: 0x%x\n", __func__, e);
		return 1;
	}

	return 0;
}

int
lws_esp32_spi_init(const lws_spi_ops_t *spi_ops)
{
	lws_bb_spi_t *bb = lws_container_of(spi_ops, lws_bb_spi_t, bb_ops);
	spi_bus_config_t bc;

	/* This inits the specified SPI BUS */

	memset(&bc, 0, sizeof(bc));

	/*
	 * data0..3 are the same members as mosi, miso, quadwp and quadhd.
	 * The display buses are write-only, miso is only used as the second
	 * data line of a quad bus
	 */

	bc.sclk_io_num = bb->clk;
	bc.data0_io_num = bb->mosi;
	bc.data1_io_num = bb->quad ? bb->miso : -1;
	bc.data2_io_num = bb->quad ? bb->d2 : -1;
	bc.data3_io_num = bb->quad ? bb->d3 : -1;
	bc.data4_io_num = -1;
	bc.data5_io_num = -1;
	bc.data6_io_num = -1;
	bc.data7_io_num = -1;
	bc.max_transfer_sz = LWS_ESP32_SPI_MAX_XFER;
	bc.flags = SPICOMMON_BUSFLAG_MASTER;
	if (bb->quad)
		bc.flags |= SPICOMMON_BUSFLAG_QUAD;

	if (spi_bus_initialize(bb->unit, &bc, SPI_DMA_CH_AUTO) != ESP_OK) {
		lwsl_err("%s: SPI init failed\n", __func__);
		return 1;
	}

	memset((void *)&sat, 0, sizeof(sat));

	return 0;
}

int
lws_esp32_spi_queue(const lws_spi_ops_t *spi_ops, const lws_spi_desc_t *desc)
{
	lws_bb_spi_t *bb = lws_container_of(spi_ops, lws_bb_spi_t, bb_ops);
	spi_device_handle_t h = sdh[bb->unit][desc->channel];
	uint8_t *d = (uint8_t *)desc->data;
	size_t cw = desc->count_write;
//	spi_transaction_t *ett;
	esp_err_t e;

	if (!h) {
		spi_device_interface_config_t edic;

		/* We need to create the device at these coordinates */

		memset(&edic, 0, sizeof(edic));

		edic.mode = spi_ops->bus_mode;
		edic.clock_speed_hz = spi_ops->spi_clk_hz ?
					spi_ops->spi_clk_hz : 16000000;
		edic.input_delay_ns = 50;
		edic.spics_io_num = bb->ncs[desc->channel];
		edic.queue_size = 7;
		edic.post_cb = lcd_spi_post_transfer_callback;

		if (bb->quad) {
			/* multi-line data needs half duplex */
			edic.command_bits = 8;
			edic.address_bits = 24;
			edic.flags = SPI_DEVICE_HALFDUPLEX;
		} else {
			edic.pre_cb = lcd_spi_pre_transfer_callback;
			edic.flags = SPI_DEVICE_NO_DUMMY;

			/* we do these manually in callbacks */

			bb->gpio->mode(bb->ncmd[desc->channel],
				       LWSGGPIO_FL_WRITE);
			bb->gpio->mode(bb->ncs[desc->channel],
				       LWSGGPIO_FL_WRITE);
		}

		e = spi_bus_add_device(bb->unit, &edic, &h);
		if (e != ESP_OK) {
			lwsl_err("%s: failed to add device: 0x%x\n", __func__, e);
			return 1;
		}
		sdh[bb->unit][desc->channel] = h;
	}

	if (bb->quad)
		return lws_esp32_spi_queue_quad(h, desc);

	if (desc->count_cmd) {
		lws_spi_async_txn_t *at = NULL;

		while (!at)
			at = find_idle_sat();

		if (at->dma_stash && at->dma_stash_len != 4) {
			/* we lazily free these to avoid heap apis in IRQ ctx */
			lws_esp32_spi_free_dma(NULL, (void **)&at->dma_stash);
			at->dma_stash_len = 0;
		}

		if (at->dma_stash_len != 4) {

			at->dma_stash = lws_esp32_spi_alloc_dma(NULL, 4);
			if (!at->dma_stash) {
				lwsl_err("%s: OOM getting DMA bounce\n", __func__);
				return -1;
			}

			at->dma_stash_len = 4;
		}

		at->esp_txn.tx_buffer = at->dma_stash;

		{
			uint32_t u = 0;
			size_t i;

			for (i = 0; i < desc->count_cmd; i++) {
				((uint8_t *)&u)[i & 3] = desc->src[i];
				((uint32_t *)at->esp_txn.tx_buffer)[i >> 2] = u;
			}
		}

		at->esp_txn.flags = 0;
		at->esp_txn.length = desc->count_cmd * 8;
		at->esp_txn.rx_buffer = NULL;
		at->esp_txn.rxlength = 0;
		at->esp_txn.user = (void *)((bb->ncs[desc->channel] << 16) |
				    (bb->ncmd[desc->channel] << 8) |
				    !!(desc->flags & LWS_SPI_FLAG_DC_CMD_IS_HIGH));

		e = spi_device_queue_trans(h, &at->esp_txn, 50);
		if (e != ESP_OK) {
			lwsl_err("%s: failed to queue cmd trans: 0x%x\n",
							__func__, e);
			return 1;
		}
#if 0
		ett = &at->esp_txn;
	       e = spi_device_get_trans_result(h, &ett, 50);
	       if (e != ESP_OK) {
		       lwsl_err("%s: failed to get trans result\n", __func__);
		       return 1;
	       }
#endif
	}

	while (cw) {
		size_t chunk = cw < 4000 ? cw : 4000;
		lws_spi_async_txn_t *at = NULL;

		while (!at)
			at = find_idle_sat();

		if (stage_data(at, d, chunk, desc->flags))
			return -1;
		d += chunk;

		at->esp_txn.rx_buffer = NULL;
		at->esp_txn.rxlength = 0;
		at->esp_txn.length = chunk * 8;
		at->esp_txn.user = (void *)((bb->ncs[desc->channel] << 16) |
					    (bb->ncmd[desc->channel] << 8) |
					    !(desc->flags & LWS_SPI_FLAG_DC_CMD_IS_HIGH));
		at->esp_txn.flags = 0;

		e = spi_device_queue_trans(h, &at->esp_txn, 50);
		if (e != ESP_OK) {
			lwsl_err("%s: failed to queue data trans\n", __func__);
			assert(0);
			return 1;
		}

#if 0
		ett = &at->esp_txn;
               e = spi_device_get_trans_result(h, &ett, 50);
               if (e != ESP_OK) {
                       lwsl_err("%s: failed to get trans result\n", __func__);
                       return 1;
               }
#endif
		cw -= chunk;
	}

	return 0;
}
