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

int
lws_esp32_spi_init(const lws_spi_ops_t *spi_ops)
{
	lws_bb_spi_t *bb = lws_container_of(spi_ops, lws_bb_spi_t, bb_ops);
	spi_bus_config_t bc;

	/* This inits the specified SPI BUS */

	memset(&bc, 0, sizeof(bc));

	bc.mosi_io_num = -1; // bb->mosi;
	bc.miso_io_num = -1; // bb->miso;
	bc.sclk_io_num = bb->clk;
	bc.data0_io_num = bb->mosi;
	bc.data1_io_num = -1;
	bc.data2_io_num = -1;
	bc.data3_io_num = -1;
	bc.data4_io_num = -1;
	bc.data5_io_num = -1;
	bc.data6_io_num = -1;
	bc.data7_io_num = -1;
	bc.quadwp_io_num = -1;
	bc.quadhd_io_num = -1;
	bc.flags = SPICOMMON_BUSFLAG_MASTER;

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
		edic.pre_cb = lcd_spi_pre_transfer_callback;
		edic.post_cb = lcd_spi_post_transfer_callback;
		edic.flags = SPI_DEVICE_NO_DUMMY;

		/* we do these manually in callbacks */

		bb->gpio->mode(bb->ncmd[desc->channel], LWSGGPIO_FL_WRITE);
		bb->gpio->mode(bb->ncs[desc->channel], LWSGGPIO_FL_WRITE);

		e = spi_bus_add_device(bb->unit, &edic, &h);
		if (e != ESP_OK) {
			lwsl_err("%s: failed to add device: 0x%x\n", __func__, e);
			return 1;
		}
		sdh[bb->unit][desc->channel] = h;
	}

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

		if (at->dma_stash && at->dma_stash_len != chunk) {
			/* we lazily free these to avoid heap apis in IRQ ctx */
			lws_esp32_spi_free_dma(NULL, (void **)&at->dma_stash);
			at->dma_stash_len = 0;
		}

		if (at->dma_stash_len != chunk &&
		    !(desc->flags & LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED)) {
			/* allocate a bounce buffer and fill it */

			at->dma_stash = lws_esp32_spi_alloc_dma(NULL, chunk);
			if (!at->dma_stash) {
				lwsl_err("%s: OOM getting DMA bounce\n", __func__);
				return -1;
			}

			at->dma_stash_len = chunk;

		}
		if (desc->flags & LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED) {
			at->esp_txn.tx_buffer = d;
			d += chunk;
		} else {
			uint32_t u = 0;
			size_t i;

			at->esp_txn.tx_buffer = at->dma_stash;

			for (i = 0; i < chunk; i++) {
				((uint8_t *)&u)[i & 3] = *d++;
				((uint32_t *)at->esp_txn.tx_buffer)[i >> 2] = u;
			}
		}

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
