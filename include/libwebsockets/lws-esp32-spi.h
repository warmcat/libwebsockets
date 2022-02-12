/*
 * SPI - esp32 esp-idf api implementation
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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
 *
 * This is like an abstract class for gpio, a real implementation provides
 * functions for the ops that use the underlying OS gpio arrangements.
 */

#if defined(ESP_PLATFORM)

#define lws_esp32_spi_ops \
		.init		= lws_esp32_spi_init, \
		.queue		= lws_esp32_spi_queue, \
		.alloc_dma	= lws_esp32_spi_alloc_dma, \
		.free_dma	= lws_esp32_spi_free_dma, \
		.in_flight	= lws_esp32_spi_in_flight

LWS_VISIBLE LWS_EXTERN int
lws_esp32_spi_init(const lws_spi_ops_t *spi_ops);

LWS_VISIBLE LWS_EXTERN int
lws_esp32_spi_queue(const lws_spi_ops_t *spi_ops, const lws_spi_desc_t *desc);

LWS_VISIBLE LWS_EXTERN void *
lws_esp32_spi_alloc_dma(const struct lws_spi_ops *ctx, size_t size);

LWS_VISIBLE LWS_EXTERN void
lws_esp32_spi_free_dma(const struct lws_spi_ops *ctx, void **p);

LWS_VISIBLE LWS_EXTERN int
lws_esp32_spi_in_flight(const struct lws_spi_ops *ctx);

#endif
