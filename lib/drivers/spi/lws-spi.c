/*
 * Generic SPI
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
	
int
lws_spi_table_issue(const lws_spi_ops_t *spi_ops, uint32_t flags,
		    const uint8_t *p, size_t len)
{
	lws_spi_desc_t desc;
	size_t pos = 0;

	memset(&desc, 0, sizeof(desc));
	desc.count_cmd = 1;
	desc.flags = flags;

	while (pos < len) {

		desc.count_write = p[pos++];

		desc.src = (uint8_t *)&p[pos++];
		if (desc.count_write)
			desc.data = (uint8_t *)&p[pos];
		else
			desc.data = NULL;

		if (spi_ops->queue(spi_ops, &desc) != ESP_OK) {
			lwsl_err("%s: unable to queue\n", __func__);
			return 1;
		}

		pos += desc.count_write;
	}

	return 0;
}

int
lws_spi_readback(const lws_spi_ops_t *spi_ops, uint32_t flags,
                 const uint8_t *p, size_t len, uint8_t *rb, size_t rb_len)
{
        lws_spi_desc_t desc;
        size_t pos = 0;

        memset(&desc, 0, sizeof(desc));
        desc.count_cmd = 1;
        desc.flags = flags;

        while (pos < len) {

                desc.count_write = p[pos++];

                desc.src = (uint8_t *)&p[pos++];
                if (desc.count_write)
                        desc.data = (uint8_t *)&p[pos];
                else
                        desc.data = NULL;

		desc.dest = rb;
		desc.count_read = rb_len;

                if (spi_ops->queue(spi_ops, &desc) != ESP_OK) {
                        lwsl_err("%s: unable to queue\n", __func__);
                        return 1;
                }

                pos += desc.count_write;
        }

	return 0;
}

