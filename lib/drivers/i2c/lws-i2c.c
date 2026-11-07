/*
 * Generic I2C
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
 * These are generic helpers made up of calls to the i2c driver ops, so they
 * just need implementing once like this and are usable for any i2c underlying
 * implementation via the ops.
 */

#include <libwebsockets.h>
	
int
lws_i2c_command(const lws_i2c_ops_t *ctx, uint8_t ads7, uint8_t c)
{
	if (ctx->start(ctx))
		return 1;

	if (ctx->write(ctx, (uint8_t)(ads7 << 1))) {
		ctx->stop(ctx);

		return 1;
	}

	ctx->write(ctx, 0);
	ctx->write(ctx, c);
	ctx->stop(ctx);

	return 0;
}

int
lws_i2c_command_list(const lws_i2c_ops_t *ctx, uint8_t ads7, const uint8_t *buf,
		     size_t len)
{
	while (len--)
		if (lws_i2c_command(ctx, ads7, *buf++))
			return 1;

	return 0;
}

/*
 * Address the device for writing and send it the register address: the
 * common start of both register helpers.  On failure the bus has been
 * released again.
 */

static int
lws_i2c_reg_select(const lws_i2c_ops_t *ctx, uint8_t ads7, uint8_t reg)
{
	if (ctx->start(ctx))
		return 1;

	if (ctx->write(ctx, (uint8_t)(ads7 << 1)) || ctx->write(ctx, reg)) {
		ctx->stop(ctx);

		return 1;
	}

	return 0;
}

int
lws_i2c_read_regs(const lws_i2c_ops_t *ctx, uint8_t ads7, uint8_t reg,
		  uint8_t *buf, size_t len)
{
	int n;

	if (!len)
		return 1;

	if (lws_i2c_reg_select(ctx, ads7, reg))
		return 1;

	/* repeated START, turning the bus around to read from the device */

	if (ctx->start(ctx) || ctx->write(ctx, (uint8_t)((ads7 << 1) | 1)))
		goto bail;

	while (len--) {
		n = ctx->read(ctx);
		if (n < 0 || n > 0xff)
			goto bail;
		*buf++ = (uint8_t)n;

		/* ACK every byte but the last, which is NAKed to end it */
		ctx->set_ack(ctx, !len);
	}

	ctx->stop(ctx);

	return 0;

bail:
	ctx->stop(ctx);

	return 1;
}

int
lws_i2c_write_regs(const lws_i2c_ops_t *ctx, uint8_t ads7, uint8_t reg,
		   const uint8_t *buf, size_t len)
{
	if (lws_i2c_reg_select(ctx, ads7, reg))
		return 1;

	while (len--)
		if (ctx->write(ctx, *buf++)) {
			ctx->stop(ctx);

			return 1;
		}

	ctx->stop(ctx);

	return 0;
}
