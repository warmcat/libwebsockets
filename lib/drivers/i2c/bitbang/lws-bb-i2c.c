/*
 * I2C bitbang implementation using generic gpio
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
#include <libwebsockets.h>

int
lws_bb_i2c_init(const lws_i2c_ops_t *octx)
{
	lws_bb_i2c_t *ctx = (lws_bb_i2c_t *)octx;

	/*
	 * i2c lines are only ever pulled low: the peripheral has to be able
	 * to pull SDA low to ACK and send data, and SCL to stretch the clock,
	 * while we have "set" them to 1
	 */

	ctx->gpio->mode(ctx->scl, LWSGGPIO_FL_WRITE | LWSGGPIO_FL_READ |
				  LWSGGPIO_FL_OPEN_DRAIN | LWSGGPIO_FL_PULLUP);
	ctx->gpio->mode(ctx->sda, LWSGGPIO_FL_WRITE | LWSGGPIO_FL_READ |
				  LWSGGPIO_FL_OPEN_DRAIN | LWSGGPIO_FL_PULLUP);

	return 0;
}

/*
 * Let SCL go high, and wait until it is: a peripheral may stretch the clock
 * by holding it low until it's ready, eg, while it updates the registers
 * being read.  Clocking on regardless loses the bit, and with it, maybe the
 * register address the read starts from.  One that is wedged or absent with
 * the line stuck mustn't hang us forever: nonzero if it never went high.
 */

static int
lws_bb_i2c_scl_release(lws_bb_i2c_t *ctx)
{
	int n = LWS_BB_I2C_STRETCH_LIMIT;

	ctx->gpio->set(ctx->scl, 1);
	ctx->delay();

	while (!ctx->gpio->read(ctx->scl) && --n)
		ctx->delay();

	if (n)
		return 0;

	lwsl_warn("%s: SCL held low\n", __func__);

	return 1;
}

int
lws_bb_i2c_start(const lws_i2c_ops_t *octx)
{
	lws_bb_i2c_t *ctx = (lws_bb_i2c_t *)octx;

	ctx->gpio->set(ctx->sda, 1);
	if (lws_bb_i2c_scl_release(ctx))
		return 1;

	if (!ctx->gpio->read(ctx->sda))
		return 1;

	ctx->gpio->set(ctx->sda, 0);
	ctx->delay();
	ctx->gpio->set(ctx->scl, 0);

	return 0;
}

void
lws_bb_i2c_stop(const lws_i2c_ops_t *octx)
{
	lws_bb_i2c_t *ctx = (lws_bb_i2c_t *)octx;

	ctx->gpio->set(ctx->sda, 0);
	lws_bb_i2c_scl_release(ctx);
	ctx->gpio->set(ctx->sda, 1);
	ctx->delay();
}

int
lws_bb_i2c_write(const lws_i2c_ops_t *octx, uint8_t data)
{
	lws_bb_i2c_t *ctx = (lws_bb_i2c_t *)octx;
	int n;

	for (n = 0; n < 8; n++) {
		ctx->gpio->set(ctx->sda, !!(data & (1 << 7)));
		ctx->delay();
		if (lws_bb_i2c_scl_release(ctx))
			return 1;
		data = (uint8_t)(data << 1);
		ctx->gpio->set(ctx->scl, 0);
	}

	ctx->gpio->set(ctx->sda, 1);
	ctx->delay();
	if (lws_bb_i2c_scl_release(ctx))
		return 1;
	n = ctx->gpio->read(ctx->sda);
	ctx->gpio->set(ctx->scl, 0);
	ctx->delay();

	return !!n; /* 0 = ACKED = OK */
}

int
lws_bb_i2c_read(const lws_i2c_ops_t *octx)
{
	lws_bb_i2c_t *ctx = (lws_bb_i2c_t *)octx;
	int n, r = 0;

	ctx->gpio->set(ctx->sda, 1);

	for (n = 7; n >= 0; n--) {
		ctx->gpio->set(ctx->scl, 0);
		ctx->delay();
		if (lws_bb_i2c_scl_release(ctx))
			return -1;
		if (ctx->gpio->read(ctx->sda))
			r |= 1 << n;
	}
	ctx->gpio->set(ctx->scl, 0);

	return r;
}

void
lws_bb_i2c_set_ack(const lws_i2c_ops_t *octx, int ack)
{
	lws_bb_i2c_t *ctx = (lws_bb_i2c_t *)octx;

	ctx->gpio->set(ctx->scl, 0);
	ctx->gpio->set(ctx->sda, !!ack);
	ctx->delay();
	lws_bb_i2c_scl_release(ctx);
	ctx->gpio->set(ctx->scl, 0);
	ctx->delay();
	ctx->gpio->set(ctx->sda, 1);
}
