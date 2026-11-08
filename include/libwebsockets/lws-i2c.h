/*
 * Generic I2C ops
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
 * This is like an abstract class for i2c, a real implementation provides
 * functions for the ops that use the underlying OS arrangements.
 */

#if !defined(__LWS_I2C_H__)
#define __LWS_I2C_H__

#include <stdint.h>
#include <stddef.h>

typedef struct lws_i2c_ops {
	int  (*init)(const struct lws_i2c_ops *ctx);
	/**< prepare the bus, 0 = OK */
	int  (*start)(const struct lws_i2c_ops *ctx);
	/**< issue a START, or a repeated START inside a transaction, 0 = OK,
	 * nonzero if the bus could not be taken */
	void (*stop)(const struct lws_i2c_ops *ctx);
	/**< issue a STOP, releasing the bus */
	int  (*write)(const struct lws_i2c_ops *ctx, uint8_t data);
	/**< send a byte, 0 = the peer ACKed it, nonzero = NAK */
	int  (*read)(const struct lws_i2c_ops *ctx);
	/**< receive a byte, 0..255, or < 0 on error.  It must be followed by
	 * set_ack() to tell the peer whether to send another */
	void (*set_ack)(const struct lws_i2c_ops *octx, int ack);
	/**< clock out the acknowledge bit for a byte just read, as the bus
	 * level: 0 (low) ACKs it, asking the peer for more, 1 (high) NAKs it,
	 * as must be done after the last byte read before stop or restart */
} lws_i2c_ops_t;

/*
 * These are implemented by calling the ops above, and so are generic
 */

/**
 * lws_i2c_read_regs() - read consecutive registers from an i2c device
 *
 * \param ctx: the i2c ops for the bus the device is on
 * \param ads7: the device's 7-bit address
 * \param reg: the first register to read
 * \param buf: where to put the register contents
 * \param len: how many consecutive registers to read, at least 1
 *
 * Writes the register address, then uses a repeated START to read \p len
 * bytes from the device, as most i2c peripherals expect.  Returns 0 if
 * the whole transaction succeeded, else nonzero, in which case the
 * contents of \p buf are undefined.
 */
LWS_VISIBLE LWS_EXTERN int
lws_i2c_read_regs(const lws_i2c_ops_t *ctx, uint8_t ads7, uint8_t reg,
		  uint8_t *buf, size_t len);

/**
 * lws_i2c_write_regs() - write consecutive registers on an i2c device
 *
 * \param ctx: the i2c ops for the bus the device is on
 * \param ads7: the device's 7-bit address
 * \param reg: the first register to write
 * \param buf: the values to write
 * \param len: how many consecutive registers to write, may be 0
 *
 * Writes the register address followed by \p len bytes in one
 * transaction.  Returns 0 if the device ACKed everything, else nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_i2c_write_regs(const lws_i2c_ops_t *ctx, uint8_t ads7, uint8_t reg,
		   const uint8_t *buf, size_t len);


/**
 * lws_i2c_read_regs16() - read consecutive registers, 16-bit register address
 *
 * \param ctx: the i2c ops for the bus the device is on
 * \param ads7: the device's 7-bit address
 * \param reg: the first register to read
 * \param buf: where to put the register contents
 * \param len: how many consecutive registers to read, at least 1
 *
 * As lws_i2c_read_regs(), for devices whose register addresses are 16-bit,
 * sent most significant byte first.
 */
LWS_VISIBLE LWS_EXTERN int
lws_i2c_read_regs16(const lws_i2c_ops_t *ctx, uint8_t ads7, uint16_t reg,
		    uint8_t *buf, size_t len);

/**
 * lws_i2c_write_regs16() - write consecutive registers, 16-bit register address
 *
 * \param ctx: the i2c ops for the bus the device is on
 * \param ads7: the device's 7-bit address
 * \param reg: the first register to write
 * \param buf: the values to write
 * \param len: how many consecutive registers to write, may be 0
 *
 * As lws_i2c_write_regs(), for devices whose register addresses are 16-bit,
 * sent most significant byte first.
 */
LWS_VISIBLE LWS_EXTERN int
lws_i2c_write_regs16(const lws_i2c_ops_t *ctx, uint8_t ads7, uint16_t reg,
		     const uint8_t *buf, size_t len);


LWS_VISIBLE LWS_EXTERN int
lws_i2c_command(const lws_i2c_ops_t *ctx, uint8_t ads7, uint8_t c);

LWS_VISIBLE LWS_EXTERN int
lws_i2c_command_list(const lws_i2c_ops_t *ctx, uint8_t ads7, const uint8_t *buf,
		     size_t len);

#endif
