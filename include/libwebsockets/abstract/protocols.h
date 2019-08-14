/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

typedef struct lws_abs_protocol {
	const char	*name;
	int		alloc;

	int (*create)(const struct lws_abs *ai);
	void (*destroy)(lws_abs_protocol_inst_t **d);

	/* events the transport invokes (handled by abstract protocol) */

	int (*accept)(lws_abs_protocol_inst_t *d);
	int (*rx)(lws_abs_protocol_inst_t *d, uint8_t *buf, size_t len);
	int (*writeable)(lws_abs_protocol_inst_t *d, size_t budget);
	int (*closed)(lws_abs_protocol_inst_t *d);
	int (*heartbeat)(lws_abs_protocol_inst_t *d);
} lws_abs_protocol_t;

/**
 * lws_abs_protocol_get_by_name() - returns a pointer to the named protocol ops
 *
 * \param name: the name of the abstract protocol
 *
 * Returns a pointer to the named protocol ops struct if available, otherwise
 * NULL.
 */
LWS_VISIBLE LWS_EXTERN const lws_abs_protocol_t *
lws_abs_protocol_get_by_name(const char *name);

/*
 * bring in public api pieces from protocols
 */

#include <libwebsockets/abstract/protocols/smtp.h>
