/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * included from libwebsockets.h
 */

/*
 * Abstract transport ops
 */

typedef struct lws_abs_transport {
	const char *name;
	int alloc;

	int (*create)(struct lws_abs *abs);
	void (*destroy)(lws_abs_transport_inst_t **d);

	/* events the abstract protocol invokes (handled by transport) */

	int (*tx)(lws_abs_transport_inst_t *d, uint8_t *buf, size_t len);
	int (*client_conn)(const lws_abs_t *abs);
	int (*close)(lws_abs_transport_inst_t *d);
	int (*ask_for_writeable)(lws_abs_transport_inst_t *d);
	int (*set_timeout)(lws_abs_transport_inst_t *d, int reason, int secs);
	int (*state)(lws_abs_transport_inst_t *d);
} lws_abs_transport_t;

/**
 * lws_abs_protocol_get_by_name() - returns a pointer to the named protocol ops
 *
 * \param name: the name of the abstract protocol
 *
 * Returns a pointer to the named protocol ops struct if available, otherwise
 * NULL.
 */
LWS_VISIBLE LWS_EXTERN const lws_abs_transport_t *
lws_abs_transport_get_by_name(const char *name);

/*
 * bring in public api pieces from transports
 */

#include <libwebsockets/abstract/transports/raw-skt.h>
#include <libwebsockets/abstract/transports/unit-test.h>
