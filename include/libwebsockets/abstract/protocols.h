/*
 * libwebsockets - abstract protocol definitions
 *
 * Copyright (C) 2019 Andy Green <andy@warmcat.com>
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
