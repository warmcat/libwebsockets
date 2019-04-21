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
 */

struct lws_abstract;

typedef void lws_abs_user_t;
typedef void lws_abs_t;

/*
 * The abstract callbacks are in three parts
 *
 *  - create and destroy
 *
 *  - events handled by the transport
 *
 *  - events handled by the user of the transport
 *
 * the canned abstract transports only define the first two types... the
 * remaining callbacks must be filled in to callback functions specific to
 * the user of the abstract transport.
 */

typedef struct lws_abstract {

	const char *name;

	lws_abs_user_t * (*create)(struct lws_abstract *abs, void *user);
	void (*destroy)(lws_abs_user_t **d);

	/* events the abstract object invokes (filled in by transport) */

	int (*tx)(lws_abs_user_t *d, uint8_t *buf, size_t len);
	int (*client_conn)(lws_abs_user_t *d, struct lws_vhost *vh,
			   const char *ip, uint16_t port, int tls_flags);
	int (*close)(lws_abs_user_t *d);
	int (*ask_for_writeable)(lws_abs_user_t *d);
	int (*set_timeout)(lws_abs_user_t *d, int reason, int secs);
	int (*state)(lws_abs_user_t *d);

	/* events the transport invokes (filled in by abstract object) */

	int (*accept)(lws_abs_user_t *d);
	int (*rx)(lws_abs_user_t *d, uint8_t *buf, size_t len);
	int (*writeable)(lws_abs_user_t *d, size_t budget);
	int (*closed)(lws_abs_user_t *d);
	int (*heartbeat)(lws_abs_user_t *d);

} lws_abstract_t;


