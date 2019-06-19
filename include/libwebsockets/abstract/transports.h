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

typedef void lws_abs_user_t;
typedef void lws_abs_t;

/*
 * These are used to optionally pass an array of index = C string or binary
 * array tokens to the abstract transport.  For example if it's raw socket
 * transport, then the DNS address to connect to and the port are passed using
 * these when the client created and bound to the transport.
 */

typedef struct lws_token_map {
	union {
		const char *value;
		uint8_t *bvalue;
		unsigned long lvalue;
	} u;
	short name_index;		/* 0 here indicates end of array */
	short length_or_zero;
} lws_token_map_t;

enum {
	LTMI_END_OF_ARRAY,

	LTMI_PEER_DNS_ADDRESS,		/* u.value */
	LTMI_PEER_PORT,			/* u.lvalue */
	LTMI_PEER_TLS_FLAGS,		/* u.lvalue */
};

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
 *
 * This abi has to be public so the user can create their own private abstract
 * transports.
 */

typedef struct lws_abstract {

	const char *name;

	lws_abs_user_t * (*create)(struct lws_abstract *abs, void *user);
	void (*destroy)(lws_abs_user_t **d);

	/* events the abstract object invokes (filled in by transport) */
	int (*tx)(lws_abs_user_t *d, uint8_t *buf, size_t len);
	int (*client_conn)(lws_abs_user_t *d, struct lws_vhost *vh,
			   const lws_token_map_t *token_map);
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


LWS_VISIBLE LWS_EXTERN void
lws_abstract_copy(lws_abstract_t *dest, const lws_abstract_t *src);

LWS_VISIBLE LWS_EXTERN const lws_abstract_t *
lws_abstract_get_by_name(const char *name);

LWS_VISIBLE LWS_EXTERN const lws_token_map_t *
lws_abstract_get_token(const lws_token_map_t *token_map, short name_index);
