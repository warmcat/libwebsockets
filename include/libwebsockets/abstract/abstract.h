/*
 * libwebsockets - abstract top level header
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

/*
 * These are used to optionally pass an array of index = C string, binary array,
 * or ulong tokens to the abstract transport or protocol.  For example if it's
 * raw socket transport, then the DNS address to connect to and the port are
 * passed using these when the client created and bound to the transport.
 */

typedef struct lws_token_map {
	union {
		const char	*value;
		uint8_t		*bvalue;
		unsigned long	lvalue;
	} u;
	short			name_index;  /* 0 here indicates end of array */
	short			length_or_zero;
} lws_token_map_t;

/*
 * The indvidual protocols and transports define their own name_index-es which
 * are meaningful to them.  Define index 0 globally as the end of an array of
 * them, and separate the ones used for protocols and transport so we can
 * sanity check they are at least in the correct category.
 */

enum {
	LTMI_END_OF_ARRAY,

	LTMI_PROTOCOL_BASE	= 2048,

	LTMI_TRANSPORT_BASE	= 4096
};

struct lws_abs_transport;
struct lws_abs_protocol;

LWS_VISIBLE LWS_EXTERN const lws_token_map_t *
lws_abs_get_token(const lws_token_map_t *token_map, short name_index);

/*
 * the combination of a protocol, transport, and token maps for each
 */

typedef void lws_abs_transport_inst_t;
typedef void lws_abs_protocol_inst_t;

typedef struct lws_abs {
	void				*user;
	struct lws_vhost		*vh;

	const struct lws_abs_protocol	*ap;
	const lws_token_map_t		*ap_tokens;
	const struct lws_abs_transport	*at;
	const lws_token_map_t		*at_tokens;

	lws_seq_t			*seq;
	void				*opaque_user_data;

	/*
	 * These are filled in by lws_abs_bind_and_create_instance() in the
	 * instance copy.  They do not need to be set when creating the struct
	 * for use by lws_abs_bind_and_create_instance()
	 */

	struct lws_dll2			abstract_instances;
	lws_abs_transport_inst_t	*ati;
	lws_abs_protocol_inst_t		*api;
} lws_abs_t;

/**
 * lws_abs_bind_and_create_instance - use an abstract protocol and transport
 *
 * \param abs: the lws_abs_t describing the combination desired
 *
 * This instantiates an abstract protocol and abstract transport bound together.
 * A single heap allocation is made for the combination and the protocol and
 * transport creation ops are called on it.  The ap_tokens and at_tokens
 * are consulted by the creation ops to decide the details of the protocol and
 * transport for the instance.
 */
LWS_VISIBLE LWS_EXTERN lws_abs_t *
lws_abs_bind_and_create_instance(const lws_abs_t *ai);

/**
 * lws_abs_destroy_instance() - destroys an instance
 *
 * \param ai: pointer to the ai pointer to destroy
 *
 * This is for destroying an instance created by
 * lws_abs_bind_and_create_instance() above.
 *
 * Calls the protocol and transport destroy operations on the instance, then
 * frees the combined allocation in one step.  The pointer ai is set to NULL.
 */
LWS_VISIBLE LWS_EXTERN void
lws_abs_destroy_instance(lws_abs_t **ai);

/*
 * bring in all the protocols and transports definitions
 */

#include <libwebsockets/abstract/protocols.h>
#include <libwebsockets/abstract/transports.h>
