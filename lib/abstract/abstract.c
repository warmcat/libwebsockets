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

#include <core/private.h>
#include <abstract/private.h>

extern const lws_abs_transport_t lws_abs_transport_cli_raw_skt,
				 lws_abs_transport_cli_unit_test;
#if defined(LWS_WITH_SMTP)
extern const lws_abs_protocol_t lws_abs_protocol_smtp;
#endif

static const lws_abs_transport_t * const available_abs_transports[] = {
	&lws_abs_transport_cli_raw_skt,
	&lws_abs_transport_cli_unit_test,
};

/* HACK: microsoft compiler can't handle zero length array definition */
#if defined(LWS_WITH_SMTP)
static const lws_abs_protocol_t * const available_abs_protocols[] = {
#if defined(LWS_WITH_SMTP)
	&lws_abs_protocol_smtp,
#endif
};
#endif

const lws_abs_transport_t *
lws_abs_transport_get_by_name(const char *name)
{
	int n;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(available_abs_transports); n++)
		if (!strcmp(name, available_abs_transports[n]->name))
			return available_abs_transports[n];

	lwsl_err("%s: cannot find '%s'\n", __func__, name);

	return NULL;
}

const lws_abs_protocol_t *
lws_abs_protocol_get_by_name(const char *name)
{
#if defined(LWS_WITH_SMTP)
	int n;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(available_abs_protocols); n++)
		if (!strcmp(name, available_abs_protocols[n]->name))
			return available_abs_protocols[n];
#endif
	lwsl_err("%s: cannot find '%s'\n", __func__, name);

	return NULL;
}

const lws_token_map_t *
lws_abs_get_token(const lws_token_map_t *token_map, short name_index)
{
	if (!token_map)
		return NULL;

	do {
		if (token_map->name_index == name_index)
			return token_map;
		token_map++;
	} while (token_map->name_index);

	return NULL;
}

void
lws_abs_destroy_instance(lws_abs_t **ai)
{
	lws_abs_t *a = *ai;

	if (a->api)
		a->ap->destroy(&a->api);
	if (a->ati)
		a->at->destroy(&a->ati);

	lws_dll2_remove(&a->abstract_instances);

	*ai = NULL;
	free(a);
}

lws_abs_t *
lws_abs_bind_and_create_instance(const lws_abs_t *abs)
{
	size_t size = sizeof(lws_abs_t) + abs->ap->alloc + abs->at->alloc;
	lws_abs_t *ai;

	/*
	 * since we know we will allocate the lws_abs_t, the protocol's
	 * instance allocation, and the transport's instance allocation,
	 * we merge it into a single heap allocation
	 */
	ai = lws_malloc(size, "abs inst");
	if (!ai)
		return NULL;

	*ai = *abs;
	ai->ati = NULL;

	ai->api = (char *)ai + sizeof(lws_abs_t);
	if (ai->ap->create(ai)) {
		ai->api = NULL;
		goto bail;
	}

	ai->ati = (char *)ai->api + abs->ap->alloc;
	if (ai->at->create(ai)) {
		ai->ati = NULL;
		goto bail;
	}

	/* add us to the vhost's dll2 of instances */

	lws_dll2_clear(&ai->abstract_instances);
	lws_dll2_add_head(&ai->abstract_instances,
			  &ai->vh->abstract_instances_owner);

	return ai;

bail:
	lws_abs_destroy_instance(&ai);

	return NULL;
}
