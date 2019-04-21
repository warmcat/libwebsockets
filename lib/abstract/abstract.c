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

extern lws_abstract_t lws_abstract_transport_cli_raw_skt;

static const lws_abstract_t *available_abstractions[] = {
	&lws_abstract_transport_cli_raw_skt,
};

/*
 * the definition is opaque, so a helper to copy it into place
 */

void
lws_abstract_copy(lws_abstract_t *dest, const lws_abstract_t *src)
{
	memcpy(dest, src, sizeof(*dest));
}


const lws_abstract_t *
lws_abstract_get_by_name(const char *name)
{
	int n;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(available_abstractions); n++)
		if (!strcmp(name, available_abstractions[n]->name))
			return available_abstractions[n];

	return NULL;
}
