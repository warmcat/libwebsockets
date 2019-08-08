/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

#include "core/private.h"

lws_usec_t
__lws_event_service_get_earliest_wake(struct lws_context_per_thread *pt,
				      lws_usec_t usnow)
{
	lws_usec_t t, us = 0;
	char seen = 0;

	t =  __lws_hrtimer_service(pt, usnow);
	if (t && (!seen || t < us)) {
		us = t;
		seen = 1;
	}
	t = __lws_seq_timeout_check(pt, usnow);
	if (t && (!seen || t < us)) {
		us = t;
		seen = 1;
	}

	return us;
}
