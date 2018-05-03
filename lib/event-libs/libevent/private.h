/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
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
 *  This is included from core/private.h if LWS_WITH_LIBEVENT
 */

#include <event2/event.h>

struct lws_pt_eventlibs_libevent {
	struct event_base *io_loop;
	struct event *hrtimer;
	struct event *idle_timer;
};

struct lws_io_watcher_libevent {
	struct event *watcher;
};

struct lws_signal_watcher_libevent {
	struct event *watcher;
};

struct lws_context_eventlibs_libevent {
	int placeholder;
};

extern struct lws_event_loop_ops event_loop_ops_event;
