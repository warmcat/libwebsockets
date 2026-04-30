/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 */

#ifndef _PROTOCOL_RTC_CAMERA_H
#define _PROTOCOL_RTC_CAMERA_H

#define LWS_RTC_CAMERA_OPS_ABI_VERSION 2

enum lws_rtc_camera_states {
	LWS_RTC_CAMERA_STATE_CONNECTING = 0,
	LWS_RTC_CAMERA_STATE_ESTABLISHED = 1,
	LWS_RTC_CAMERA_STATE_CLOSED = 2,
	LWS_RTC_CAMERA_STATE_ERROR = 3
};

struct lws_rtc_camera_ops {
	uint32_t abi_version;

	/* Dynamically attach a new camera unit to the WebRTC mixer */
	int (*attach)(struct lws_vhost *vh, const char *url, const char *device_path, const char *audio_device_path, const char *name, uint32_t width, uint32_t height, const char *auth_token);

	/* Detach a previously attached camera */
	int (*detach)(struct lws_vhost *vh, const char *device_path);

	/* Optional callback to application about connection state */
	void (*state_cb)(const char *device_path, enum lws_rtc_camera_states state);
};

#endif
