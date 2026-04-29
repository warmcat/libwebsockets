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

#ifndef _PROTOCOL_LWS_AUTH_DEVICE_CLIENT_H
#define _PROTOCOL_LWS_AUTH_DEVICE_CLIENT_H

#define LWS_AUTH_DEVICE_CLIENT_ABI_VERSION 1

struct lws_auth_device_client_ops {
	uint32_t abi_version;

	/* Called when authorization completes successfully to let the app proceed */
	void (*auth_success)(struct lws_vhost *vh, const char *logical_name, const char *access_token);

	/* Called to start / stop flashing an LED or similar "pairing indication" */
	void (*pairing_indication)(struct lws_vhost *vh, const char *logical_name, int start);

	/* Optional callback when code is retrieved */
	void (*display_code)(struct lws_vhost *vh, const char *logical_name, const char *user_code);

	/* Optional callback to get a human-readable name for the device */
	const char *(*get_device_name)(struct lws_vhost *vh, const char *logical_name);
};

struct lws_auth_device_client_api {
	uint32_t abi_version;

	/* Start the auth flow against the given mixer URL for a specific logical device */
	void (*start_auth_flow)(struct lws_vhost *vh, const char *mixer_url, const char *logical_name);
};

#endif
