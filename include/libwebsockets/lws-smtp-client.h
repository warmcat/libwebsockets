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

#ifndef _LWS_SMTP_CLIENT_H
#define _LWS_SMTP_CLIENT_H

typedef struct lws_smtp_email {
	void *data;
	const char *from;
	const char *to;
	const char *subject;
	const char *body;
} lws_smtp_email_t;

typedef struct lws_smtp_client_ops {
	int (*send_email)(struct lws_context *cx, struct lws_vhost *vh, const lws_smtp_email_t *email);
} lws_smtp_client_ops_t;

#endif
