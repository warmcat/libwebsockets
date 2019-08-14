/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/*! \defgroup generic-sessions plugin: generic-sessions
 * \ingroup Protocols-and-Plugins
 *
 * ##Plugin Generic-sessions related
 *
 * generic-sessions plugin provides a reusable, generic session and login /
 * register / forgot password framework including email verification.
 */
///@{

#define LWSGS_EMAIL_CONTENT_SIZE 16384
/**< Maximum size of email we might send */

/* SHA-1 binary and hexified versions */
/** typedef struct lwsgw_hash_bin */
typedef struct { unsigned char bin[32]; /**< binary representation of hash */} lwsgw_hash_bin;
/** typedef struct lwsgw_hash */
typedef struct { char id[65]; /**< ascii hex representation of hash */ } lwsgw_hash;

/** enum lwsgs_auth_bits */
enum lwsgs_auth_bits {
	LWSGS_AUTH_LOGGED_IN	= 1, /**< user is logged in as somebody */
	LWSGS_AUTH_ADMIN	= 2, /**< logged in as the admin user */
	LWSGS_AUTH_VERIFIED	= 4, /**< user has verified his email */
	LWSGS_AUTH_FORGOT_FLOW	= 8, /**< just completed "forgot password" */
};

/** struct lws_session_info - information about user session status */
struct lws_session_info {
	char username[32]; /**< username logged in as, or empty string */
	char email[100]; /**< email address associated with login, or empty string */
	char ip[72]; /**< ip address session was started from */
	unsigned int mask; /**< access rights mask associated with session
	 	 	    * see enum lwsgs_auth_bits */
	char session[42]; /**< session id string, usable as opaque uid when not logged in */
};

/** enum lws_gs_event */
enum lws_gs_event {
	LWSGSE_CREATED, /**< a new user was created */
	LWSGSE_DELETED  /**< an existing user was deleted */
};

/** struct lws_gs_event_args */
struct lws_gs_event_args {
	enum lws_gs_event event; /**< which event happened */
	const char *username; /**< which username the event happened to */
	const char *email; /**< the email address of that user */
};

///@}
