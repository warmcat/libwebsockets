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
 *
 * This provides a clean way to interface lws user code to be able to
 * work unchanged on different systems for fetching common system information,
 * and performing common system operations like reboot.
 *
 * An ops struct with the system-specific implementations is set at
 * context creation time, and apis are provided that call through to
 * those where they exist.
 */

typedef enum {
	LWS_SYSI_HRS_DEVICE_MODEL = 1,
	LWS_SYSI_HRS_DEVICE_SERIAL,
	LWS_SYSI_HRS_FIRMWARE_VERSION,
	LWS_SYSI_HRS_NTP_SERVER,

	LWS_SYSI_USER_BASE = 100
} lws_system_item_t;

typedef struct lws_system_arg {
	union {
		const char	*hrs;	/* human readable string */
		void		*data;
		time_t		t;
	} u;
	size_t len;
} lws_system_arg_t;

/*
 * Lws view of system state... normal operation from user code perspective is
 * dependent on implicit (eg, knowing the date for cert validation) and
 * explicit dependencies.
 *
 * Bit of lws and user code can register notification handlers that can enforce
 * dependent operations before state transitions can complete.
 */

typedef enum {
	LWS_SYSTATE_UNKNOWN,
	LWS_SYSTATE_CONTEXT_CREATED,	/* context was just created */
	LWS_SYSTATE_INITIALIZED,	 /* protocols initialized.  Lws itself
					  * can operate normally */
	LWS_SYSTATE_TIME_VALID,		/* ntpclient ran, or hw time valid...
					  * tls cannot work until we reach here
					  */
	LWS_SYSTATE_POLICY_VALID,	 /* user code knows how to operate... it
					  * can set up prerequisites */
	LWS_SYSTATE_OPERATIONAL,	 /* user code can operate normally */

	LWS_SYSTATE_POLICY_INVALID, /* user code is changing its policies
					  * drop everything done with old
					  * policy, switch to new then enter
					  * LWS_SYSTATE_POLICY_VALID */
} lws_system_states_t;

typedef struct lws_system_ops {
	int (*get_info)(lws_system_item_t i, lws_system_arg_t *arg);
	int (*reboot)(void);
	int (*set_clock)(lws_usec_t us);
	int (*auth)(int idx, uint8_t *buf, size_t *plen, int set);
	/**< Systemwide ephemeral auth tokens get or set... set *plen to max
	 * size for get, will be set to actual size on return of 0, return 1
	 * means token is too big for buffer.  idx is token index if multiple.
	 * Auth tokens are potentially large, and should be stored as binary
	 * and converted to a transport format like hex.  */
} lws_system_ops_t;

/**
 * lws_system_get_state_manager() - return the state mgr object for system state
 *
 * \param context: the lws_context
 *
 * The returned pointer can be used with the lws_state_ apis
 */

LWS_EXTERN LWS_VISIBLE lws_state_manager_t *
lws_system_get_state_manager(struct lws_context *context);



/* wrappers handle NULL members or no ops struct set at all cleanly */

/**
 * lws_system_get_info() - get standardized system information
 *
 * \param context: the lws_context
 * \param item: which information to fetch
 * \param arg: where to place the result
 *
 * This queries a standardized information-fetching ops struct that can be
 * applied to the context... the advantage is it allows you to get common items
 * of information like a device serial number writing the code once, even if the
 * actual serial number must be fetched in wildly different ways depending on
 * the exact platform it's running on.
 *
 * Point arg to your lws_system_arg_t, on return it will be set.  It doesn't
 * copy the content just sets pointer and length.
 */
LWS_EXTERN LWS_VISIBLE int
lws_system_get_info(struct lws_context *context, lws_system_item_t item,
		    lws_system_arg_t *arg);


#define LWSSYSGAUTH_HEX (1 << 0)

/**
 * lws_system_get_auth() - retreive system auth token helper
 *
 * \param context: the lws_context
 * \param idx: which auth token
 * \param buf: where to store result
 * \param buflen: size of buf
 * \param flags: how to write the result
 *
 * Attempts to fill buf with the requested system auth token.  If flags has
 * LWSSYSGAUTH_HEX set, then the auth token is written as pairs of hex chars
 * for each byte.  If not set, written as 1 byte per byte binary.
 */
LWS_EXTERN LWS_VISIBLE int
lws_system_get_auth(struct lws_context *context, int idx, uint8_t *buf, size_t buflen, int flags);

/**
 * lws_system_get_ops() - get ahold of the system ops struct from the context
 *
 * \param context: the lws_context
 *
 * Returns the system ops struct.  It may return NULL and if not, anything in
 * there may be NULL.
 */
LWS_EXTERN LWS_VISIBLE const lws_system_ops_t *
lws_system_get_ops(struct lws_context *context);
