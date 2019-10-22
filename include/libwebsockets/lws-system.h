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
	LWS_SYSI_HRS_CLIENT_CERT_DER,

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

typedef enum { /* keep system_state_names[] in sync in context.c */
	LWS_SYSTATE_UNKNOWN,

	LWS_SYSTATE_CONTEXT_CREATED,	 /* context was just created */
	LWS_SYSTATE_INITIALIZED,	 /* protocols initialized.  Lws itself
					  * can operate normally */
	LWS_SYSTATE_IFACE_COLDPLUG,	 /* existing net ifaces iterated */
	LWS_SYSTATE_DHCP,		 /* at least one net iface configured */
	LWS_SYSTATE_TIME_VALID,		 /* ntpclient ran, or hw time valid...
					  * tls cannot work until we reach here
					  */
	LWS_SYSTATE_POLICY_VALID,	 /* user code knows how to operate... */
	LWS_SYSTATE_REGISTERED,		 /* device has an identity... */
	LWS_SYSTATE_AUTH1,		 /* identity used for main auth token */
	LWS_SYSTATE_AUTH2,		 /* identity used for optional auth */

	LWS_SYSTATE_OPERATIONAL,	 /* user code can operate normally */

	LWS_SYSTATE_POLICY_INVALID,	/* user code is changing its policies
					  * drop everything done with old
					  * policy, switch to new then enter
					  * LWS_SYSTATE_POLICY_VALID */
} lws_system_states_t;

typedef enum {
	LWSSYS_AUTH_GET,
	LWSSYS_AUTH_TOTAL_LENGTH,
	LWSSYS_AUTH_APPEND,
	LWSSYS_AUTH_FREE,
} lws_system_auth_op_t;

typedef int (*lws_system_auth_cb_t)(struct lws_context *context, int idx,
				    size_t ofs, uint8_t *buf, size_t *plen,
				    lws_system_auth_op_t set);

typedef struct lws_system_ops {
	int (*get_info)(lws_system_item_t i, lws_system_arg_t *arg);
	int (*reboot)(void);
	int (*set_clock)(lws_usec_t us);
	lws_system_auth_cb_t auth;
	/**< Systemwide auth token management. For set, content may be appended
	 * incrementally safely.  For get, content may be read out in arbitrary
	 * fragments using \p ofs. */
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
 * \param ofs: offset in source to copy from
 * \param buf: where to store result, or NULL
 * \param buflen: size of buf
 * \param flags: how to write the result
 *
 * Attempts to fill buf with the requested system auth token.  If flags has
 * LWSSYSGAUTH_HEX set, then the auth token is written as pairs of hex chars
 * for each byte.  If not set, written as 1 byte per byte binary.
 *
 * If buf is NULL, returns <= 0 if auth token is not set or > 0 if set, without
 * writing anything.  *buflen is still set to the size of the auth token.
 */
LWS_EXTERN LWS_VISIBLE int
lws_system_get_auth(struct lws_context *context, int idx, size_t ofs,
		    uint8_t *buf, size_t buflen, int flags);

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

/**
 * lws_system_context_from_system_mgr() - return context from system state mgr
 *
 * \param mgr: pointer to specifically the system state mgr
 *
 * Returns the context from the system state mgr.  Helper since the lws_context
 * is opaque.
 */
LWS_EXTERN LWS_VISIBLE struct lws_context *
lws_system_context_from_system_mgr(lws_state_manager_t *mgr);

typedef int (*dhcpc_cb_t)(void *opaque, int af, uint8_t *ip, int ip_len);

/**
 * lws_dhcpc_request() - add a network interface to dhcpc management
 *
 * \param c: the lws_context
 * \param i: the interface name, like "eth0"
 * \param af: address family
 * \param cb: the change callback
 * \param opaque: opaque pointer given to the callback
 *
 * Register a network interface as being managed by DHCP.  lws will proceed to
 * try to acquire an IP.  Requires LWS_WITH_SYS_DHCP_CLIENT at cmake.
 */
int
lws_dhcpc_request(struct lws_context *c, const char *i, int af, dhcpc_cb_t cb,
		void *opaque);

/**
 * lws_dhcpc_remove() - remove a network interface to dhcpc management
 *
 * \param context: the lws_context
 * \param iface: the interface name, like "eth0"
 *
 * Remove handling of the network interface from dhcp.
 */
int
lws_dhcpc_remove(struct lws_context *context, const char *iface);

/**
 * lws_dhcpc_status() - has any interface reached BOUND state
 *
 * \param context: the lws_context
 * \param sa46: set to a DNS server from a bound interface, or NULL
 *
 * Returns 1 if any network interface managed by dhcpc has reached the BOUND
 * state (has acquired an IP, gateway and DNS server), otherwise 0.
 */
int
lws_dhcpc_status(struct lws_context *context, lws_sockaddr46 *sa46);
