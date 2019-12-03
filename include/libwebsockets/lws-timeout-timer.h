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

/*! \defgroup timeout Connection timeouts

    APIs related to setting connection timeouts
*/
//@{

/*
 * NOTE: These public enums are part of the abi.  If you want to add one,
 * add it at where specified so existing users are unaffected.
 */
enum pending_timeout {
	NO_PENDING_TIMEOUT					=  0,
	PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE			=  1,
	PENDING_TIMEOUT_AWAITING_CONNECT_RESPONSE		=  2,
	PENDING_TIMEOUT_ESTABLISH_WITH_SERVER			=  3,
	PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE		=  4,
	PENDING_TIMEOUT_AWAITING_PING				=  5,
	PENDING_TIMEOUT_CLOSE_ACK				=  6,
	PENDING_TIMEOUT_UNUSED1					=  7,
	PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE			=  8,
	PENDING_TIMEOUT_SSL_ACCEPT				=  9,
	PENDING_TIMEOUT_HTTP_CONTENT				= 10,
	PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND			= 11,
	PENDING_FLUSH_STORED_SEND_BEFORE_CLOSE			= 12,
	PENDING_TIMEOUT_SHUTDOWN_FLUSH				= 13,
	PENDING_TIMEOUT_CGI					= 14,
	PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE			= 15,
	PENDING_TIMEOUT_WS_PONG_CHECK_SEND_PING			= 16,
	PENDING_TIMEOUT_WS_PONG_CHECK_GET_PONG			= 17,
	PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD			= 18,
	PENDING_TIMEOUT_AWAITING_SOCKS_GREETING_REPLY	        = 19,
	PENDING_TIMEOUT_AWAITING_SOCKS_CONNECT_REPLY		= 20,
	PENDING_TIMEOUT_AWAITING_SOCKS_AUTH_REPLY		= 21,
	PENDING_TIMEOUT_KILLED_BY_SSL_INFO			= 22,
	PENDING_TIMEOUT_KILLED_BY_PARENT			= 23,
	PENDING_TIMEOUT_CLOSE_SEND				= 24,
	PENDING_TIMEOUT_HOLDING_AH				= 25,
	PENDING_TIMEOUT_UDP_IDLE				= 26,
	PENDING_TIMEOUT_CLIENT_CONN_IDLE			= 27,
	PENDING_TIMEOUT_LAGGING					= 28,
	PENDING_TIMEOUT_THREADPOOL				= 29,
	PENDING_TIMEOUT_THREADPOOL_TASK				= 30,
	PENDING_TIMEOUT_KILLED_BY_PROXY_CLIENT_CLOSE		= 31,
	PENDING_TIMEOUT_USER_OK					= 32,

	/****** add new things just above ---^ ******/

	PENDING_TIMEOUT_USER_REASON_BASE			= 1000
};

#define lws_time_in_microseconds lws_now_usecs

#define LWS_TO_KILL_ASYNC -1
/**< If LWS_TO_KILL_ASYNC is given as the timeout sec in a lws_set_timeout()
 * call, then the connection is marked to be killed at the next timeout
 * check.  This is how you should force-close the wsi being serviced if
 * you are doing it outside the callback (where you should close by nonzero
 * return).
 */
#define LWS_TO_KILL_SYNC -2
/**< If LWS_TO_KILL_SYNC is given as the timeout sec in a lws_set_timeout()
 * call, then the connection is closed before returning (which may delete
 * the wsi).  This should only be used where the wsi being closed is not the
 * wsi currently being serviced.
 */
/**
 * lws_set_timeout() - marks the wsi as subject to a timeout some seconds hence
 *
 * \param wsi:	Websocket connection instance
 * \param reason:	timeout reason
 * \param secs:	how many seconds.  You may set to LWS_TO_KILL_ASYNC to
 *		force the connection to timeout at the next opportunity, or
 *		LWS_TO_KILL_SYNC to close it synchronously if you know the
 *		wsi is not the one currently being serviced.
 */
LWS_VISIBLE LWS_EXTERN void
lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs);

/**
 * lws_set_timeout_us() - marks the wsi as subject to a timeout some us hence
 *
 * \param wsi:	Websocket connection instance
 * \param reason:	timeout reason
 * \param us:	0 removes the timeout, otherwise number of us to wait
 *
 * Higher-resolution version of lws_set_timeout().  Actual resolution depends
 * on platform and load, usually ms.
 */
void
lws_set_timeout_us(struct lws *wsi, enum pending_timeout reason, lws_usec_t us);

#define LWS_SET_TIMER_USEC_CANCEL ((lws_usec_t)-1ll)
#define LWS_USEC_PER_SEC ((lws_usec_t)1000000)

/**
 * lws_set_timer_usecs() - schedules a callback on the wsi in the future
 *
 * \param wsi:	Websocket connection instance
 * \param usecs:  LWS_SET_TIMER_USEC_CANCEL removes any existing scheduled
 *		  callback, otherwise number of microseconds in the future
 *		  the callback will occur at.
 *
 * NOTE: event loop support for this:
 *
 *  default poll() loop:   yes
 *  libuv event loop:      yes
 *  libev:    not implemented (patch welcome)
 *  libevent: not implemented (patch welcome)
 *
 * After the deadline expires, the wsi will get a callback of type
 * LWS_CALLBACK_TIMER and the timer is exhausted.  The deadline may be
 * continuously deferred by further calls to lws_set_timer_usecs() with a later
 * deadline, or cancelled by lws_set_timer_usecs(wsi, -1).
 *
 * If the timer should repeat, lws_set_timer_usecs() must be called again from
 * LWS_CALLBACK_TIMER.
 *
 * Accuracy depends on the platform and the load on the event loop or system...
 * all that's guaranteed is the callback will come after the requested wait
 * period.
 */
LWS_VISIBLE LWS_EXTERN void
lws_set_timer_usecs(struct lws *wsi, lws_usec_t usecs);

/*
 * lws_timed_callback_vh_protocol() - calls back a protocol on a vhost after
 * 					the specified delay in seconds
 *
 * \param vh:	 the vhost to call back
 * \param protocol: the protocol to call back
 * \param reason: callback reason
 * \param secs:	how many seconds in the future to do the callback.
 *
 * Callback the specified protocol with a fake wsi pointing to the specified
 * vhost and protocol, with the specified reason, at the specified time in the
 * future.
 *
 * Returns 0 if OK or 1 on OOM.
 *
 * In the multithreaded service case, the callback will occur in the same
 * service thread context as the call to this api that requested it.  If it is
 * called from a non-service thread, tsi 0 will handle it.
 */
LWS_VISIBLE LWS_EXTERN int
lws_timed_callback_vh_protocol(struct lws_vhost *vh,
			       const struct lws_protocols *prot,
			       int reason, int secs);

/*
 * lws_timed_callback_vh_protocol_us() - calls back a protocol on a vhost after
 * 					 the specified delay in us
 *
 * \param vh:	 the vhost to call back
 * \param protocol: the protocol to call back
 * \param reason: callback reason
 * \param us:	how many us in the future to do the callback.
 *
 * Callback the specified protocol with a fake wsi pointing to the specified
 * vhost and protocol, with the specified reason, at the specified time in the
 * future.
 *
 * Returns 0 if OK or 1 on OOM.
 *
 * In the multithreaded service case, the callback will occur in the same
 * service thread context as the call to this api that requested it.  If it is
 * called from a non-service thread, tsi 0 will handle it.
 */
LWS_VISIBLE LWS_EXTERN int
lws_timed_callback_vh_protocol_us(struct lws_vhost *vh,
				  const struct lws_protocols *prot, int reason,
				  lws_usec_t us);

struct lws_sorted_usec_list;

typedef void (*sul_cb_t)(struct lws_sorted_usec_list *sul);

typedef struct lws_sorted_usec_list {
	struct lws_dll2 list;	/* simplify the code by keeping this at start */
	sul_cb_t	cb;
	lws_usec_t	us;
} lws_sorted_usec_list_t;


/*
 * lws_sul_schedule() - schedule a callback
 *
 * \param context: the lws_context
 * \param tsi: the thread service index (usually 0)
 * \param sul: pointer to the sul element
 * \param cb: the scheduled callback
 * \param us: the delay before the callback arrives, or
 *		LWS_SET_TIMER_USEC_CANCEL to cancel it.
 *
 * Generic callback-at-a-later time function.  The callback happens on the
 * event loop thread context.
 *
 * Although the api has us resultion, the actual resolution depends on the
 * platform and is commonly 1ms.
 *
 * This doesn't allocate and doesn't fail.
 *
 * You can call it again with another us value to change the delay.
 */
LWS_VISIBLE LWS_EXTERN void
lws_sul_schedule(struct lws_context *context, int tsi,
	         lws_sorted_usec_list_t *sul, sul_cb_t cb, lws_usec_t us);

/*
 * lws_validity_confirmed() - reset the validity timer for a network connection
 *
 * \param wsi: the connection that saw traffic proving the connection valid
 *
 * Network connections are subject to intervals defined by the context, the
 * vhost if server connections, or the client connect info if a client
 * connection.  If the connection goes longer than the specified time since
 * last observing traffic that can only happen if traffic is passing in both
 * directions, then lws will try to create a PING transaction on the network
 * connection.
 *
 * If the connection reaches the specified `.secs_since_valid_hangup` time
 * still without any proof of validity, the connection will be closed.
 *
 * If the PONG comes, or user code observes traffic that satisfies the proof
 * that both directions are passing traffic to the peer and calls this api,
 * the connection validity timer is reset and the scheme repeats.
 */
LWS_VISIBLE LWS_EXTERN void
lws_validity_confirmed(struct lws *wsi);

/*
 * These are not normally needed, they're exported for the case there's code
 * using lws_sul for which lws is an optional link dependency.
 */

LWS_VISIBLE LWS_EXTERN int
__lws_sul_insert(lws_dll2_owner_t *own, lws_sorted_usec_list_t *sul,
		 lws_usec_t us);

LWS_VISIBLE LWS_EXTERN lws_usec_t
__lws_sul_service_ripe(lws_dll2_owner_t *own, lws_usec_t usnow);

///@}
