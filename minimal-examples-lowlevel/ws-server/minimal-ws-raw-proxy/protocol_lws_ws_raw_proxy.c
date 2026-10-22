/*
 * ws protocol handler plugins for "lws-ws-raw-ws" and "lws-ws-raw-raw"
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This is a ws (server) -> raw (client) proxy,  it's a ws server that accepts
 * connections, creates an onward client connection to some other no-protocol
 * server, eg, nc -l 127.0.0.1 1234
 *
 * The idea is to show the general approach for making async proxies using lws
 * that are robust and valgrind-clean.
 *
 * There's no vhd or pss on either side.  Instead when the ws server gets an
 * incoming connection and negotiates the ws link, he creates an object
 * representing the proxied connection, it is not destroyed automatically when
 * any particular wsi is closed, instead the last wsi that is part of the
 * proxied connection destroys it when he is closed.  Whichever side closes
 * first, including the onward connection failing to connect, closes the
 * other side, after letting it send what is already queued for it.
 *
 * Each side can only be sent to as fast as its peer reads.  So we don't let
 * what is waiting to be sent to one side grow without limit: when more than
 * PROXY_QUEUE_HIGH bytes are waiting, we stop reading from the other side
 * (lws_rx_flow_control()), until it has drained below PROXY_QUEUE_LOW.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

/* stop reading from a side when more than this is waiting to go the other */
#define PROXY_QUEUE_HIGH	(64 * 1024)
/* ...and start reading from it again when less than this is waiting */
#define PROXY_QUEUE_LOW		(16 * 1024)

/* where the onward raw connections go */

static struct {
	const char		*address;
	int			port;
} proxy_backend = { "127.0.0.1", 1234 };

/* one of these created for each pending message that is to be forwarded */

typedef struct proxy_msg {
	lws_dll2_t		list;
	size_t			len;
	/*
	 * the packet content is overallocated here, if p is a pointer to
	 * this struct, you can get a pointer to the message contents by
	 * ((uint8_t)&p[1]) + LWS_PRE.
	 *
	 * Notice we additionally take care to overallocate LWS_PRE before the
	 * actual message data, so we can simplify sending it.
	 */
} proxy_msg_t;

/* the two directions a proxy_conn forwards in */

enum {
	PROXY_TO_WS,
	PROXY_TO_RAW,
};

/* what is waiting to be sent in one direction */

typedef struct proxy_queue {
	lws_dll2_owner_t	owner;		/* proxy_msg_t waiting */
	size_t			bytes;		/* total of their len */
	char			src_paused;	/* we stopped reading its source */
} proxy_queue_t;

/*
 * One of these is created when a inbound ws connection joins, it represents
 * the proxy action provoked by that.
 */

typedef struct proxy_conn {
	struct lws		*wsi_ws; /* wsi for the inbound ws conn */
	struct lws		*wsi_raw; /* wsi for the outbound raw conn */

	proxy_queue_t		q[2]; /* PROXY_TO_WS, PROXY_TO_RAW */
} proxy_conn_t;

static int
proxy_other_dir(int dir)
{
	return dir == PROXY_TO_WS ? PROXY_TO_RAW : PROXY_TO_WS;
}

/* the wsi a queue's messages come from */

static struct lws *
proxy_queue_src(proxy_conn_t *pc, int dir)
{
	return dir == PROXY_TO_WS ? pc->wsi_raw : pc->wsi_ws;
}

/* the wsi a queue's messages go to */

static struct lws *
proxy_queue_sink(proxy_conn_t *pc, int dir)
{
	return dir == PROXY_TO_WS ? pc->wsi_ws : pc->wsi_raw;
}

static int
proxy_ws_raw_msg_destroy(struct lws_dll2 *d, void *user)
{
	proxy_msg_t *msg = lws_container_of(d, proxy_msg_t, list);

	lws_dll2_remove(d);
	free(msg);

	return 0;
}

static void
proxy_queue_destroy(proxy_conn_t *pc, int dir)
{
	lws_dll2_foreach_safe(&pc->q[dir].owner, NULL,
			      proxy_ws_raw_msg_destroy);
	pc->q[dir].bytes = 0;
}

/*
 * Queue a copy of what one side sent us, to be sent to the other side, and
 * stop reading from the sending side if too much is waiting now.
 */

static int
proxy_queue_add(proxy_conn_t *pc, int dir, const void *in, size_t len)
{
	proxy_queue_t *q = &pc->q[dir];
	struct lws *src = proxy_queue_src(pc, dir),
		   *sink = proxy_queue_sink(pc, dir);
	proxy_msg_t *msg;

	/* notice we over-allocate by LWS_PRE + rx len */
	msg = (proxy_msg_t *)malloc(sizeof(*msg) + LWS_PRE + len);
	if (!msg) {
		lwsl_user("OOM: dropping\n");
		return 1;
	}

	memset(msg, 0, sizeof(*msg));
	msg->len = len;
	memcpy((uint8_t *)&msg[1] + LWS_PRE, in, len);

	/* add us on to the list of packets to send to the other side */
	lws_dll2_add_tail(&msg->list, &q->owner);
	q->bytes += len;

	if (!q->src_paused && q->bytes > PROXY_QUEUE_HIGH && src) {
		/* the other side is behind: stop taking more for it */
		q->src_paused = 1;
		lws_rx_flow_control(src, 0);
	}

	/* ask to send on the other side (the raw one may still connect) */
	if (sink)
		lws_callback_on_writable(sink);

	return 0;
}

/*
 * Send the next message waiting in the queue to its side, which is writeable.
 */

static int
proxy_queue_send(proxy_conn_t *pc, int dir, struct lws *wsi)
{
	proxy_queue_t *q = &pc->q[dir];
	struct lws *src = proxy_queue_src(pc, dir);
	proxy_msg_t *msg;
	uint8_t *data;
	int m, a;

	if (!lws_dll2_get_head(&q->owner))
		return 0;

	msg = lws_container_of(lws_dll2_get_head(&q->owner), proxy_msg_t, list);
	data = (uint8_t *)&msg[1] + LWS_PRE;

	/*
	 * What the raw side sent us is a byte stream, cut wherever its reads
	 * happened to end, so it is no kind of text message: it may not be
	 * UTF-8 at all, or end partway through a character.  A browser must
	 * fail its connection on a TEXT message that is not valid UTF-8, so
	 * pass it on as BINARY; the page decodes the stream as UTF-8 itself.
	 *
	 * Notice we allowed for LWS_PRE in the payload already
	 */
	m = lws_write(wsi, data, msg->len, dir == PROXY_TO_WS ?
					LWS_WRITE_BINARY : LWS_WRITE_RAW);
	a = (int)msg->len;
	q->bytes -= msg->len;
	lws_dll2_remove(&msg->list);
	free(msg);

	if (m < a) {
		lwsl_err("ERROR %d writing to %s\n", m,
			 dir == PROXY_TO_WS ? "ws" : "raw");
		return -1;
	}

	if (q->src_paused && q->bytes < PROXY_QUEUE_LOW) {
		/* we caught up enough: take more from the other side */
		q->src_paused = 0;
		if (src)
			lws_rx_flow_control(src, 1);
	}

	/*
	 * If more to do...
	 */
	if (lws_dll2_get_head(&q->owner))
		lws_callback_on_writable(wsi);

	return 0;
}

/*
 * One side of the proxy is going away.  If the other side is still there, it
 * may send what is already queued for it, but no more than 3s more, then it
 * closes too; it destroys the proxy_conn when it goes.  If the other side is
 * already gone, we are the last one using the proxy_conn, so we destroy it.
 *
 * dir is the direction towards the side that is going away.
 */

static void
proxy_side_gone(struct lws *wsi, proxy_conn_t *pc, int dir)
{
	int odir = proxy_other_dir(dir);
	struct lws *other;

	/*
	 * Clean up any pending messages to us that are never going to get
	 * delivered now, we are in the middle of closing
	 */
	proxy_queue_destroy(pc, dir);

	/* Remove our pointer from the proxy_conn... we are going */
	if (dir == PROXY_TO_WS)
		pc->wsi_ws = NULL;
	else
		pc->wsi_raw = NULL;
	lws_set_opaque_user_data(wsi, NULL);

	other = proxy_queue_sink(pc, odir);
	if (!other) {
		/*
		 * The other side never got started or is already closed...
		 * then we are the last guy still holding on to the
		 * proxy_conn... and we're going away, so let's destroy it
		 */
		proxy_queue_destroy(pc, odir);
		free(pc);
		return;
	}

	/* nothing more is coming for it, so don't hold its rx back */
	if (pc->q[dir].src_paused) {
		pc->q[dir].src_paused = 0;
		lws_rx_flow_control(other, 1);
	}

	/*
	 * Other side still alive... does he have stuff left to deliver?
	 */
	if (lws_dll2_get_head(&pc->q[odir].owner)) {
		/*
		 * Yes, let him get on with trying to send the remaining
		 * pieces... but put a time limit on how hard he will try now
		 * our side is disappearing... give him 3s
		 */
		lws_set_timeout(other, PENDING_TIMEOUT_KILLED_BY_PROXY_CLIENT_CLOSE,
				3);
		return;
	}

	/*
	 * Other side doesn't have anything left to do, let's close him right
	 * after this, he will take care to destroy the proxy_conn when he goes
	 * down after he sees we have already been closed
	 */
	lws_wsi_close(other, LWS_TO_KILL_ASYNC);
}

/*
 * First the ws server side
 */

static int
callback_proxy_ws_server(struct lws *wsi, enum lws_callback_reasons reason,
			 void *user, void *in, size_t len)
{
	proxy_conn_t *pc = (proxy_conn_t *)lws_get_opaque_user_data(wsi);
	struct lws_client_connect_info i;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		/* so let's create the proxy connection object */
		pc = malloc(sizeof(*pc));
		if (!pc)
			return -1;
		memset(pc, 0, sizeof(*pc));

		/* mark this accepted ws connection with the proxy conn obj */
		lws_set_opaque_user_data(wsi, pc);
		/* tell the proxy conn object that we are the ws side of it */
		pc->wsi_ws = wsi;

		/*
		 * For this example proxy, our job is to create a new, onward,
		 * raw client connection to proxy stuff on to
		 */

		memset(&i, 0, sizeof(i));

		i.method = "RAW";
		i.context = lws_get_context(wsi);
		/* our vhost has the protocol for the raw side too */
		i.vhost = lws_get_vhost(wsi);
		i.port = proxy_backend.port;
		i.address = proxy_backend.address;
		i.ssl_connection = 0;
		i.local_protocol_name = "lws-ws-raw-raw";

		/* also mark the onward, raw client conn with the proxy_conn */
		i.opaque_user_data = pc;
		/* if it succeeds, set the wsi into the proxy_conn */
		i.pwsi = &pc->wsi_raw;

		if (!lws_client_connect_via_info(&i)) {
			lwsl_warn("%s: onward connection failed\n", __func__);
			/*
			 * hang up on the ws client, triggering _CLOSE flow,
			 * which destroys pc since there is no raw side
			 */
			pc->wsi_raw = NULL;
			return -1;
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (pc)
			proxy_side_gone(wsi, pc, PROXY_TO_WS);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (pc && proxy_queue_send(pc, PROXY_TO_WS, wsi))
			return -1;
		break;

	case LWS_CALLBACK_RECEIVE:
		/*
		 * The raw side is a byte stream, so we pass on what the ws
		 * client sends as it comes, whatever ws message boundaries it
		 * had.  Until the raw side connects, it waits in the queue.
		 */
		if (!pc || !pc->wsi_raw)
			/* the raw side is gone, and we are closing */
			break;

		if (proxy_queue_add(pc, PROXY_TO_RAW, in, len))
			return -1;
		break;

	default:
		break;
	}

	return 0;
}

/*
 * Then the onward, raw client side
 */

static int
callback_proxy_raw_client(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	proxy_conn_t *pc = (proxy_conn_t *)lws_get_opaque_user_data(wsi);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_warn("%s: onward raw connection failed: %s\n", __func__,
			  in ? (const char *)in : "");
		/*
		 * We never connected, so there's no RAW_CLOSE coming: this is
		 * our only chance to let go of the proxy_conn, and if the ws
		 * side is still up, it has nothing to talk to: close it too
		 */
		if (pc)
			proxy_side_gone(wsi, pc, PROXY_TO_RAW);
		break;

	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_user("LWS_CALLBACK_RAW_ADOPT\n");
		if (!pc)
			return -1;
		pc->wsi_raw = wsi;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		lwsl_user("LWS_CALLBACK_RAW_CLOSE\n");
		if (pc)
			proxy_side_gone(wsi, pc, PROXY_TO_RAW);
		break;

	case LWS_CALLBACK_RAW_RX:
		lwsl_info("LWS_CALLBACK_RAW_RX (%d)\n", (int)len);
		if (!pc || !pc->wsi_ws)
			break;

		if (proxy_queue_add(pc, PROXY_TO_WS, in, len))
			return -1;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pc && proxy_queue_send(pc, PROXY_TO_RAW, wsi))
			return -1;
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_WS_RAW_PROXY \
	{ "lws-ws-raw-ws", callback_proxy_ws_server, 0, 1024, 0, NULL, 0 }, \
	{ "lws-ws-raw-raw", callback_proxy_raw_client, 0, 1024, 0, NULL, 0 }
