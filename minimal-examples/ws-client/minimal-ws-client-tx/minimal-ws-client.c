/*
 * lws-minimal-ws-client-tx
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a ws "publisher" to go with the minimal-ws-broker
 * example.
 *
 * Two threads are spawned that produce messages to be sent to the broker,
 * via a local ringbuffer.  Locking is provided to make ringbuffer access
 * threadsafe.
 *
 * When a nailed-up client connection to the broker is established, the
 * ringbuffer is sent to the broker, which distributes the events to all
 * connected clients.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

static int interrupted;

/* one of these created for each message */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
};

struct per_vhost_data__minimal {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	pthread_t pthread_spam[2];

	pthread_mutex_t lock_ring; /* serialize access to the ring buffer */
	struct lws_ring *ring; /* ringbuffer holding unsent messages */
	uint32_t tail;

	struct lws_client_connect_info i;
	struct lws *client_wsi;

	int counter;
	char finished;
	char established;
};

static void
__minimal_destroy_message(void *_msg)
{
	struct msg *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

static void *
thread_spam(void *d)
{
	struct per_vhost_data__minimal *vhd =
			(struct per_vhost_data__minimal *)d;
	struct msg amsg;
	int len = 128, index = 1, n;

	do {
		/* don't generate output if client not connected */
		if (!vhd->established)
			goto wait;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */

		/* only create if space in ringbuffer */
		n = (int)lws_ring_get_count_free_elements(vhd->ring);
		if (!n) {
			lwsl_user("dropping!\n");
			goto wait_unlock;
		}

		amsg.payload = malloc(LWS_PRE + len);
		if (!amsg.payload) {
			lwsl_user("OOM: dropping\n");
			goto wait_unlock;
		}
		n = lws_snprintf((char *)amsg.payload + LWS_PRE, len,
			         "tid: %p, msg: %d",
			         (void *)pthread_self(), index++);
		amsg.len = n;
		n = lws_ring_insert(vhd->ring, &amsg, 1);
		if (n != 1) {
			__minimal_destroy_message(&amsg);
			lwsl_user("dropping!\n");
		} else
			/*
			 * This will cause a LWS_CALLBACK_EVENT_WAIT_CANCELLED
			 * in the lws service thread context.
			 */
			lws_cancel_service(vhd->context);

wait_unlock:
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

wait:
		usleep(100000);

	} while (!vhd->finished);

	lwsl_notice("thread_spam %p exiting\n", (void *)pthread_self());

	pthread_exit(NULL);
}

static int
connect_client(struct per_vhost_data__minimal *vhd)
{
	vhd->i.context = vhd->context;
	vhd->i.port = 7681;
	vhd->i.address = "localhost";
	vhd->i.path = "/publisher";
	vhd->i.host = vhd->i.address;
	vhd->i.origin = vhd->i.address;
	vhd->i.ssl_connection = 0;

	vhd->i.protocol = "lws-minimal-broker";
	vhd->i.pwsi = &vhd->client_wsi;

	return !lws_client_connect_via_info(&vhd->i);
}

static int
callback_minimal_broker(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct per_vhost_data__minimal *vhd =
			(struct per_vhost_data__minimal *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	const struct msg *pmsg;
	void *retval;
	int n, m, r = 0;

	switch (reason) {

	/* --- protocol lifecycle callbacks --- */

	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__minimal));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		vhd->ring = lws_ring_create(sizeof(struct msg), 8,
					    __minimal_destroy_message);
		if (!vhd->ring)
			return 1;

		pthread_mutex_init(&vhd->lock_ring, NULL);

		/* start the content-creating threads */

		for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++)
			if (pthread_create(&vhd->pthread_spam[n], NULL,
					   thread_spam, vhd)) {
				lwsl_err("thread creation failed\n");
				r = 1;
				goto init_fail;
			}

		if (connect_client(vhd))
			lws_timed_callback_vh_protocol(vhd->vhost,
					vhd->protocol, LWS_CALLBACK_USER, 1);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
init_fail:
		vhd->finished = 1;
		for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++)
			if (vhd->pthread_spam[n])
				pthread_join(vhd->pthread_spam[n], &retval);

		if (vhd->ring)
			lws_ring_destroy(vhd->ring);

		pthread_mutex_destroy(&vhd->lock_ring);

		return r;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		vhd->client_wsi = NULL;
		lws_timed_callback_vh_protocol(vhd->vhost,
				vhd->protocol, LWS_CALLBACK_USER, 1);
		break;

	/* --- client callbacks --- */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_user("%s: established\n", __func__);
		vhd->established = 1;
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		pmsg = lws_ring_get_element(vhd->ring, &vhd->tail);
		if (!pmsg)
			goto skip;

		/* notice we allowed for LWS_PRE in the payload already */
		m = lws_write(wsi, pmsg->payload + LWS_PRE, pmsg->len,
			      LWS_WRITE_TEXT);
		if (m < (int)pmsg->len) {
			pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock */
			lwsl_err("ERROR %d writing to ws socket\n", m);
			return -1;
		}

		lws_ring_consume_single_tail(vhd->ring, &vhd->tail, 1);

		/* more to do for us? */
		if (lws_ring_get_element(vhd->ring, &vhd->tail))
			/* come back as soon as we can write more */
			lws_callback_on_writable(wsi);

skip:
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		vhd->client_wsi = NULL;
		vhd->established = 0;
		lws_timed_callback_vh_protocol(vhd->vhost, vhd->protocol,
					       LWS_CALLBACK_USER, 1);
		break;

	case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
		/*
		 * When the "spam" threads add a message to the ringbuffer,
		 * they create this event in the lws service thread context
		 * using lws_cancel_service().
		 *
		 * We respond by scheduling a writable callback for the
		 * connected client, if any.
		 */
		if (vhd->client_wsi && vhd->established)
			lws_callback_on_writable(vhd->client_wsi);
		break;

	/* rate-limited client connect retries */

	case LWS_CALLBACK_USER:
		lwsl_notice("%s: LWS_CALLBACK_USER\n", __func__);
		if (connect_client(vhd))
			lws_timed_callback_vh_protocol(vhd->vhost,
						vhd->protocol,
						LWS_CALLBACK_USER, 1);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"lws-minimal-broker",
		callback_minimal_broker,
		0,
		0,
	},
	{ NULL, NULL, 0, 0 }
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal ws client tx\n");
	lwsl_user("  Run minimal-ws-broker and browse to that\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
	info.protocols = protocols;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 1000);

	lws_context_destroy(context);
	lwsl_user("Completed\n");

	return 0;
}
