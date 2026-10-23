/*
 * lws-minimal-http-server-sse
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http server that can serve both normal static
 * content and server-side event connections.
 *
 * To keep it simple, it serves the static stuff from the subdirectory
 * "./mount-origin" of the directory it was started in.
 *
 * You can change that by changing mount.origin below.
 *
 * The per-vhost data below is shared by the lws service thread and the
 * "spam" threads.  The rules are:
 *
 *  - connections are only ever touched by lws apis from the lws service
 *    thread.  The only lws api that is safe to call from another thread is
 *    lws_cancel_service().
 *
 *  - the lock covers the ringbuffer, the connections' tails in it, and the
 *    membership of the list of connections, which the spam threads look at.
 *    Only the service thread changes the list, so it can walk it without the
 *    lock.
 *
 *  - nothing calls into lws while holding the lock, so it can't get mixed
 *    up with lws' own locks.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_D,
	LWS_SW_PORT,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_PORT]	= { "--port",          "Port to listen on (default 7681)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <string.h>
#include <stdlib.h>
#include <signal.h>
#if defined(WIN32)
#define HAVE_STRUCT_TIMESPEC
#if defined(pid_t)
#undef pid_t
#endif
#endif
#include <pthread.h>
#include <time.h>

/* one of these created for each message in the ringbuffer */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
};

/*
 * Unlike ws, http is a stateless protocol.  This pss only exists for the
 * duration of a single http transaction.  With http/1.1 keep-alive and http/2,
 * that is unrelated to (shorter than) the lifetime of the network connection.
 */
struct pss {
	lws_dll2_t list; /* {lock_ring} in vhd->pss_list */
	struct lws *wsi;
	uint32_t tail; /* {lock_ring} */
};

/* one of these is created for each vhost our protocol is used with */

struct vhd {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	lws_dll2_owner_t pss_list; /* {lock_ring} live pss */

	pthread_t pthread_spam[2];
	int count_spam; /* how many spam threads we started */

	pthread_mutex_t lock_ring; /* serialize access to the ring buffer */
	struct lws_ring *ring; /* {lock_ring} ringbuffer holding unsent messages */
	char finished; /* {lock_ring} */
};

static struct lws_context *context;

#if defined(WIN32)
static void usleep(unsigned long l) { Sleep(l / 1000); }
#endif


/*
 * Destroys the message when everyone has had a copy of it.  This runs under
 * both lws service and "spam threads" contexts, serialized by vhd->lock_ring.
 */

static void
__minimal_destroy_message(void *_msg)
{
	struct msg *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

/*
 * {lock_ring} must be held.  Ringbuffer elements before the oldest tail of
 * any connection have been sent to everybody and can be freed.
 */

static void
__minimal_update_oldest_tail(struct vhd *vhd)
{
	struct pss *oldest = NULL;
	uint32_t most = 0, w;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->pss_list)) {
		struct pss *pss = lws_container_of(d, struct pss, list);

		w = (uint32_t)lws_ring_get_count_waiting_elements(vhd->ring,
								  &pss->tail);
		if (!oldest || w > most) {
			most = w;
			oldest = pss;
		}
	} lws_end_foreach_dll(d);

	if (oldest)
		lws_ring_update_oldest_tail(vhd->ring, oldest->tail);
}

/* is anything waiting to be sent to this connection? */

static int
minimal_behind(struct vhd *vhd, struct pss *pss)
{
	int behind;

	pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
	behind = !!lws_ring_get_element(vhd->ring, &pss->tail);
	pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

	return behind;
}

/*
 * This runs under the "spam thread" thread context only.
 *
 * We spawn two threads that generate messages with this.
 *
 */

static void *
thread_spam(void *d)
{
	struct vhd *vhd = (struct vhd *)d;
	struct msg amsg;
	int len = 128, index = 1, n, whoami = 0, finished, added;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++)
		if (pthread_equal(pthread_self(), vhd->pthread_spam[n]))
			whoami = n + 1;

	do {
		added = 0;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */

		/* don't generate output if nobody connected */
		if (!vhd->pss_list.count)
			goto wait_unlock;

		/* only create if space in ringbuffer */
		n = (int)lws_ring_get_count_free_elements(vhd->ring);
		if (!n) {
			lwsl_user("dropping!\n");
			goto wait_unlock;
		}

		amsg.payload = malloc((unsigned int)len);
		if (!amsg.payload) {
			lwsl_user("OOM: dropping\n");
			goto wait_unlock;
		}
		n = lws_snprintf((char *)amsg.payload, (unsigned int)len,
			         "%s: tid: %d, msg: %d", __func__, whoami, index++);
		amsg.len = (unsigned int)n;
		n = (int)lws_ring_insert(vhd->ring, &amsg, 1);
		if (n != 1) {
			__minimal_destroy_message(&amsg);
			lwsl_user("dropping!\n");
		} else
			added = 1;

wait_unlock:
		finished = vhd->finished;
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		if (added)
			/*
			 * This will cause a LWS_CALLBACK_EVENT_WAIT_CANCELLED
			 * in the lws service thread context.
			 */
			lws_cancel_service(vhd->context);

		if (!finished)
			/* rand() would make more sense but coverity shrieks */
			usleep((useconds_t)(100000 + (time(NULL) & 0xffff)));

	} while (!finished);

	lwsl_notice("thread_spam %d exiting\n", whoami);

	pthread_exit(NULL);

	return NULL;
}


/* this runs under the lws service thread context only */

static int
callback_sse(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(
			lws_get_vhost(wsi), lws_get_protocol(wsi));
	uint8_t buf[LWS_PRE + LWS_RECOMMENDED_MIN_HEADER_SPACE],
		*start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	const struct msg *pmsg;
	void *retval;
	int n, more;

	switch (reason) {

	/* --- vhost protocol lifecycle --- */

	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd));
		if (!vhd)
			return 1;
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		pthread_mutex_init(&vhd->lock_ring, NULL);

		vhd->ring = lws_ring_create(sizeof(struct msg), 8,
					    __minimal_destroy_message);
		if (!vhd->ring) {
			lwsl_err("%s: failed to create ring\n", __func__);
			goto init_fail;
		}

		/* start the content-creating threads */

		for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++) {
			if (pthread_create(&vhd->pthread_spam[n], NULL,
					   thread_spam, vhd)) {
				lwsl_err("thread creation failed\n");
				goto init_fail;
			}
			vhd->count_spam++;
		}

		return 0;

init_fail:
		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		vhd->finished = 1;
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		/* only join the threads we actually started */
		for (n = 0; n < vhd->count_spam; n++)
			pthread_join(vhd->pthread_spam[n], &retval);
		vhd->count_spam = 0;

		if (vhd->ring)
			lws_ring_destroy(vhd->ring);
		vhd->ring = NULL;

		pthread_mutex_destroy(&vhd->lock_ring);
		return 1;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd || !vhd->ring)
			/* init failed and cleaned up after itself */
			return 0;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		vhd->finished = 1;
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		for (n = 0; n < vhd->count_spam; n++)
			pthread_join(vhd->pthread_spam[n], &retval);

		if (vhd->ring)
			lws_ring_destroy(vhd->ring);

		pthread_mutex_destroy(&vhd->lock_ring);
		return 0;

	/* --- http connection lifecycle --- */

	case LWS_CALLBACK_HTTP:
		/*
		 * `in` contains the url part after our mountpoint /sse, if any
		 * you can use this to determine what data to return and store
		 * that in the pss
		 */
		lwsl_info("%s: LWS_CALLBACK_HTTP: '%s'\n", __func__,
			  (const char *)in);

		if (!vhd || !vhd->ring)
			return 1;

		/* SSE requires a http OK response with this content-type */

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/event-stream",
						LWS_ILLEGAL_HTTP_CONTENT_LEN,
						&p, end))
			return 1;

		if (lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		pss->wsi = wsi;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		/* add ourselves to the list of live pss held in the vhd */
		lws_dll2_add_tail(&pss->list, &vhd->pss_list);
		pss->tail = lws_ring_get_oldest_tail(vhd->ring);
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		/*
		 * This tells lws we are no longer a normal http stream,
		 * but are an "immortal" (plus or minus whatever timeout you
		 * set on it afterwards) SSE stream.  In http/2 case that also
		 * stops idle timeouts being applied to the network connection
		 * while this wsi is still open.
		 */
		lws_http_mark_sse(wsi);

		/* write the body separately */

		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (!vhd || !vhd->ring)
			return 0;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		/* remove our closing pss from the list of live pss */
		if (!lws_dll2_is_detached(&pss->list)) {
			lws_dll2_remove(&pss->list);
			/* we may have been the one holding the oldest tail */
			__minimal_update_oldest_tail(vhd);
		}
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */
		return 0;

	/* --- data transfer --- */

	case LWS_CALLBACK_HTTP_WRITEABLE:

		lwsl_info("%s: LWS_CALLBACK_HTTP_WRITEABLE\n", __func__);

		if (!vhd || !vhd->ring || lws_dll2_is_detached(&pss->list))
			break;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */

		pmsg = lws_ring_get_element(vhd->ring, &pss->tail);
		if (!pmsg) {
			pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock - */
			break;
		}

		/* take our copy of it to send, outside the lock */
		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "data: %.*s\x0d\x0a\x0d\x0a",
				  (int)pmsg->len, (const char *)pmsg->payload);

		/* we are done with that element... */
		lws_ring_consume(vhd->ring, &pss->tail, NULL, 1);
		/* ...if it was the last one waiting for anybody, free it */
		__minimal_update_oldest_tail(vhd);

		more = !!lws_ring_get_element(vhd->ring, &pss->tail);

		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		if (lws_write(wsi, (uint8_t *)start, lws_ptr_diff_size_t(p, start),
			      LWS_WRITE_HTTP) != lws_ptr_diff(p, start))
			return 1;

		if (more)
			/* come back as soon as we can write more */
			lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
		if (!vhd || !vhd->ring)
			break;
		/*
		 * When the "spam" threads add a message to the ringbuffer,
		 * they create this event in the lws service thread context
		 * using lws_cancel_service().
		 *
		 * We respond by scheduling a writable callback for all
		 * connected clients with something waiting for them.
		 *
		 * Only this thread changes the list, and we are on it, so we
		 * can walk it without the lock, and without holding the lock
		 * while we call into lws.
		 */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&vhd->pss_list)) {
			struct pss *ps = lws_container_of(d, struct pss, list);

			if (minimal_behind(vhd, ps))
				lws_callback_on_writable(ps->wsi);
		} lws_end_foreach_dll(d);
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "sse", callback_sse, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* override the default mount for /sse in the URL space */

static const struct lws_http_mount mount_sse = {
	.mountpoint		= "/sse",		/* mountpoint URL */
	.protocol		= "sse",
	.origin_protocol	= LWSMPRO_CALLBACK,	/* dynamic */
	.mountpoint_len		= 4,		  	/* char count */
};

/* default mount serves the URL space from ./mount-origin */

static const struct lws_http_mount mount = {
	.mount_next		= &mount_sse,		/* linked-list "next" */
	.mountpoint		= "/",			/* mountpoint URL */
	.origin			= "./mount-origin",	/* serve from dir */
	.def			= "index.html",		/* default filename */
	.origin_protocol	= LWSMPRO_FILE,		/* files in a dir */
	.mountpoint_len		= 1,			/* char count */
};

void sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}


	signal(SIGINT, sigint_handler);


	lwsl_user("LWS minimal http Server-Side Events + ring | visit http://localhost:7681\n");

	lws_context_info_defaults(&info, NULL);
	/* a server: size the fds tables to the process limit */
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = 7681;
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw))) {
		int pt = atoi(p);

		if (pt <= 0 || pt > 65535) {
			lwsl_err("Port %d is outside valid 16-bit range\n", pt);
			return 1;
		}
		info.port = pt;
	}
	info.protocols = protocols;
	info.mounts = &mount;
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
