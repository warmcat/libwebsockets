#include <pthread.h>
#include <systemd/sd-event.h>

#include <private-lib-core.h>
#include "private-lib-event-libs-sdevent.h"

#define pt_to_priv_sd(_pt) ((struct lws_pt_eventlibs_sdevent *)(_pt)->evlib_pt)
#define wsi_to_priv_sd(_w) ((struct lws_wsi_watcher_sdevent *)(_w)->evlib_wsi)

struct lws_context_eventlibs_sdevent {
};

struct lws_pt_eventlibs_sdevent {
    struct lws_context_per_thread *pt;
    struct sd_event *io_loop;
};

struct lws_vh_eventlibs_sdevent {
};

struct lws_wsi_watcher_sdevent {
};

static int init_context_sd(struct lws_context *context, const struct lws_context_creation_info *info) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);

    // extra info, can be removed
    printf("%s(%d) %s info->signal_cb is %p\n", __FILE__, __LINE__, __func__, info->signal_cb);
    printf("%s(%d) %s context->count_threads is %d\n", __FILE__, __LINE__, __func__, context->count_threads);

    return 0;
}

static int destroy_context1_sd(struct lws_context *context) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
    return 0;
}

static int destroy_context2_sd(struct lws_context *context) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
    return 0;
}

static int init_vhost_listen_wsi_sd(struct lws *wsi) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
    return 0;
}

static int init_pt_sd(struct lws_context *context, void *_loop, int tsi) {

    struct lws_context_per_thread *pt = &context->pt[tsi];
    struct lws_pt_eventlibs_sdevent *ptpriv = pt_to_priv_sd(pt);

    struct sd_event *loop = (struct sd_event *)_loop;
    int first = 1;  // we are the first that create and initialize the loop

    ptpriv->pt = pt;

    // make sure we have an event loop
    if (!ptpriv->io_loop) {
        if (!loop) {
            if (sd_event_default(&loop) < 0) {
                lwsl_err("cannot get/create event loop, possibly out-of-memory\n");
                return -1;
            }
            pt->event_loop_foreign = 0;
        } else {
            pt->event_loop_foreign = 1;
        }

        ptpriv->io_loop = loop;

        // TODO for full libwebsockets support, add handling for  LWS_SERVER_OPTION_UV_NO_SIGSEGV_SIGFPE_SPIN

    } else {
        first = 0;  // the loop was initialized before, we do not need to do full initialization
    }

    // initialize accept/read for vhosts
    for (struct lws_vhost *vh = context->vhost_list; vh; vh = vh->vhost_next) {
        // call lws_event_loop_ops->init_vhost_listen_wsi
        if (init_vhost_listen_wsi_sd(vh->lserv_wsi) == -1) {
            return -1;
        }
    }

    if (first) {
        // TODO init sultimer
    }

    return 0;
}

static int wsi_logical_close_sd(struct lws *wsi) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
    return 0;
}

static int check_client_connect_ok_sd(struct lws *wsi) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
    return 0;
}

static void close_handle_manually_sd(struct lws *wsi) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
}

static int sock_accept_sd(struct lws *wsi) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
    return 0;
}

static void io_sd(struct lws *wsi, int flags) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);

    // extra info, can be removed
    printf("%s(%d) %s wsi is %p\n", __FILE__, __LINE__, __func__, wsi);
    printf("%s(%d) %s flags is %x\n", __FILE__, __LINE__, __func__, flags);
}

static void run_pt_sd(struct lws_context *context, int tsi) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
    sleep(1);
}

static void destroy_pt_sd(struct lws_context *context, int tsi) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
}

static void destroy_wsi_sd(struct lws *wsi) {
    pthread_t pt_id = pthread_self();
    printf("%s(%d) [%lu] %s not implemented\n", __FILE__, __LINE__, pt_id, __func__);
}

const struct lws_event_loop_ops event_loop_ops_sdevent = {
        .name = "sdevent",
        .init_context = init_context_sd,
        .destroy_context1 = destroy_context1_sd,
        .destroy_context2 = destroy_context2_sd,
        .init_vhost_listen_wsi = init_vhost_listen_wsi_sd,
        .init_pt = init_pt_sd,
        .wsi_logical_close = wsi_logical_close_sd,
        .check_client_connect_ok = check_client_connect_ok_sd,
        .close_handle_manually = close_handle_manually_sd,
        .sock_accept = sock_accept_sd,
        .io = io_sd,
        .run_pt = run_pt_sd,
        .destroy_pt = destroy_pt_sd,
        .destroy_wsi = destroy_wsi_sd,

        .flags = 0,

        .evlib_size_ctx = sizeof(struct lws_context_eventlibs_sdevent),
        .evlib_size_pt = sizeof(struct lws_pt_eventlibs_sdevent),
        .evlib_size_vh = sizeof(struct lws_vh_eventlibs_sdevent),
        .evlib_size_wsi = sizeof(struct lws_wsi_watcher_sdevent),
};

#if defined(LWS_WITH_EVLIB_PLUGINS)
LWS_VISIBLE
#endif
const lws_plugin_evlib_t evlib_sd = {
        .hdr = {
                "systemd event loop",
                "lws_evlib_plugin",
                LWS_PLUGIN_API_MAGIC
        },

        .ops	= &event_loop_ops_sdevent
};