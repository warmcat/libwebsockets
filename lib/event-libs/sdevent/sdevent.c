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
    struct sd_event_source *sultimer;
};

struct lws_vh_eventlibs_sdevent {
};

struct lws_wsi_watcher_sdevent {
    struct sd_event_source *source;
    uint32_t events;
};

static int sock_accept_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
    printf("%s(%d) entered %s\n", __FILE__, __LINE__, __func__);

    struct lws *wsi = (struct lws*) userdata;
    struct lws_context *context = wsi->a.context;
    struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
    struct lws_pollfd eventfd;

    lws_context_lock(pt->context, __func__);
    lws_pt_lock(pt, __func__);

    if (pt->is_destroyed)
        goto bail;

    eventfd.fd = fd;
    eventfd.events = 0;
    eventfd.revents = 0;

    // TODO handle revents error bits

    if (revents & EPOLLIN) {
        eventfd.events |= LWS_POLLIN;
        eventfd.revents |= LWS_POLLIN;
    }

    if (revents & EPOLLOUT) {
        eventfd.events |= LWS_POLLOUT;
        eventfd.revents |= LWS_POLLOUT;
    }

    lws_pt_unlock(pt);
    lws_context_unlock(pt->context);

    printf("%s(%d) called lws_service_fd_tsi\n", __FILE__, __LINE__);
    lws_service_fd_tsi(context, &eventfd, wsi->tsi);

    if (pt->destroy_self) {
        lws_context_destroy(pt->context);
    }

    return 0;

    bail:
    lws_pt_unlock(pt);
    lws_context_unlock(pt->context);

    return 0;
}

static int init_context_sd(struct lws_context *context, const struct lws_context_creation_info *info) {
    printf("%s(%d) entered (not impl!) %s\n", __FILE__, __LINE__, __func__);

    // extra info, can be removed
    printf("%s(%d) %s info->signal_cb is %p\n", __FILE__, __LINE__, __func__, info->signal_cb);
    printf("%s(%d) %s context->count_threads is %d\n", __FILE__, __LINE__, __func__, context->count_threads);

    return 0;
}

static int destroy_context1_sd(struct lws_context *context) {
    printf("%s(%d) entered (not impl!) %s\n", __FILE__, __LINE__, __func__);
    return 0;
}

static int destroy_context2_sd(struct lws_context *context) {
    printf("%s(%d) entered (not impl!) %s\n", __FILE__, __LINE__, __func__);
    return 0;
}

static void io_sd(struct lws *wsi, int flags) {
    printf("%s(%d) entered %s\n", __FILE__, __LINE__, __func__);

    struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

    // only manipulate if there is an event source
    if (!pt_to_priv_sd(pt)->io_loop || !wsi_to_priv_sd(wsi)->source) {
        lwsl_info("%s: no io loop yet\n", __func__);
        return;
    }

    // assert that the requested flags do not contain anything unexpected
    if (!((flags & (LWS_EV_START | LWS_EV_STOP)) &&
          (flags & (LWS_EV_READ | LWS_EV_WRITE)))) {
        lwsl_err("%s: assert: flags %d", __func__, flags);
        assert(0);
    }

    // we are overdoing a bit here, so it resembles the structure in libuv.c
    if (flags & LWS_EV_START) {
        if (flags & LWS_EV_WRITE)
            wsi_to_priv_sd(wsi)->events |= EPOLLOUT;

        if (flags & LWS_EV_READ)
            wsi_to_priv_sd(wsi)->events |= EPOLLIN;

        sd_event_source_set_io_events(wsi_to_priv_sd(wsi)->source, wsi_to_priv_sd(wsi)->events);
        sd_event_source_set_enabled(wsi_to_priv_sd(wsi)->source, SD_EVENT_ON);
    } else {
        if (flags & LWS_EV_WRITE)
            wsi_to_priv_sd(wsi)->events &= ~EPOLLOUT;

        if (flags & LWS_EV_READ)
            wsi_to_priv_sd(wsi)->events &= ~EPOLLIN;

        sd_event_source_set_io_events(wsi_to_priv_sd(wsi)->source, wsi_to_priv_sd(wsi)->events);

        if (!(wsi_to_priv_sd(wsi)->events & (EPOLLIN | EPOLLOUT)))
            sd_event_source_set_enabled(wsi_to_priv_sd(wsi)->source, SD_EVENT_ON);
        else
            sd_event_source_set_enabled(wsi_to_priv_sd(wsi)->source, SD_EVENT_OFF);
    }
}

static int init_vhost_listen_wsi_sd(struct lws *wsi) {
    printf("%s(%d) entered %s wsi=%p\n", __FILE__, __LINE__, __func__, wsi);

    if (!wsi)
        return 0;

    struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

    void *userdata = wsi;

    sd_event_add_io(
            pt_to_priv_sd(pt)->io_loop,
            &wsi_to_priv_sd(wsi)->source,
            wsi->desc.sockfd,
            wsi_to_priv_sd(wsi)->events,
            sock_accept_handler,
            userdata
    );

    io_sd(wsi, LWS_EV_START | LWS_EV_READ);

    return 0;
}

static int sultimer_handler(sd_event_source *s, uint64_t usec, void *userdata) {
    printf("%s(%d) entered (not impl!) %s\n", __FILE__, __LINE__, __func__);
    return 0;
}

static int init_pt_sd(struct lws_context *context, void *_loop, int tsi) {
    printf("%s(%d) entered %s\n", __FILE__, __LINE__, __func__);

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
    // Note: default vhost usually not included here
    for (struct lws_vhost *vh = context->vhost_list; vh; vh = vh->vhost_next) {
        // call lws_event_loop_ops->init_vhost_listen_wsi
        if (init_vhost_listen_wsi_sd(vh->lserv_wsi) == -1) {
            return -1;
        }
    }

    if (first) {
        if (0 > sd_event_add_time(
                loop,
                &ptpriv->sultimer,
                CLOCK_MONOTONIC,
                0,
                0,
                sultimer_handler,
                NULL
        )) {
            return -1;
        }

        if (0 > sd_event_source_set_priority(
                ptpriv->sultimer,
                SD_EVENT_PRIORITY_IDLE
        )) {
            return -1;
        }
    }

    return 0;
}

static int wsi_logical_close_sd(struct lws *wsi) {
    printf("%s(%d) entered (not impl!) %s\n", __FILE__, __LINE__, __func__);
    return 0;
}

static int check_client_connect_ok_sd(struct lws *wsi) {
    printf("%s(%d) entered (not impl!) %s\n", __FILE__, __LINE__, __func__);
    return 0;
}

static void close_handle_manually_sd(struct lws *wsi) {
    printf("%s(%d) entered (not impl!) %s\n", __FILE__, __LINE__, __func__);
}

static int sock_accept_sd(struct lws *wsi) {
    printf("%s(%d) entered %s wsi=%p\n", __FILE__, __LINE__, __func__, wsi);

    struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

    void *userdata = wsi;

    if (wsi->role_ops->file_handle)
        sd_event_add_io(
                pt_to_priv_sd(pt)->io_loop,
                &wsi_to_priv_sd(wsi)->source,
                wsi->desc.filefd,
                wsi_to_priv_sd(wsi)->events,
                sock_accept_handler,
                userdata
        );
    else
        sd_event_add_io(
                pt_to_priv_sd(pt)->io_loop,
                &wsi_to_priv_sd(wsi)->source,
                wsi->desc.sockfd,
                wsi_to_priv_sd(wsi)->events,
                sock_accept_handler,
                userdata
        );

    return 0;
}

static void run_pt_sd(struct lws_context *context, int tsi) {
    printf("%s(%d) entered %s\n", __FILE__, __LINE__, __func__);

    struct lws_context_per_thread *pt = &context->pt[tsi];
    struct lws_pt_eventlibs_sdevent *ptpriv = pt_to_priv_sd(pt);
    if(ptpriv->io_loop) {
        sd_event_run(ptpriv->io_loop, (uint64_t) -1);
    }
}

static void destroy_pt_sd(struct lws_context *context, int tsi) {
    printf("%s(%d) entered (not impl!) %s\n", __FILE__, __LINE__, __func__);
}

static void destroy_wsi_sd(struct lws *wsi) {
    printf("%s(%d) entered (not impl!) %s\n", __FILE__, __LINE__, __func__);
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