#include <private-lib-core.h>
#include "private-lib-event-libs-sdevent.h"

struct lws_context_eventlibs_sdevent {
};

struct lws_pt_eventlibs_sdevent {
};

struct lws_vh_eventlibs_sdevent {
};

struct lws_io_watcher_sdevent {
};

static int init_context_sd(struct lws_context *context, const struct lws_context_creation_info *info) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return 0;
}

static int destroy_context1_sd(struct lws_context *context) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return 0;
}

static int destroy_context2_sd(struct lws_context *context) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return 0;
}

static int init_vhost_listen_wsi_sd(struct lws *wsi) {
printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
return 0;
}

static int init_pt_sd(struct lws_context *context, void *_loop, int tsi) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return 0;
}

static int wsi_logical_close_sd(struct lws *wsi) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return 0;
}

static int check_client_connect_ok_sd(struct lws *wsi) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return 0;
}

static void close_handle_manually_sd(struct lws *wsi) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return;
}

static int sock_accept_sd(struct lws *wsi) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return 0;
}

static void io_sd(struct lws *wsi, int flags) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return;
}

static void run_pt_sd(struct lws_context *context, int tsi) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    sleep(1);
    return;
}

static void destroy_pt_sd(struct lws_context *context, int tsi) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return;
}

static void destroy_wsi_sd(struct lws *wsi) {
    printf("%s(%d) %s not implemented\n", __FILE__, __LINE__, __func__);
    return;
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
        .evlib_size_wsi = sizeof(struct lws_io_watcher_sdevent),
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