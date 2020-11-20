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

const struct lws_event_loop_ops event_loop_ops_sdevent = {
        .name = "sdevent",
        .init_context = NULL,
        .destroy_context1 = NULL,
        .destroy_context2 = NULL,
        .init_vhost_listen_wsi = NULL,
        .init_pt = NULL,
        .wsi_logical_close = NULL,
        .check_client_connect_ok = NULL,
        .close_handle_manually = NULL,
        .sock_accept = NULL,
        .io = NULL,
        .run_pt = NULL,
        .destroy_pt = NULL,
        .destroy_wsi = NULL,

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