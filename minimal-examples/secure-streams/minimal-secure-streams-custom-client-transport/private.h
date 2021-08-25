/*
 * lws-minimal-secure-streams-custom-proxy-transport
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *                         Kutoga <kutoga@user.github.invalid>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#define LWS_SS_USE_SSPC
#include <libwebsockets.h>

#define MAX_CUSTOM_POLLFDS 10

typedef struct custom_poll_ctx {
	struct pollfd		pollfds[MAX_CUSTOM_POLLFDS];
	void			*priv[MAX_CUSTOM_POLLFDS];
	int			count_pollfds;
	struct lws_dll2_owner	scheduler;
	lws_transport_mux_t	*tm;
} custom_poll_ctx_t;

extern custom_poll_ctx_t a_cpcx;
extern int interrupted, transport_fd, log_level;

extern const lws_transport_client_ops_t lws_sss_ops_client_serial;
extern const lws_ss_info_t ssi_binance;
extern int open_transport_file(custom_poll_ctx_t *cpcx, const char *filepath, void *priv);

extern int custom_poll_add_fd(custom_poll_ctx_t *cpcx, lws_sockfd_type fd,
				int events, void *priv);
extern int custom_poll_del_fd(custom_poll_ctx_t *cpcx, lws_sockfd_type fd);

extern int custom_poll_change_fd(custom_poll_ctx_t *cpcx, lws_sockfd_type fd,
				 int events_add, int events_remove);
extern int custom_poll_run(custom_poll_ctx_t *cpcx);
extern int custom_transport_event(struct pollfd *pfd, void *priv);
