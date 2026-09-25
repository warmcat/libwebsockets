/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * private-lib-io.h: the IO half's private prototypes, split out of
 * private-lib-core-net.h by the file that defines each: lib/core-net/IO,
 * lib/plat, lib/tls, lib/event-libs, lib/drivers, the async dns.  See
 * READMEs/README.sans-io-split.md, "The headers".
 *
 * Not included when LWS_SANSIO_CHECK is defined: scripts/sans-io-check.sh
 * compiles the sansIO sources that way, so a sansIO file that reaches for
 * one of these fails to compile, naming the line.
 */

#if !defined(__LWS_PRIVATE_LIB_IO_H__)
#define __LWS_PRIVATE_LIB_IO_H__

/**
 * lws_wsi_is_async_dns(): true if the wsi is one of the async resolver's
 * own sockets, which are exempt from forced-family policy so they can
 * reach the configured nameservers over either family
 */
int
lws_wsi_is_async_dns(const struct lws *wsi);

lws_usec_t
__lws_sul_service_ripe(lws_dll2_owner_t *own, int num_own, lws_usec_t usnow);

void
lws_async_dns_cancel(struct lws *wsi);

void
lws_async_dns_drop_server(lws_async_dns_server_t *dsrv);

#if (defined(LWS_WITH_ASYNC_QUEUE))
void *
lws_async_worker_worker(void *d);

#endif
#if (defined(LWS_WITH_SPAWN))
void
lws_spawn_piped_destroy(struct lws_spawn_piped **lsp);

int
lws_spawn_reap(struct lws_spawn_piped *lsp);

#endif
void
lws_service_do_ripe_rxflow(struct lws_context_per_thread *pt);

int
lws_socket_bind(struct lws_vhost *vhost, struct lws *wsi,
		lws_sockfd_type sockfd, int port, const char *iface,
		int ipv6_allowed);

#if (defined(LWS_WITH_IPV6))
unsigned long
lws_get_addr_scope(struct lws *wsi, const char *ipaddr);

#endif
int
lws_service_wsi_as_writable(struct lws *wsi);

lws_handling_result_t
lws_rx_pump(struct lws_context_per_thread *pt, struct lws *wsi,
	    struct lws_pollfd *pollfd, int flags, size_t max, int *nothing,
	    int *consumed);

#if (defined(LWS_WITH_UDP))
lws_handling_result_t
lws_rx_pump_dgram(struct lws_context_per_thread *pt, struct lws *wsi,
		  struct lws_pollfd *pollfd, int *nothing);

#endif
int
lws_wsi_can_consume_parked_rx(struct lws *wsi);

int
lws_plat_set_nonblocking(lws_sockfd_type fd);

int
lws_plat_set_socket_options(struct lws_vhost *vhost, lws_sockfd_type fd,
			    int unix_skt);

int
lws_plat_set_socket_options_ip(lws_sockfd_type fd, uint8_t pri, int lws_flags);

int
lws_plat_check_connection_error(struct lws *wsi);

int LWS_WARN_UNUSED_RESULT
lws_change_pollfd(struct lws *wsi, int _and, int _or);

int
__remove_wsi_socket_from_fds(struct lws *wsi);

int
_lws_plat_service_forced_tsi(struct lws_context *context, int tsi);


int
lws_service_flag_pending(struct lws_context *context, int tsi);

void
lws_sa46_copy_address(lws_sockaddr46 *sa46a, const void *in, int af);

void
lws_libuv_closehandle(struct lws *wsi);

int
lws_libuv_check_watcher_active(struct lws *wsi);

#if (defined(LWS_WITH_EVLIB_PLUGINS) || defined(LWS_WITH_PLUGINS) || defined(LWS_WITH_PLUGINS_API))
const lws_plugin_header_t *
lws_plat_dlopen(struct lws_plugin **pplugin, const char *libpath,
		const char *sofilename, const char *_class,
		each_plugin_cb_t each, void *each_user);

int
lws_plat_destroy_dl(struct lws_plugin *p);

#endif
struct lws *
lws_adopt_socket_vhost(struct lws_vhost *vh, lws_sockfd_type accept_fd);

void
_lws_event_loop_ops_io(struct lws *wsi, unsigned int flags);

int
__lws_change_pollfd(struct lws *wsi, int _and, int _or);


int
lws_alpn_comma_to_openssl(const char *comma, uint8_t *os, int len);

int
lws_tls_server_conn_alpn(struct lws *wsi);

int LWS_WARN_UNUSED_RESULT
__insert_wsi_socket_into_fds(struct lws_context *context, struct lws *wsi);

int LWS_WARN_UNUSED_RESULT
lws_issue_raw(struct lws *wsi, unsigned char *buf, size_t len);

void
lws_client_happy_eyeballs_cb(lws_sorted_usec_list_t *sul);


struct lws *
lws_http_client_connect_via_info2(struct lws *wsi);

int
_lws_change_pollfd(struct lws *wsi, int _and, int _or, struct lws_pollargs *pa);

void
lws_plat_delete_socket_from_fds(struct lws_context *context,
				struct lws *wsi, int m);

void
lws_plat_insert_socket_into_fds(struct lws_context *context,
				struct lws *wsi);

int
lws_plat_change_pollfd(struct lws_context *context, struct lws *wsi,
		       struct lws_pollfd *pfd);

#if (defined(LWS_WITH_SERVER) && defined(LWS_WITH_SECURE_STREAMS))
int
lws_adopt_ss_server_accept(struct lws *new_wsi);

#endif
int
lws_plat_pipe_create(struct lws *wsi);

int
lws_plat_pipe_signal(struct lws_context *ctx, int tsi);

void
lws_plat_pipe_close(struct lws *wsi);

int
lws_plat_pipe_is_fd_assocated(struct lws_context *cx, int tsi, lws_sockfd_type fd);

int
lws_poll_listen_fd(struct lws_pollfd *fd);

int
lws_plat_service(struct lws_context *context, int timeout_ms);

LWS_VISIBLE int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi);

const char * LWS_WARN_UNUSED_RESULT
lws_plat_inet_ntop(int af, const void *src, char *dst, socklen_t cnt);

int LWS_WARN_UNUSED_RESULT
lws_plat_inet_pton(int af, const char *src, void *dst);





int
_lws_route_pt_close_unroutable(struct lws_context_per_thread *pt);

void
_lws_routing_entry_dump(struct lws_context *cx, lws_route_t *rou);

void
_lws_routing_table_dump(struct lws_context *cx);

lws_route_t *
_lws_route_remove(struct lws_context_per_thread *pt, lws_route_t *robj, int flags);

void
_lws_route_table_empty(struct lws_context_per_thread *pt);

void
_lws_route_table_ifdown(struct lws_context_per_thread *pt, int idx);

lws_route_uidx_t
_lws_route_get_uidx(struct lws_context *cx);

int
_lws_route_pt_close_route_users(struct lws_context_per_thread *pt,
			        lws_route_uidx_t uidx);

lws_route_t *
_lws_route_est_outgoing(struct lws_context_per_thread *pt,
		        const lws_sockaddr46 *dest);

const char *
lws_errno_describe(int en, char *result, size_t len);

#if (defined(_DEBUG))
void
lws_service_assert_loop_thread(struct lws_context *cx, int tsi);

#endif



int
lws_buflist_aware_read(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_tokens *ebuf, char fr, const char *hint);

int
lws_buflist_aware_finished_consuming(struct lws *wsi, struct lws_tokens *ebuf,
				     int used, int buffered, const char *hint);

#if (defined(LWS_WITH_SYS_ASYNC_DNS))
lws_async_dns_server_check_t
lws_plat_asyncdns_init(struct lws_context *context, lws_async_dns_t *dns);

int
lws_async_dns_init(struct lws_context *context);

void
lws_async_dns_deinit(lws_async_dns_t *dns);

int
lws_adns_servers_known(struct lws_context *context);

int
lws_adns_gate_ok(struct lws_context *context);

void
lws_adns_kick(struct lws_context *context);

void
lws_adns_smd_destroy(struct lws_context *context);

#endif
#if (defined(_DEBUG) && !defined(LWS_PLAT_FREERTOS) && !defined(WIN32) && !defined(LWS_PLAT_OPTEE))
int
sanity_assert_no_wsi_traces(const struct lws_context *context, struct lws *wsi);

int
sanity_assert_no_sockfd_traces(const struct lws_context *context,
			       lws_sockfd_type sfd);

#endif
void
delete_from_fdwsi(const struct lws_context *context, struct lws *wsi);

int
lws_plat_mbedtls_net_send(void *ctx, const uint8_t *buf, size_t len);

int
lws_plat_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len);

lws_usec_t
lws_sul_nonmonotonic_adjust(struct lws_context *ctx, int64_t step_us);

void
lws_netdev_instance_remove_destroy(struct lws_netdev_instance *ni);

#if (defined(LWS_WITH_SYS_SMD))
int
lws_netdev_smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
		  void *buf, size_t len);

#endif
void
lws_netdev_instance_create(lws_netdev_instance_t *ni, struct lws_context *ctx,
			   const lws_netdev_ops_t *ops, const char *name,
			   void *platinfo);

int
lws_netdev_wifi_rssi_sort_compare(const lws_dll2_t *d, const lws_dll2_t *i);

void
lws_netdev_wifi_scan_empty(lws_netdev_instance_wifi_t *wnd);

lws_wifi_sta_t *
lws_netdev_wifi_scan_find(lws_netdev_instance_wifi_t *wnd, const char *ssid,
			  const uint8_t *bssid);

int
lws_netdev_wifi_scan_select(lws_netdev_instance_wifi_t *wnd);

lws_wifi_creds_t *
lws_netdev_credentials_find(lws_netdevs_t *netdevs, const char *ssid,
			    const uint8_t *bssid);

int
lws_netdev_wifi_redo_last(lws_netdev_instance_wifi_t *wnd);

void
lws_netdev_wifi_scan(lws_sorted_usec_list_t *sul);

void
lws_4to6(uint8_t *v6addr, const uint8_t *v4addr);

void
lws_sa46_4to6(lws_sockaddr46 *sa46, const uint8_t *v4addr, uint16_t port);

#if (defined(LWS_WITH_CLIENT))
void
lws_remove_parallel_fd_safely(struct lws *wsi, int pidx);

#endif

#if defined(LWS_WITH_UDP)
int
lws_io_send_dgram(struct lws *wsi, const uint8_t *buf, size_t len,
		  const lws_sockaddr46 *dest);
#endif

/* the vhost's listen sockets, the pt pipe, a wsi's place in the loop */
#if defined(LWS_WITH_SERVER)
int _lws_vhost_init_server(const struct lws_context_creation_info *info,
			   struct lws_vhost *vhost);
#else
#define _lws_vhost_init_server(_a, _b) (0)
#endif
void
lws_destroy_event_pipe(struct lws *wsi);
int
lws_wsi_inject_to_loop(struct lws_context_per_thread *pt, struct lws *wsi);
int
lws_wsi_extract_from_loop(struct lws *wsi);

/* connect attempts, restarts and the staged close */
void
lws_io_abort_connect(struct lws *wsi);
void
lws_io_unwatch(struct lws *wsi);
int
lws_io_shutdown_write(struct lws *wsi);
int
lws_io_close_staged(struct lws *wsi);
int
lws_io_transfer_socket(struct lws *wsi, struct lws *wnew);
void
lws_io_adjunct_init(struct lws *wsi);
void
lws_io_socket_wait_cancel(struct lws *wsi);
int
lws_io_socket_wait_pending(struct lws *wsi);
void
lws_io_socket_waiters_close(struct lws_vhost *vh, int tsi);
int
lws_io_service_now(struct lws *wsi);
int
lws_io_flag_pending_rx(struct lws *wsi);
void
lws_io_connect_timers_cancel(struct lws *wsi);
int
lws_io_dns_next(struct lws *wsi, char *ads, size_t len);
void
lws_addrinfo_clean(struct lws *wsi);
void
lws_io_set_peer(struct lws *wsi, const lws_sockaddr46 *sa46);
void
lws_io_peer_copy(struct lws *dst, const struct lws *src);
void
lws_io_peer_address(struct lws *wsi, char *buf, size_t len);
#if defined(LWS_ROLE_QUIC)
int
lws_io_udp_swap_socket(struct lws *nwsi, const lws_sockaddr46 *to_sa46);
int
lws_io_udp_connect_peer(struct lws *nwsi, const lws_sockaddr46 *sa46);
void
lws_io_udp_enable_ecn(struct lws *wsi);
int
lws_io_udp_is_bound(struct lws *wsi);
int
lws_io_udp_transfer_socket(struct lws *wsi, struct lws *nwsi);
#endif
void
lws_pipe_wsi_release_fds(struct lws *wsi);
#if defined(LWS_WITH_ASYNC_QUEUE)
int
lws_async_queue_submit(struct lws_context *cx, struct lws_async_job *job);
#endif

#endif /* __LWS_PRIVATE_LIB_IO_H__ */
