#include "private-libwebsockets.h"

#include "ip_addr.h"

/* forced into this because new espconn accepted callbacks carry no context ptr */
static struct lws_context *hacky_context;
static unsigned int time_high, ot;

/*
 * included from libwebsockets.c for esp8266 builds
 */

unsigned long long time_in_microseconds(void)
{
	unsigned int t = system_get_time();
	
	if (ot > t)
		time_high++;
	ot = t;
	
	return (((long long)time_high) << 32) | t;
}

int gettimeofday(struct timeval *tv, void *tz)
{
	unsigned long long t = time_in_microseconds();
	
	tv->tv_sec = t / 1000000;
	tv->tv_usec = t % 1000000;

	return 0;
}

time_t time(time_t *tloc)
{
	unsigned long long t = time_in_microseconds();

	if (tloc)
		*tloc = t / 1000000;

	return 0;
}

LWS_VISIBLE int
lws_get_random(struct lws_context *context, void *buf, int len)
{
//	return read(context->fd_random, (char *)buf, len);
	return 0;
}

LWS_VISIBLE int
lws_send_pipe_choked(struct lws *wsi)
{
	return wsi->pending_send_completion;
}

LWS_VISIBLE struct lws *
wsi_from_fd(const struct lws_context *context, lws_sockfd_type fd)
{
	int n;

	for (n = 0; n < context->max_fds; n++)
		if (context->connpool[n] == fd)
			return (struct lws *)context->connpool[n + context->max_fds];

	return NULL;
}

LWS_VISIBLE int
lws_ssl_capable_write_no_ssl(struct lws *wsi, unsigned char *buf, int len)
{
	//lwsl_notice("%s: wsi %p: len %d\n", __func__, wsi, len);	
	
	wsi->pending_send_completion++;
	espconn_send(wsi->desc.sockfd, buf, len);
	
	return len;
}

void abort(void)
{
	while(1) ;
}

void exit(int n)
{
	abort();
}

void _sint(void *s)
{
}

LWS_VISIBLE int
insert_wsi(struct lws_context *context, struct lws *wsi)
{
	(void)context;
	(void)wsi;

	return 0;
}

LWS_VISIBLE int
delete_from_fd(struct lws_context *context, lws_sockfd_type fd)
{
	(void)context;
	(void)fd;

	return 1;
}

struct tm *localtime(const time_t *timep)
{
	return NULL;
}
struct tm *localtime_r(const time_t *timep, struct tm *t)
{
	return NULL;
}

int atoi(const char *s)
{
	int n = 0;

	while (*s && (*s >= '0' && *s <= '9'))
		n = (n * 10) + ((*s++) - '0');

	return n;
}

#undef isxdigit
int isxdigit(int c)
{
	if (c >= 'A' && c <= 'F')
		return 1;

	if (c >= 'a' && c <= 'f')
		return 1;

	if (c >= '0' && c <= '9')
		return 1;

	return 0;
}

int strcasecmp(const char *s1, const char *s2)
{
	char a, b;
	while (*s1 && *s2) {
		a = *s1++;
		b = *s2++;

		if (a == b)
			continue;

		if (a >= 'a' && a <= 'z')
			a -= 'a' - 'A';
		if (b >= 'a' && b <= 'z')
			b -= 'a' - 'A';

		if (a != b)
			return 1;
	}

	return 0;
}

LWS_VISIBLE int
lws_poll_listen_fd(struct lws_pollfd *fd)
{
	return 0;
}

LWS_VISIBLE void
lws_cancel_service_pt(struct lws *wsi)
{
}

LWS_VISIBLE void
lws_cancel_service(struct lws_context *context)
{
}

LWS_VISIBLE void lwsl_emit_syslog(int level, const char *line)
{
	extern void output_redirect(const char *str);
	output_redirect(line);
}

LWS_VISIBLE LWS_EXTERN int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	return 0;
}

LWS_VISIBLE int
lws_plat_check_connection_error(struct lws *wsi)
{
	return 0;
}

LWS_VISIBLE int
lws_plat_service(struct lws_context *context, int timeout_ms)
{
//	return _lws_plat_service_tsi(context, timeout_ms, 0);
	return 0;
}

static int
esp8266_find_free_conn(struct lws_context *context)
{
	int n;

	for (n = 0; n < context->max_fds; n++)
		if (!context->connpool[n]) {
			lwsl_info(" using connpool %d\n", n);
			return n;
		}
	
	lwsl_err("%s: no free conns\n", __func__);
	
	return -1;
}

lws_sockfd_type
esp8266_create_tcp_listen_socket(struct lws_vhost *vh)
{
	int n = esp8266_find_free_conn(vh->context);
	struct espconn *conn;
	
	if (n < 0)
		return NULL;
	
	conn = lws_zalloc(sizeof *conn, "listen skt");
	if (!conn)
		return NULL;
	
	vh->context->connpool[n] = conn;
	
	conn->type = ESPCONN_TCP;
	conn->state = ESPCONN_NONE;
	conn->proto.tcp = &vh->tcp;
	
	return conn;
}

const char *
lws_plat_get_peer_simple(struct lws *wsi, char *name, int namelen)
{
	unsigned char *p = wsi->desc.sockfd->proto.tcp->remote_ip;

	lws_snprintf(name, namelen, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);

	return name;
}

LWS_VISIBLE int
lws_ssl_capable_read_no_ssl(struct lws *wsi, unsigned char *buf, int len)
{
	//lwsl_notice("%s\n", __func__);
	
	if (!wsi->context->rxd)
		return 0;

	if (len < wsi->context->rxd_len)
		lwsl_err("trunc read (%d vs %d)\n", len, wsi->context->rxd_len);
	else
		len = wsi->context->rxd_len;
	
	ets_memcpy(buf, wsi->context->rxd, len);
	
	wsi->context->rxd = NULL;
	
	return len;
}

static void
cb_1Hz(void *arg)
{
	struct lws_context *context = arg;
	struct lws_context_per_thread *pt = &context->pt[0];
	struct lws *wsi;
	struct lws_pollfd *pollfd;
	int n;

	/* Service any ah that has pending rx */
	for (n = 0; n < context->max_http_header_pool; n++)
		if (pt->ah_pool[n].rxpos != pt->ah_pool[n].rxlen) {
			wsi = pt->ah_pool[n].wsi;
			pollfd = &pt->fds[wsi->position_in_fds_table];
			if (pollfd->events & LWS_POLLIN) {
				pollfd->revents |= LWS_POLLIN;
				lws_service_fd(context, pollfd);
			}
		}

	/* handle timeouts */

	lws_service_fd(context, NULL);
}

static void
esp8266_cb_rx(void *arg, char *data, unsigned short len)
{
	struct espconn *conn = arg;
	struct lws *wsi = conn->reverse;
	struct lws_context_per_thread *pt = &wsi->context->pt[0];
	struct lws_pollfd pollfd;
	int n = 0;

	/*
	 * if we're doing HTTP headers, and we have no ah, check if there is
	 * a free ah, if not, have to buffer it
	 */
	if (!wsi->hdr_parsing_completed && !wsi->u.hdr.ah) {
		for (n = 0; n < wsi->context->max_http_header_pool; n++)
			if (!pt->ah_pool[n].in_use)
				break;

		n = n == wsi->context->max_http_header_pool;
	}

	if (!(pt->fds[wsi->position_in_fds_table].events & LWS_POLLIN) || n) {
		wsi->premature_rx = realloc(wsi->premature_rx,
					    wsi->prem_rx_size + len);
		if (!wsi->premature_rx)
			return;
		os_memcpy((char *)wsi->premature_rx + wsi->prem_rx_size, data, len);
		wsi->prem_rx_size += len;
	//	lwsl_notice("%s: wsi %p: len %d BUFFERING\n", __func__, wsi, len);

		if (n) /* we know it will fail, but we will get on the wait list */
			n = lws_header_table_attach(wsi, 0);

		(void)n;
		return;
	}

	//lwsl_err("%s: wsi %p. len %d\n", __func__, wsi, len);

        pollfd.fd = arg;
        pollfd.events = LWS_POLLIN;
        pollfd.revents = LWS_POLLIN;
        
        wsi->context->rxd = data;
        wsi->context->rxd_len = len;

        lws_service_fd(lws_get_context(wsi), &pollfd);

}

static void
esp8266_cb_sent(void *arg)
{
	struct espconn *conn = arg;
	struct lws *wsi = conn->reverse;
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	
//	lwsl_err("%s: wsi %p (psc %d) wsi->position_in_fds_table=%d\n", __func__, wsi, wsi->pending_send_completion, wsi->position_in_fds_table);
	
	wsi->pending_send_completion--;
	if (wsi->close_is_pending_send_completion &&
	    !wsi->pending_send_completion &&
	    !lws_partial_buffered(wsi)) {
		lwsl_notice("doing delayed close\n");
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS);
	}
	
	if (pt->fds[wsi->position_in_fds_table].events & LWS_POLLOUT) {
		struct lws_pollfd pollfd;

	        pollfd.fd = arg;
	        pollfd.events = LWS_POLLOUT;
	        pollfd.revents = LWS_POLLOUT;

//	        lwsl_notice("informing POLLOUT\n");
	        
	        lws_service_fd(lws_get_context(wsi), &pollfd);
	}
}

static void
esp8266_cb_disconnected(void *arg)
{
	struct espconn *conn = arg;
	struct lws *wsi = conn->reverse;
	int n;

	lwsl_notice("%s: %p\n", __func__, wsi);
	
	for (n = 0; n < hacky_context->max_fds; n++)
		if (hacky_context->connpool[n] == arg) {
			hacky_context->connpool[n] = NULL;
			lwsl_info(" freed connpool %d\n", n);
		}
	
	if (wsi) {
		conn->reverse = NULL;
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS);
		lwsl_notice("closed ok\n");
	}
}

static void
esp8266_cb_recon(void *arg, signed char err)
{
	struct espconn *conn = arg;

	lwsl_err("%s: wsi %p. err %d\n", __func__, conn->reverse, err);

	conn->state = ESPCONN_CLOSE;		

	esp8266_cb_disconnected(arg);	
}

/*
 * there is no reliable indication of which listen socket we were accepted on.
 */

static void
esp8266_cb_connect(void *arg)
{
	struct espconn *cs = arg;
//	struct ip_addr *ipa = (struct ip_addr *)cs->proto.tcp->remote_ip;
	struct lws_vhost *vh = hacky_context->vhost_list;
//	struct ip_info info;
	struct lws *wsi;
	int n;

	lwsl_notice("%s: (wsi coming): %p\n", __func__, cs->reverse);
#if 0
	wifi_get_ip_info(0, &info);
	if (ip_addr_netcmp(ipa, &info.ip, &info.netmask)) {
		/* we are on the same subnet as the AP, ie, connected to AP */
		while (vh && strcmp(vh->name, "ap"))
			vh = vh->vhost_next;
	} else
		while (vh && !strcmp(vh->name, "ap"))
			vh = vh->vhost_next;

	if (!vh)
		goto bail;
#endif
	n = esp8266_find_free_conn(hacky_context);
	if (n < 0)
		goto bail;
	
	hacky_context->connpool[n] = cs;
	
	espconn_recv_hold(cs);

	wsi = lws_adopt_socket_vhost(vh, cs);
	if (!wsi)
		goto bail;
	
	lwsl_err("%s: wsi %p (using free_conn %d): vh %s\n", __func__, wsi, n, vh->name);

	espconn_regist_recvcb(cs, esp8266_cb_rx);
	espconn_regist_reconcb(cs, esp8266_cb_recon);
	espconn_regist_disconcb(cs, esp8266_cb_disconnected);
	espconn_regist_sentcb(cs, esp8266_cb_sent);
	
	espconn_set_opt(cs, ESPCONN_NODELAY | ESPCONN_REUSEADDR);
	espconn_regist_time(cs, 7200, 1);

	return;

bail:
	lwsl_err("%s: bailed]n", __func__);
	espconn_disconnect(cs);
}

void
esp8266_tcp_stream_bind(lws_sockfd_type fd, int port, struct lws *wsi)
{
	fd->proto.tcp->local_port = port;
	fd->reverse = wsi;
	
	hacky_context = wsi->context;
	
	espconn_regist_connectcb(fd, esp8266_cb_connect);
	/* hmmm it means, listen() + accept() */
	espconn_accept(fd);

	espconn_tcp_set_max_con_allow(fd, 10);
}

void
esp8266_tcp_stream_accept(lws_sockfd_type fd, struct lws *wsi)
{
	int n;

	fd->reverse = wsi;

	for (n = 0; n < wsi->context->max_fds ; n++)
		if (wsi->context->connpool[n] == wsi->desc.sockfd)
			wsi->position_in_fds_table = n;
}

LWS_VISIBLE int
lws_plat_set_socket_options(struct lws_vhost *vhost, lws_sockfd_type fd)
{
	return 0;
}

LWS_VISIBLE void
lws_plat_drop_app_privileges(struct lws_context_creation_info *info)
{
}

LWS_VISIBLE int
lws_plat_context_early_init(void)
{
	espconn_tcp_set_max_con(12);

	return 0;
}

LWS_VISIBLE void
lws_plat_context_early_destroy(struct lws_context *context)
{
}

LWS_VISIBLE void
lws_plat_context_late_destroy(struct lws_context *context)
{
#if 0
	struct lws_context_per_thread *pt = &context->pt[0];
	int m = context->count_threads;

	if (context->lws_lookup)
		lws_free(context->lws_lookup);

	while (m--) {
		close(pt->dummy_pipe_fds[0]);
		close(pt->dummy_pipe_fds[1]);
		pt++;
	}
#endif
//	close(context->fd_random);
}

/* cast a struct sockaddr_in6 * into addr for ipv6 */

LWS_VISIBLE int
lws_interface_to_sa(int ipv6, const char *ifname, struct sockaddr_in *addr,
		    size_t addrlen)
{
	return 0;
}

LWS_VISIBLE void
lws_plat_insert_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	context->connpool[wsi->position_in_fds_table + context->max_fds] = (lws_sockfd_type)wsi;
	wsi->desc.sockfd->reverse = wsi;
	pt->fds_count++;
}

LWS_VISIBLE void
lws_plat_delete_socket_from_fds(struct lws_context *context,
						struct lws *wsi, int m)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];	
	int n;
	
	for (n = 0; n < wsi->context->max_fds; n++)
		if (wsi->context->connpool[n] == wsi->desc.sockfd) {
			wsi->context->connpool[n] = NULL;
			wsi->context->connpool[n + wsi->context->max_fds] = NULL;
			lwsl_notice(" freed connpool %d\n", n);
		}
	
	wsi->desc.sockfd->reverse = NULL;
	pt->fds_count--;
}

LWS_VISIBLE void
lws_plat_service_periodic(struct lws_context *context)
{
}

LWS_VISIBLE int
lws_plat_change_pollfd(struct lws_context *context,
		       struct lws *wsi, struct lws_pollfd *pfd)
{
	void *p;

	//lwsl_notice("%s: %p: wsi->pift=%d, events %d\n",
	//		__func__, wsi, wsi->position_in_fds_table, pfd->events);
	
	if (pfd->events & LWS_POLLIN) {
		if (wsi->premature_rx) {
			lwsl_notice("replaying buffered rx: wsi %p\n", wsi);
			p = wsi->premature_rx;
			wsi->premature_rx = NULL;
			esp8266_cb_rx(wsi->desc.sockfd,
				      (char *)p + wsi->prem_rx_pos,
				      wsi->prem_rx_size - wsi->prem_rx_pos);
			wsi->prem_rx_size = 0;
			wsi->prem_rx_pos = 0;
			lws_free(p);
		}
		if (espconn_recv_unhold(wsi->desc.sockfd) < 0)
			return -1;
	} else
		if (espconn_recv_hold(wsi->desc.sockfd) < 0)
			return -1;
	
	if (!(pfd->events & LWS_POLLOUT))
		return 0;
	
	if (!wsi->pending_send_completion) {
		pfd->revents |= LWS_POLLOUT;

//		lwsl_notice("doing POLLOUT\n");
		lws_service_fd(lws_get_context(wsi), pfd);
	} //else
		//lwsl_notice("pending sc\n");

	return 0;
}

LWS_VISIBLE const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{
//	return inet_ntop(af, src, dst, cnt);
	return 0;
}

LWS_VISIBLE int
lws_plat_inet_pton(int af, const char *src, void *dst)
{
	//return inet_pton(af, src, dst);
	return 1;
}

LWS_VISIBLE int
lws_plat_init(struct lws_context *context,
	      struct lws_context_creation_info *info)
{
//	struct lws_context_per_thread *pt = &context->pt[0];
//	int n = context->count_threads, fd;

	/* master context has the global fd lookup array */
	context->connpool = lws_zalloc(sizeof(struct espconn *) *
					 context->max_fds * 2, "connpool");
	if (context->connpool == NULL) {
		lwsl_err("OOM on lws_lookup array for %d connections\n",
			 context->max_fds);
		return 1;
	}

	lwsl_notice(" mem: platform fd map: %5u bytes\n",
		    sizeof(struct espconn *) * context->max_fds);
//	fd = open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);

//	context->fd_random = fd;
//	if (context->fd_random < 0) {
//		lwsl_err("Unable to open random device %s %d\n",
//			 SYSTEM_RANDOM_FILEPATH, context->fd_random);
//		return 1;
//	}

        os_memset(&context->to_timer, 0, sizeof(os_timer_t));
        os_timer_disarm(&context->to_timer);
        os_timer_setfn(&context->to_timer, (os_timer_func_t *)cb_1Hz, context);
        os_timer_arm(&context->to_timer, 1000, 1);

	if (!lws_libev_init_fd_table(context) &&
	    !lws_libuv_init_fd_table(context) &&
	    !lws_libevent_init_fd_table(context)) {
		/* otherwise libev handled it instead */
#if 0
		while (n--) {
			if (pipe(pt->dummy_pipe_fds)) {
				lwsl_err("Unable to create pipe\n");
				return 1;
			}

			/* use the read end of pipe as first item */
			pt->fds[0].fd = pt->dummy_pipe_fds[0];
			pt->fds[0].events = LWS_POLLIN;
			pt->fds[0].revents = 0;
			pt->fds_count = 1;
			pt++;
		}
#endif
	}


#ifdef LWS_WITH_PLUGINS
	if (info->plugin_dirs)
		lws_plat_plugins_init(context, info->plugin_dirs);
#endif

	return 0;
}
