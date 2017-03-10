#include "private-libwebsockets.h"
#include "freertos/timers.h"
#include <esp_attr.h>
/*
 * included from libwebsockets.c for unix builds
 */

unsigned long long time_in_microseconds(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((unsigned long long)tv.tv_sec * 1000000LL) + tv.tv_usec;
}

LWS_VISIBLE int
lws_get_random(struct lws_context *context, void *buf, int len)
{
	// !!!
	return 0;
}

LWS_VISIBLE int
lws_send_pipe_choked(struct lws *wsi)
{
	fd_set writefds;
	struct timeval tv = { 0, 0 };

	/* treat the fact we got a truncated send pending as if we're choked */
	if (wsi->trunc_len)
		return 1;

	FD_ZERO(&writefds);
	FD_SET(wsi->desc.sockfd, &writefds);

	if (select(wsi->desc.sockfd + 1, NULL, &writefds, NULL, &tv) < 1)
		return 1;

	return 0;
}

LWS_VISIBLE int
lws_poll_listen_fd(struct lws_pollfd *fd)
{
	fd_set readfds;
	struct timeval tv = { 0, 0 };

	FD_ZERO(&readfds);
	FD_SET(fd->fd, &readfds);

	return select(fd->fd + 1, &readfds, NULL, NULL, &tv);
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
	printf("%d: %s", level, line);
}

LWS_VISIBLE LWS_EXTERN int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt;
	int n = -1, m, c;

	/* stay dead once we are dead */

	if (!context || !context->vhost_list)
		return 1;

	pt = &context->pt[tsi];

	if (timeout_ms < 0)
		goto faked_service;

	if (!context->service_tid_detected) {
		struct lws _lws;

		memset(&_lws, 0, sizeof(_lws));
		_lws.context = context;

		context->service_tid_detected =
			context->vhost_list->protocols[0].callback(
			&_lws, LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
	}
	context->service_tid = context->service_tid_detected;

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!lws_service_adjust_timeout(context, 1, tsi)) {
		/* -1 timeout means just do forced service */
		_lws_plat_service_tsi(context, -1, pt->tid);
		/* still somebody left who wants forced service? */
		if (!lws_service_adjust_timeout(context, 1, pt->tid))
			/* yes... come back again quickly */
			timeout_ms = 0;
	}

//	n = poll(pt->fds, pt->fds_count, timeout_ms);
	{
		fd_set readfds, writefds, errfds;
		struct timeval tv = { timeout_ms / 1000,
				      (timeout_ms % 1000) * 1000 };
		int max_fd = 0;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&errfds);

		for (n = 0; n < pt->fds_count; n++) {
			pt->fds[n].revents = 0;
			if (pt->fds[n].fd >= max_fd)
				max_fd = pt->fds[n].fd;
			if (pt->fds[n].events & LWS_POLLIN)
				FD_SET(pt->fds[n].fd, &readfds);
			if (pt->fds[n].events & LWS_POLLOUT)
				FD_SET(pt->fds[n].fd, &writefds);
			FD_SET(pt->fds[n].fd, &errfds);
		}

		n = select(max_fd + 1, &readfds, &writefds, &errfds, &tv);
		for (n = 0; n < pt->fds_count; n++) {
			if (FD_ISSET(pt->fds[n].fd, &readfds))
				pt->fds[n].revents |= LWS_POLLIN;
			if (FD_ISSET(pt->fds[n].fd, &writefds))
				pt->fds[n].revents |= LWS_POLLOUT;
			if (FD_ISSET(pt->fds[n].fd, &errfds))
				pt->fds[n].revents |= LWS_POLLHUP;
		}
	}


#ifdef LWS_OPENSSL_SUPPORT
	if (!pt->rx_draining_ext_list &&
	    !lws_ssl_anybody_has_buffered_read_tsi(context, tsi) && !n) {
#else
	if (!pt->rx_draining_ext_list && !n) /* poll timeout */ {
#endif
		lws_service_fd_tsi(context, NULL, tsi);
		return 0;
	}

faked_service:
	m = lws_service_flag_pending(context, tsi);
	if (m)
		c = -1; /* unknown limit */
	else
		if (n < 0) {
			if (LWS_ERRNO != LWS_EINTR)
				return -1;
			return 0;
		} else
			c = n;

	/* any socket with events to service? */
	for (n = 0; n < pt->fds_count && c; n++) {
		if (!pt->fds[n].revents)
			continue;

		c--;

		m = lws_service_fd_tsi(context, &pt->fds[n], tsi);
		if (m < 0)
			return -1;
		/* if something closed, retry this slot */
		if (m)
			n--;
	}

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
	return _lws_plat_service_tsi(context, timeout_ms, 0);
}

LWS_VISIBLE int
lws_plat_set_socket_options(struct lws_vhost *vhost, int fd)
{
	int optval = 1;
	socklen_t optlen = sizeof(optval);

#if defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__NetBSD__) || \
    defined(__OpenBSD__)
	struct protoent *tcp_proto;
#endif

	if (vhost->ka_time) {
		/* enable keepalive on this socket */
		optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
			       (const void *)&optval, optlen) < 0)
			return 1;

#if defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__NetBSD__) || \
        defined(__CYGWIN__) || defined(__OpenBSD__) || defined (__sun)

		/*
		 * didn't find a way to set these per-socket, need to
		 * tune kernel systemwide values
		 */
#else
		/* set the keepalive conditions we want on it too */
		optval = vhost->ka_time;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
			       (const void *)&optval, optlen) < 0)
			return 1;

		optval = vhost->ka_interval;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
			       (const void *)&optval, optlen) < 0)
			return 1;

		optval = vhost->ka_probes;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
			       (const void *)&optval, optlen) < 0)
			return 1;
#endif
	}
#if 0
	/* Disable Nagle */
	optval = 1;
//	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, (const void *)&optval, optlen) < 0)
//		return 1;
	tcp_proto = getprotobyname("TCP");
	if (setsockopt(fd, tcp_proto->p_proto, TCP_NODELAY, &optval, optlen) < 0)
		return 1;
#endif
	/* We are nonblocking... */
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
		return 1;

	return 0;
}

LWS_VISIBLE void
lws_plat_drop_app_privileges(struct lws_context_creation_info *info)
{
}

LWS_VISIBLE int
lws_plat_context_early_init(void)
{
	//signal(SIGPIPE, SIG_IGN);

//	signal(SIGABRT, sigabrt_handler);

	return 0;
}

LWS_VISIBLE void
lws_plat_context_early_destroy(struct lws_context *context)
{
}

LWS_VISIBLE void
lws_plat_context_late_destroy(struct lws_context *context)
{
#ifdef LWS_WITH_PLUGINS
	if (context->plugin_list)
		lws_plat_plugins_destroy(context);
#endif

	if (context->lws_lookup)
		lws_free(context->lws_lookup);
}

/* cast a struct sockaddr_in6 * into addr for ipv6 */

LWS_VISIBLE int
lws_interface_to_sa(int ipv6, const char *ifname, struct sockaddr_in *addr,
		    size_t addrlen)
{
#if 0
	int rc = -1;

	struct ifaddrs *ifr;
	struct ifaddrs *ifc;
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
#endif

	getifaddrs(&ifr);
	for (ifc = ifr; ifc != NULL && rc; ifc = ifc->ifa_next) {
		if (!ifc->ifa_addr)
			continue;

		lwsl_info(" interface %s vs %s\n", ifc->ifa_name, ifname);

		if (strcmp(ifc->ifa_name, ifname))
			continue;

		switch (ifc->ifa_addr->sa_family) {
		case AF_INET:
#ifdef LWS_USE_IPV6
			if (ipv6) {
				/* map IPv4 to IPv6 */
				bzero((char *)&addr6->sin6_addr,
						sizeof(struct in6_addr));
				addr6->sin6_addr.s6_addr[10] = 0xff;
				addr6->sin6_addr.s6_addr[11] = 0xff;
				memcpy(&addr6->sin6_addr.s6_addr[12],
					&((struct sockaddr_in *)ifc->ifa_addr)->sin_addr,
							sizeof(struct in_addr));
			} else
#endif
				memcpy(addr,
					(struct sockaddr_in *)ifc->ifa_addr,
						    sizeof(struct sockaddr_in));
			break;
#ifdef LWS_USE_IPV6
		case AF_INET6:
			memcpy(&addr6->sin6_addr,
			  &((struct sockaddr_in6 *)ifc->ifa_addr)->sin6_addr,
						       sizeof(struct in6_addr));
			break;
#endif
		default:
			continue;
		}
		rc = 0;
	}

	freeifaddrs(ifr);

	if (rc == -1) {
		/* check if bind to IP address */
#ifdef LWS_USE_IPV6
		if (inet_pton(AF_INET6, ifname, &addr6->sin6_addr) == 1)
			rc = 0;
		else
#endif
		if (inet_pton(AF_INET, ifname, &addr->sin_addr) == 1)
			rc = 0;
	}

	return rc;
#endif

	return -1;
}

LWS_VISIBLE void
lws_plat_insert_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	pt->fds[pt->fds_count++].revents = 0;
}

LWS_VISIBLE void
lws_plat_delete_socket_from_fds(struct lws_context *context,
						struct lws *wsi, int m)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

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
	return 0;
}

LWS_VISIBLE const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{
	return inet_ntop(af, src, dst, cnt);
}

LWS_VISIBLE lws_fop_fd_t IRAM_ATTR
_lws_plat_file_open(const struct lws_plat_file_ops *fops, const char *filename,
		    const char *vpath, lws_fop_flags_t *flags)
{
	struct stat stat_buf;
	lws_fop_fd_t fop_fd;
	int ret = open(filename, *flags, 0664);

	if (ret < 0)
		return NULL;

	if (fstat(ret, &stat_buf) < 0)
		goto bail;

	fop_fd = malloc(sizeof(*fop_fd));
	if (!fop_fd)
		goto bail;

	fop_fd->fops = fops;
	fop_fd->fd = ret;
	fop_fd->flags = *flags;
	fop_fd->filesystem_priv = NULL; /* we don't use it */
	fop_fd->pos = 0;
	fop_fd->len = stat_buf.st_size;

	return fop_fd;

bail:
	close(ret);

	return NULL;
}

LWS_VISIBLE int IRAM_ATTR
_lws_plat_file_close(lws_fop_fd_t *fops_fd)
{
	int fd = (*fops_fd)->fd;

	free(*fops_fd);
	*fops_fd = NULL;

	return close(fd);
}

LWS_VISIBLE lws_fileofs_t IRAM_ATTR
_lws_plat_file_seek_cur(lws_fop_fd_t fops_fd, lws_fileofs_t offset)
{
	return lseek(fops_fd->fd, offset, SEEK_CUR);
}

LWS_VISIBLE int IRAM_ATTR
_lws_plat_file_read(lws_fop_fd_t fops_fd, lws_filepos_t *amount,
		    uint8_t *buf, lws_filepos_t len)
{
	long n;

	n = read(fops_fd->fd, buf, len);
	if (n == -1) {
		*amount = 0;
		return -1;
	}
	fops_fd->pos += n;
	*amount = n;

	return 0;
}

LWS_VISIBLE int IRAM_ATTR
_lws_plat_file_write(lws_fop_fd_t fops_fd, lws_filepos_t *amount,
		     uint8_t *buf, lws_filepos_t len)
{
	long n;

	n = write(fops_fd->fd, buf, len);
	if (n == -1) {
		*amount = 0;
		return -1;
	}
	fops_fd->pos += n;
	*amount = n;

	return 0;
}


LWS_VISIBLE int
lws_plat_init(struct lws_context *context,
	      struct lws_context_creation_info *info)
{
	/* master context has the global fd lookup array */
	context->lws_lookup = lws_zalloc(sizeof(struct lws *) *
					 context->max_fds);
	if (context->lws_lookup == NULL) {
		lwsl_err("OOM on lws_lookup array for %d connections\n",
			 context->max_fds);
		return 1;
	}

	lwsl_notice(" mem: platform fd map: %5lu bytes\n",
		    (unsigned long)(sizeof(struct lws *) * context->max_fds));

#ifdef LWS_WITH_PLUGINS
	if (info->plugin_dirs)
		lws_plat_plugins_init(context, info->plugin_dirs);
#endif

	return 0;
}


LWS_VISIBLE void esp32_uvtimer_cb(TimerHandle_t t)
{
	struct timer_mapping *p = pvTimerGetTimerID(t);

	p->cb(p->t);
}

void ERR_error_string_n(unsigned long e, char *buf, size_t len)
{
	strncpy(buf, "unknown", len);
}

void ERR_free_strings(void)
{
}

char *ERR_error_string(unsigned long e, char *buf)
{
	if (buf)
		strcpy(buf, "unknown");

	return "unknown";
}


/* helper functionality */

#include "romfs.h"

void (*lws_cb_scan_done)(void *);
void *lws_cb_scan_done_arg;
char lws_esp32_serial[16] = "unknown", lws_esp32_force_ap = 0,
     lws_esp32_region = WIFI_COUNTRY_US; // default to safest option

static romfs_t lws_esp32_romfs;

/*
 * configuration related to the AP setup website
 *
 * The 'esplws-scan' protocol drives the configuration
 * site, and updates the scan results in realtime over
 * a websocket link.
 */

#include "../plugins/protocol_esp32_lws_scan.c"

static const struct lws_protocols protocols_ap[] = {
	{
		"http-only",
		lws_callback_http_dummy,
		0,	/* per_session_data_size */
		900, 0, NULL
	},
	LWS_PLUGIN_PROTOCOL_ESPLWS_SCAN,
	{ NULL, NULL, 0, 0, 0, NULL } /* terminator */
};

static const struct lws_protocol_vhost_options ap_pvo = {
	NULL,
	NULL,
	"esplws-scan",
	""
};

static const struct lws_http_mount mount_ap = {
        .mountpoint		= "/",
        .origin			= "/ap",
        .def			= "index.html",
        .origin_protocol	= LWSMPRO_FILE,
        .mountpoint_len		= 1,
};

struct esp32_file {
	const struct inode *i;
};

esp_err_t lws_esp32_event_passthru(void *ctx, system_event_t *event)
{
	switch(event->event_id) {
	case SYSTEM_EVENT_SCAN_DONE:
		if (lws_cb_scan_done)
			lws_cb_scan_done(lws_cb_scan_done_arg);
		break;
	case SYSTEM_EVENT_STA_START:
		esp_wifi_connect();
		break;
	case SYSTEM_EVENT_STA_DISCONNECTED:
		/* This is a workaround as ESP32 WiFi libs don't currently
		   auto-reassociate. */
		esp_wifi_connect();
		break;
	default:
		break;
	}
	return ESP_OK;
}

static lws_fop_fd_t IRAM_ATTR
esp32_lws_fops_open(const struct lws_plat_file_ops *fops, const char *filename,
                const char *vfs_path, lws_fop_flags_t *flags)
{
	struct esp32_file *f = malloc(sizeof(*f));
	lws_fop_fd_t fop_fd;
	size_t len;

	lwsl_notice("%s: %s\n", __func__, filename);

	if (!f)
		return NULL;

	f->i = romfs_get_info(lws_esp32_romfs, filename, &len);
	if (!f->i)
		goto bail;

        fop_fd = malloc(sizeof(*fop_fd));
        if (!fop_fd)
                goto bail;

        fop_fd->fops = fops;
        fop_fd->filesystem_priv = f;
	fop_fd->flags = *flags;
	
	fop_fd->len = len;
	fop_fd->pos = 0;

	return fop_fd;

bail:
	free(f);

	return NULL;
}

static int IRAM_ATTR
esp32_lws_fops_close(lws_fop_fd_t *fop_fd)
{
	free((*fop_fd)->filesystem_priv);
	free(*fop_fd);

	*fop_fd = NULL;

	return 0;
}
static lws_fileofs_t IRAM_ATTR
esp32_lws_fops_seek_cur(lws_fop_fd_t fop_fd, lws_fileofs_t offset_from_cur_pos)
{
	fop_fd->pos += offset_from_cur_pos;
	
	if (fop_fd->pos > fop_fd->len)
		fop_fd->pos = fop_fd->len;

       return 0;
}

static int IRAM_ATTR
esp32_lws_fops_read(lws_fop_fd_t fop_fd, lws_filepos_t *amount, uint8_t *buf,
                   lws_filepos_t len)
{
       struct esp32_file *f = fop_fd->filesystem_priv;

       if ((long)buf & 3) {
               lwsl_err("misaligned buf\n");

               return -1;
       }

       if (fop_fd->pos >= fop_fd->len)
               return 0;

       if (len > fop_fd->len - fop_fd->pos)
               len = fop_fd->len - fop_fd->pos;

       spi_flash_read((uint32_t)(char *)f->i + fop_fd->pos, buf, len);

       *amount = len;
       fop_fd->pos += len;

       return 0;
}

static const struct lws_plat_file_ops fops = {
	.LWS_FOP_OPEN = esp32_lws_fops_open,
	.LWS_FOP_CLOSE = esp32_lws_fops_close,
	.LWS_FOP_READ = esp32_lws_fops_read,
	.LWS_FOP_SEEK_CUR = esp32_lws_fops_seek_cur,
};

static wifi_config_t sta_config = {
		.sta = {
			.bssid_set = false
		}
	}, ap_config = {
		.ap = {
		    .channel = 6,
		    .authmode = WIFI_AUTH_OPEN,
		    .max_connection = 1,
		}
	};

void
lws_esp32_wlan_config(void)
{
	nvs_handle nvh;
	char r[2];
	size_t s;

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));

	s = sizeof(sta_config.sta.ssid) - 1;
	if (nvs_get_str(nvh, "ssid", (char *)sta_config.sta.ssid, &s) != ESP_OK)
		lws_esp32_force_ap = 1;
	s = sizeof(sta_config.sta.password) - 1;
	if (nvs_get_str(nvh, "password", (char *)sta_config.sta.password, &s) != ESP_OK)
		lws_esp32_force_ap = 1;
	s = sizeof(lws_esp32_serial) - 1;
	if (nvs_get_str(nvh, "serial", lws_esp32_serial, &s) != ESP_OK)
		lws_esp32_force_ap = 1;
	else
		snprintf((char *)ap_config.ap.ssid, sizeof(ap_config.ap.ssid) - 1,
			 "config-%s-%s", lws_esp32_model, lws_esp32_serial);
	s = sizeof(r);
	if (nvs_get_str(nvh, "region", r, &s) != ESP_OK)
		lws_esp32_force_ap = 1;
	else
		lws_esp32_region = atoi(r);

	nvs_close(nvh);

	tcpip_adapter_init();
}

void
lws_esp32_wlan_start(void)
{
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

	ESP_ERROR_CHECK( esp_wifi_init(&cfg));
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK( esp_wifi_set_country(lws_esp32_region));

	if (!lws_esp32_is_booting_in_ap_mode() && !lws_esp32_force_ap) {
		ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA));
		ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &sta_config));
	} else {
		ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_APSTA) );
		ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_AP, &ap_config) );
	}

	ESP_ERROR_CHECK( esp_wifi_start());
	tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, (const char *)&ap_config.ap.ssid[7]);

	if (!lws_esp32_is_booting_in_ap_mode() && !lws_esp32_force_ap)
		ESP_ERROR_CHECK( esp_wifi_connect());
}

struct lws_context *
lws_esp32_init(struct lws_context_creation_info *info, unsigned int _romfs)
{
	size_t romfs_size;
	struct lws_context *context;

	lws_set_log_level(65535, lwsl_emit_syslog);

	context = lws_create_context(info);
	if (context == NULL) {
		lwsl_err("Failed to create context\n");
		return NULL;
	}

	lws_esp32_romfs = (romfs_t)(void *)_romfs;
	romfs_size = romfs_mount_check(lws_esp32_romfs);
	if (!romfs_size) {
		lwsl_err("Failed to mount ROMFS\n");
		return NULL;
	}

	lwsl_notice("ROMFS length %uKiB\n", romfs_size >> 10);

	/* set the lws vfs to use our romfs */

	lws_set_fops(context, &fops);

	if (lws_esp32_is_booting_in_ap_mode() || lws_esp32_force_ap) {
		info->vhost_name = "ap";
		info->protocols = protocols_ap;
		info->mounts = &mount_ap;
		info->pvo = &ap_pvo;
	}

	if (!lws_create_vhost(context, info))
		lwsl_err("Failed to create vhost\n");

	lws_protocol_init(context);

	return context;
}

