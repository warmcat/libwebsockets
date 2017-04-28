/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "private-libwebsockets.h"
#include "freertos/timers.h"
#include <esp_attr.h>
#include <esp_system.h>

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
	uint8_t *pb = buf;

	while (len) {
		uint32_t r = esp_random();
		uint8_t *p = (uint8_t *)&r;
		int b = 4;

		if (len < b)
			b = len;

		len -= b;

		while (b--)
			*pb++ = p[b];
	}

	return pb - (uint8_t *)buf;
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
				      (timeout_ms % 1000) * 1000 }, *ptv = &tv;
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

		n = select(max_fd + 1, &readfds, &writefds, &errfds, ptv);
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

	/* Disable Nagle */
	optval = 1;
//	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, (const void *)&optval, optlen) < 0)
//		return 1;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, optlen) < 0)
		return 1;

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
#include <esp_ota_ops.h>
#include <tcpip_adapter.h>
#include <esp_image_format.h>
#include <esp_task_wdt.h>

struct lws_esp32 lws_esp32 = {
	.model = CONFIG_LWS_MODEL_NAME,
	.serial = "unknown",
	.region = WIFI_COUNTRY_US, // default to safest option
};

static romfs_t lws_esp32_romfs;

struct esp32_file {
	const struct inode *i;
};

uint32_t lws_esp32_get_reboot_type(void)
{
	uint32_t *p = (uint32_t *)LWS_MAGIC_REBOOT_TYPE_ADS, val = *p;
	nvs_handle nvh;
	size_t s = 0;
	int n = 0;

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
	if (nvs_get_blob(nvh, "ssl-pub.der", NULL, &s) == ESP_OK)
		n = 1;
	if (nvs_get_blob(nvh, "ssl-pri.der", NULL, &s) == ESP_OK)
		n |= 2;
	nvs_close(nvh);

	/*
	 * in the case the SSL certs are not there, don't require
	 * the button to be down to access all features.
	 */
	if (n != 3)
		val = LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON;

	return val;
}

static void render_ip(char *dest, int len, uint8_t *ip)
{
	snprintf(dest, len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void lws_esp32_restart_guided(uint32_t type)
{
        uint32_t *p_force_factory_magic = (uint32_t *)LWS_MAGIC_REBOOT_TYPE_ADS;

	lwsl_notice("%s: %x\n", __func__, type);
        *p_force_factory_magic = type;

	esp_restart();
}

esp_err_t lws_esp32_event_passthru(void *ctx, system_event_t *event)
{
	switch(event->event_id) {
	case SYSTEM_EVENT_STA_START:
		esp_wifi_connect();
		break;
	case SYSTEM_EVENT_STA_DISCONNECTED:
		lws_esp32.inet = 0;
		esp_wifi_connect();
		break;
	case SYSTEM_EVENT_STA_GOT_IP:
		lws_esp32.inet = 1;
		render_ip(lws_esp32.sta_ip, sizeof(lws_esp32.sta_ip) - 1, (uint8_t *)&event->event_info.got_ip.ip_info.ip);
		render_ip(lws_esp32.sta_mask, sizeof(lws_esp32.sta_mask) - 1, (uint8_t *)&event->event_info.got_ip.ip_info.netmask);
		render_ip(lws_esp32.sta_gw, sizeof(lws_esp32.sta_gw) - 1, (uint8_t *)&event->event_info.got_ip.ip_info.gw);
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
	size_t len, csum;

	lwsl_notice("%s: %s\n", __func__, filename);

	if (!f)
		return NULL;
	f->i = romfs_get_info(lws_esp32_romfs, filename, &len, &csum);
	if (!f->i)
		goto bail;

        fop_fd = malloc(sizeof(*fop_fd));
        if (!fop_fd)
                goto bail;

        fop_fd->fops = fops;
        fop_fd->filesystem_priv = f;
	fop_fd->mod_time = csum;
	*flags |= LWS_FOP_FLAG_MOD_TIME_VALID;
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
#if 0
       if ((long)buf & 3) {
               lwsl_err("misaligned buf\n");

               return -1;
       }
#endif
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
	.next = &fops_zip,
	.LWS_FOP_OPEN = esp32_lws_fops_open,
	.LWS_FOP_CLOSE = esp32_lws_fops_close,
	.LWS_FOP_READ = esp32_lws_fops_read,
	.LWS_FOP_SEEK_CUR = esp32_lws_fops_seek_cur,
};

static wifi_config_t config = {
	.ap = {
	    .channel = 6,
	    .authmode = WIFI_AUTH_OPEN,
	    .max_connection = 1,
	} }, sta_config = {
	.sta = {
		.bssid_set = 0,
	} };

int
lws_esp32_wlan_nvs_get(int retry)
{
	nvs_handle nvh;
	char r[2], lws_esp32_force_ap = 0;
	size_t s;
	uint8_t mac[6];

	esp_efuse_read_mac(mac);
	mac[5] |= 1; /* match the AP MAC */
	snprintf(lws_esp32.serial, sizeof(lws_esp32.serial) - 1, "%02X%02X%02X", mac[3], mac[4], mac[5]);

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));

	s = sizeof(config.sta.ssid) - 1;
	if (nvs_get_str(nvh, "ssid", (char *)sta_config.sta.ssid, &s) != ESP_OK)
		lws_esp32_force_ap = 1;
	s = sizeof(config.sta.password) - 1;
	if (nvs_get_str(nvh, "password", (char *)sta_config.sta.password, &s) != ESP_OK)
		lws_esp32_force_ap = 1;
	s = sizeof(lws_esp32.serial) - 1;
	if (nvs_get_str(nvh, "serial", lws_esp32.serial, &s) != ESP_OK)
		lws_esp32_force_ap = 1;
	else
		snprintf((char *)config.ap.ssid, sizeof(config.ap.ssid) - 1,
			 "config-%s-%s", lws_esp32.model, lws_esp32.serial);
	s = sizeof(lws_esp32.opts) - 1;
	if (nvs_get_str(nvh, "opts", lws_esp32.opts, &s) != ESP_OK)
		lws_esp32_force_ap = 1;

	s = sizeof(r);
	if (nvs_get_str(nvh, "region", r, &s) != ESP_OK)
		lws_esp32_force_ap = 1;
	else
		lws_esp32.region = atoi(r);
	lws_esp32.access_pw[0] = '\0';
	nvs_get_str(nvh, "access_pw", lws_esp32.access_pw, &s);

	nvs_close(nvh);

	if (retry && sta_config.sta.ssid[0]) {
		tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, (const char *)&config.ap.ssid[7]);
		ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &sta_config));
		ESP_ERROR_CHECK( esp_wifi_connect());

		ESP_ERROR_CHECK(mdns_init(TCPIP_ADAPTER_IF_STA, &lws_esp32.mdns));
		mdns_set_hostname(lws_esp32.mdns,  (const char *)&config.ap.ssid[7]);
		mdns_set_instance(lws_esp32.mdns, "instance");
	}

	return lws_esp32_force_ap;
}

void
lws_esp32_wlan_config(void)
{
	lws_esp32_wlan_nvs_get(0);
	tcpip_adapter_init();
}

void
lws_esp32_wlan_start_ap(void)
{
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

	ESP_ERROR_CHECK( esp_wifi_init(&cfg));
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM));
	esp_wifi_set_country(lws_esp32.region);

	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_APSTA) );
	ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_AP, &config) );
	ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &sta_config));
	ESP_ERROR_CHECK( esp_wifi_start());

	if (sta_config.sta.ssid[0]) {
		tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, (const char *)&config.ap.ssid[7]);
		esp_wifi_set_auto_connect(1);
		ESP_ERROR_CHECK( esp_wifi_connect());
		ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &sta_config));
		ESP_ERROR_CHECK( esp_wifi_connect());
	}
}

void
lws_esp32_wlan_start_station(void)
{
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

	ESP_ERROR_CHECK( esp_wifi_init(&cfg));
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM));
	esp_wifi_set_country(lws_esp32.region);

	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &sta_config));

	ESP_ERROR_CHECK( esp_wifi_start());

	tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, (const char *)&config.ap.ssid[7]);
	esp_wifi_set_auto_connect(1);
	ESP_ERROR_CHECK( esp_wifi_connect());

	ESP_ERROR_CHECK(mdns_init(TCPIP_ADAPTER_IF_STA, &lws_esp32.mdns));
	mdns_set_hostname(lws_esp32.mdns,  (const char *)&config.ap.ssid[7]);
	mdns_set_instance(lws_esp32.mdns, "instance");
}

const esp_partition_t *
lws_esp_ota_get_boot_partition(void)
{
	const esp_partition_t *part = esp_ota_get_boot_partition(), *factory_part, *ota;
	esp_image_header_t eih, ota_eih;
	uint32_t *p_force_factory_magic = (uint32_t *)LWS_MAGIC_REBOOT_TYPE_ADS;

	/* confirm what we are told is the boot part is sane */
	spi_flash_read(part->address , &eih, sizeof(eih));
	factory_part = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
			ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
 	ota = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
			ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL);
	spi_flash_read(ota->address , &ota_eih, sizeof(ota_eih));

	if (eih.spi_mode == 0xff ||
	    *p_force_factory_magic == LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY ||
	    *p_force_factory_magic == LWS_MAGIC_REBOOT_TYPE_FORCED_FACTORY_BUTTON
	   ) {
		/*
		 * we believed we were going to boot OTA, but we fell
		 * back to FACTORY in the bootloader when we saw it
		 * had been erased.  esp_ota_get_boot_partition() still
		 * says the OTA partition then even if we are in the
		 * factory partition right now.
		 */
		part = factory_part;
	} 
	
#ifdef CONFIG_LWS_IS_FACTORY_APPLICATION
	else
		if (ota_eih.spi_mode != 0xff &&
		    part->address != factory_part->address) {
			uint8_t buf[4096];
			uint32_t n;
			/*
			 * we are a FACTORY image running in an OTA slot...
			 * it means we were just written and need to copy
			 * ourselves into the FACTORY slot.
			 */
			lwsl_notice("Copying FACTORY update into place 0x%x len 0x%x\n",
				    factory_part->address, factory_part->size);
			esp_task_wdt_feed();
			if (spi_flash_erase_range(factory_part->address, factory_part->size) != ESP_OK) {
	               	        lwsl_err("spi: Failed to erase\n");
	               	        goto retry;
	               	}

			for (n = 0; n < factory_part->size; n += sizeof(buf)) {
				esp_task_wdt_feed();
				spi_flash_read(part->address + n , buf, sizeof(buf));
	                	if (spi_flash_write(factory_part->address + n, buf, sizeof(buf)) != ESP_OK) {
	                	        lwsl_err("spi: Failed to write\n");
	                	        goto retry;
	                	}
			}

			/* destroy our OTA image header */
			spi_flash_erase_range(ota->address, 4096);

			/*
			 * with no viable OTA image, we will come back up in factory
			 * where the user can reload the OTA image
			 */
			lwsl_notice("  FACTORY copy successful, rebooting\n");
retry:
			esp_restart();
		}
#endif

	return part;
}


void
lws_esp32_set_creation_defaults(struct lws_context_creation_info *info)
{
	const esp_partition_t *part;

	memset(info, 0, sizeof(*info));

	lws_set_log_level(63, lwsl_emit_syslog);

	part = lws_esp_ota_get_boot_partition();
	(void)part;

	info->port = 443;
	info->fd_limit_per_thread = 30;
	info->max_http_header_pool = 2;
	info->max_http_header_data = 1024;
	info->pt_serv_buf_size = 4096;
	info->keepalive_timeout = 5;
	info->simultaneous_ssl_restriction = 2;
	info->options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	info->ssl_cert_filepath = "ssl-pub.der";
	info->ssl_private_key_filepath = "ssl-pri.der";
}

int
lws_esp32_get_image_info(const esp_partition_t *part, struct lws_esp32_image *i,
			 char *json, int json_len)
{
	esp_image_segment_header_t eis;
	esp_image_header_t eih;
	uint32_t hdr;

	spi_flash_read(part->address , &eih, sizeof(eih));
	hdr = part->address + sizeof(eih);

	if (eih.magic != ESP_IMAGE_HEADER_MAGIC)
		return 1;

	eis.data_len = 0;
	while (eih.segment_count-- && eis.data_len != 0xffffffff) {
		spi_flash_read(hdr, &eis, sizeof(eis));
		hdr += sizeof(eis) + eis.data_len;
	}
	hdr += (~hdr & 15) + 1;

	i->romfs = hdr + 4;
	spi_flash_read(hdr, &i->romfs_len, sizeof(i->romfs_len));
	i->json = i->romfs + i->romfs_len + 4;
	spi_flash_read(i->json - 4, &i->json_len, sizeof(i->json_len));

	if (i->json_len < json_len - 1)
		json_len = i->json_len;
	spi_flash_read(i->json, json, json_len);
	json[json_len] = '\0';

	return 0;
}

struct lws_context *
lws_esp32_init(struct lws_context_creation_info *info)
{
	const esp_partition_t *part = lws_esp_ota_get_boot_partition();
	struct lws_context *context;
	struct lws_esp32_image i;
	struct lws_vhost *vhost;
	nvs_handle nvh;
	char buf[512];
	size_t s;
	int n;

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
	n = 0;
	s = 1;
	if (nvs_get_blob(nvh, "ssl-pub.der", NULL, &s) == ESP_OK)
		n = 1;
	s = 1;
	if (nvs_get_blob(nvh, "ssl-pri.der", NULL, &s) == ESP_OK)
		n |= 2;
	nvs_close(nvh);

	if (n != 3) {
		/* we are not configured for SSL yet... fall back to port 80 / http */
		info->port = 80;
		info->options &= ~LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
		lwsl_notice("No SSL certs... using port 80\n");
	}

	context = lws_create_context(info);
	if (context == NULL) {
		lwsl_err("Failed to create context\n");
		return NULL;
	}

	lws_esp32_get_image_info(part, &i, buf, sizeof(buf) - 1);
	
	lws_esp32_romfs = (romfs_t)i.romfs;
	if (!romfs_mount_check(lws_esp32_romfs)) {
		lwsl_err("Failed to mount ROMFS at %p 0x%x\n", lws_esp32_romfs, i.romfs);
		return NULL;
	}

	lwsl_notice("ROMFS length %uKiB\n", i.romfs_len >> 10);

	puts(buf);

	/* set the lws vfs to use our romfs */

	lws_set_fops(context, &fops);

	vhost = lws_create_vhost(context, info);
	if (!vhost)
		lwsl_err("Failed to create vhost\n");
	else
		lws_init_vhost_client_ssl(info, vhost); 

	lws_protocol_init(context);

	return context;
}
