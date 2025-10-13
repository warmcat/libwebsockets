/*
 * lws-minimal-secure-streams-custom-proxy-transport
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This is an SS Proxy that uses the UART + lws_transport_mux as the custom
 * transport.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <termios.h>
#include <sys/ioctl.h>

#if defined(__linux__)
#include <asm/ioctls.h>
#include <linux/serial.h>
#endif

#include <assert.h>

#include "private.h"

extern int interrupted;

static const char *filepath = "/dev/ttyUSB0";

#define LWS_PSS_MAGIC LWS_FOURCC('p', 'p', 's', 's')
#define assert_is_pss(_p) lws_assert_fourcc(_p->magic, LWS_PSS_MAGIC)

struct pss {
	uint32_t				magic;
	lws_txp_path_proxy_t			txp_ppath;
	struct lws				*wsi;
	int					filefd;
};

/*
 * Open and configure the serial transport fd
 */

int
open_serial_port(const char *filepath)
{
#if defined(__linux__)
	struct serial_struct s_s;
#endif
	struct termios tio;
	int fd = open(filepath, O_RDWR);

	if (fd == -1) {
		lwsl_err("Unable to open %s: %d\n", filepath, errno);

		return -1;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK))
		lwsl_info("%s: fcntl failed errno %d\n", __func__, errno);
	tcflush(fd, TCIOFLUSH);

#if defined(__linux__)
	if (ioctl(fd, TIOCGSERIAL, &s_s) == 0) {
		s_s.closing_wait = ASYNC_CLOSING_WAIT_NONE;
		s_s.flags = (int)((int)s_s.flags | (int)ASYNC_LOW_LATENCY);
		ioctl(fd, TIOCSSERIAL, &s_s);
	}
#endif

	/* enforce suitable tty state */

	memset(&tio, 0, sizeof tio);
	if (tcgetattr(fd, &tio)) {
		close(fd);
		fd = -1;
		return -1;
	}

	cfsetispeed(&tio, B2000000); // B921600);
	cfsetospeed(&tio, B2000000); // B921600);

	tio.c_lflag &= (tcflag_t)~(ISIG | ICANON | IEXTEN | ECHO |
#if defined(__linux__)
			XCASE |
#endif
			 ECHOE | ECHOK | ECHONL | ECHOCTL | ECHOKE);
	tio.c_iflag &= (tcflag_t)~(INLCR | IGNBRK | IGNPAR | IGNCR | ICRNL |
			 IMAXBEL | IXON | IXOFF | IXANY
#if defined(__linux__)
			 | IUCLC
#endif
			| 0xff);
	tio.c_oflag = 0;

	tio.c_cc[VMIN]  = 1;
	tio.c_cc[VTIME] = 0;
	tio.c_cc[VEOF] = 1;
#if 0
	tio.c_cflag = tio.c_cflag & (unsigned long) ~(
#if defined(__linux__)
			CBAUD |
#endif
			CSIZE | CSTOPB | PARENB | CRTSCTS);
#endif
	tio.c_cflag = B2000000 | /* 0x1412 | */CS8 | CREAD | CLOCAL;

	tcsetattr(fd, TCSANOW, &tio);

	lwsl_notice("%s: serial port opened %d\n", __func__, fd);

	return fd;
}

static int
cb_proxy_serial_transport(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)lws_get_opaque_user_data(wsi);
	uint8_t buf[1024];
	int n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		lwsl_user("%s: PROTOCOL_INIT %s\n", __func__,
				lws_get_vhost_name(lws_get_vhost(wsi)));
		break;

	/* callbacks related to raw file descriptor */

	case LWS_CALLBACK_RAW_ADOPT_FILE:
		lwsl_notice("LWS_CALLBACK_RAW_ADOPT_FILE\n");

		break;

	case LWS_CALLBACK_RAW_RX_FILE:
//		lwsl_notice("LWS_CALLBACK_RAW_RX_FILE\n");

		if (pss)
			assert_is_pss(pss);

		n = (int)read(pss->filefd, buf, sizeof(buf));
		if (n <= 0) {
			lwsl_err("Reading from %s failed\n", filepath);
			interrupted = 1;
			return 1;
		}
		lwsl_hexdump_notice(buf, (size_t)n);
#if 0
		lwsl_info("%s: passing read to %s, priv_in %p\n", __func__,
			  pss->txp_ppath.ops_in->name, pss->txp_ppath.priv_in);
#endif
		pss->txp_ppath.ops_in->proxy_read(pss->txp_ppath.priv_in, buf,
				(size_t)n);

		break;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		lwsl_notice("LWS_CALLBACK_RAW_CLOSE_FILE\n");

		if (pss) {
			assert_is_pss(pss);

			lws_set_opaque_user_data(wsi, NULL);
			/*
			 * We also have to eliminate the pss reference in
			 * 	tm->info.txp_ppath.priv_onw
			 */

			((lws_transport_mux_t *)pss->txp_ppath.priv_in)->
					info.txp_ppath.priv_onw = NULL;

			free(pss);
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE_FILE:
		//lwsl_notice("%s: LWS_CALLBACK_RAW_WRITEABLE_FILE: %p\n",
		//		__func__, pss->txp_ppath.priv_in);

		if (pss) {
			assert_is_pss(pss);

			/* pass the event back inwards */
			pss->txp_ppath.ops_in->event_proxy_can_write(
				pss->txp_ppath.priv_in
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
					, NULL
#endif
				);
		}
		break;

	default:
		break;
	}

	return 0;
}

struct lws_protocols protocol_sspc_serial_transport =
	{ "sspc-serial-transport",
	  cb_proxy_serial_transport,
	  0, 1300, 0, NULL, 0 };


static void
txp_serial_onward_bind(lws_transport_priv_t priv, struct lws_ss_handle *h)
{
}

static void
txp_serial_req_write(lws_transport_priv_t priv)
{
	struct pss *pss = (struct pss *)priv;

	assert_is_pss(pss);

	if (pss->wsi)
		lws_callback_on_writable(pss->wsi);
}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
static const lws_fi_ctx_t *
txp_serial_fault_context(lws_transport_priv_t priv)
{
	return NULL;
}
#endif

/*
 * Partial writes are quite possible
 */

static int
txp_serial_write(lws_transport_priv_t priv, uint8_t *buf, size_t *len)
{
	struct pss *pss = (struct pss *)priv;
	ssize_t r;

	assert_is_pss(pss);

//	lwsl_warn("%s: write %d\n", __func__, (int)*len);
//	lwsl_hexdump_warn(buf, *len);

	r = write(pss->filefd, buf, *len);
	if (r < 0) {
		lwsl_wsi_notice(pss->wsi, "failed");
		assert(0);
		return -1;
	}

	if ((size_t)r != *len)
		lwsl_warn("%s: partial, had %d accepted %d\n", __func__, (int)*len, (int)r);
	*len = (size_t)r;

	return 0;
}

int
txp_serial_init_proxy_server(struct lws_context *cx,
				 const struct lws_transport_proxy_ops *txp_ops_inward,
				 lws_transport_priv_t txp_priv_inward,
				 lws_txp_path_proxy_t *txp_ppath,
				 const void *txp_info,
				 const char *bind, int port)
{
	int fd = open_serial_port(bind);
	lws_adopt_desc_t ad;
	struct pss *pss;

	lwsl_user("%s: txp_priv_inward %p\n", __func__, txp_priv_inward);

	if (fd < 0) {
		lwsl_err("%s: unable to open %s\n", __func__, bind);
		return 1;
	}

	pss = malloc(sizeof(*pss));
	if (!pss) {
		close(fd);
		return 1;
	}

	pss->magic = LWS_PSS_MAGIC;
	pss->filefd = fd;

	memset(&ad, 0, sizeof(ad));
	ad.vh = lws_get_vhost_by_name(cx, "default");
	ad.type = LWS_ADOPT_RAW_FILE_DESC;
	ad.fd.filefd = (lws_filefd_type)(long long)fd;
	ad.opaque = pss;
	ad.vh_prot_name = "sspc-serial-transport";

	pss->wsi = lws_adopt_descriptor_vhost_via_info(&ad);
	if (!pss->wsi) {
		lwsl_err("%s: Failed to adopt fifo\n", __func__);
		close(fd);
		free(pss);

		return 1;
	}

	pss->txp_ppath.ops_in = txp_ops_inward;
	pss->txp_ppath.priv_in = txp_priv_inward;
	txp_ppath->priv_onw = (lws_transport_priv_t)pss;

	lwsl_user("%s: OK (txp_priv_in %p)\n", __func__, txp_priv_inward);

	return 0;
}

static void
txp_serial_client_up(lws_transport_priv_t priv)
{
	//struct lws *wsi = (struct lws *)priv;

	//lws_set_timeout(wsi, 0, 0);
}

static int
txp_serial_proxy_check_write_more(lws_transport_priv_t priv)
{
	struct pss *pss = (struct pss *)priv;

	if (pss->wsi && !lws_send_pipe_choked(pss->wsi))
		return 1;

	return 0;
}

const lws_transport_proxy_ops_t lws_transport_ops_serial = {
	.name			= "txpserial",
	.init_proxy_server	= txp_serial_init_proxy_server,
	.proxy_req_write	= txp_serial_req_write,
	.proxy_write		= txp_serial_write,

	.event_onward_bind	= txp_serial_onward_bind,
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	.fault_context		= txp_serial_fault_context,
#endif
	.event_client_up	= txp_serial_client_up,
	.proxy_check_write_more = txp_serial_proxy_check_write_more,
	.flags			= LWS_DSHFLAG_ENABLE_COALESCE |
				  LWS_DSHFLAG_ENABLE_SPLIT
};
