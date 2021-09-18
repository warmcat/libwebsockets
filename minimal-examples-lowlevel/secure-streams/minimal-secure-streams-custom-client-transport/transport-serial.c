/*
 * lws-minimal-secure-streams-custom-client-transport
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * The serial port based custom transport
 */

#include "private.h"

#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <termios.h>
#include <sys/ioctl.h>

#if defined(__linux__)
#include <asm/ioctls.h>
#include <linux/serial.h>
#endif

#include <errno.h>

/* debug helper */

void
lwsl_hexdump_level(int hexdump_level, const void *vbuf, size_t len)
{
	unsigned char *buf = (unsigned char *)vbuf;
	unsigned int n;

	for (n = 0; n < len;) {
		unsigned int start = n, m;
		char line[80], *p = line;

		p += snprintf(p, 10, "%04X: ", start);

		for (m = 0; m < 16 && n < len; m++)
			p += snprintf(p, 5, "%02X ", buf[n++]);
		while (m++ < 16)
			p += snprintf(p, 5, "   ");

		p += snprintf(p, 6, "   ");

		for (m = 0; m < 16 && (start + m) < len; m++) {
			if (buf[start + m] >= ' ' && buf[start + m] < 127)
				*p++ = (char)buf[start + m];
			else
				*p++ = '.';
		}
		while (m++ < 16)
			*p++ = ' ';

		*p++ = '\n';
		*p = '\0';
		_lws_log(hexdump_level, "%s", line);
		(void)line;
	}

	_lws_log(hexdump_level, "\n");
}

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
		lwsl_err("Unable to open %s\n", filepath);

		return -1;
	}

	fcntl(fd, F_SETFL, O_NONBLOCK);
	tcflush(fd, TCIOFLUSH);

#if defined(__linux__)
	if (ioctl(fd, TIOCGSERIAL, &s_s) == 0) {
		s_s.closing_wait = ASYNC_CLOSING_WAIT_NONE;
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

	cfsetispeed(&tio, B2000000);
	cfsetospeed(&tio, B2000000);

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
	tio.c_cflag = B2000000 | /*0x1412 | */ CS8 | CREAD | CLOCAL;

	tcsetattr(fd, TCSANOW, &tio);

	return fd;
}

int
open_transport_file(custom_poll_ctx_t *cpcx, const char *filepath, void *priv)
{
	int fd = open_serial_port(filepath);

	if (fd < 0)
		return -1;

	transport_fd = fd;

	/* let's add it to the event loop, and set POLLIN */

	if (custom_poll_add_fd(cpcx, fd, POLLIN, priv)) {
		close(fd);
		return -1;
	}

	return fd;
}

/****** custom transport to proxy
 *
 *
 **/

/* incoming parsed channel cbs */

static int
ltm_ch_payload(lws_transport_mux_ch_t *tmc, const uint8_t *buf, size_t len)
{
	lwsl_notice("%s\n", __func__);
	return 0;
}

static int
ltm_ch_opens_serial(lws_transport_mux_ch_t *tmc, int determination)
{
	lws_transport_mux_t *tm = lws_container_of(tmc->list.owner,
						   lws_transport_mux_t, owner);
	struct lws_sspc_handle *h = (struct lws_sspc_handle *)tmc->priv;

	assert_is_tm(tm);

	lwsl_sspc_err(h, "%d", determination);

       	if (tm->info.txp_cpath.ops_in->event_connect_disposition(h, determination))
        		return -1;

	return 0;
}
static int
ltm_ch_closes(lws_transport_mux_ch_t *tmc)
{
	lwsl_notice("%s\n", __func__);
	return 0;
}

static void
ltm_txp_req_write(lws_transport_mux_t *tm)
{
	a_cpcx.tm->info.txp_cpath.ops_onw->req_write(
						a_cpcx.tm->info.txp_cpath.priv_onw);
}

static int
ltm_txp_can_write(lws_transport_mux_ch_t *tmc)
{
	assert_is_tmch(tmc);
	return lws_txp_inside_sspc.event_can_write((struct lws_sspc_handle *)tmc->priv, 2048);
}

static const lws_txp_mux_parse_cbs_t cbs = {
	.payload		= ltm_ch_payload,
	.ch_opens		= ltm_ch_opens_serial,
	.ch_closes		= ltm_ch_closes,
	.txp_req_write		= ltm_txp_req_write,
	.txp_can_write		= ltm_txp_can_write,
};

int
custom_transport_event(struct pollfd *pfd, void *priv)
{
	uint8_t buf[2048];
	ssize_t r = sizeof(buf);

	lwsl_notice("%s: fd %d, revents %d\n", __func__, pfd->fd, pfd->revents);

	if (pfd->revents & POLLOUT) {
		custom_poll_change_fd(&a_cpcx, pfd->fd, 0, POLLOUT);
		/*
		 * We can write something on the transport... if the transport
		 * mux layer has something, let that use the write preferentally
		 * and request another write for whatever this was
		 */

		lwsl_notice("%s: doing POLLOUT\n", __func__);

		if (lws_transport_mux_pending(a_cpcx.tm, buf, (size_t *)&r, &cbs)) {

			lws_transport_path_client_dump(&a_cpcx.tm->info.txp_cpath, "cpath");

			a_cpcx.tm->info.txp_cpath.ops_onw->_write(
				a_cpcx.tm->info.txp_cpath.priv_onw,
				buf, (size_t)r);

			return 0;
		}
	}

	if (pfd->revents & POLLIN) {

		r = read(pfd->fd, buf, sizeof(buf));
		if (r < 0) {
			int eno = errno;

			lwsl_warn("%s: read says %d, errno %d\n", __func__,
					(int)r, eno);
			return -1;
		}

		//lwsl_hexdump_notice(buf, (size_t)r);

		if (a_cpcx.tm && a_cpcx.tm->info.txp_cpath.ops_in) {

#if 0
			lwsl_user("%s: passing read to %s, priv_in %p\n",
					__func__,
					a_cpcx.tm->info.txp_cpath.ops_in->name,
					a_cpcx.tm->info.txp_cpath.priv_in);
#endif

			a_cpcx.tm->info.txp_cpath.ops_in->event_read(
					a_cpcx.tm->info.txp_cpath.priv_in,
					buf, (size_t)r);
		}
	}

	return 0;
}

/*
 * We get called while an individual SS is trying to connect to the proxy to
 * be recognized as operational.  It's the equivalent of trying to bring up the
 * Unix Domain socket
 */

static int
txp_serial_retry_connect(lws_txp_path_client_t *path,
				       struct lws_sspc_handle *h)
{
	lwsl_user("%s\n", __func__);

	if (path->ops_onw->event_connect_disposition(h,
				a_cpcx.tm->link_state != LWSTM_OPERATIONAL))
	        return -1;

	return 0;
}

static void
txp_serial_req_write(lws_transport_priv_t priv)
{
	lwsl_notice("%s\n", __func__);
	custom_poll_change_fd(&a_cpcx, transport_fd, POLLOUT, 0);
}

static int
txp_serial_write(lws_transport_priv_t priv, uint8_t *buf, size_t len)
{
	lwsl_notice("%s: writing %u\n", __func__, (unsigned int)len);
	// lwsl_hexdump_notice(buf, len);
	if (write(transport_fd, buf, len) != (ssize_t)len) {
		lwsl_warn("%s: write %u failed\n", __func__, (unsigned int)len);

		return 1;
	}
	return 0;
}

static void
txp_serial_close(lws_transport_priv_t priv)
{
#if 0
	struct lws *wsi = (struct lws *)priv;

	if (!wsi)
		return;

	lws_set_opaque_user_data(wsi, NULL);
	lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
	*priv = NULL;
#endif
}

static void
txp_serial_stream_up(lws_transport_priv_t priv)
{
//	struct lws *wsi = (struct lws *)priv;

//	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
}

const lws_transport_client_ops_t lws_sss_ops_client_serial = {
	.name			= "txpserial",
	.event_retry_connect	= txp_serial_retry_connect,
	.req_write		= txp_serial_req_write,
	._write			= txp_serial_write,
	._close			= txp_serial_close,
	.event_stream_up	= txp_serial_stream_up,
};
