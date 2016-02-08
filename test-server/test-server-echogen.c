/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */
#include "test-server.h"

/* echogen protocol
 *
 * if you connect to him using his protocol, he'll send you a file chopped
 * up in various frame sizes repeated until he reaches a limit.
 */

#define TOTAL 993840

int
callback_lws_echogen(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	unsigned char buf[LWS_PRE + 8192];
	struct per_session_data__echogen *pss =
			(struct per_session_data__echogen *)user;
	unsigned char *p = &buf[LWS_PRE];
	int n, m;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		pss->total = TOTAL;
		pss->fragsize = 2048;
		pss->total_rx = 0;
		sprintf((char *)buf, "%s/test.html", resource_path);
		pss->fd = open((char *)buf, LWS_O_RDONLY);
		if (pss->fd < 0) {
			lwsl_err("Failed to open %s\n", buf);
			return -1;
		}
		pss->wr = LWS_WRITE_TEXT | LWS_WRITE_NO_FIN;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLOSED:
		if (pss->fd >= 0)
			close(pss->fd);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:

//		pss->fragsize += 16;
//		if (pss->fragsize >= 4096)
//			pss->fragsize = 32;

		lwsl_err("%s: cb writeable, total left %ld\n", __func__, (long)pss->total);
		m = pss->fragsize;
		if ((size_t)m >=  pss->total) {
			m = (int)pss->total;
			pss->wr = LWS_WRITE_CONTINUATION; /* ie, FIN */
		}
		n = read(pss->fd, p, m);
		if (n < 0) {
			lwsl_err("failed read\n");
			return -1;
		}
		if (n < m) {
			lseek(pss->fd, 0, SEEK_SET);
			m = read(pss->fd, p + n, m - n);
			if (m < 0)
				return -1;
		} else
			m = 0;
		pss->total -= n + m;
		m = lws_write(wsi, p, n + m, pss->wr);
		if (m < n) {
			lwsl_err("ERROR %d writing to di socket\n", n);
			return -1;
		}
		if (!pss->total) {
			lwsl_err("Completed OK\n");
			break;
		}
		pss->wr = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		pss->total_rx += len;
		lwsl_err("rx %ld\n", (long)pss->total_rx);
		if (pss->total_rx == TOTAL) {
			lws_close_reason(wsi, LWS_CLOSE_STATUS_NORMAL,
					 (unsigned char *)"done", 4);
			return -1;
		}
		break;

	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		lwsl_notice("LWS_CALLBACK_WS_PEER_INITIATED_CLOSE: len %d\n",
			    len);
		for (n = 0; n < (int)len; n++)
			lwsl_notice(" %d: 0x%02X\n", n,
				    ((unsigned char *)in)[n]);
		break;

	default:
		break;
	}

	return 0;
}
