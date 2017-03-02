/*
 * ws protocol handler plugin for testing raw file and raw socket
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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
 * These test plugins are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 *
 * Enable on a vhost like this
 *
 *        "protocol-lws-raw-test": {
 *                 "status": "ok",
 *                 "fifo-path": "/tmp/lws-test-raw"
 *        },
 *
 * Then you can feed it data through the FIFO like this
 *
 *  $ sudo sh -c "echo hello > /tmp/lws-test-raw"
 *
 * This plugin simply prints the data.  But it does it through the lws event loop /
 * service poll.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#endif

#include <string.h>

struct per_vhost_data__raw_test {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	char fifo_path[100];
	int fifo;
	char zero_length_read;
};

struct per_session_data__raw_test {
	int number;
};

static int
callback_raw_test(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct per_session_data__raw_test *pss =
			(struct per_session_data__raw_test *)user;
	struct per_vhost_data__raw_test *vhd =
			(struct per_vhost_data__raw_test *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	lws_sock_file_fd_type u;

	(void)pss;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__raw_test));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		{
			const struct lws_protocol_vhost_options *pvo =
					(const struct lws_protocol_vhost_options *)in;
			while (pvo) {
				if (!strcmp(pvo->name, "fifo-path"))
					strncpy(vhd->fifo_path, pvo->value, sizeof(vhd->fifo_path) - 1);
				pvo = pvo->next;
			}
			if (vhd->fifo_path[0] == '\0') {
				lwsl_err("Missing pvo \"fifo-path\"\n");
				return 1;
			}
		}
		unlink(vhd->fifo_path);
		if (mkfifo(vhd->fifo_path, 0666)) {
			lwsl_err("mkfifo failed\n");
			return 1;
		}
		vhd->fifo = open(vhd->fifo_path, O_NONBLOCK | O_RDONLY);
		if (vhd->fifo == -1) {
			lwsl_err("opening fifo failed\n");
			unlink(vhd->fifo_path);
			return 1;
		}
		lwsl_notice("FIFO %s created\n", vhd->fifo_path);
		u.filefd = vhd->fifo;
		if (!lws_adopt_descriptor_vhost(vhd->vhost, 0, u, "protocol-lws-raw-test", NULL)) {
			lwsl_err("Failed to adopt fifo descriptor\n");
			close(vhd->fifo);
			unlink(vhd->fifo_path);
			return 1;
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
		if (vhd->fifo >- 0) {
			close(vhd->fifo);
			unlink(vhd->fifo_path);
		}
		break;

	case LWS_CALLBACK_RAW_ADOPT_FILE:
		lwsl_notice("LWS_CALLBACK_RAW_ADOPT_FILE\n");
		break;


	case LWS_CALLBACK_RAW_RX_FILE:
		lwsl_notice("LWS_CALLBACK_RAW_RX_FILE\n");
		{
			char buf[256];
			int n;
			
			n = read(vhd->fifo, buf, sizeof(buf) - 1);
			if (n < 0) {
				lwsl_err("FIFO read failed\n");
				return 1;
			}
			/*
			 * When nobody opened the other side of the FIFO, the FIFO fd acts well and
			 * only signals POLLIN when somebody opened and wrote to it.
			 *
			 * But if the other side of the FIFO closed it, we will see an endless
			 * POLLIN and 0 available to read.
			 *
			 * The only way to handle it is to reopen the FIFO our side and wait for a
			 * new peer.  This is a quirk of FIFOs not of LWS.
			 */
			if (n == 0) { /* peer closed - do reopen in close processing */
				vhd->zero_length_read = 1;
				return 1;
			}
			buf[n] = '\0';
			lwsl_info("read %d\n", n);
			puts(buf);
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		lwsl_notice("LWS_CALLBACK_RAW_CLOSE_FILE\n");
		if (vhd->zero_length_read) {
			vhd->zero_length_read = 0;
			close(vhd->fifo);
			/* the wsi that adopted the fifo file is closing... reopen the fifo and readopt */
			vhd->fifo = open(vhd->fifo_path, O_NONBLOCK | O_RDONLY);
			if (vhd->fifo == -1) {
				lwsl_err("opening fifo failed\n");
				return 1;
			}
			lwsl_notice("FIFO %s reopened\n", vhd->fifo_path);
			u.filefd = vhd->fifo;
			if (!lws_adopt_descriptor_vhost(vhd->vhost, 0, u, "protocol-lws-raw-test", NULL)) {
				lwsl_err("Failed to adopt fifo descriptor\n");
				close(vhd->fifo);
				return 1;
			}
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE_FILE:
		lwsl_notice("LWS_CALLBACK_RAW_WRITEABLE_FILE\n");
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_RAW_TEST \
	{ \
		"protocol-lws-raw-test", \
		callback_raw_test, \
		sizeof(struct per_session_data__raw_test), \
		1024, /* rx buf size must be >= permessage-deflate rx size */ \
	}

#if !defined (LWS_PLUGIN_STATIC)
		
static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_RAW_TEST
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_raw_test(struct lws_context *context,
			     struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_lws_raw_test(struct lws_context *context)
{
	return 0;
}

#endif
