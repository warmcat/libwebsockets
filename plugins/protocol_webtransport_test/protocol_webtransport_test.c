/*
 * WebTransport test protocol plugin
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#if !defined (LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif
#include <libwebsockets/lws-webtransport.h>

#include <string.h>
#include <stdlib.h>

#define BLOB_SIZE (4 * 1024 * 1024)
#define HASH_SIZE 32
#define TOTAL_SEND_SIZE (BLOB_SIZE + HASH_SIZE)
#define TEST_ITERATIONS 10

struct vhd__wt_test {
	uint8_t *blob;
	uint8_t hash[HASH_SIZE];
};

struct pss__wt_test {
	int send_count;
	size_t send_pos;

	int recv_count;
	size_t recv_pos;
	struct lws_genhash_ctx hash_ctx_rx;
	uint8_t hash_rx_expected[HASH_SIZE];
	
	int established;
};

static int
callback_wt_test(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct pss__wt_test *pss = (struct pss__wt_test *)user;
	struct vhd__wt_test *vhd =
			(struct vhd__wt_test *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	uint8_t *p;
	size_t chunk, to_send;
	int m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct vhd__wt_test));
		if (!vhd)
			return -1;

		vhd->blob = malloc(BLOB_SIZE);
		if (!vhd->blob)
			return -1;

		{
			struct lws_xos xos;
			struct lws_genhash_ctx hctx;
			size_t i;
			
			lws_xos_init(&xos, 0x12345678);
			for (i = 0; i < BLOB_SIZE; i++)
				vhd->blob[i] = (uint8_t)lws_xos(&xos);

			if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA256)) {
				lwsl_err("genhash init failed\n");
				return -1;
			}
			if (lws_genhash_update(&hctx, vhd->blob, BLOB_SIZE)) {
				lwsl_err("genhash update failed\n");
				return -1;
			}
			lws_genhash_destroy(&hctx, vhd->hash);
		}
		lwsl_notice("WT Test Plugin Initialized\n");
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd && vhd->blob) {
			free(vhd->blob);
			vhd->blob = NULL;
		}
		break;

	case LWS_CALLBACK_ESTABLISHED:
		/* We only care about WebTransport child streams for data transfer */
		if (lws_wt_is_session(wsi)) {
			lwsl_user("Session established\n");
		} else {
			lwsl_user("Stream established\n");
			pss->send_count = 0;
			pss->send_pos = 0;
			pss->recv_count = 0;
			pss->recv_pos = 0;
			
			if (lws_genhash_init(&pss->hash_ctx_rx, LWS_GENHASH_TYPE_SHA256)) {
				return -1;
			}
			pss->established = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!pss->established || pss->send_count >= TEST_ITERATIONS)
			break;

		to_send = TOTAL_SEND_SIZE - pss->send_pos;
		if (to_send > 65536)
			to_send = 65536; /* write in chunks */

		{
			uint8_t buf[LWS_PRE + 65536];
			p = &buf[LWS_PRE];
			
			if (pss->send_pos < BLOB_SIZE) {
				chunk = BLOB_SIZE - pss->send_pos;
				if (chunk > to_send) chunk = to_send;
				memcpy(p, vhd->blob + pss->send_pos, chunk);
				
				if (chunk < to_send) {
					/* Append hash */
					memcpy(p + chunk, vhd->hash, to_send - chunk);
				}
			} else {
				memcpy(p, vhd->hash + (pss->send_pos - BLOB_SIZE), to_send);
			}

			m = lws_write(wsi, p, (unsigned int)to_send, LWS_WRITE_BINARY);
			if (m < 0) {
				lwsl_err("write error\n");
				return -1;
			}

			pss->send_pos += (size_t)m;
			if (pss->send_pos == TOTAL_SEND_SIZE) {
				pss->send_pos = 0;
				pss->send_count++;
				lwsl_user("Sent blob %d/%d\n", pss->send_count, TEST_ITERATIONS);
			}
			
			if (pss->send_count < TEST_ITERATIONS)
				lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (!pss->established || pss->recv_count >= TEST_ITERATIONS)
			break;

		p = (uint8_t *)in;
		while (len > 0) {
			if (pss->recv_pos < BLOB_SIZE) {
				chunk = BLOB_SIZE - pss->recv_pos;
				if (chunk > len) chunk = len;
				
				if (lws_genhash_update(&pss->hash_ctx_rx, p, chunk))
					return -1;
				
				pss->recv_pos += chunk;
				p += chunk;
				len -= chunk;
			} else {
				chunk = TOTAL_SEND_SIZE - pss->recv_pos;
				if (chunk > len) chunk = len;
				
				memcpy(pss->hash_rx_expected + (pss->recv_pos - BLOB_SIZE), p, chunk);
				
				pss->recv_pos += chunk;
				p += chunk;
				len -= chunk;
				
				if (pss->recv_pos == TOTAL_SEND_SIZE) {
					uint8_t computed[HASH_SIZE];
					lws_genhash_destroy(&pss->hash_ctx_rx, computed);
					
					if (memcmp(computed, pss->hash_rx_expected, HASH_SIZE) == 0) {
						pss->recv_count++;
						lwsl_user("Received and verified blob %d/%d\n", 
							  pss->recv_count, TEST_ITERATIONS);
					} else {
						lwsl_err("Hash mismatch on blob %d\n", pss->recv_count + 1);
						return -1;
					}
					
					/* Prepare for next blob */
					pss->recv_pos = 0;
					if (pss->recv_count < TEST_ITERATIONS) {
						if (lws_genhash_init(&pss->hash_ctx_rx, LWS_GENHASH_TYPE_SHA256))
							return -1;
					}
				}
			}
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (pss->established) {
			/* If we haven't finished the hash, destroy it to avoid leaks */
			if (pss->recv_count < TEST_ITERATIONS && pss->recv_pos < TOTAL_SEND_SIZE) {
				uint8_t computed[HASH_SIZE];
				lws_genhash_destroy(&pss->hash_ctx_rx, computed);
			}
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_WT_TEST \
	{ \
		"webtransport-test", \
		callback_wt_test, \
		sizeof(struct pss__wt_test), \
		65536, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols wt_test_protocols[] = {
	LWS_PLUGIN_PROTOCOL_WT_TEST
};

LWS_VISIBLE const lws_plugin_protocol_t webtransport_test = {
	.hdr = {
		.name = "webtransport test",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = wt_test_protocols,
	.count_protocols = LWS_ARRAY_SIZE(wt_test_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
