/*
 * lws-api-test-http-compression
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * One process: a file mount serves a large generated text file whose name
 * is its own sha256, and the client side fetches it back over h1 and h2c
 * with every content-encoding the server can offer (identity, deflate and
 * brotli when built), plus one it cannot (gzip).  The client decodes what
 * it receives and checks the digest and length against the name, so a
 * corrupted, truncated or mis-framed compressed transfer shows up as a
 * digest mismatch, not a silent success.
 *
 * The file is text/plain because lws only compresses text-ish mimetypes,
 * and its content is a pseudo-random hex stream interleaved with repeated
 * words, so the compressors have real work to do without collapsing it.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <zlib.h>
#if defined(LWS_WITH_HTTP_BROTLI)
#include <brotli/decode.h>
#endif

enum dec {
	DEC_IDENTITY,
	DEC_DEFLATE,		/* lws sends raw deflate, windowBits -15 */
	DEC_BR,
};

struct xcase {
	const char	*name;
	const char	*accept;	/* accept-encoding to send, or NULL */
	const char	*expect_ce;	/* content-encoding expected, or NULL */
	enum dec	dec;
	int		h2;
};

static const struct xcase cases[] = {
	{ "h1 no accept-encoding",	NULL,	   NULL,      DEC_IDENTITY, 0 },
	{ "h1 accept gzip (not offered)", "gzip",  NULL,      DEC_IDENTITY, 0 },
	{ "h1 accept deflate",		"deflate", "deflate", DEC_DEFLATE,  0 },
#if defined(LWS_WITH_HTTP_BROTLI)
	{ "h1 accept br",		"br",	   "br",      DEC_BR,	    0 },
#endif
#if defined(LWS_WITH_HTTP2)
	{ "h2 no accept-encoding",	NULL,	   NULL,      DEC_IDENTITY, 1 },
	{ "h2 accept gzip (not offered)", "gzip",  NULL,      DEC_IDENTITY, 1 },
	{ "h2 accept deflate",		"deflate", "deflate", DEC_DEFLATE,  1 },
#if defined(LWS_WITH_HTTP_BROTLI)
	{ "h2 accept br",		"br",	   "br",      DEC_BR,	    1 },
#endif
#endif
};

struct conn {
	struct lws_genhash_ctx	hash;
	z_stream		zs;
#if defined(LWS_WITH_HTTP_BROTLI)
	BrotliDecoderState	*br;
#endif
	size_t			rx_raw, rx_dec;
	int			status;
	char			ce[32];
	char			ce_present;
	char			stream_ended;
	char			completed;
	char			failed;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int cur = -1, failures, port_h1 = 7681, port_h2 = 7682, interrupted;
static size_t file_size = 3 * 1024 * 1024;
static char tmpdir[64], file_path[128], file_name[80];
static uint8_t file_sha[32];
static const char *server_addr = "127.0.0.1";

static void
next_case(lws_sorted_usec_list_t *sul);

/*
 * deterministic content: a xorshift32 hex stream with repeated words, so it
 * is neither incompressible nor trivially compressible
 */

static int
generate_file(void)
{
	static const char * const words[] = {
		"lorem", "ipsum", "dolor", "sit", "amet", "consectetur",
		"adipiscing", "elit", "sed", "do", "eiusmod", "tempor" };
	struct lws_genhash_ctx hc;
	uint32_t x = 0x12345678u;
	size_t done = 0;
	char line[128];
	FILE *f;
	int n;

	if (!mkdtemp(strcpy(tmpdir, "/tmp/lws-http-comp-XXXXXX"))) {
		lwsl_err("%s: mkdtemp failed\n", __func__);
		return 1;
	}

	lws_snprintf(file_path, sizeof(file_path), "%s/gen.txt", tmpdir);
	f = fopen(file_path, "wb");
	if (!f) {
		lwsl_err("%s: cannot create %s\n", __func__, file_path);
		return 1;
	}

	if (lws_genhash_init(&hc, LWS_GENHASH_TYPE_SHA256)) {
		fclose(f);
		return 1;
	}

	while (done < file_size) {
		size_t l;

		x ^= x << 13; x ^= x >> 17; x ^= x << 5;
		n = lws_snprintf(line, sizeof(line), "%08x %s %s %u\n", x,
				 words[x % LWS_ARRAY_SIZE(words)],
				 words[(x >> 8) % LWS_ARRAY_SIZE(words)],
				 (unsigned int)done);
		l = (size_t)n;
		if (l > file_size - done)
			l = file_size - done;
		if (fwrite(line, 1, l, f) != l ||
		    lws_genhash_update(&hc, line, l)) {
			lwsl_err("%s: write failed\n", __func__);
			fclose(f);
			lws_genhash_destroy(&hc, NULL);
			return 1;
		}
		done += l;
	}
	fclose(f);
	if (lws_genhash_destroy(&hc, file_sha))
		return 1;

	lws_hex_from_byte_array(file_sha, sizeof(file_sha), file_name,
				sizeof(file_name));
	strcat(file_name, ".txt");

	lws_snprintf(line, sizeof(line), "%s/%s", tmpdir, file_name);
	if (rename(file_path, line)) {
		lwsl_err("%s: rename failed\n", __func__);
		return 1;
	}
	lws_strncpy(file_path, line, sizeof(file_path));

	lwsl_user("%s: %s, %u bytes\n", __func__, file_path,
		  (unsigned int)file_size);

	return 0;
}

static void
cleanup_file(void)
{
	if (file_path[0])
		unlink(file_path);
	if (tmpdir[0])
		rmdir(tmpdir);
}

static int
conn_decoder_init(struct conn *cn, const struct xcase *c)
{
	if (lws_genhash_init(&cn->hash, LWS_GENHASH_TYPE_SHA256))
		return 1;

	switch (c->dec) {
	case DEC_DEFLATE:
		memset(&cn->zs, 0, sizeof(cn->zs));
		if (inflateInit2(&cn->zs, -15) != Z_OK)
			return 1;
		break;
#if defined(LWS_WITH_HTTP_BROTLI)
	case DEC_BR:
		cn->br = BrotliDecoderCreateInstance(NULL, NULL, NULL);
		if (!cn->br)
			return 1;
		break;
#endif
	default:
		break;
	}

	return 0;
}

static void
conn_decoder_destroy(struct conn *cn, const struct xcase *c)
{
	lws_genhash_destroy(&cn->hash, NULL);
	if (c->dec == DEC_DEFLATE)
		inflateEnd(&cn->zs);
#if defined(LWS_WITH_HTTP_BROTLI)
	if (c->dec == DEC_BR && cn->br)
		BrotliDecoderDestroyInstance(cn->br);
#endif
}

/* feed received body bytes through the case's decoder into the digest */

static int
conn_rx(struct conn *cn, const struct xcase *c, const uint8_t *in, size_t len)
{
	uint8_t buf[16384];

	cn->rx_raw += len;

	switch (c->dec) {
	case DEC_IDENTITY:
		cn->rx_dec += len;
		return lws_genhash_update(&cn->hash, in, len);

	case DEC_DEFLATE:
		cn->zs.next_in = (Bytef *)in;
		cn->zs.avail_in = (uInt)len;
		do {
			size_t produced;
			int r;

			cn->zs.next_out = buf;
			cn->zs.avail_out = sizeof(buf);
			r = inflate(&cn->zs, Z_NO_FLUSH);
			if (r != Z_OK && r != Z_STREAM_END && r != Z_BUF_ERROR) {
				lwsl_err("%s: inflate failed %d\n", __func__, r);
				return 1;
			}
			produced = sizeof(buf) - cn->zs.avail_out;
			cn->rx_dec += produced;
			if (produced &&
			    lws_genhash_update(&cn->hash, buf, produced))
				return 1;
			if (r == Z_STREAM_END) {
				cn->stream_ended = 1;
				break;
			}
		} while (cn->zs.avail_out == 0 || cn->zs.avail_in);
		return 0;

#if defined(LWS_WITH_HTTP_BROTLI)
	case DEC_BR: {
		const uint8_t *next_in = in;
		size_t avail_in = len;

		do {
			uint8_t *next_out = buf;
			size_t avail_out = sizeof(buf), produced;
			BrotliDecoderResult r;

			r = BrotliDecoderDecompressStream(cn->br, &avail_in,
							  &next_in, &avail_out,
							  &next_out, NULL);
			if (r == BROTLI_DECODER_RESULT_ERROR) {
				lwsl_err("%s: brotli decode failed\n", __func__);
				return 1;
			}
			produced = sizeof(buf) - avail_out;
			cn->rx_dec += produced;
			if (produced &&
			    lws_genhash_update(&cn->hash, buf, produced))
				return 1;
			if (r == BROTLI_DECODER_RESULT_SUCCESS) {
				cn->stream_ended = 1;
				break;
			}
			if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT)
				break;
		} while (1);
		return 0;
	}
#endif
	default:
		return 1;
	}
}

static void
conn_finish(struct conn *cn, const struct xcase *c, int completed)
{
	uint8_t sha[32];
	int ok = 1;

	if (cn->completed)
		return;
	cn->completed = 1;

	if (!completed) {
		lwsl_err("%s: connection closed before completion\n", __func__);
		ok = 0;
	}
	if (cn->status != HTTP_STATUS_OK) {
		lwsl_err("%s: status %d\n", __func__, cn->status);
		ok = 0;
	}
	if (c->expect_ce) {
		if (!cn->ce_present || strcmp(cn->ce, c->expect_ce)) {
			lwsl_err("%s: expected content-encoding %s, got '%s'\n",
				 __func__, c->expect_ce,
				 cn->ce_present ? cn->ce : "(none)");
			ok = 0;
		}
	} else if (cn->ce_present) {
		lwsl_err("%s: unexpected content-encoding '%s'\n", __func__,
			 cn->ce);
		ok = 0;
	}
	if (c->dec != DEC_IDENTITY && !cn->stream_ended) {
		lwsl_err("%s: compressed stream did not end cleanly\n",
			 __func__);
		ok = 0;
	}
	if (cn->rx_dec != file_size) {
		lwsl_err("%s: decoded %u bytes, expected %u\n", __func__,
			 (unsigned int)cn->rx_dec, (unsigned int)file_size);
		ok = 0;
	}
	if (lws_genhash_destroy(&cn->hash, sha) ||
	    memcmp(sha, file_sha, sizeof(sha))) {
		lwsl_err("%s: sha256 mismatch\n", __func__);
		ok = 0;
	}
	/* the digest ctx is gone now, only the decoders remain */
	if (c->dec == DEC_DEFLATE)
		inflateEnd(&cn->zs);
#if defined(LWS_WITH_HTTP_BROTLI)
	if (c->dec == DEC_BR && cn->br) {
		BrotliDecoderDestroyInstance(cn->br);
		cn->br = NULL;
	}
#endif
	if (cn->failed)
		ok = 0;

	lwsl_user("%s: %s: %s (%u bytes on the wire, %u decoded)\n", __func__,
		  c->name, ok ? "PASS" : "FAIL", (unsigned int)cn->rx_raw,
		  (unsigned int)cn->rx_dec);
	if (!ok)
		failures++;

	lws_sul_schedule(context, 0, &sul_next, next_case, LWS_US_PER_MS);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct conn *cn = (struct conn *)lws_get_opaque_user_data(wsi);
	const struct xcase *c = cur >= 0 ? &cases[cur] : NULL;
	char buf[1024];
	char *px = buf;
	int lenx = sizeof(buf);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (c && c->accept &&
		    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_ACCEPT_ENCODING,
				(unsigned char *)c->accept,
				(int)strlen(c->accept), p, end))
			return -1;
		break;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		if (cn && c) {
			cn->failed = 1;
			conn_finish(cn, c, 0);
		}
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!cn || !c)
			break;
		cn->status = (int)lws_http_client_http_response(wsi);
		if (lws_hdr_copy(wsi, cn->ce, sizeof(cn->ce),
				 WSI_TOKEN_HTTP_CONTENT_ENCODING) > 0)
			cn->ce_present = 1;
		lwsl_user("%s: status %d, content-encoding '%s'\n", __func__,
			  cn->status, cn->ce_present ? cn->ce : "(none)");
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!cn || !c || cn->completed)
			break;
		if (conn_rx(cn, c, (const uint8_t *)in, len)) {
			cn->failed = 1;
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (cn && c)
			conn_finish(cn, c, 1);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (cn && c)
			conn_finish(cn, c, 0);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static struct conn conn;

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct xcase *c;
	char path[96];

	cur++;
	if (cur >= (int)LWS_ARRAY_SIZE(cases)) {
		interrupted = 1;
		lws_cancel_service(context);
		return;
	}
	c = &cases[cur];

	lwsl_user("--- case %d: %s ---\n", cur, c->name);

	memset(&conn, 0, sizeof(conn));
	if (conn_decoder_init(&conn, c)) {
		lwsl_err("%s: decoder init failed\n", __func__);
		failures++;
		lws_sul_schedule(context, 0, &sul_next, next_case,
				 LWS_US_PER_MS);
		return;
	}

	lws_snprintf(path, sizeof(path), "/%s", file_name);

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.port = c->h2 ? port_h2 : port_h1;
	if (c->h2)
		i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;
	i.path = path;
	i.method = "GET";
	i.protocol = "http-comp";
	i.opaque_user_data = &conn;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		conn_decoder_destroy(&conn, c);
		conn.completed = 1;
		failures++;
		lws_sul_schedule(context, 0, &sul_next, next_case,
				 LWS_US_PER_MS);
	}
}

static void
watchdog(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: test timed out in case %d\n", __func__, cur);
	failures++;
	interrupted = 1;
	lws_cancel_service(context);
}

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "http-comp", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_http_mount mount = {
	.mountpoint		= "/",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_vhost *vh;
	const char *p;
	int result = 1;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);
	lws_set_log_level(logs, NULL);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2-port")))
		port_h2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--size")))
		file_size = (size_t)atol(p);

	lwsl_user("LWS API selftest: http stream compression\n");

	if (generate_file())
		goto bail_file;

	mount.origin = tmpdir;

	memset(&info, 0, sizeof(info));
	lws_context_info_defaults(&info, NULL);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.fd_limit_per_thread = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		goto bail_file;
	}

	info.port = port_h1;
	info.vhost_name = "srv-h1";
	info.protocols = protocols_srv;
	info.mounts = &mount;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h1 server vhost\n");
		goto bail;
	}

#if defined(LWS_WITH_HTTP2)
	info.port = port_h2;
	info.vhost_name = "srv-h2";
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h2 server vhost\n");
		goto bail;
	}
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.mounts = NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog,
			 90 * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_next, next_case, LWS_US_PER_MS);

	while (!interrupted && lws_service(context, 0) >= 0)
		;

	result = failures ? 1 : 0;

	lwsl_user("Completed: %s (%d cases, %d failures)\n",
		  result ? "FAIL" : "PASS", (int)LWS_ARRAY_SIZE(cases),
		  failures);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(context);
bail_file:
	cleanup_file();

	return result;
}
