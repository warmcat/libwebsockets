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
 * (and h3, when built and given a certificate) with every content-encoding
 * the server can offer (identity, deflate and brotli when built), plus one it
 * cannot (gzip).  The client decodes what
 * it receives and checks the digest and length against the name, so a
 * corrupted, truncated or mis-framed compressed transfer shows up as a
 * digest mismatch, not a silent success.
 *
 * Each response's framing and caching headers are checked too:
 *
 *  - a response whose coding was chosen from accept-encoding, the identity
 *    ones included, says "vary: accept-encoding", so a shared cache keeps
 *    the codings apart, and so does a 304 revalidating it (RFC 9110 15.4.5)
 *  - one whose coding was not chosen from it does not: a mimetype lws does
 *    not compress (the same file as .bin), a 206 (never coded), or a vhost
 *    with LWS_SERVER_OPTION_NO_HTTP_STREAM_COMPRESSION
 *  - a coded body has no content-length, since it is coded on the fly: on
 *    h1 it goes chunked, on h2 it ends with the stream.  An identity one
 *    has its content-length and no transfer-encoding, and h2 never has one
 *
 * A callback mount, /dyn, answers with the same content as an app would:
 * /dyn/compose composes the headers with lws_add_http_common_headers() and
 * writes the body itself, /dyn/file passes the file to lws_serve_http_file().
 * Both are compressed as the mount is.  /dyn/compose-optout and
 * /dyn/file-optout do the same after lws_http_compression_opt_out(), and must
 * come uncompressed, without vary, on every role (BREACH, G-201).
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
	DEC_DEFLATE,		/* zlib format (RFC 9110), windowBits 15 */
	DEC_BR,
};

/* the length of the range the range cases ask for, from the start */
#define RANGE_LEN 100

enum vh {
	VH_DEFAULT,
	VH_NO_COMPRESSION,	/* LWS_SERVER_OPTION_NO_HTTP_STREAM_COMPRESSION */
};

enum role {
	ROLE_H1,
	ROLE_H2,		/* h2c, prior knowledge */
	ROLE_H3,		/* on its own tls vhost, VH_DEFAULT only */
};

/* the body /dyn/compose writes at a time */
#define DYN_CHUNK 4096

struct xcase {
	const char	*name;
	const char	*accept;	/* accept-encoding to send, or NULL */
	const char	*expect_ce;	/* content-encoding expected, or NULL */
	enum dec	dec;
	enum role	role;
	enum vh		vh;
	const char	*dyn;		/* a path under the /dyn mount, or NULL */
	int		bin;		/* the .bin name, not compressible */
	int		revalidate;	/* if-none-match the last etag, want 304 */
	int		range;		/* ask for the first RANGE_LEN, want 206 */
	int		vary;		/* expect vary: accept-encoding */
};

static const struct xcase cases[] = {
	{ .name = "h1 no accept-encoding", .vary = 1 },
	{ .name = "h1 accept gzip (not offered)", .accept = "gzip", .vary = 1 },
	{ .name = "h1 accept deflate", .accept = "deflate",
	  .expect_ce = "deflate", .dec = DEC_DEFLATE, .vary = 1 },
	/* q=0 is "not this one", and a coding is matched whole */
	{ .name = "h1 accept deflate;q=0", .accept = "deflate;q=0", .vary = 1 },
	{ .name = "h1 accept xdeflate", .accept = "xdeflate", .vary = 1 },
	{ .name = "h1 accept gzip, deflate;q=0.5",
	  .accept = "gzip, deflate;q=0.5", .expect_ce = "deflate",
	  .dec = DEC_DEFLATE, .vary = 1 },
#if defined(LWS_WITH_HTTP_BROTLI)
	{ .name = "h1 accept br", .accept = "br", .expect_ce = "br",
	  .dec = DEC_BR, .vary = 1 },
#endif
	{ .name = "h1 revalidate, accept deflate", .accept = "deflate",
	  .revalidate = 1, .vary = 1 },
	{ .name = "h1 not compressible, accept deflate", .accept = "deflate",
	  .bin = 1 },
	{ .name = "h1 not compressible, revalidate", .accept = "deflate",
	  .bin = 1, .revalidate = 1 },
	{ .name = "h1 vhost without compression, accept deflate",
	  .accept = "deflate", .vh = VH_NO_COMPRESSION },
	{ .name = "h1 vhost without compression, revalidate",
	  .accept = "deflate", .vh = VH_NO_COMPRESSION, .revalidate = 1 },
#if defined(LWS_WITH_RANGES)
	{ .name = "h1 range, accept deflate", .accept = "deflate", .range = 1 },
#endif
#if defined(LWS_WITH_HTTP2)
	{ .name = "h2 no accept-encoding", .role = ROLE_H2, .vary = 1 },
	{ .name = "h2 accept gzip (not offered)", .accept = "gzip", .role = ROLE_H2,
	  .vary = 1 },
	{ .name = "h2 accept deflate", .accept = "deflate",
	  .expect_ce = "deflate", .dec = DEC_DEFLATE, .role = ROLE_H2, .vary = 1 },
#if defined(LWS_WITH_HTTP_BROTLI)
	{ .name = "h2 accept br", .accept = "br", .expect_ce = "br",
	  .dec = DEC_BR, .role = ROLE_H2, .vary = 1 },
#endif
	{ .name = "h2 revalidate, accept deflate", .accept = "deflate",
	  .role = ROLE_H2, .revalidate = 1, .vary = 1 },
	{ .name = "h2 not compressible, accept deflate", .accept = "deflate",
	  .role = ROLE_H2, .bin = 1 },
	{ .name = "h2 vhost without compression, accept deflate",
	  .accept = "deflate", .role = ROLE_H2, .vh = VH_NO_COMPRESSION },
	{ .name = "h2 vhost without compression, revalidate",
	  .accept = "deflate", .role = ROLE_H2, .vh = VH_NO_COMPRESSION,
	  .revalidate = 1 },
#if defined(LWS_WITH_RANGES)
	{ .name = "h2 range, accept deflate", .accept = "deflate", .role = ROLE_H2,
	  .range = 1 },
#endif
#endif
#if defined(LWS_ROLE_H3)
	{ .name = "h3 no accept-encoding", .role = ROLE_H3, .vary = 1 },
	{ .name = "h3 accept deflate", .accept = "deflate",
	  .expect_ce = "deflate", .dec = DEC_DEFLATE, .role = ROLE_H3,
	  .vary = 1 },
	{ .name = "h3 revalidate, accept deflate", .accept = "deflate",
	  .role = ROLE_H3, .revalidate = 1, .vary = 1 },
#endif

	/*
	 * The app's own answers, and the ones it opted out of compression.
	 * These come last: they leave no ETag for the revalidations
	 */

	{ .name = "h1 composed, accept deflate", .accept = "deflate",
	  .expect_ce = "deflate", .dec = DEC_DEFLATE, .dyn = "/compose",
	  .vary = 1 },
	{ .name = "h1 composed, opted out", .accept = "deflate",
	  .dyn = "/compose-optout" },
	{ .name = "h1 served, accept deflate", .accept = "deflate",
	  .expect_ce = "deflate", .dec = DEC_DEFLATE, .dyn = "/file",
	  .vary = 1 },
	{ .name = "h1 served, opted out", .accept = "deflate",
	  .dyn = "/file-optout" },
#if defined(LWS_WITH_HTTP2)
	{ .name = "h2 composed, accept deflate", .accept = "deflate",
	  .expect_ce = "deflate", .dec = DEC_DEFLATE, .dyn = "/compose",
	  .role = ROLE_H2, .vary = 1 },
	{ .name = "h2 composed, opted out", .accept = "deflate",
	  .dyn = "/compose-optout", .role = ROLE_H2 },
	{ .name = "h2 served, accept deflate", .accept = "deflate",
	  .expect_ce = "deflate", .dec = DEC_DEFLATE, .dyn = "/file",
	  .role = ROLE_H2, .vary = 1 },
	{ .name = "h2 served, opted out", .accept = "deflate",
	  .dyn = "/file-optout", .role = ROLE_H2 },
#endif
#if defined(LWS_ROLE_H3)
	{ .name = "h3 composed, accept deflate", .accept = "deflate",
	  .expect_ce = "deflate", .dec = DEC_DEFLATE, .dyn = "/compose",
	  .role = ROLE_H3, .vary = 1 },
	{ .name = "h3 composed, opted out", .accept = "deflate",
	  .dyn = "/compose-optout", .role = ROLE_H3 },
	{ .name = "h3 served, accept deflate", .accept = "deflate",
	  .expect_ce = "deflate", .dec = DEC_DEFLATE, .dyn = "/file",
	  .role = ROLE_H3, .vary = 1 },
	{ .name = "h3 served, opted out", .accept = "deflate",
	  .dyn = "/file-optout", .role = ROLE_H3 },
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
	char			vary[64];
	char			te[32];
	char			cl[24];
	uint8_t			head[RANGE_LEN]; /* the first decoded bytes */
	char			ce_present;
	char			stream_ended;
	char			completed;
	char			failed;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int cur = -1, failures, interrupted;
/* the listen ports, by vhost and then h1 / h2 */
static int ports[2][2] = { { 7681, 7682 }, { 7683, 7684 } }, h3_port = 7685;
static const char *cert, *key;
static size_t file_size = 3 * 1024 * 1024;
static uint8_t *file_mem; /* the file's content, for /dyn/compose */
static char tmpdir[256], file_path[384], bin_path[384], file_name[80],
	    etag[64];
static const char *tmpbase = ".";
static uint8_t file_sha[32], file_head[RANGE_LEN];
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
	char line[512];
	FILE *f;
	int n;

	/* scratch dir under the caller's choice (the build dir from ctest) */
	lws_snprintf(tmpdir, sizeof(tmpdir), "%s/lws-http-comp-XXXXXX", tmpbase);
	if (!mkdtemp(tmpdir)) {
		lwsl_err("%s: mkdtemp %s failed\n", __func__, tmpdir);
		tmpdir[0] = '\0';
		return 1;
	}

	file_mem = malloc(file_size + 1);
	if (!file_mem) {
		lwsl_err("%s: OOM\n", __func__);
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
		if (done < sizeof(file_head))
			memcpy(file_head + done, line,
			       l < sizeof(file_head) - done ? l :
					sizeof(file_head) - done);
		memcpy(file_mem + done, line, l);
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

	/* the same file under a name whose mimetype lws does not compress */
	lws_snprintf(bin_path, sizeof(bin_path), "%s/%.64s.bin", tmpdir,
		     file_name);
	if (link(file_path, bin_path)) {
		lwsl_err("%s: link failed\n", __func__);
		bin_path[0] = '\0';
		return 1;
	}

	lwsl_user("%s: %s, %u bytes\n", __func__, file_path,
		  (unsigned int)file_size);

	return 0;
}

static void
cleanup_file(void)
{
	free(file_mem);
	file_mem = NULL;
	if (bin_path[0])
		unlink(bin_path);
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
		if (inflateInit2(&cn->zs, 15) != Z_OK)
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
		if (cn->rx_dec < sizeof(cn->head))
			memcpy(cn->head + cn->rx_dec, in,
			       len < sizeof(cn->head) - cn->rx_dec ? len :
					sizeof(cn->head) - cn->rx_dec);
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
	int ok = 1, status = HTTP_STATUS_OK;
	size_t expect_len = file_size;
	char expect_cl[24];
	uint8_t sha[32];

	if (c->revalidate) {
		status = HTTP_STATUS_NOT_MODIFIED;
		expect_len = 0;
	}
	if (c->range) {
		status = HTTP_STATUS_PARTIAL_CONTENT;
		expect_len = RANGE_LEN;
	}

	if (cn->completed)
		/* finished already: a kept-warm connection closing late */
		return;
	cn->completed = 1;

	if (!completed) {
		lwsl_err("%s: connection closed before completion\n", __func__);
		ok = 0;
	}
	if (cn->status != status) {
		lwsl_err("%s: status %d, expected %d\n", __func__, cn->status,
			 status);
		ok = 0;
	}
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS) || defined(LWS_ROLE_H2) || \
    defined(LWS_HTTP_HEADERS_ALL)
	if (strcmp(cn->vary, c->vary ? "accept-encoding" : "")) {
		lwsl_err("%s: expected vary '%s', got '%s'\n", __func__,
			 c->vary ? "accept-encoding" : "", cn->vary);
		ok = 0;
	}
#endif
	/* a coded body goes chunked on h1; nothing else has a coding */
	if (strcmp(cn->te, c->role == ROLE_H1 && c->expect_ce ? "chunked" : "")) {
		lwsl_err("%s: unexpected transfer-encoding '%s'\n", __func__,
			 cn->te);
		ok = 0;
	}
	/*
	 * An identity body says how long it is, a coded one can't know.  h2
	 * and h3 end a body with its stream, and lws' file serving leaves the
	 * content-length out there: one it does send must be right
	 */
	if (status == HTTP_STATUS_NOT_MODIFIED || c->expect_ce)
		expect_cl[0] = '\0';
	else
		lws_snprintf(expect_cl, sizeof(expect_cl), "%u",
			     (unsigned int)expect_len);
	if (strcmp(cn->cl, expect_cl) && (c->role == ROLE_H1 || cn->cl[0])) {
		lwsl_err("%s: expected content-length '%s', got '%s'\n",
			 __func__, expect_cl, cn->cl);
		ok = 0;
	}
	if (c->dec != DEC_IDENTITY && !cn->stream_ended) {
		lwsl_err("%s: compressed stream did not end cleanly\n",
			 __func__);
		ok = 0;
	}
	if (cn->rx_dec != expect_len) {
		lwsl_err("%s: decoded %u bytes, expected %u\n", __func__,
			 (unsigned int)cn->rx_dec, (unsigned int)expect_len);
		ok = 0;
	}
	/* the whole file is checked by its digest, a range by its bytes */
	if (lws_genhash_destroy(&cn->hash, sha) ||
	    (status == HTTP_STATUS_OK && memcmp(sha, file_sha, sizeof(sha))) ||
	    (c->range && memcmp(cn->head, file_head, RANGE_LEN))) {
		lwsl_err("%s: content mismatch\n", __func__);
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
		if (c && c->revalidate &&
		    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_IF_NONE_MATCH,
				(unsigned char *)etag, (int)strlen(etag),
				p, end))
			return -1;
		if (c && c->range &&
		    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_RANGE,
				(unsigned char *)"bytes=0-99", 10, p, end))
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
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS) || defined(LWS_ROLE_H2) || \
    defined(LWS_HTTP_HEADERS_ALL)
		if (lws_hdr_copy(wsi, cn->vary, sizeof(cn->vary),
				 WSI_TOKEN_HTTP_VARY) < 0)
			cn->vary[0] = '\0';
#endif
		if (lws_hdr_copy(wsi, cn->te, sizeof(cn->te),
				 WSI_TOKEN_HTTP_TRANSFER_ENCODING) < 0)
			cn->te[0] = '\0';
		if (lws_hdr_copy(wsi, cn->cl, sizeof(cn->cl),
				 WSI_TOKEN_HTTP_CONTENT_LENGTH) < 0)
			cn->cl[0] = '\0';
		/* the ETag is the same whatever the coding, for revalidation */
		if (!c->revalidate && !c->range &&
		    lws_hdr_copy(wsi, etag, sizeof(etag),
				 WSI_TOKEN_HTTP_ETAG) < 0)
			etag[0] = '\0';
		lwsl_user("%s: status %d, content-encoding '%s', vary '%s', "
			  "transfer-encoding '%s', content-length '%s'\n",
			  __func__, cn->status,
			  cn->ce_present ? cn->ce : "(none)", cn->vary, cn->te,
			  cn->cl);
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

/*
 * Each case's own: a connection of an earlier case may still be heard from
 * after its case finished (closed by the server while kept warm), and must
 * not be taken for the current case's
 */
static struct conn conns[LWS_ARRAY_SIZE(cases)];

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct xcase *c;
	struct conn *cn;
	char path[96];

	cur++;
	if (cur >= (int)LWS_ARRAY_SIZE(cases)) {
		interrupted = 1;
		lws_cancel_service(context);
		return;
	}
	c = &cases[cur];

	lwsl_user("--- case %d: %s ---\n", cur, c->name);

	if ((c->range && file_size < RANGE_LEN) ||
	    /* an empty composed body has nothing to code */
	    (c->dyn && !file_size && !strncmp(c->dyn, "/compose", 8)) ||
	    (c->role == ROLE_H3 && (!cert || !key))) {
		lwsl_user("%s: skipped, %s\n", __func__,
			  c->role == ROLE_H3 && (!cert || !key) ?
				"h3 needs --cert and --key" :
				"the file is too short for it");
		lws_sul_schedule(context, 0, &sul_next, next_case,
				 LWS_US_PER_MS);
		return;
	}

	cn = &conns[cur];
	if (conn_decoder_init(cn, c)) {
		lwsl_err("%s: decoder init failed\n", __func__);
		failures++;
		lws_sul_schedule(context, 0, &sul_next, next_case,
				 LWS_US_PER_MS);
		return;
	}

	if (c->dyn)
		lws_snprintf(path, sizeof(path), "/dyn%s", c->dyn);
	else
		lws_snprintf(path, sizeof(path), "/%s", file_name);
	if (c->bin)
		/* the same file, as .bin */
		memcpy(path + strlen(path) - 4, ".bin", 4);

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	switch (c->role) {
	case ROLE_H1:
		i.port = ports[c->vh][0];
		break;
	case ROLE_H2:
		i.port = ports[c->vh][1];
		i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;
		break;
	case ROLE_H3:
		i.port = h3_port;
		i.alpn = "h3";
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		/* decided on h3, not by a fallback to tcp */
		i.disable_h3_fallback = 1;
		break;
	}
	i.path = path;
	i.method = "GET";
	i.protocol = "http-comp";
	i.opaque_user_data = cn;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		conn_decoder_destroy(cn, c);
		cn->completed = 1;
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

/*
 * The /dyn mount: answers as an app composes them.  "/compose" composes the
 * headers with lws_add_http_common_headers() and writes the file's content
 * itself, "/file" passes the file to lws_serve_http_file().  "-optout" on
 * either opts the response out of compression first.
 */

struct pss_dyn {
	size_t		sent;
	char		composing;
};

static int
callback_dyn(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct pss_dyn *pss = (struct pss_dyn *)user;
	uint8_t buf[LWS_PRE + DYN_CHUNK], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	const char *path = (const char *)in;
	size_t n, base;
	int r;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->sent = 0;
		pss->composing = 0;

		/* the url's last part, whether in has the mountpoint or not */
		n = 0;
		while (n < len && path[len - n - 1] != '/')
			n++;
		path += len - n;
		base = n;

		if (n > 7 && !strncmp(path + n - 7, "-optout", 7)) {
			if (lws_http_compression_opt_out(wsi))
				return -1;
			base = n - 7;
		}

		if (base == 4 && !strncmp(path, "file", 4)) {
			r = lws_serve_http_file(wsi, file_path, "text/plain",
						NULL, 0);
			if (r < 0 || (r > 0 &&
				      lws_http_transaction_completed(wsi)))
				return -1;

			return 0;
		}

		if (base != 7 || strncmp(path, "compose", 7))
			return lws_return_http_status(wsi,
					HTTP_STATUS_NOT_FOUND, NULL) ? -1 :
				lws_http_transaction_completed(wsi);

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						(lws_filepos_t)file_size,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;

		pss->composing = 1;
		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->composing)
			break;

		n = file_size - pss->sent;
		if (n > DYN_CHUNK)
			n = DYN_CHUNK;
		memcpy(start, file_mem + pss->sent, n);
		pss->sent += n;

		if (lws_write(wsi, start, n, pss->sent == file_size ?
				LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) != (int)n)
			return -1;

		if (pss->sent != file_size) {
			lws_callback_on_writable(wsi);
			return 0;
		}

		pss->composing = 0;
		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "dyn", callback_dyn, sizeof(struct pss_dyn), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "http-comp", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* .bin is served, but as a mimetype lws does not compress */
static const struct lws_protocol_vhost_options mimetype_bin = {
	NULL, NULL, ".bin", "application/octet-stream"
};

static const struct lws_http_mount mount_dyn = {
	.mountpoint		= "/dyn",
	.origin			= "dyn",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 4,
};

static struct lws_http_mount mount = {
	.mount_next		= &mount_dyn,
	.mountpoint		= "/",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
	.extra_mimetypes	= &mimetype_bin,
};

/* the server vhosts, by enum vh and then h1 / h2 */
static const char * const vh_names[2][2] = {
	{ "srv-h1", "srv-h2" }, { "srv-nc-h1", "srv-nc-h2" }
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	const char *p;
	int result = 1, n;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);
	lws_set_log_level(logs, NULL);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		ports[VH_DEFAULT][0] = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2-port")))
		ports[VH_DEFAULT][1] = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--nc-port")))
		ports[VH_NO_COMPRESSION][0] = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--nc-h2-port")))
		ports[VH_NO_COMPRESSION][1] = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h3-port")))
		h3_port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--cert")))
		cert = p;
	if ((p = lws_cmdline_option(argc, argv, "--key")))
		key = p;
	if ((p = lws_cmdline_option(argc, argv, "--size")))
		file_size = (size_t)atol(p);
	if ((p = lws_cmdline_option(argc, argv, "--tmpdir")))
		tmpbase = p;

	lwsl_user("LWS API selftest: http stream compression\n");

	if (generate_file())
		goto bail_file;

	mount.origin = tmpdir;

	memset(&info, 0, sizeof(info));
	lws_context_info_defaults(&info, NULL);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.fd_limit_per_thread = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		goto bail_file;
	}

	info.protocols = protocols_srv;
	info.mounts = &mount;
	for (n = 0; n < 2; n++) {
		uint64_t opts = info.options;
		int h;

		if (n == VH_NO_COMPRESSION)
			info.options |=
				LWS_SERVER_OPTION_NO_HTTP_STREAM_COMPRESSION;

		for (h = 0; h < 2; h++) {
#if !defined(LWS_WITH_HTTP2)
			if (h)
				break;
#else
			if (h)
				info.options |=
					LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif
			info.port = ports[n][h];
			info.vhost_name = vh_names[n][h];
			if (!lws_create_vhost(context, &info)) {
				lwsl_err("Failed to create vhost %s\n",
					 info.vhost_name);
				goto bail;
			}
		}
		info.options = opts;
	}

#if defined(LWS_ROLE_H3)
	if (cert && key) {
		info.port = h3_port;
		info.vhost_name = "srv-h3";
		info.ssl_cert_filepath = cert;
		info.ssl_private_key_filepath = key;
		info.alpn = "h2,http/1.1,h3";
		if (!lws_create_vhost(context, &info)) {
			lwsl_err("Failed to create vhost %s\n",
				 info.vhost_name);
			goto bail;
		}
		info.ssl_cert_filepath = NULL;
		info.ssl_private_key_filepath = NULL;
		info.alpn = NULL;
	}
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
