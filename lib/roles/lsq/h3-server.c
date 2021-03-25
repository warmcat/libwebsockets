/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The lsquic bits of this are modified from lsquic http_server example,
 * originally
 *
 *    Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE.
 *
 * lsquic license is also MIT same as lws.
 */

#include <sys/queue.h>

#include <private-lib-core.h>

struct index_html_ctx
{
	struct resp resp;
};

struct ver_head_ctx
{
	struct resp resp;
	unsigned char   *req_body;
	size_t           req_sz;    /* Expect it to be the same as qif_sz */
};


struct md5sum_ctx
{
	char        resp_buf[0x100];
	MD5_CTX     md5ctx;
	struct resp resp;
	int         done;
};


struct req
{
	enum method {
		UNSET, GET, POST, UNSUPPORTED,
	}            method;
	enum {
		HAVE_XHDR   = 1 << 0,
	}            flags;
	char        *path;
	char        *method_str;
	char        *authority_str;
	char        *qif_str;
	size_t       qif_sz;
	struct lsxpack_header
	xhdr;
	size_t       decode_off;
	char         decode_buf[(LSXPACK_MAX_STRLEN + 1) < 65536 ?
					(LSXPACK_MAX_STRLEN + 1) : 64 * 1024];
};


struct interop_push_path
{
	STAILQ_ENTRY(interop_push_path)     next;
	char                                path[0];
};


struct gen_file_ctx
{
	STAILQ_HEAD(, interop_push_path)    push_paths;
	size_t      remain;
	unsigned    idle_off;
};


static lsquic_conn_ctx_t *
http_server_on_new_conn(void *stream_if_ctx, lsquic_conn_t *conn)
{
	struct server_ctx *server_ctx = stream_if_ctx;
	lsquic_conn_ctx_t *conn_h;
	const char *sni;

	sni = lsquic_conn_get_sni(conn);
	lwsl_debug("new connection, SNI: %s", sni ? sni : "<not set>");

	conn_h = malloc(sizeof(*conn_h));
	conn_h->conn = conn;
	conn_h->server_ctx = server_ctx;
	server_ctx->conn_h = conn_h;
	++server_ctx->n_current_conns;

	return conn_h;
}


static void
http_server_on_goaway(lsquic_conn_t *conn)
{
	lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
	conn_h->flags |= RECEIVED_GOAWAY;

	lwsl_info("received GOAWAY");
}


static void
http_server_on_conn_closed(lsquic_conn_t *conn)
{
	lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);

	lwsl_info("Connection closed");

	--conn_h->server_ctx->n_current_conns;

	/* No provision is made to stop HTTP server */
	free(conn_h);
}

static lsquic_stream_ctx_t *
http_server_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream)
{
	lsquic_stream_ctx_t *st_h = calloc(1, sizeof(*st_h));

	st_h->stream = stream;
	st_h->server_ctx = stream_if_ctx;
	lsquic_stream_wantread(stream, 1);

	return st_h;
}

static int
ends_with(const char *filename, const char *ext)
{
	const char *where;

	where = strstr(filename, ext);
	return where && strlen(where) == strlen(ext);
}


static const char *
select_content_type(lsquic_stream_ctx_t *st_h)
{
	if (     ends_with(st_h->req_filename, ".html"))
		return "text/html";
	else if (ends_with(st_h->req_filename, ".png"))
		return "image/png";
	else if (ends_with(st_h->req_filename, ".css"))
		return "text/css";
	else if (ends_with(st_h->req_filename, ".gif"))
		return "image/gif";
	else if (ends_with(st_h->req_filename, ".txt"))
		return "text/plain";
	else
		return "application/octet-stream";
}

static int
header_set_ptr(struct lsxpack_header *hdr, struct header_buf *header_buf,
               const char *name, size_t name_len, const char *val, size_t val_len)
{
	if (header_buf->off + name_len + val_len > sizeof(header_buf->buf))
		return -1;

	memcpy(header_buf->buf + header_buf->off, name, name_len);
	memcpy(header_buf->buf + header_buf->off + name_len, val, val_len);
	lsxpack_header_set_offset2(hdr, header_buf->buf + header_buf->off,
					    0, name_len, name_len, val_len);
	header_buf->off += (unsigned int)(name_len + val_len);

	return 0;
}

static int
send_headers(struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
	struct lsxpack_header headers_arr[2];
	lsquic_http_headers_t headers = {
		.count = sizeof(headers_arr) / sizeof(headers_arr[0]),
		.headers = headers_arr,
	};
	const char *content_type;
	struct header_buf hbuf;

	content_type = select_content_type(st_h);

	hbuf.off = 0;
	header_set_ptr(&headers_arr[0], &hbuf, ":status", 7, "200", 3);
	header_set_ptr(&headers_arr[1], &hbuf, "content-type", 12,
		       content_type, strlen(content_type));

	if (lsquic_stream_send_headers(stream, &headers, 0)) {
		lwsl_err("cannot send headers: %s", strerror(errno));

		return -1;
	}

	st_h->flags |= SH_HEADERS_SENT;

	return 0;
}

static void
http_server_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
 //	ssize_t nw;

	if (!(st_h->flags & SH_HEADERS_SENT)) {
		if (send_headers(stream, st_h))
			goto bail;

		return;
	}

#if 0
	if (bytes_left(st_h) <= 0)
		goto bail;

	nw = lsquic_stream_writef(stream, &st_h->reader);

	if (nw < 0) {
		struct lsquic_conn *conn = lsquic_stream_conn(stream);
		lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);

		if (conn_h->flags & RECEIVED_GOAWAY) {
			lwsl_notice("cannot write: goaway received");
			lsquic_stream_close(stream);
		} else {
			lwsl_err("write error: %s", strerror(errno));
			goto bail;
		}
	}

	if (bytes_left(st_h) <= 0)
		goto bail;
#endif
//	st_h->written += (size_t) nw;
	lsquic_stream_wantwrite(stream, 1);

	return;

bail:
	lsquic_stream_shutdown(stream, 1);
	lsquic_stream_wantread(stream, 1);
}

#if 0
static void
http_server_on_read_pushed(struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
	struct hset_fm *hfm;

	hfm = lsquic_stream_get_hset(stream);
	if (!hfm) {
		lwsl_err("%s: error fetching hset: %s", __func__,
							strerror(errno));
		lsquic_stream_close(stream);

		return;
	}

	lwsl_info("got push request #%u for %s", hfm->id, hfm->path);

	st_h->req_path = malloc(strlen(st_h->server_ctx->document_root) + 1 +
				strlen(hfm->path) + 1);
	strcpy(st_h->req_path, st_h->server_ctx->document_root);
	strcat(st_h->req_path, "/");
	strcat(st_h->req_path, hfm->path);
	st_h->req_filename = strdup(st_h->req_path);
		/* XXX Only used for ends_with: drop it? */

	process_request(stream, st_h);

	free(st_h->req_buf);

	lsquic_stream_shutdown(stream, 0);
	destroy_hset_fm(hfm);
}


static void
http_server_on_read_regular(struct lsquic_stream *stream,
			    lsquic_stream_ctx_t *st_h)
{
	unsigned char buf[0x400];
	ssize_t nread;
	int s;

	if (!st_h->req_fh)
		st_h->req_fh = open_memstream(&st_h->req_buf, &st_h->req_sz);

	nread = lsquic_stream_read(stream, buf, sizeof(buf));
	if (nread > 0) {
		fwrite(buf, 1, nread, st_h->req_fh);
		return;
	}

	if (nread) {
		lwsl_err("error reading: %s", strerror(errno));
		lsquic_stream_close(stream);
		return;
	}

	fwrite("", 1, 1, st_h->req_fh);  /* NUL-terminate so that we can regex the string */
	fclose(st_h->req_fh);

	lwsl_info("got request: `%.*s'", (int)st_h->req_sz, st_h->req_buf);
	parse_request(stream, st_h);

	if (st_h->server_ctx->push_path &&
	    strcmp(st_h->req_path, st_h->server_ctx->push_path) &&
	    push_promise(st_h, stream)) {
		lsquic_stream_close(stream);
		return;
	}

	process_request(stream, st_h);

	free(st_h->req_buf);
	lsquic_stream_shutdown(stream, 0);
}
#endif


static void
http_server_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{

}
static void
interop_server_hset_destroy (void *hset_p)
{
    struct req *req = hset_p;
    free(req->qif_str);
    free(req->path);
    free(req->method_str);
    free(req->authority_str);
    free(req);
}

static void
http_server_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
	free(st_h->req_filename);
	free(st_h->req_path);

	if (st_h->req)
		interop_server_hset_destroy(st_h->req);

	free(st_h);

	lwsl_info("%s called, has unacked data: %d", __func__,
			lsquic_stream_has_unacked_data(stream));
}

const struct lsquic_stream_if http_server_if = {
	.on_new_conn            = http_server_on_new_conn,
	.on_conn_closed         = http_server_on_conn_closed,
	.on_new_stream          = http_server_on_new_stream,
	.on_read                = http_server_on_read,
	.on_write               = http_server_on_write,
	.on_close               = http_server_on_close,
	.on_goaway_received     = http_server_on_goaway,
};
