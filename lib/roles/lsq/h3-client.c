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
 * The lsquic bits of this are modified from lsquic http_client example,
 * originally
 *
 *    Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE.
 *
 * lsquic license is also MIT same as lws.
 */

#if __GNUC__
#undef _GNU_SOURCE
#define _GNU_SOURCE     /* For struct in6_pktinfo */
#undef __USE_GNU
#define __USE_GNU
#endif

#include <sys/queue.h>

#include <private-lib-core.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int s_discard_response;
static int s_display_cert_chain;


static struct priority_spec *s_priority_specs;

//!!!
struct priority_spec *priority_specs = NULL;

//!!! static scope HACKS

/* Set to true value to use header bypass.  This means that the use code
 * creates header set via callbacks and then fetches it by calling
 * lsquic_stream_get_hset() when the first "on_read" event is called.
 */
static int g_header_bypass;
static unsigned s_n_prio_specs;

int
header_set_ptr(struct lsxpack_header *hdr, struct header_buf *header_buf,
	       const char *name, size_t name_len, const char *val,
	       size_t val_len)
{
	if (header_buf->off + name_len + val_len > sizeof(header_buf->buf))
		return -1;

	memcpy(header_buf->buf + header_buf->off, name, name_len);
	memcpy(header_buf->buf + header_buf->off + name_len, val, val_len);
	lsxpack_header_set_offset2(hdr, header_buf->buf + header_buf->off,
			0, name_len, name_len, val_len);
	header_buf->off = header_buf->off + (unsigned int)(name_len + val_len);

	return 0;
}


static int
hsk_status_ok (enum lsquic_hsk_status status)
{
	return status == LSQ_HSK_OK || status == LSQ_HSK_RESUMED_OK;
}


/* This is here to exercise lsquic_conn_get_server_cert_chain() API */
static void
display_cert_chain (lsquic_conn_t *conn)
{
#if 0
	STACK_OF(X509) *chain;
	X509_NAME *name;
	X509 *cert;
	int i;
	char buf[100];

	chain = lsquic_conn_get_server_cert_chain(conn);
	if (!chain)
	{
		lwsl_warn("could not get server certificate chain");
		return;
	}

	for (i = 0; i < sk_X509_num(chain); ++i)
	{
		cert = sk_X509_value(chain, i);
		name = X509_get_subject_name(cert);
		lwsl_info("cert #%u: name: %s", i,
				X509_NAME_oneline(name, buf, sizeof(buf)));
		X509_free(cert);
	}

	sk_X509_free(chain);
#endif
}


static void
create_streams (struct http_client_ctx *ccx, lsquic_conn_ctx_t *conn_h)
{
	while (conn_h->ch_n_reqs - conn_h->ch_n_cc_streams &&
			conn_h->ch_n_cc_streams < ccx->hcc_cc_reqs_per_conn)
	{
		lsquic_conn_make_stream(conn_h->conn);
		conn_h->ch_n_cc_streams++;
	}
}

static void
maybe_perform_priority_actions (struct lsquic_stream *stream,
		lsquic_stream_ctx_t *st_h)
{
	const lsquic_stream_id_t stream_id = lsquic_stream_id(stream);
	struct priority_spec *spec;
	unsigned n_active;
	int s;

	n_active = 0;
	for (spec = s_priority_specs; spec < s_priority_specs + s_n_prio_specs;
			++spec)
	{
		if ((spec->flags & PRIORITY_SPEC_ACTIVE)
				&& spec->stream_id == stream_id
				&& st_h->sh_nread >= spec->nread)
		{
			s = lsquic_stream_set_http_prio(stream, &spec->ehp);
			if (s) {
				lwsl_err("could not apply priorities to stream %"PRIu64,
						stream_id);
				exit(1);
			}
			spec->flags = spec->flags & (unsigned int)(~PRIORITY_SPEC_ACTIVE);
		}
		n_active += !!(spec->flags & PRIORITY_SPEC_ACTIVE);
	}

	if (n_active == 0)
		s_priority_specs = NULL;
}


static size_t
discard (void *ctx, const unsigned char *buf, size_t sz, int fin)
{
	lsquic_stream_ctx_t *st_h = ctx;

	if (st_h->sh_flags & ABANDON)
	{
		if (sz > st_h->sh_stop - st_h->sh_nread)
			sz = st_h->sh_stop - st_h->sh_nread;
	}

	return sz;
}

static void
http_client_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
	struct http_client_ctx *const ccx = st_h->ccx;
	unsigned char buf[0x200], *p = buf;
	const char *cce = "unset";
	unsigned nreads = 0;
	ssize_t nread;

	do {
		if (!ccx->notified_http_hdr_sent &&
				st_h->sh_flags & HEADERS_SENT) {
			lwsi_set_state(ccx->wsi, LRS_WAITING_SERVER_REPLY);
			ccx->notified_http_hdr_sent = 1;
		}

		if (nread = (s_discard_response
				? lsquic_stream_readf(stream, discard, st_h)
						: lsquic_stream_read(stream, buf,
								st_h->sh_flags & ABANDON
								? MIN(sizeof(buf), st_h->sh_nread - st_h->sh_stop)
										: sizeof(buf))),
				nread > 0)
		{
			int n = (int)nread;
			st_h->sh_nread += (size_t) nread;

			if (!g_header_bypass && !(st_h->sh_flags & PROCESSED_HEADERS))
			{
				/* First read is assumed to be the first byte */
				st_h->sh_ttfb = lws_now_usecs();

				st_h->sh_flags |= PROCESSED_HEADERS;

				lwsi_set_state(ccx->wsi, LRS_ESTABLISHED);

				if (user_callback_handle_rxflow(
						ccx->wsi->a.protocol->callback,
						ccx->wsi,
						LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
						ccx->wsi->user_space, NULL, 0)) {
					lwsl_info("%s: ESTABLISHED_CLIENT_HTTP closed it\n", __func__);
					lsquic_stream_close(stream);
					break;
				}
			}
			if (!s_discard_response) {

#if defined(LWS_WITH_CLIENT)
				if (!ccx->wsi->hdr_parsing_completed &&
				    !ccx->wsi->told_user_closed) {
					struct lws_tokens eb;

					eb.token = buf;
					eb.len = (int)nread;

					if (eb.len) {
						n = eb.len;

						if (!ccx->wsi->http.ah &&
						    lws_header_table_attach(ccx->wsi, 0)) {
							cce = "no ah";
							goto bail;
						}

						if (lws_parse(ccx->wsi, eb.token, &n)) {
							lwsl_warn("problems parsing header\n");
							cce = "problems parsing header";
							goto bail;
						}

						p += (eb.len - n);
					}
				}

				/*
				 * ...we might well use part of the buffer for
				 * headers and then want to report the rest as
				 * the start of the body...
				 */

				if (ccx->wsi->hdr_parsing_completed &&
				    !ccx->wsi->told_user_closed) {

					if (!ccx->subsequent) {
						if (lws_client_interpret_server_handshake(ccx->wsi)) {
							lwsl_info("interp closed it\n");
							lsquic_stream_close(stream);
							break;
						}
						ccx->subsequent = 1;
					}


					/*
					 *  !!! directly goes to
					 * LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ
					 * as we already read it
					 */
					if (user_callback_handle_rxflow(
							ccx->wsi->a.protocol->callback,
							ccx->wsi,
							LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ,
							ccx->wsi->user_space, p, (size_t)n)) {
						lwsl_info("RECEIVE_CLIENT_HTTP closed it\n");
						lsquic_stream_close(stream);
						break;
					}

				}
#endif
			}

			if (s_priority_specs)
				maybe_perform_priority_actions(stream, st_h);

			if ((st_h->sh_flags & ABANDON) &&
			     st_h->sh_nread >= st_h->sh_stop)
			{
				lwsl_debug("closing stream early having read %zd bytes",
						st_h->sh_nread);
				lsquic_stream_close(stream);
				break;
			}

			continue;
		}
		if (!nread) {
			ccx->hcc_flags |= HCC_SEEN_FIN;
			lsquic_stream_shutdown(stream, 0);
			break;
		}
		if (ccx->context->lsq.settings.es_rw_once &&
		    errno == EWOULDBLOCK) {
			lwsl_notice("emptied the buffer in 'once' mode\n");
			break;
		}
		if (lsquic_stream_is_rejected(stream)) {
			lwsl_notice("stream was rejected");
			lsquic_stream_close(stream);
			break;
		}

		lwsl_err("could not read: %s", strerror(errno));
		exit(2);

	} while (ccx->context->lsq.settings.es_rw_once
			&& nreads++ < 3 /* Emulate just a few reads */);

	return;

bail:
	lws_inform_client_conn_fail(ccx->wsi, (void *)cce, strlen(cce));
	lsquic_stream_close(stream);
}

static void
http_client_on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
	const int pushed = lsquic_stream_is_pushed(stream);
	struct http_client_ctx *ccx;
	lsquic_conn_ctx_t *conn_h;
	lsquic_conn_t *conn;

	if (pushed) {
		assert(NULL == st_h);
		return;
	}

	lwsl_notice("%s\n", __func__);

	conn = lsquic_stream_conn(stream);
	conn_h = lsquic_conn_get_ctx(conn);
	ccx = st_h->ccx;

	if (ccx->wsi->hdr_parsing_completed &&
	    !ccx->wsi->http.content_length_given)
		if (user_callback_handle_rxflow(ccx->wsi->a.protocol->callback,
			ccx->wsi,
			LWS_CALLBACK_COMPLETED_CLIENT_HTTP,
			ccx->wsi->user_space, NULL, 0)) {
				lwsl_info("LWS_CALLBACK_COMPLETED_CLIENT_HTTP closed it\n");
			}

	--conn_h->ch_n_reqs;
	--conn_h->ch_n_cc_streams;

	if (!conn_h->ch_n_reqs) {
		lwsl_info("all requests completed, closing connection\n");
		lsquic_conn_close(conn_h->conn);
	} else {
		lwsl_info("%u active stream, %u request remain, creating %u new stream\n",
				conn_h->ch_n_cc_streams,
				conn_h->ch_n_reqs - conn_h->ch_n_cc_streams,
				MIN((conn_h->ch_n_reqs - conn_h->ch_n_cc_streams),
						(ccx->hcc_cc_reqs_per_conn -
						 conn_h->ch_n_cc_streams)));
		create_streams(ccx, conn_h);
	}

	TAILQ_REMOVE(&ccx->hcc_path_elems, ccx->hcc_cur_pe, next_pe);

	if (ccx->wsi) {
		lws_wsi_close(ccx->wsi, LWS_TO_KILL_ASYNC);
		ccx->wsi = NULL;
	}

	lws_free(st_h);
}


static lsquic_conn_ctx_t *
http_client_on_new_conn(void *stream_if_ctx, lsquic_conn_t *conn)
{
	struct http_client_ctx *ccx = stream_if_ctx;
	lsquic_conn_ctx_t *conn_h = lws_zalloc(sizeof(*conn_h), __func__);

	conn_h->conn = conn;
	conn_h->ccx = ccx;
	conn_h->ch_n_reqs = MIN(ccx->hcc_total_n_reqs, ccx->hcc_reqs_per_conn);
	ccx->hcc_total_n_reqs -= conn_h->ch_n_reqs;
	++conn_h->ccx->hcc_n_open_conns;

	if (!TAILQ_EMPTY(&ccx->hcc_path_elems))
		create_streams(ccx, conn_h);
	//    conn_h->ch_created = lws_now_usecs();
	return conn_h;
}

static void
http_client_on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
	lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
	struct http_client_ctx *ccx = conn_h->ccx;

	if (hsk_status_ok(status))
		lwsl_info("handshake success %s\n",
				status == LSQ_HSK_RESUMED_OK ? "(session resumed)" : "");
	else if (status == LSQ_HSK_FAIL)
		lwsl_info("handshake failed\n");
	else if (status == LSQ_HSK_RESUMED_FAIL) {
		lwsl_info("%s: handshake failed because of session resumption, will retry "
				"without it\n", __func__);
		ccx->hcc_flags |= HCC_SKIP_SESS_RESUME;
		++ccx->hcc_concurrency;
		++ccx->hcc_total_n_reqs;
	} else
		assert(0);

	if (hsk_status_ok(status) && s_display_cert_chain)
		display_cert_chain(conn);

	if (!hsk_status_ok(status))
		return;

	conn_h = lsquic_conn_get_ctx(conn);

	if (TAILQ_EMPTY(&ccx->hcc_path_elems)) {
		lwsl_info("no paths mode: close connection\n");
		lsquic_conn_close(conn_h->conn);
	}
}


static void
http_client_on_conn_closed(lsquic_conn_t *conn)
{
	lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
	//struct http_client_ctx *hcc = conn_h->ccx;
	enum LSQUIC_CONN_STATUS status;
	char errmsg[80];

	status = lsquic_conn_status(conn, errmsg, sizeof(errmsg));
	lwsl_info("Connection closed.  Status: %d.  Message: %s\n", status,
			errmsg[0] ? errmsg : "<not set>");

	if (conn_h->ccx->hcc_flags & HCC_ABORT_ON_INCOMPLETE)
		if (!(conn_h->ccx->hcc_flags & HCC_SEEN_FIN))
			abort();

	--conn_h->ccx->hcc_n_open_conns;

	lws_free(conn_h);
}

static lsquic_stream_ctx_t *
http_client_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream)
{
	const int pushed = lsquic_stream_is_pushed(stream);

	if (pushed)
	{
		lwsl_info("not accepting server push");
		lsquic_stream_refuse_push(stream);
		return NULL;
	}

	lsquic_stream_ctx_t *st_h = lws_zalloc(sizeof(*st_h), __func__);
	st_h->stream = stream;
	st_h->ccx = stream_if_ctx;
	st_h->sh_created = lws_now_usecs();
	if (st_h->ccx->hcc_cur_pe) {
		st_h->ccx->hcc_cur_pe = TAILQ_NEXT(
				st_h->ccx->hcc_cur_pe, next_pe);
		if (!st_h->ccx->hcc_cur_pe)  /* Wrap around */
			st_h->ccx->hcc_cur_pe =
					TAILQ_FIRST(&st_h->ccx->hcc_path_elems);
	}
	else
		st_h->ccx->hcc_cur_pe = TAILQ_FIRST(
				&st_h->ccx->hcc_path_elems);
	st_h->path = st_h->ccx->hcc_cur_pe->path;

	lwsl_info("created new stream, path: %s\n", st_h->path);
	lsquic_stream_wantwrite(stream, 1);

	if (s_priority_specs)
		maybe_perform_priority_actions(stream, st_h);

#if 0
	if (s_abandon_early) {
		st_h->sh_stop = (size_t)(random() % (s_abandon_early + 1));
		st_h->sh_flags |= ABANDON;
	}
#endif

	return st_h;
}


static void
lws_lsq_send_headers(lsquic_stream_ctx_t *st_h)
{
	const char *hostname = st_h->ccx->hostname;
	struct header_buf hbuf;
	unsigned int h_idx = 0;

	if (!hostname)
		hostname = st_h->ccx->context->lsq.hostname;
	hbuf.off = 0;
	struct lsxpack_header headers_arr[9];
#define V(v) (v), strlen(v)
	header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":method"), V(st_h->ccx->method));
	header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":scheme"), V("https"));
	header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":path"), V(st_h->path));
	header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":authority"), V(hostname));
	header_set_ptr(&headers_arr[h_idx++], &hbuf, V("user-agent"), V(st_h->ccx->context->lsq.settings.es_ua));
#if 0
	if (randomly_reprioritize_streams)
	{
		char pfv[10];
		sprintf(pfv, "u=%ld", random() & 7);
		header_set_ptr(&headers_arr[h_idx++], &hbuf, V("priority"), V(pfv));
		if (random() & 1)
			sprintf(pfv, "i");
		else
			sprintf(pfv, "i=?0");
		header_set_ptr(&headers_arr[h_idx++], &hbuf, V("priority"), V(pfv));
	}
#endif
	if (st_h->ccx->payload)
	{
		header_set_ptr(&headers_arr[h_idx++], &hbuf, V("content-type"), V("application/octet-stream"));
		header_set_ptr(&headers_arr[h_idx++], &hbuf, V("content-length"), V( st_h->ccx->payload_size));
	}
	lsquic_http_headers_t headers = {
			.count = (int)h_idx,
			.headers = headers_arr,
	};
	if (0 != lsquic_stream_send_headers(st_h->stream, &headers,
			st_h->ccx->payload == NULL))
	{
		lwsl_err("cannot send headers: %s", strerror(errno));
		exit(1);
	}
}

static void
http_client_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
//	ssize_t nw;

	if (!(st_h->sh_flags & HEADERS_SENT)) {
		st_h->sh_flags |= HEADERS_SENT;
		lws_lsq_send_headers(st_h);
		return;
	}

#if 0
	if (st_h->ccx->payload &&
	    test_reader_size(st_h->reader.lsqr_ctx) > 0) {
		nw = lsquic_stream_writef(stream, &st_h->reader);
		if (nw < 0) {
			lwsl_err("write error: %s", strerror(errno));
			exit(1);
		}
		if (test_reader_size(st_h->reader.lsqr_ctx) > 0) {
			lsquic_stream_wantwrite(stream, 1);

			return;
		}
	}
#endif

	lsquic_stream_shutdown(stream, 1);
	lsquic_stream_wantread(stream, 1);
}


struct lsquic_stream_if http_client_if = {
	.on_new_conn            = http_client_on_new_conn,
	.on_conn_closed         = http_client_on_conn_closed,
	.on_new_stream          = http_client_on_new_stream,
	.on_read                = http_client_on_read,
	.on_write               = http_client_on_write,
	.on_close               = http_client_on_close,
	.on_hsk_done            = http_client_on_hsk_done,
};
