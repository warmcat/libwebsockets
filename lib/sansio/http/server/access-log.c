/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 */

#include "private-lib-core.h"

/*
 * Produce Apache-compatible log string for wsi, like this:
 *
 * 2.31.234.19 - - [27/Mar/2016:03:22:44 +0800]
 * "GET /aep-screen.png HTTP/1.1"
 * 200 152987 "https://libwebsockets.org/index.html"
 * "Mozilla/5.0 (Macint... Chrome/49.0.2623.87 Safari/537.36"
 *
 */

extern const char * const method_names[];

static const char * const hver[] = {
	"HTTP/1.0", "HTTP/1.1", "HTTP/2"
};

/*
 * The parts of the request line we prepare are bounded by their buffers, so
 * the prepared part of the line is never longer than this, and the line has
 * room for it and at least 512 bytes of status, size, referrer and user agent
 */
#define LWS_AL_DATE_LEN		64
#define LWS_AL_URI_LEN		256
#define LWS_AL_METHOD_MAX	15
#define LWS_AL_HDR_MAX		(LWS_PEER_DESC_LEN + LWS_AL_DATE_LEN + \
				 LWS_AL_METHOD_MAX + LWS_AL_URI_LEN + 8 + 16)
#define LWS_AL_LINE_LEN		(LWS_AL_HDR_MAX + 512)

/*
 * The log line is one record per request; peer-controlled fields must not
 * be able to add fake records (CR / LF), hide the rest of the line (NUL /
 * other C0 controls), break the quoting, or reach the terminal of whoever
 * reads the log with anything but printable ASCII.  h1 framing already
 * excludes CR / LF from header values and hpack refuses them on h2, so this
 * is defence in depth for the log format itself.
 *
 * A '"' becomes '\'' and a C0 control '_', as they always did, so ordinary
 * text is logged as it came.  A backslash is doubled and DEL and every byte
 * above it, UTF-8 and C1 controls like CSI included, is written \xhh, as
 * Apache's mod_log_config does: readers of the format that honour escapes
 * then never see a field's closing quote escaped by the peer's backslash.
 *
 * Writes the escaped form of up to len bytes of src (less at a NUL) to dst,
 * no more than max bytes of it and never part of an escape, without a NUL,
 * and returns how many bytes that is.  With dst NULL, only counts them.
 */
static size_t
lws_access_log_escape(char *dst, size_t max, const char *src, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	size_t n = 0, m, el;
	unsigned char c;

	for (m = 0; m < len && src[m]; m++) {
		c = (unsigned char)src[m];
		el = c == '\\' ? 2 : (c >= 0x7f ? 4 : 1);
		if (n + el > max)
			break;

		if (dst) {
			if (el == 1)
				dst[n] = c == '\"' ? '\'' :
					 (c < 0x20 ? '_' : (char)c);
			else {
				dst[n] = '\\';
				if (el == 2)
					dst[n + 1] = '\\';
				else {
					dst[n + 1] = 'x';
					dst[n + 2] = hex[c >> 4];
					dst[n + 3] = hex[c & 15];
				}
			}
		}
		n += el;
	}

	return n;
}

void
lws_prepare_access_log_info(struct lws *wsi, char *uri_ptr, int uri_len, int meth)
{
	char da[LWS_AL_DATE_LEN], uri[LWS_AL_URI_LEN], ta[LWS_PEER_DESC_LEN];
	time_t t = lws_wsi_now_wall(wsi);
	const char *me;
#if defined(LWS_ROLE_H2)
	char me_buf[LWS_AL_METHOD_MAX + 1], me_esc[LWS_AL_METHOD_MAX + 1];
#endif
	size_t m;
	int l;
	struct tm *ptm = NULL;
#if defined(LWS_HAVE_LOCALTIME_R)
	struct tm tm;
#endif

	if (!wsi->a.vhost)
		return;

	/* only worry about preparing it if we store it */
	if (wsi->a.vhost->log_fd == (int)LWS_INVALID_FILE)
		return;

	if (wsi->access_log_pending)
		lws_access_log(wsi);

	/*
	 * The host field: the client's address, as it always was, unless the
	 * connection's peer address stack has more layers than the transport's
	 * own peer (eg, a trusted front's PROXY v2 header), when it is all of
	 * them, top first, each with its cred, as one token, eg
	 * "192.0.2.10:40000~v<10.0.0.2:40122~r".  A stream on a connection has
	 * the connection's.
	 */
	lws_io_peer_describe(wsi, ta, sizeof(ta),
			     LWS_PEER_DESC_TOKEN | LWS_PEER_DESC_BARE_SINGLE);

#if defined(LWS_HAVE_LOCALTIME_R)
	ptm = localtime_r(&t, &tm);
#else
	ptm = localtime(&t);
#endif
	if (ptm)
		strftime(da, sizeof(da), "%d/%b/%Y:%H:%M:%S %z", ptm);
	else
		strcpy(da, "01/Jan/1970:00:00:00 +0000");

#if defined(LWS_ROLE_H2)
	if (wsi->mux_substream) {
		/*
		 * :method is peer-chosen text on h2; take a bounded, escaped
		 * copy rather than pointing into the ah
		 */
		if (lws_hdr_copy(wsi, me_buf, sizeof(me_buf),
				 WSI_TOKEN_HTTP_COLON_METHOD) > 0) {
			m = lws_access_log_escape(me_esc, sizeof(me_esc) - 1,
						  me_buf, sizeof(me_buf));
			me_esc[m] = '\0';
			me = me_esc;
		} else
			me = NULL;
	} else
#endif
		me = method_names[meth];

	if (!me)
		me = "(null)";

	/* as much of it as fits, escaped */
	m = lws_access_log_escape(uri, sizeof(uri) - 1, uri_ptr,
				  uri_len > 0 ? (size_t)uri_len : 0);
	uri[m] = '\0';

	/*
	 * The peer's referrer and user agent are kept as they came, and
	 * escaped as they are written into the line, where it is decided
	 * how much of each fits.
	 *
	 * Room for all of it, so the request is never cut short, which would
	 * lose its closing quote and put the peer's referrer outside quotes
	 */
	wsi->stream.access_log.header_log = lws_malloc(LWS_AL_HDR_MAX,
						       "access log");
	if (!wsi->stream.access_log.header_log)
		return;

	lws_snprintf(wsi->stream.access_log.header_log, LWS_AL_HDR_MAX,
		     "%s - - [%s] \"%.*s %s %s\"", ta, da, LWS_AL_METHOD_MAX,
		     me, uri, hver[wsi->stream.request_version]);

	//lwsl_notice("%s\n", wsi->stream.access_log.header_log);

	l = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_USER_AGENT);
	if (l) {
		wsi->stream.access_log.user_agent =
				lws_malloc((unsigned int)l + 5, "access log");
		if (!wsi->stream.access_log.user_agent) {
			lwsl_err("OOM getting user agent\n");
			lws_free_set_NULL(wsi->stream.access_log.header_log);
			return;
		}
		wsi->stream.access_log.user_agent[0] = '\0';

		if (lws_hdr_copy(wsi, wsi->stream.access_log.user_agent, l + 4,
				 WSI_TOKEN_HTTP_USER_AGENT) < 0)
			wsi->stream.access_log.user_agent[0] = '\0';
	}
	l = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_REFERER);
	if (l) {
		wsi->stream.access_log.referrer = lws_malloc((unsigned int)l + 5, "referrer");
		if (!wsi->stream.access_log.referrer) {
			lwsl_err("OOM getting referrer\n");
			lws_free_set_NULL(wsi->stream.access_log.user_agent);
			lws_free_set_NULL(wsi->stream.access_log.header_log);
			return;
		}
		wsi->stream.access_log.referrer[0] = '\0';
		if (lws_hdr_copy(wsi, wsi->stream.access_log.referrer,
				l + 4, WSI_TOKEN_HTTP_REFERER) < 0)
			wsi->stream.access_log.referrer[0] = '\0';
	}
	wsi->access_log_pending = 1;
}


int
lws_access_log(struct lws *wsi)
{
	const char *ua = wsi->stream.access_log.user_agent,
		   *ref = wsi->stream.access_log.referrer;
	size_t room, rl, ul;
	char ass[LWS_AL_LINE_LEN];
	int n;

	if (!wsi->a.vhost)
		return 0;

	if (wsi->a.vhost->log_fd == (int)LWS_INVALID_FILE)
		return 0;

	if (!wsi->access_log_pending)
		return 0;

	if (!wsi->stream.access_log.header_log)
		return 0;

	if (!ua)
		ua = "";

	if (!ref)
		ref = "";

	n = lws_snprintf(ass, sizeof(ass), "%s %d %lu \"",
			 wsi->stream.access_log.header_log,
			 wsi->stream.access_log.response,
			 wsi->stream.access_log.sent);

	/*
	 * One request is one line, always: whatever is too long to fit is cut
	 * from the peer's referrer and user agent, never the quotes around
	 * them, the newline, or an escape.  After the referrer, the line is
	 * '" "', the user agent and '"\n', and there is the NUL.  The budget
	 * is in escaped bytes.
	 */
	if ((size_t)n + 6 >= sizeof(ass)) {
		/* the prepared part is bounded well below this */
		lwsl_wsi_err(wsi, "access log line too long");
		goto bail;
	}
	room = sizeof(ass) - 1 - (size_t)n - 5;

	/* how long each is escaped, as far as it could matter */
	rl = lws_access_log_escape(NULL, room, ref, strlen(ref));
	ul = lws_access_log_escape(NULL, room, ua, strlen(ua));
	if (rl + ul > room) {
		/* each gets half, or more if the other needs less */
		if (rl > room / 2)
			rl = ul < room / 2 ? room - ul : room / 2;
		if (ul > room - rl)
			ul = room - rl;
	}

	n += (int)lws_access_log_escape(ass + (size_t)n, rl, ref, strlen(ref));
	memcpy(ass + (size_t)n, "\" \"", 3);
	n += 3;
	n += (int)lws_access_log_escape(ass + (size_t)n, ul, ua, strlen(ua));
	memcpy(ass + (size_t)n, "\"\n", 3); /* with the NUL */
	n += 2;

	if ((int)write(wsi->a.vhost->log_fd, ass, (size_t)n) != n)
		lwsl_err("Failed to write log\n");

bail:
	if (wsi->stream.access_log.header_log) {
		lws_free(wsi->stream.access_log.header_log);
		wsi->stream.access_log.header_log = NULL;
	}
	if (wsi->stream.access_log.user_agent) {
		lws_free(wsi->stream.access_log.user_agent);
		wsi->stream.access_log.user_agent = NULL;
	}
	if (wsi->stream.access_log.referrer) {
		lws_free(wsi->stream.access_log.referrer);
		wsi->stream.access_log.referrer = NULL;
	}
	wsi->access_log_pending = 0;

	return 0;
}

