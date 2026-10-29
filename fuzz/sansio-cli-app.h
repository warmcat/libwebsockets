/*
 * lws fuzzing: the client application, whose server is the fuzzer
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws connects out to servers it doesn't control, so everything a client
 * reads is as untrusted as what a server does.  This application makes one
 * connection per input over the sansIO transport (../sansio-peer.h), how
 * from the input's first byte, the config, and takes what comes back the
 * way real ones do: it pulls the body of an h1 response at its own pace
 * (lws_http_client_read()), writes a POST body a piece at a time, and on ws
 * sends a message when it can and again for each it gets.
 *
 *   config bit 0 - 1:  GET, HEAD, POST, or GET of a ws upgrade where the
 *		       harness allows it
 *   config bit 2:      the app leaves a body's pull until an EVENT 2 op
 *   config bit 3 - 5:  how many 64-byte pieces of POST body, 1 .. 8
 *
 * The harness' EVENT ops 2 .. 5 are the application of its own accord:
 * pulling the body it left, stopping and restarting rx, and closing the
 * connection from its next callback.
 */

struct fzc {
	struct lws	*wsi;		/* while it exists */
	int		post_pieces;
	int		defer;
	int		pull_owed;
	int		close_next;
	int		ws_owed;	/* messages it may send */
};

static struct fzc fzc;

static int
fzc_pull(struct lws *wsi)
{
	uint8_t buf[LWS_PRE + 1024];
	char *px = (char *)buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	fzc.pull_owed = 0;

	return lws_http_client_read(wsi, &px, &lenx) < 0 ? -1 : 0;
}

static int
fzc_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 256];
	int n;

	(void)user;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CLOSED:
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		if (wsi == fzc.wsi)
			fzc.wsi = NULL;
		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		fzc.wsi = wsi;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		fzc.wsi = wsi;
		if (fzc.defer) {
			fzc.pull_owed = 1;
			break;
		}
		if (fzc_pull(wsi))
			return -1;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		fzc.wsi = wsi;
		if (fzc.post_pieces) {
			unsigned char **pp = (unsigned char **)in,
				      *end = *pp + len;
			char cl[16];

			n = lws_snprintf(cl, sizeof(cl), "%d",
					 fzc.post_pieces * 64);
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(unsigned char *)cl, n, pp, end))
				return -1;
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		fzc.wsi = wsi;
		if (!fzc.post_pieces)
			break;
		memset(buf + LWS_PRE, 'b', 64);
		if (lws_write(wsi, buf + LWS_PRE, 64, --fzc.post_pieces ?
			      LWS_WRITE_HTTP : LWS_WRITE_HTTP_FINAL) != 64)
			return -1;
		if (fzc.post_pieces)
			lws_callback_on_writable(wsi);
		else
			lws_client_http_body_pending(wsi, 0);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		fzc.wsi = wsi;
		fzc.ws_owed = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		fzc.wsi = wsi;
		if (lws_is_final_fragment(wsi) && fzc.ws_owed < 4) {
			fzc.ws_owed++;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		fzc.wsi = wsi;
		if (!fzc.ws_owed)
			break;
		memset(buf + LWS_PRE, 'w', 200);
		if (lws_write(wsi, buf + LWS_PRE, 200, LWS_WRITE_TEXT) < 200)
			return -1;
		if (--fzc.ws_owed)
			lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	if (fzc.close_next && wsi == fzc.wsi) {
		fzc.close_next = 0;
		return -1;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols fzc_protocols[] = {
	{ "fuzz-client", fzc_callback, 0, 1024, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

#if !defined(LWS_WITHOUT_EXTENSIONS)
static const struct lws_extension fzc_extensions[] = {
	{ "permessage-deflate", lws_extension_callback_pm_deflate,
	  "permessage-deflate; client_max_window_bits" },
	{ NULL, NULL, NULL }
};
#endif

static void
fzc_event(struct fzp_transport *t, int ev)
{
	(void)t;

	if (!fzc.wsi)
		return;

	switch (ev) {
	case 2:
		if (fzc.pull_owed)
			fzc_pull(fzc.wsi);
		break;
	case 3:
		lws_rx_flow_control(fzc.wsi, 0);
		break;
	case 4:
		lws_rx_flow_control(fzc.wsi, 1);
		break;
	case 5:
		fzc.close_next = 1;
		lws_callback_on_writable(fzc.wsi);
		break;
	default:
		break;
	}
}

static struct lws_vhost *fzc_vh;

static int
fzc_init(void)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	if (fzp_init(&info))
		return 1;

	info.vhost_name = "fuzz";
	info.protocols = fzc_protocols;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	info.extensions = fzc_extensions;
#endif
	fzc_vh = lws_create_vhost(fzp_cx, &info);
	fzp_event_hook = fzc_event;

	return !fzc_vh;
}

/*
 * Starts the connection the config byte asks for, ws or not as the harness
 * allows, with any client flags it wants: returns its transport or NULL
 */
static struct fzp_transport *
fzc_connect(uint8_t cfg, int ws_ok, int ssl_flags)
{
	static const char * const methods[] = { "GET", "HEAD", "POST", "GET" };
	struct lws_client_connect_info ci;
	int m = cfg & 3;

	if (m == 3 && !ws_ok)
		m = 0;

	memset(&fzc, 0, sizeof(fzc));
	fzc.defer = !!(cfg & 4);
	if (m == 2)
		fzc.post_pieces = ((cfg >> 3) & 7) + 1;

	memset(&ci, 0, sizeof(ci));
	ci.vhost		= fzc_vh;
	ci.address		= "fuzz";
	ci.port			= 80;
	ci.host			= ci.address;
	ci.origin		= ci.address;
	ci.path			= "/fuzz";
	ci.local_protocol_name	= "fuzz-client";
	ci.ssl_connection	= ssl_flags;
	if (m == 3)
		ci.protocol	= "echo";
	else
		ci.method	= methods[m];

	return fzp_client_start(&ci);
}
