/*
 * lws fuzz target: one request over h1 and over h2 must mean the same thing
 *
 * Written in 2010 - 2026 Andy Green
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The request smuggling and path bypass class of bug lives in the places
 * where two ways of saying the same request don't arrive as the same request:
 * an h2 :path from the hpack dynamic table that skipped the uri sanitiser, a
 * header h1 refuses and h2 lets through, a body framed one way here and
 * another way there.  None of them crash.
 *
 * So each input is one request, described by the fuzzer, and the harness
 * sends it to the application of ../sansio-srv-app.h three ways:
 *
 *  - as h1, with header name case, whitespace around values, and how the
 *    bytes are split as they arrive, chosen by the input
 *
 *  - as h2, with each field's hpack representation chosen by the input:
 *    literal with or without indexing, or never indexed, and its name by its
 *    static table index or as a literal
 *
 *  - as h2 twice on one connection: first with every field added to the
 *    dynamic table, then with every field, the pseudo-headers too, sent as
 *    a reference to its dynamic table entry
 *
 * What the application is told of each (method, path, args, authority, every
 * known and custom header, the body it's given, the file opened for it) and
 * the status lws answers it with must be the same every time.  A request lws
 * refuses before the application hears of it is the same as any other refusal:
 * h1 answers it with a status, h2 with a stream or connection error.
 *
 * Input:
 *
 *   method byte: GET POST HEAD PUT DELETE OPTIONS PATCH, by value % 7
 *   delivery byte: bits 0 - 4, the size of the pieces the bytes arrive in
 *	(0: as one); bits 5 - 7 spare
 *   path length, path
 *   header count (% 7), then each header:
 *	name byte: below 0xc0, one of the names in xp_names, else a custom
 *	    name: its length and its bytes, made x-<token chars>
 *	style byte: bits 0 - 1 h1 name case, bits 2 - 3 h1 whitespace, bits
 *	    4 - 5 h2 representation, bit 6 h2 name by its static index
 *	value length, value
 *   body length (* 4, POST PUT and PATCH only), body
 *
 * Every byte is taken into the alphabet of the place it's going, that both
 * h1 and h2 can carry, so every input is a valid request in both.
 */

#define FZP_SERVER
#include "../sansio-peer.h"
#include "../sansio-srv-app.h"

#include <ctype.h>

#define XP_PATH_MAX	200
#define XP_HDRS		6
#define XP_NAME_MAX	24
#define XP_VAL_MAX	96
#define XP_BODY_MAX	512
#define XP_VIEW_MAX	3072
#define XP_FILE_MAX	128
#define XP_REQS		2
#define XP_TX_MAX	(512 * 1024)
#define XP_PROG_MAX	32768

/* the request, as the input describes it */

struct xp_hdr {
	char		name[XP_NAME_MAX + 3];
	char		val[XP_VAL_MAX + 1];
	size_t		nlen, vlen;
	unsigned int	sidx;	/* its name's hpack static table index, or 0 */
	uint8_t		style;
};

struct xp_req {
	struct xp_hdr	h[XP_HDRS];
	char		path[XP_PATH_MAX + 2];
	uint8_t		body[XP_BODY_MAX];
	size_t		plen, blen;
	int		nh, method;
	uint8_t		chunk;
};

/* what the application was told, and what lws answered, for a request */

struct xp_view {
	char		s[XP_VIEW_MAX];
	uint8_t		body[XP_BODY_MAX * 2];
	char		file[XP_FILE_MAX];
	size_t		len, blen;
	struct lws	*wsi;
	int		seen, status, overflow;
	/*
	 * the application was given all of the body.  If not, because it
	 * answered first, or gave up on what it couldn't decode, how much it
	 * was given by then is down to how the body was cut up
	 */
	int		body_done;
};

static const char * const xp_methods[] = {
	"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"
};

/*
 * Request header names both h1 and h2 may carry, with their hpack static
 * table index (RFC 7541 Appendix A) where they have one.  Not the ones h2
 * forbids (connection, keep-alive, transfer-encoding, upgrade, te), nor
 * host or content-length, which the harness sends itself, nor expect, which
 * gets an h1 interim answer that h2 has no part in.
 */
static const struct {
	const char	*name;
	unsigned int	sidx;
} xp_names[] = {
	{ "accept",		19 },	{ "accept-charset",	15 },
	{ "accept-encoding",	16 },	{ "accept-language",	17 },
	{ "authorization",	23 },	{ "cache-control",	24 },
	{ "content-type",	31 },	{ "cookie",		32 },
	{ "if-match",		39 },	{ "if-modified-since",	40 },
	{ "if-none-match",	41 },	{ "if-range",		42 },
	{ "range",		50 },	{ "referer",		51 },
	{ "user-agent",		58 },	{ "origin",		0 },
	{ "x-forwarded-for",	0 },	{ "forwarded",		0 },
	{ "dnt",		0 },	{ "pragma",		0 },
};

static struct lws_vhost *vh1, *vh2;
static struct xp_req req;
static struct xp_view views[XP_REQS];
static int xp_cur;	/* which request of the connection is arriving */
static uint8_t xp_tx[XP_TX_MAX];
static size_t xp_tx_len;
static uint8_t prog[XP_PROG_MAX];
static uint8_t blk[8192];

static const uint8_t preface[] =
	"PRI * HTTP/2.0\x0d\x0a\x0d\x0aSM\x0d\x0a\x0d\x0a"
	"\x00\x00\x00" "\x04" "\x00" "\x00\x00\x00\x00"; /* empty SETTINGS */

/* the input, read without going past its end */

struct xp_rd {
	const uint8_t	*p;
	size_t		len, pos;
};

static uint8_t
xp_u8(struct xp_rd *r)
{
	return r->pos < r->len ? r->p[r->pos++] : 0;
}

/*
 * A byte into the range lo .. 0x7e: as it is if it's in it already, so the
 * dictionary's tokens and the seeds are what they look like
 */
static char
xp_in(uint8_t c, uint8_t lo)
{
	if (c >= lo && c <= 0x7e)
		return (char)c;

	return (char)(lo + (c % (0x7f - lo)));
}

static void
xp_parse(const uint8_t *data, size_t size)
{
	static const char tchar[] = "abcdefghijklmnopqrstuvwxyz0123456789-_";
	struct xp_rd r = { data, size, 0 };
	size_t n, l, k;
	int i, j;

	memset(&req, 0, sizeof(req));
	req.method = xp_u8(&r) % (int)LWS_ARRAY_SIZE(xp_methods);
	req.chunk = xp_u8(&r) & 31;

	/* the path: visible ascii but '#', starting with '/' */
	l = xp_u8(&r);
	if (l > XP_PATH_MAX)
		l = XP_PATH_MAX;
	req.path[req.plen++] = '/';
	for (n = 0; n < l && r.pos < r.len; n++) {
		char c = xp_in(xp_u8(&r), 0x21);

		if (!n && c == '/')
			continue;
		req.path[req.plen++] = c == '#' ? '/' : c;
	}

	k = xp_u8(&r) % 7;
	for (i = 0; i < (int)k && req.nh < XP_HDRS && r.pos < r.len; i++) {
		struct xp_hdr *h = &req.h[req.nh];
		uint8_t nb = xp_u8(&r);

		if (nb < 0xc0) {
			n = nb % LWS_ARRAY_SIZE(xp_names);
			h->nlen = strlen(xp_names[n].name);
			memcpy(h->name, xp_names[n].name, h->nlen);
			h->sidx = xp_names[n].sidx;
		} else {
			/* a custom name, x- so it can't be one h2 forbids */
			l = (size_t)(xp_u8(&r) % XP_NAME_MAX) + 1;
			memcpy(h->name, "x-", 2);
			h->nlen = 2;
			for (n = 0; n < l; n++)
				h->name[h->nlen++] =
					tchar[xp_u8(&r) % (sizeof(tchar) - 1)];
		}
		h->style = xp_u8(&r);

		/* the value: printable ascii, with no space at either end */
		l = xp_u8(&r);
		if (l > XP_VAL_MAX)
			l = XP_VAL_MAX;
		for (n = 0; n < l; n++)
			h->val[h->vlen++] = xp_in(xp_u8(&r), 0x20);
		while (h->vlen && h->val[h->vlen - 1] == ' ')
			h->vlen--;
		for (n = 0; n < h->vlen && h->val[n] == ' '; n++)
			;
		memmove(h->val, h->val + n, h->vlen - n);
		h->vlen -= n;

		/* each name once: a repeat would be joined, differently */
		for (j = 0; j < req.nh; j++)
			if (req.h[j].nlen == h->nlen &&
			    !memcmp(req.h[j].name, h->name, h->nlen))
				break;
		if (j == req.nh)
			req.nh++;
		else
			memset(h, 0, sizeof(*h));
	}

	if (req.method == 1 || req.method == 3 || req.method == 6) {
		l = (size_t)xp_u8(&r) * 4;
		if (l > XP_BODY_MAX)
			l = XP_BODY_MAX;
		if (l > r.len - r.pos)
			l = r.len - r.pos;
		memcpy(req.body, r.p + r.pos, l);
		req.blen = l;
	}
}

/*
 * Append to the program (../sansio-peer.h) the harness' op 7 announcing
 * request a.  It returns the new end, or 0 if it doesn't fit: a cut-short
 * program wouldn't mean the same request, so the input is skipped
 */
static size_t
xp_prog_op(size_t pos, int a)
{
	if (pos >= sizeof(prog))
		return 0;

	prog[pos++] = (uint8_t)((a << 3) | 7);

	return pos;
}

/*
 * ... and RX ops sending b, in pieces of chunk bytes, or as few pieces of
 * up to 64KiB as it takes if chunk is 0.  It returns the new end, or 0 if
 * it doesn't all fit
 */
static size_t
xp_prog_rx(size_t pos, const uint8_t *b, size_t len, uint8_t chunk)
{
	size_t k;

	while (len) {
		k = chunk ? (len < chunk ? len : chunk) :
			    (len < 65535 + 32 ? len : 65535 + 32);
		/* the op and its length take up to 3 bytes */
		if (pos > sizeof(prog) || k + 3 > sizeof(prog) - pos)
			return 0;
		if (k < 32) {
			prog[pos++] = (uint8_t)((k - 1) << 3);
		} else {
			/* the long form, u16 + 32 bytes */
			prog[pos++] = (uint8_t)(31 << 3);
			prog[pos++] = (uint8_t)((k - 32) >> 8);
			prog[pos++] = (uint8_t)(k - 32);
		}
		memcpy(prog + pos, b, k);
		pos += k;
		b += k;
		len -= k;
	}

	return pos;
}

/* the harness' op 7: request a of the connection is the one arriving next */
static size_t
xp_op(struct fzp_transport *t, int a, const uint8_t *in, size_t len)
{
	(void)t;
	(void)in;
	(void)len;

	xp_cur = a;

	return 0;
}

/* h1 */

static size_t
xp_h1(uint8_t *b, size_t max)
{
	static const char * const ows[] = { "", " ", "\t", " \t " };
	size_t n;
	int i, k;

	n = (size_t)lws_snprintf((char *)b, max, "%s %.*s HTTP/1.1\r\n"
				 "Host: fuzz\r\n", xp_methods[req.method],
				 (int)req.plen, req.path);

	for (i = 0; i < req.nh; i++) {
		const struct xp_hdr *h = &req.h[i];
		const char *w = ows[(h->style >> 2) & 3];
		char name[XP_NAME_MAX + 3];

		/* names are case insensitive in h1 */
		for (k = 0; k < (int)h->nlen; k++) {
			char c = h->name[k];

			if ((h->style & 3) == 2 ||
			    ((h->style & 3) == 1 && (!k || h->name[k - 1] == '-')))
				c = (char)toupper((int)(unsigned char)c);
			name[k] = c;
		}

		/* whitespace before the value, and the same after it */
		n += (size_t)lws_snprintf((char *)b + n, max - n,
				"%.*s:%s%.*s%s\r\n", (int)h->nlen, name, w,
				(int)h->vlen, h->val, w);
	}

	if (req.blen)
		n += (size_t)lws_snprintf((char *)b + n, max - n,
					  "Content-Length: %u\r\n",
					  (unsigned int)req.blen);
	n += (size_t)lws_snprintf((char *)b + n, max - n, "\r\n");

	if (n + req.blen >= max)
		return 0;
	memcpy(b + n, req.body, req.blen);

	return n + req.blen;
}

/* h2: hpack (RFC 7541) without huffman, and frames */

static size_t
hp_int(uint8_t *p, uint8_t first, int bits, size_t v)
{
	size_t lim = ((size_t)1 << bits) - 1, n = 0;

	if (v < lim) {
		p[n++] = (uint8_t)(first | v);
		return n;
	}
	p[n++] = (uint8_t)(first | lim);
	v -= lim;
	while (v >= 128) {
		p[n++] = (uint8_t)(0x80 | (v & 0x7f));
		v >>= 7;
	}
	p[n++] = (uint8_t)v;

	return n;
}

static size_t
hp_str(uint8_t *p, const char *s, size_t len)
{
	size_t n = hp_int(p, 0, 7, len);

	memcpy(p + n, s, len);

	return n + len;
}

enum {
	XP_REP_LIT,		/* literal without indexing */
	XP_REP_NEVER,		/* literal never indexed */
	XP_REP_INCR,		/* literal with incremental indexing */
	XP_REP_INDEXED,		/* a dynamic table entry */
};

/*
 * A field as rep says, with its name by its static index sidx if not 0.  An
 * indexed one is entry dyn of the dynamic table.
 */
static size_t
hp_field(uint8_t *p, int rep, unsigned int sidx, size_t dyn,
	 const char *name, size_t nlen, const char *val, size_t vlen)
{
	static const uint8_t first[] = { 0x00, 0x10, 0x40 };
	static const int bits[] = { 4, 4, 6 };
	size_t n;

	if (rep == XP_REP_INDEXED)
		return hp_int(p, 0x80, 7, dyn);

	n = hp_int(p, first[rep], bits[rep], sidx);
	if (!sidx)
		n += hp_str(p + n, name, nlen);

	return n + hp_str(p + n, val, vlen);
}

/* the fields of the request, in the order they're sent */

#define XP_FIELDS (5 + XP_HDRS)

struct xp_field {
	const char	*name, *val;
	size_t		nlen, vlen;
	unsigned int	sidx;
	int		rep;
};

static int
xp_fields(struct xp_field *f)
{
	static char clen[16];
	int n = 0, i;

	memset(f, 0, sizeof(*f) * XP_FIELDS);

	f[n].name = ":method";
	f[n].sidx = 2;
	f[n].val = xp_methods[req.method];
	f[n++].vlen = strlen(xp_methods[req.method]);
	f[n].name = ":scheme";
	f[n].sidx = 6;
	f[n].val = "http";
	f[n++].vlen = 4;
	f[n].name = ":authority";
	f[n].sidx = 1;
	f[n].val = "fuzz";
	f[n++].vlen = 4;
	f[n].name = ":path";
	f[n].sidx = 4;
	f[n].val = req.path;
	f[n++].vlen = req.plen;

	for (i = 0; i < req.nh; i++) {
		f[n].name = req.h[i].name;
		f[n].nlen = req.h[i].nlen;
		f[n].sidx = req.h[i].style & 0x40 ? req.h[i].sidx : 0;
		f[n].val = req.h[i].val;
		f[n].vlen = req.h[i].vlen;
		/* nothing is in the dynamic table for it to be indexed */
		f[n++].rep = ((req.h[i].style >> 4) & 3) % XP_REP_INDEXED;
	}

	if (req.blen) {
		f[n].name = "content-length";
		f[n].sidx = 28;
		f[n].val = clen;
		f[n++].vlen = (size_t)lws_snprintf(clen, sizeof(clen), "%u",
						   (unsigned int)req.blen);
	}

	for (i = 0; i < n; i++)
		if (!f[i].nlen)
			f[i].nlen = strlen(f[i].name);

	return n;
}

static size_t
xp_frame(uint8_t *b, uint8_t type, uint8_t flags, uint32_t sid,
	 const uint8_t *pl, size_t len)
{
	b[0] = (uint8_t)(len >> 16);
	b[1] = (uint8_t)(len >> 8);
	b[2] = (uint8_t)len;
	b[3] = type;
	b[4] = flags;
	b[5] = (uint8_t)((sid >> 24) & 0x7f);
	b[6] = (uint8_t)(sid >> 16);
	b[7] = (uint8_t)(sid >> 8);
	b[8] = (uint8_t)sid;
	memcpy(b + 9, pl, len);

	return 9 + len;
}

/*
 * The request as h2 frames on stream sid: its HEADERS, with each field as
 * the input says if rep_all is -1, else all of them as rep_all says, then
 * its body.  With rep_all XP_REP_INDEXED, each field is the dynamic table
 * entry the same request sent with XP_REP_INCR made: the last field sent is
 * entry 62, the first, 61 + the count of fields.
 */
static size_t
xp_h2(uint8_t *b, size_t max, uint32_t sid, int rep_all)
{
	struct xp_field f[XP_FIELDS];
	size_t n = 0, o;
	int nf, i;

	nf = xp_fields(f);
	for (i = 0; i < nf; i++)
		n += hp_field(blk + n, rep_all < 0 ? f[i].rep : rep_all,
			      f[i].sidx, 62 + (size_t)(nf - 1 - i),
			      f[i].name, f[i].nlen, f[i].val, f[i].vlen);

	if (9 + n + 9 + req.blen > max)
		return 0;

	o = xp_frame(b, 1, (uint8_t)(4 | (req.blen ? 0 : 1)), sid, blk, n);
	if (req.blen)
		o += xp_frame(b + o, 0, 1, sid, req.body, req.blen);

	return o;
}

/* what the application is told */

static struct xp_view *
xp_view_of(struct lws *wsi)
{
	int n;

	for (n = XP_REQS - 1; n >= 0; n--)
		if (views[n].seen && views[n].wsi == wsi)
			return &views[n];

	return NULL;
}

static void
xp_add(struct xp_view *v, const char *what, const char *a, size_t al)
{
	int n = lws_snprintf(v->s + v->len, sizeof(v->s) - v->len, "%s%.*s\n",
			     what, (int)al, a);

	if (v->len + (size_t)n >= sizeof(v->s) - 1)
		v->overflow = 1;
	v->len += (size_t)n;
}

#if defined(LWS_WITH_CUSTOM_HEADERS)
static void
xp_custom(const char *name, int nlen, void *opaque)
{
	struct lws *wsi = (struct lws *)opaque;
	struct xp_view *v = xp_view_of(wsi);
	char line[64 + XP_VAL_MAX * 2 + 2];
	int n, vl;

	if (!v || nlen <= 0 || nlen >= 64)
		return;

	for (n = 0; n < nlen; n++)
		line[n] = (char)tolower((int)(unsigned char)name[n]);
	/* h1 keeps the name's ':', h2 has none */
	if (line[n - 1] == ':')
		n--;
	line[n++] = '=';

	vl = lws_hdr_custom_copy(wsi, line + n, (int)sizeof(line) - n, name,
				 nlen);
	xp_add(v, "c ", line, (size_t)n + (vl < 0 ? 0 : (size_t)vl));
}
#endif

static void
xp_request(struct lws *wsi, const char *uri, size_t len)
{
	static char val[XP_VIEW_MAX];
	struct xp_view *v;
	const char *m = "?";
	char *u;
	int h, n, ul;

	if (xp_cur < 0 || xp_cur >= XP_REQS)
		return;
	v = &views[xp_cur];
	if (v->seen) {
		/* a request the peer sent once was dispatched twice */
		xp_add(v, "dispatched again", "", 0);
		return;
	}
	v->seen = 1;
	v->wsi = wsi;

	n = lws_http_get_uri_and_method(wsi, &u, &ul);
	if (n == LWSHUMETH_COLON_PATH) {
		/* h2's method is its :method */
		if (lws_hdr_copy(wsi, val, (int)sizeof(val),
				 WSI_TOKEN_HTTP_COLON_METHOD) > 0)
			m = val;
	} else if (n >= 0 && n < LWSHUMETH_COLON_PATH) {
		static const char * const mn[] = {
			"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE",
			"CONNECT", "HEAD"
		};

		m = mn[n];
	}
	xp_add(v, "method ", m, strlen(m));
	xp_add(v, "path ", uri ? uri : "", uri ? len : 0);

	n = lws_hdr_copy(wsi, val, (int)sizeof(val), WSI_TOKEN_HTTP_URI_ARGS);
	xp_add(v, "args ", val, n < 0 ? 0 : (size_t)n);

	/* h1's Host is h2's :authority */
	h = lws_hdr_total_length(wsi, WSI_TOKEN_HOST) ? WSI_TOKEN_HOST :
					WSI_TOKEN_HTTP_COLON_AUTHORITY;
	n = lws_hdr_copy(wsi, val, (int)sizeof(val), (enum lws_token_indexes)h);
	xp_add(v, "authority ", val, n < 0 ? 0 : (size_t)n);

	for (h = 0; h < WSI_TOKEN_COUNT; h++) {
		const char *name = (const char *)lws_token_to_string(
						(enum lws_token_indexes)h);
		size_t nl;

		if (!name ||
		    !lws_hdr_total_length(wsi, (enum lws_token_indexes)h))
			continue;
		nl = strlen(name);
		/*
		 * Not the pseudo-headers, nor the method and version tokens of
		 * h1's request line, nor what the lines above say already
		 */
		if (!nl || name[0] == ':' || name[nl - 1] == ' ' ||
		    !strcmp(name, "host:") || !strcmp(name, "connection:") ||
		    h == WSI_TOKEN_HTTP_URI_ARGS)
			continue;

		n = lws_snprintf(val, sizeof(val), "%s", name);
		ul = lws_hdr_copy(wsi, val + n, (int)sizeof(val) - n,
				  (enum lws_token_indexes)h);
		xp_add(v, "h ", val, (size_t)n + (ul < 0 ? 0 : (size_t)ul));
	}

#if defined(LWS_WITH_CUSTOM_HEADERS)
	lws_hdr_custom_name_foreach(wsi, xp_custom, wsi);
#endif
}

static void
xp_body(struct lws *wsi, const uint8_t *in, size_t len)
{
	struct xp_view *v = xp_view_of(wsi);

	if (!v || !in)
		return;
	if (len > sizeof(v->body) - v->blen) {
		v->overflow = 1;
		len = sizeof(v->body) - v->blen;
	}
	memcpy(v->body + v->blen, in, len);
	v->blen += len;
}

static void
xp_body_done(struct lws *wsi)
{
	struct xp_view *v = xp_view_of(wsi);

	if (v)
		v->body_done = 1;
}

static void
xp_open(const char *real)
{
	if (xp_cur < 0 || xp_cur >= XP_REQS || !views[xp_cur].seen)
		return;

	/* the file, by its path in the mount */
	lws_strncpy(views[xp_cur].file, real + strlen(fza_dir_real),
		    sizeof(views[xp_cur].file));
}

static void
xp_tx_hook(const uint8_t *buf, size_t len)
{
	fza_tx_check(buf, len);

	if (len > sizeof(xp_tx) - xp_tx_len)
		len = sizeof(xp_tx) - xp_tx_len;
	memcpy(xp_tx + xp_tx_len, buf, len);
	xp_tx_len += len;
}

static int
xp_digits(const uint8_t *p)
{
	if (!isdigit(p[0]) || !isdigit(p[1]) || !isdigit(p[2]))
		return -1;

	return (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
}

/* the status lws answered with, from h1's status line */
static int
xp_status_h1(void)
{
	if (xp_tx_len < 12 || memcmp(xp_tx, "HTTP/1.1 ", 9))
		return -1;

	return xp_digits(xp_tx + 9);
}

/*
 * ... or from h2's first HEADERS on stream sid, which lws starts with
 * :status as a literal with a literal name, not huffman coded
 */
static int
xp_status_h2(uint32_t sid)
{
	size_t o = 0, fl;

	while (o + 9 <= xp_tx_len) {
		const uint8_t *f = xp_tx + o;
		uint32_t s = ((uint32_t)(f[5] & 0x7f) << 24) |
			     ((uint32_t)f[6] << 16) | ((uint32_t)f[7] << 8) |
			     f[8];

		fl = ((size_t)f[0] << 16) | ((size_t)f[1] << 8) | f[2];
		if (o + 9 + fl > xp_tx_len)
			break;
		if (f[3] == 1 && s == sid && fl >= 13 && !(f[4] & 0x28) &&
		    !memcmp(f + 9, "\x00\x07:status\x03", 10))
			return xp_digits(f + 19);
		o += 9 + fl;
	}

	return -1;
}

/* one connection, whose requests' views and tx start empty */
static void
xp_session(struct lws_vhost *vh, const uint8_t *pre, size_t pre_len,
	   size_t plen)
{
	memset(views, 0, sizeof(views));
	xp_tx_len = 0;
	xp_cur = 0;
	fza_session_start();
	fzp_server_session(vh, pre, pre_len, prog, plen);
}

static void
xp_show(const char *what, const struct xp_view *v)
{
	size_t n;

	fprintf(stderr, "--- %s: %s, status %d, file '%s', body %u%s\n", what,
		v->seen ? "dispatched" : "refused", v->status, v->file,
		(unsigned int)v->blen,
		req.blen && !v->body_done ? " (not all given)" : "");
	fwrite(v->s, 1, v->len, stderr);
	for (n = 0; n < v->blen; n++)
		fprintf(stderr, "%02x", v->body[n]);
	fprintf(stderr, "\n");
}

/* nonzero if a and b say different things */
static int
xp_differ(const struct xp_view *a, const struct xp_view *b)
{
	if (a->seen != b->seen)
		return 1;
	if (!a->seen)
		/* both refused before the application heard of it */
		return 0;

	if (a->status != b->status || a->len != b->len ||
	    memcmp(a->s, b->s, a->len) || strcmp(a->file, b->file))
		return 1;

	if (!a->body_done || !b->body_done)
		/* each must have been given the start of the same body */
		return memcmp(a->body, b->body,
			      a->blen < b->blen ? a->blen : b->blen) != 0;

	return a->blen != b->blen || memcmp(a->body, b->body, a->blen);
}

/*
 * Refused as too big.  Where each way of sending it runs out of room isn't
 * the same place: h2's pseudo-headers take header fragments h1's request
 * line doesn't, so a request at the edge is too big for one and not the
 * other, and that says nothing about what it means.
 */
static int
xp_too_big(const struct xp_view *v)
{
	return v->status == HTTP_STATUS_REQ_ENTITY_TOO_LARGE ||
	       v->status == HTTP_STATUS_REQ_URI_TOO_LONG ||
	       v->status == HTTP_STATUS_REQ_HEADER_FIELDS_TOO_LARGE;
}

static void
xp_compare(const char *an, const struct xp_view *a, const char *bn,
	   const struct xp_view *b)
{
	if (a->overflow || b->overflow || xp_too_big(a) || xp_too_big(b) ||
	    !xp_differ(a, b))
		return;

	xp_show(an, a);
	xp_show(bn, b);
	fza_broken_promise("the same request meant different things",
			   req.path, req.plen);
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	vh1 = fza_init(0);
	if (!vh1)
		return 1;
	vh2 = fza_vhost("fuzz-h2", LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE);
	if (!vh2)
		return 1;

	fzp_op_hook = xp_op;
	fzp_tx_hook = xp_tx_hook;
	fza_request_hook = xp_request;
	fza_body_hook = xp_body;
	fza_open_hook = xp_open;
	fza_body_done_hook = xp_body_done;

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static struct xp_view v_h1, v_h2, v_inc, v_dyn;
	static uint8_t b[16384];
	size_t n, p;

	xp_parse(data, size);

	/* h1 */
	n = xp_h1(b, sizeof(b));
	if (!n)
		return 0;
	p = xp_prog_rx(0, b, n, req.chunk);
	if (!p)
		return 0;
	xp_session(vh1, NULL, 0, p);
	views[0].status = xp_status_h1();
	v_h1 = views[0];

	/* h2, each field as the input says */
	n = xp_h2(b, sizeof(b), 1, -1);
	if (!n)
		return 0;
	p = xp_prog_rx(0, b, n, req.chunk);
	if (!p)
		return 0;
	xp_session(vh2, preface, sizeof(preface) - 1, p);
	views[0].status = xp_status_h2(1);
	v_h2 = views[0];

	/*
	 * h2, the request with every field put in the dynamic table, then
	 * again as references to those entries, each announced by the
	 * harness op, so the application's views know which is which
	 */
	p = xp_prog_op(0, 0);
	n = xp_h2(b, sizeof(b), 1, XP_REP_INCR);
	if (!n || !(p = xp_prog_rx(p, b, n, req.chunk)) ||
	    !(p = xp_prog_op(p, 1)))
		return 0;
	n = xp_h2(b, sizeof(b), 3, XP_REP_INDEXED);
	if (!n || !(p = xp_prog_rx(p, b, n, req.chunk)))
		return 0;
	xp_session(vh2, preface, sizeof(preface) - 1, p);
	views[0].status = xp_status_h2(1);
	views[1].status = xp_status_h2(3);
	v_inc = views[0];
	v_dyn = views[1];

	if (getenv("LWS_FUZZ_VERBOSE")) {
		/* for triage: what each way of sending it was taken as */
		xp_show("h1", &v_h1);
		xp_show("h2", &v_h2);
		xp_show("h2 indexing", &v_inc);
		xp_show("h2 from the table", &v_dyn);
	}

	xp_compare("h1", &v_h1, "h2", &v_h2);
	xp_compare("h2", &v_h2, "h2 indexing", &v_inc);
	/*
	 * the references can only be the same request if the connection was
	 * still there for them: the first was answered
	 */
	if (v_inc.seen && v_inc.status > 0)
		xp_compare("h2 indexing", &v_inc, "h2 from the table", &v_dyn);

	return 0;
}
