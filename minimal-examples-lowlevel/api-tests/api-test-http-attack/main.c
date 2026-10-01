/*
 * lws-api-test-http-attack
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Hostile requests against an lws server, over each http transport the build
 * has, checking that lws still turns them away the way it should.  It
 * replaces scripts/attack.sh, and adds the other request shapes a server is
 * expected to be proof against: request smuggling and header
 * injection on h1, slow headers, and on h2 the framing, hpack and flood
 * abuses.
 *
 * The server has two kinds of url space:
 *
 *  - /f is a file mount on ./docroot.  ./secret.txt sits beside docroot, one
 *    level above it, and nothing may ever serve it.
 *
 *  - everything else reaches an echo handler, which answers 200 with the
 *    path and urlargs exactly as lws hands them to user code, after its
 *    percent-decoding and ../ normalization.  So for each hostile path the
 *    test sees what a user callback would have been given to act on.
 *
 * For h1 and h2 (cleartext, prior knowledge) the client side is raw, so it
 * can send bytes no well-behaved client would.  For h3 it is the lws client,
 * so there only what that client composes can be sent.
 *
 * "h1s" is h1 over tls, again with a raw client, for the cases about the
 * request head's deadline: the tls accept must not trade it for a timeout
 * of its own, which each header byte then renews.
 *
 * lws is both ends here, in one process: a crash or memory error in the
 * server fails the test as well as a wrong answer does.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

/* in docroot/index.html and secret.txt respectively */
#define ATK_DOCROOT_MARK	"lws-attack-docroot-index"
#define ATK_SECRET_MARK	"lws-attack-secret"

/* what we keep of the server's reply */
#define ATK_RX_MAX		(64 * 1024)
#define ATK_H2_FRAME_MAX	(32 * 1024)	/* h2 frame reassembly */
#define ATK_FIRST_RX_MAX	4096		/* h2: the first of two answers */
#define ATK_TX_CHUNK	(16 * 1024)
/* server: time to send all of the request headers */
#define ATK_AH_IDLE_SECS	3
/*
 * server: the context's timeout_secs, set explicitly because the case
 * timeout depends on it.  Having refused a request, an h1 server shuts
 * down its side and waits up to this long for the peer's FIN, ignoring
 * what else it sends: a peer still sending, as the noise cases are, may
 * only see the connection end then.  That is a correct refusal, so a case
 * may take this long, and its watchdog must be longer.
 */
#define ATK_TIMEOUT_SECS	15
#define ATK_CASE_TIMEOUT_S	(ATK_TIMEOUT_SECS + 10)
/* a case taking longer than this says so in the log, pass or fail */
#define ATK_SLOW_CASE_MS	2000

enum xport {
	XP_H1,
	XP_H2,
	XP_H3,
	XP_H1S,		/* h1 over tls: the request head deadline cases */

	XP_COUNT
};

static const char * const xport_names[] = { "h1", "h2", "h3", "h1s" };

enum verdict {
	V_ECHO,		  /* 200, and the body is exactly "echo:" + expect */
	V_STATUS,	  /* .status, with expect in the body if given */
	V_REFUSED,	  /* refused by the request parser: 403 on h1,
			   * GOAWAY PROTOCOL_ERROR on h2, the connection
			   * closed on h3 */
	V_NO_2XX,	  /* not served, however it is turned away */
	V_GOAWAY,	  /* h2: GOAWAY with error code .status */
	V_ALIVE_OR_CALM,  /* h2: the request after the abuse is served, or the
			   * connection ends with GOAWAY ENHANCE_YOUR_CALM */
	V_PIPELINED,	  /* h1: .status responses, each 200 with expect */
	V_FIRST_ONLY,	  /* h1: the first request is served, the rest not
			   * (answered .status if given, else 200) */
	V_THEN_ECHO,	  /* h1: .status, then 200 with the echo of expect,
			   * and nothing else */
	V_DROPPED,	  /* h1: closed without a response, in time */
};

/*
 * Paths sent as the request path on every transport
 */

struct path_case {
	const char	*path;
	uint8_t		v;
	int		status;
	const char	*expect;
};

#define ATK_ECHO(p, e)	{ p, V_ECHO, 200, e }
#define ATK_REFUSED(p)	{ p, V_REFUSED, 0, NULL }
#define ATK_FILE_OK(p)	{ p, V_STATUS, 200, ATK_DOCROOT_MARK }
#define ATK_NOT_SERVED(p)	{ p, V_NO_2XX, 0, NULL }

static const struct path_case path_cases[] = {

	/* the controls: the echo handler and the file mount work at all */

	ATK_ECHO("/alive", "/alive"),
	ATK_FILE_OK("/f/index.html"),
	ATK_FILE_OK("/f/"),
	{ "/f/nope", V_STATUS, 404, NULL },

	/* urlargs, from attack.sh */

	ATK_ECHO("/cgi-bin/settingsjs?UPDATE_SETTINGS=1&Root_Channels_1_"
		 "Channel_name_http_post=%3F&Root_Channels_1_Channel_"
		 "location_http_post=%3F",
		 "/cgi-bin/settingsjs?UPDATE_SETTINGS=1&Root_Channels_1_"
		 "Channel_name_http_post=?&Root_Channels_1_Channel_"
		 "location_http_post=?"),
	ATK_ECHO("/cgi-bin/settings.js?key1=value1",
	     "/cgi-bin/settings.js?key1=value1"),
	/* an encoded = in the name part of an arg is not the name's end */
	ATK_ECHO("/t%3dest?key1%3d2=value1", "/t=est?key1_2=value1"),
	ATK_ECHO("%2f%2e%2e%2f%2e./xxtest.html?arg=1", "/xxtest.html?arg=1"),
	ATK_ECHO("%2f%2e%2e%2f%2e./xxtest.html?arg=/../.",
	     "/xxtest.html?arg=/../."),

	/* directory traversal on the file mount, from attack.sh */

	ATK_ECHO("/f/../../../../etc/passwd", "/etc/passwd"),
	ATK_FILE_OK("/f/../f/"),
	ATK_FILE_OK("/f/./"),
	ATK_FILE_OK("/f/blah/../"),
	ATK_ECHO("/f/%2e%2e%2f../../../etc/passwd", "/etc/passwd"),
	ATK_ECHO("%2f%2e%2e%2f%2e./.%2e/.%2e%2fetc/passwd", "/etc/passwd"),

	/* ... and at secret.txt, one level above the docroot */

	ATK_ECHO("/f/../secret.txt", "/secret.txt"),
	ATK_ECHO("/f/%2e%2e/secret.txt", "/secret.txt"),
	ATK_ECHO("/f/.%2e/secret.txt", "/secret.txt"),
	ATK_ECHO("/f/%2e./secret.txt", "/secret.txt"),
	ATK_ECHO("/f/..%2fsecret.txt", "/secret.txt"),
	ATK_ECHO("/f/%2e%2e%2fsecret.txt", "/secret.txt"),
	ATK_ECHO("/f//../secret.txt", "/secret.txt"),
	ATK_ECHO("/f/./../secret.txt", "/secret.txt"),
	ATK_ECHO("%2ff%2f..%2fsecret.txt", "/secret.txt"),
	ATK_NOT_SERVED("/f/..\\secret.txt"),
	ATK_NOT_SERVED("/f/%5c..%5csecret.txt"),
	ATK_NOT_SERVED("/f/..;/secret.txt"),
	ATK_NOT_SERVED("/f/....//secret.txt"),
	ATK_NOT_SERVED("/f/%252e%252e/secret.txt"),
	ATK_NOT_SERVED("/f/%c0%ae%c0%ae/secret.txt"),

	/* bad percent-encoding, and control bytes smuggled in by it */

	ATK_REFUSED("/a%"),
	ATK_REFUSED("/a%4"),
	ATK_REFUSED("/a%zz"),
	ATK_REFUSED("/a%00b"),
	ATK_REFUSED("/a%0d%0aSet-Cookie:%20a=b"),
	ATK_REFUSED("/a?b=%0d%0aSet-Cookie:%20a=b"),
	ATK_REFUSED("/a?b=%7f"),

	/* the mass uri variations of attack.sh */

	ATK_ECHO("/..../", "/..../"),
	ATK_ECHO("/.../.", "/.../"),
	ATK_ECHO("/...//", "/.../"),
	ATK_ECHO("/.../a", "/.../a"),
	ATK_ECHO("/.../w", "/.../w"),
	ATK_ECHO("/.../?", "/.../?"),
	ATK_REFUSED("/.../%"),
	ATK_ECHO("/../..", "/"),
	ATK_ECHO("/.././", "/"),
	ATK_ECHO("/../.a", "/.a"),
	ATK_ECHO("/../.w", "/.w"),
	ATK_REFUSED("/../.%"),
	ATK_ECHO("/..//.", "/"),
	ATK_ECHO("/..///", "/"),
	ATK_ECHO("/..//a", "/a"),
	ATK_ECHO("/..//w", "/w"),
	ATK_ECHO("/..//?", "/?"),
	ATK_REFUSED("/..//%"),
	ATK_ECHO("/../a.", "/a."),
	ATK_ECHO("/../a/", "/a/"),
	ATK_ECHO("/../aa", "/aa"),
	ATK_ECHO("/../aw", "/aw"),
	ATK_ECHO("/../a?", "/a?"),
	ATK_REFUSED("/../a%"),
	ATK_ECHO("/../w.", "/w."),
	ATK_ECHO("/../w/", "/w/"),
	ATK_ECHO("/../wa", "/wa"),
	ATK_ECHO("/../ww", "/ww"),
	ATK_ECHO("/../w?", "/w?"),
	ATK_REFUSED("/../w%"),
	ATK_ECHO("/../?.", "/?."),
	ATK_ECHO("/../?/", "/?/"),
	ATK_ECHO("/../?a", "/?a"),
	ATK_ECHO("/../?w", "/?w"),
	ATK_ECHO("/../??", "/??"),
	ATK_REFUSED("/../?%"),
	ATK_REFUSED("/../%."),
	ATK_REFUSED("/../%/"),
	ATK_REFUSED("/../%a"),
	ATK_REFUSED("/../%w"),
	ATK_REFUSED("/../%?"),
	ATK_REFUSED("/../%%"),
	ATK_ECHO("/./...", "/..."),
	ATK_ECHO("/./../", "/"),
	ATK_ECHO("/./..a", "/..a"),
	ATK_ECHO("/./..w", "/..w"),
	ATK_ECHO("/./..?", "/?"),
	ATK_REFUSED("/./..%"),
	ATK_ECHO("/.//..", "/"),
	ATK_ECHO("/.a../", "/.a../"),
	ATK_ECHO("/.a/..", "/"),
	ATK_ECHO("/.w../", "/.w../"),
	ATK_ECHO("/.w/..", "/"),
	ATK_ECHO("/.?../", "/?../"),
	ATK_REFUSED("/.%../"),
	ATK_REFUSED("/.%/.."),
	ATK_ECHO("//....", "/...."),
	ATK_ECHO("//.../", "/.../"),
	ATK_ECHO("//...a", "/...a"),
	ATK_ECHO("//...w", "/...w"),
	ATK_ECHO("//...?", "/...?"),
	ATK_REFUSED("//...%"),
	ATK_ECHO("//../.", "/"),
	ATK_ECHO("//..//", "/"),
	ATK_ECHO("//../a", "/a"),
	ATK_ECHO("//../w", "/w"),
	ATK_ECHO("//../?", "/?"),
	ATK_REFUSED("//../%"),
	ATK_ECHO("//..a.", "/..a."),
	ATK_ECHO("//..a/", "/..a/"),
	ATK_ECHO("//..aa", "/..aa"),
	ATK_ECHO("//..aw", "/..aw"),
	ATK_ECHO("//..a?", "/..a?"),
	ATK_REFUSED("//..a%"),
	ATK_ECHO("//..w.", "/..w."),
	ATK_ECHO("//..w/", "/..w/"),
	ATK_ECHO("//..wa", "/..wa"),
	ATK_ECHO("//..ww", "/..ww"),
	ATK_ECHO("//..w?", "/..w?"),
	ATK_REFUSED("//..w%"),
	ATK_ECHO("//..?.", "/?."),
	ATK_ECHO("//..?/", "/?/"),
	ATK_ECHO("//..?a", "/?a"),
	ATK_ECHO("//..?w", "/?w"),
	ATK_ECHO("//..??", "/??"),
	ATK_REFUSED("//..?%"),
	ATK_REFUSED("//..%."),
	ATK_REFUSED("//..%/"),
	ATK_REFUSED("//..%a"),
	ATK_REFUSED("//..%w"),
	ATK_REFUSED("//..%?"),
	ATK_REFUSED("//..%%"),
	ATK_ECHO("//./..", "/"),
	ATK_ECHO("///...", "/..."),
	ATK_ECHO("///../", "/"),
	ATK_ECHO("///..a", "/..a"),
	ATK_ECHO("///..w", "/..w"),
	ATK_ECHO("///..?", "/?"),
	ATK_REFUSED("///..%"),
	ATK_ECHO("////..", "/"),
	ATK_ECHO("//a../", "/a../"),
	ATK_ECHO("//a/..", "/"),
	ATK_ECHO("//w../", "/w../"),
	ATK_ECHO("//w/..", "/"),
	ATK_ECHO("//?../", "/?../"),
	ATK_ECHO("//?/..", "/?/.."),
	ATK_REFUSED("//%../"),
	ATK_REFUSED("//%/.."),
	ATK_ECHO("/a.../", "/a.../"),
	ATK_ECHO("/a../.", "/a../"),
	ATK_ECHO("/a..//", "/a../"),
	ATK_ECHO("/a../a", "/a../a"),
	ATK_ECHO("/a../w", "/a../w"),
	ATK_ECHO("/a../?", "/a../?"),
	ATK_REFUSED("/a../%"),
	ATK_ECHO("/a./..", "/"),
	ATK_ECHO("/a/...", "/a/..."),
	ATK_ECHO("/a/../", "/"),
	ATK_ECHO("/a/..a", "/a/..a"),
	ATK_ECHO("/a/..w", "/a/..w"),
	ATK_ECHO("/a/..?", "/?"),
	ATK_REFUSED("/a/..%"),
	ATK_ECHO("/a//..", "/"),
	ATK_ECHO("/aa../", "/aa../"),
	ATK_ECHO("/aa/..", "/"),
	ATK_ECHO("/aw../", "/aw../"),
	ATK_ECHO("/aw/..", "/"),
	ATK_ECHO("/a?../", "/a?../"),
	ATK_ECHO("/a?/..", "/a?/.."),
	ATK_REFUSED("/a%../"),
	ATK_REFUSED("/a%/.."),
	ATK_ECHO("/w.../", "/w.../"),
	ATK_ECHO("/w../.", "/w../"),
	ATK_ECHO("/w..//", "/w../"),
	ATK_ECHO("/w../a", "/w../a"),
	ATK_ECHO("/w../w", "/w../w"),
	ATK_ECHO("/w../?", "/w../?"),
	ATK_REFUSED("/w../%"),
	ATK_ECHO("/w./..", "/"),
	ATK_ECHO("/w/...", "/w/..."),
	ATK_ECHO("/w/../", "/"),
	ATK_ECHO("/w/..a", "/w/..a"),
	ATK_ECHO("/w/..w", "/w/..w"),
	ATK_ECHO("/w/..?", "/?"),
	ATK_REFUSED("/w/..%"),
	ATK_ECHO("/w//..", "/"),
	ATK_ECHO("/wa../", "/wa../"),
	ATK_ECHO("/wa/..", "/"),
	ATK_ECHO("/ww../", "/ww../"),
	ATK_ECHO("/ww/..", "/"),
	ATK_ECHO("/w?../", "/w?../"),
	ATK_ECHO("/w?/..", "/w?/.."),
	ATK_REFUSED("/w%../"),
	ATK_REFUSED("/w%/.."),
	ATK_ECHO("/?.../", "/?.../"),
	ATK_ECHO("/?../.", "/?../."),
	ATK_ECHO("/?..//", "/?..//"),
	ATK_ECHO("/?../a", "/?../a"),
	ATK_ECHO("/?../w", "/?../w"),
	ATK_ECHO("/?../?", "/?../?"),
	ATK_REFUSED("/?../%"),
	ATK_ECHO("/?./..", "/?./.."),
	ATK_ECHO("/?/...", "/?/..."),
	ATK_ECHO("/?/../", "/?/../"),
	ATK_ECHO("/?/..a", "/?/..a"),
	ATK_ECHO("/?/..w", "/?/..w"),
	ATK_ECHO("/?/..?", "/?/..?"),
	ATK_REFUSED("/?/..%"),
	ATK_ECHO("/?//..", "/?//.."),
	ATK_ECHO("/?a../", "/?a../"),
	ATK_ECHO("/?a/..", "/?a/.."),
	ATK_ECHO("/?w../", "/?w../"),
	ATK_ECHO("/?w/..", "/?w/.."),
	ATK_ECHO("/??../", "/??../"),
	ATK_ECHO("/?\?/..", "/?\?/.."),	/* not a trigraph */
	ATK_REFUSED("/?%../"),
	ATK_REFUSED("/?%/.."),
	ATK_REFUSED("/%.../"),
	ATK_REFUSED("/%../."),
	ATK_REFUSED("/%..//"),
	ATK_REFUSED("/%../a"),
	ATK_REFUSED("/%../w"),
	ATK_REFUSED("/%../?"),
	ATK_REFUSED("/%../%"),
	ATK_REFUSED("/%./.."),
	ATK_REFUSED("/%/..."),
	ATK_REFUSED("/%/../"),
	ATK_REFUSED("/%/..a"),
	ATK_REFUSED("/%/..w"),
	ATK_REFUSED("/%/..?"),
	ATK_REFUSED("/%/..%"),
	ATK_REFUSED("/%//.."),
	ATK_REFUSED("/%a../"),
	ATK_REFUSED("/%a/.."),
	ATK_REFUSED("/%w../"),
	ATK_REFUSED("/%w/.."),
	ATK_REFUSED("/%?../"),
	ATK_REFUSED("/%?/.."),
	ATK_REFUSED("/%%../"),
	ATK_REFUSED("/%%/.."),
	ATK_ECHO("/a/w/../a", "/a/a"),
	ATK_ECHO("/path/to/dir/../other/dir", "/path/to/other/dir"),
};

/*
 * h1: raw bytes.  What's sent is pre (repeat times), then fill times the
 * string fill_str (or that many pseudorandom bytes if it's NULL), then post.
 */

struct h1_attack {
	const char	*name;
	const char	*pre;
	size_t		pre_len;
	const char	*fill_str;
	uint32_t	fill;
	const char	*post;
	size_t		post_len;
	uint8_t		repeat;
	uint8_t		trickle;	/* send the fill a byte at a time */
	uint8_t		v;
	int		status;
	const char	*expect;
};

/* sizeof, so a literal may have a NUL in it */
#define ATK_L(s)	s, sizeof(s) - 1
#define ATK_NONE	NULL, 0

/* the common shapes: just these bytes, and nothing served, or the echo */
#define ATK_H1_NO_2XX(n, r) \
		{ n, ATK_L(r), NULL, 0, ATK_NONE, 1, 0, V_NO_2XX, 0, NULL }
#define ATK_H1_ECHO(n, r, e) \
		{ n, ATK_L(r), NULL, 0, ATK_NONE, 1, 0, V_ECHO, 200, e }

#define ATK_GET_INDEX "GET /f/index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"
#define ATK_GET_ALIVE "GET /alive HTTP/1.0\r\n"
#define ATK_POST_ALIVE "POST /alive HTTP/1.1\r\nHost: localhost\r\n"
#define ATK_POST_F "POST /f HTTP/1.1\r\nHost: localhost\r\n"
#define ATK_GET_NEXT "GET /alive HTTP/1.1\r\nHost: localhost\r\n" \
		     "User-Agent: next\r\nConnection: close\r\n\r\n"

static const struct h1_attack h1_attacks[] = {

	/* from attack.sh */

	ATK_H1_NO_2XX("not GET", "not GET\n"),
	{ "80 bytes of noise", ATK_NONE, NULL, 80, ATK_NONE, 1, 0,
	  V_NO_2XX, 0, NULL },
	{ "640KiB of noise", ATK_NONE, NULL, 655360, ATK_NONE, 1, 0,
	  V_NO_2XX, 0, NULL },
	{ "malformed uri", ATK_L("GET nonsense"), ".", 112,
	  ATK_L(" HTTP/1.0\r\n\r\n"), 1, 0, V_NO_2XX, 0, NULL },
	ATK_H1_NO_2XX("missing uri", "GET HTTP/1.0\r\n\r\n"),
	ATK_H1_NO_2XX("repeated method",
		      "GET blah HTTP/1.0\r\nGET blah HTTP/1.0\r\n\r\n"),
	{ "2000-byte header name", ATK_L(ATK_GET_ALIVE), ".", 2000,
	  ATK_L("\r\n\r\n"), 1, 0, V_NO_2XX, 0, NULL },
	{ "8000-byte uri", ATK_L("GET "), ".", 8000,
	  ATK_L(" HTTP/1.0\r\n\r\n"), 1, 0, V_NO_2XX, 0, NULL },
	{ "request followed by junk", ATK_L(ATK_GET_INDEX "ILLEGAL-PAYLOAD"),
	  ".", 40, ATK_NONE, 1, 0, V_FIRST_ONLY, 0, ATK_DOCROOT_MARK },
	ATK_H1_NO_2XX("relative uri", "GET nope HTTP/1.0\r\n\r\n"),
	{ "8 pipelined requests", ATK_L(ATK_GET_INDEX), NULL, 0,
	  ATK_L("GET /f/index.html HTTP/1.1\r\nHost: localhost\r\n"
		"Connection: close\r\n\r\n"), 8, 0, V_PIPELINED, 9,
	  ATK_DOCROOT_MARK },

	/* request smuggling: the body framing must be unambiguous */

	ATK_H1_NO_2XX("two different Content-Length", ATK_POST_ALIVE
		      "Content-Length: 1\r\nContent-Length: 2\r\n\r\nab"),
	ATK_H1_NO_2XX("Content-Length and chunked", ATK_POST_ALIVE
		      "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n"
		      "\r\n0\r\n\r\n"),
	ATK_H1_NO_2XX("chunk size overflow", ATK_POST_ALIVE
		      "Transfer-Encoding: chunked\r\n\r\n"
		      "fffffffffffffffffffff1\r\nab"),
	ATK_H1_NO_2XX("whitespace before a header colon",
		      "GET /alive HTTP/1.1\r\nHost : localhost\r\n\r\n"),
	ATK_H1_NO_2XX("two Host headers",
		      "GET /alive HTTP/1.1\r\nHost: localhost\r\n"
		      "Host: other\r\n\r\n"),

	/*
	 * Some requests are answered before they reach the user code: a
	 * mount asked for without its trailing '/' is redirected, an
	 * unknown upgrade is refused.  Their body is still theirs, and the
	 * request after it on the connection is the next one served.  A
	 * POST with neither Content-Length nor Transfer-Encoding has no body
	 * (RFC 9112 6.3): what follows its head is the next request, and
	 * here that is "hello world" run into a request line, refused.
	 */
	{ "a POST with a body to a mount without its /",
	  ATK_L(ATK_POST_F "Content-Length: 11\r\n\r\nhello world"
		ATK_GET_NEXT), NULL, 0, ATK_NONE, 1, 0, V_THEN_ECHO,
	  HTTP_STATUS_MOVED_PERMANENTLY, "/alive ua=next" },
	{ "a POST with a chunked body to a mount without its /",
	  ATK_L(ATK_POST_F "Transfer-Encoding: chunked\r\n\r\n"
		"6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n" ATK_GET_NEXT),
	  NULL, 0, ATK_NONE, 1, 0, V_THEN_ECHO,
	  HTTP_STATUS_MOVED_PERMANENTLY, "/alive ua=next" },
	{ "a POST with no body length to a mount without its /, junk after it",
	  ATK_L(ATK_POST_F "\r\nhello world" ATK_GET_NEXT), NULL, 0,
	  ATK_NONE, 1, 0, V_FIRST_ONLY, HTTP_STATUS_MOVED_PERMANENTLY, NULL },
	{ "an unknown upgrade with a body",
	  ATK_L(ATK_POST_ALIVE "Connection: upgrade\r\nUpgrade: other\r\n"
		"Content-Length: 11\r\n\r\nhello world" ATK_GET_NEXT), NULL,
	  0, ATK_NONE, 1, 0, V_THEN_ECHO, HTTP_STATUS_FORBIDDEN,
	  "/alive ua=next" },
	/* what follows an upgrade's head is the new protocol, not a body */
	{ "a websocket upgrade with a body",
	  ATK_L("GET /alive HTTP/1.1\r\nHost: localhost\r\n"
		"Connection: upgrade\r\nUpgrade: websocket\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
		"Content-Length: 11\r\n\r\nhello world"), NULL, 0, ATK_NONE,
	  1, 0, V_STATUS, HTTP_STATUS_BAD_REQUEST, NULL },

	/* header names: a token, then the colon */

	ATK_H1_ECHO("unknown header", ATK_GET_ALIVE "X-Unknown: a\r\n\r\n",
		    "/alive"),
	/* its name must end at its colon, not swallow the next header */
	ATK_H1_ECHO("unknown header named as the start of a known one",
		    ATK_GET_ALIVE "Accept-Lang: a\r\nUser-Agent: b\r\n\r\n",
		    "/alive ua=b"),
	ATK_H1_ECHO("... and as the last header",
		    ATK_GET_ALIVE "Accept-Lang: a\r\n\r\n", "/alive"),
	ATK_H1_NO_2XX("header line with no colon",
		      ATK_GET_ALIVE "X-Unknown\r\n\r\n"),
	ATK_H1_NO_2XX("obs-fold continuation line",
		      ATK_GET_ALIVE "User-Agent: a\r\n b\r\n\r\n"),
	/*
	 * lws knows names that are no h1 field name: the h2 pseudo-headers,
	 * which aren't tokens, and its own slot for the urlargs and the
	 * methods, which are only names on h1 like any other
	 */
	ATK_H1_NO_2XX("h2 pseudo-header", ATK_GET_ALIVE ":method: POST\r\n\r\n"),
	ATK_H1_NO_2XX("header name starting with a colon",
		      ATK_GET_ALIVE ":x: a\r\n\r\n"),
	ATK_H1_ECHO("header named as lws' urlargs",
		    ATK_GET_ALIVE "Uri-Args: a=1\r\nUser-Agent: b\r\n\r\n",
		    "/alive ua=b"),
	ATK_H1_ECHO("header named as the start of a method",
		    ATK_GET_ALIVE "Put-Id: 1\r\nUser-Agent: b\r\n\r\n",
		    "/alive ua=b"),

	/*
	 * line ends: CRLF only.  Something in front of us may not take a
	 * bare LF as a line end, and see the header after it as more of
	 * the line
	 */

	ATK_H1_NO_2XX("bare LF line ends", "GET /alive HTTP/1.0\n\n"),
	ATK_H1_NO_2XX("bare LF ending a header",
		      ATK_GET_ALIVE "User-Agent: a\nContent-Length: 5\r\n\r\n"),
	ATK_H1_NO_2XX("bare LF ending an unknown header",
		      ATK_GET_ALIVE "X-Unknown: a\nContent-Length: 5\r\n\r\n"),
	ATK_H1_NO_2XX("bare LF ending a chunked body's trailer", ATK_POST_ALIVE
		      "Transfer-Encoding: chunked\r\n\r\n0\r\nX-t: a\n\r\n"),

	/* header injection: control bytes in a header value */

	ATK_H1_NO_2XX("NUL in a header value",
		      ATK_GET_ALIVE "User-Agent: a\0b\r\n\r\n"),
	ATK_H1_NO_2XX("bare CR in a header value",
		      ATK_GET_ALIVE "User-Agent: a\rb\r\n\r\n"),
	ATK_H1_NO_2XX("bare CR in an unknown header's value",
		      ATK_GET_ALIVE "X-Unknown: a\rb\r\n\r\n"),

	/* resource exhaustion */

	{ "1000 headers", ATK_L(ATK_GET_ALIVE), "Accept: x\r\n", 1000,
	  ATK_L("\r\n"), 1, 0, V_NO_2XX, 0, NULL },
	/*
	 * Each urlarg takes one of the ah's header fragments.  A long query
	 * string that fits them is served; one with more args than the ah
	 * has fragments for is a 414, and the ah is free for the request
	 * after it.  Neither is hostile, the second just too many.
	 */
	{ "40 urlargs", ATK_L("GET /alive?"), "a=1&", 40,
	  ATK_L("a=1 HTTP/1.1\r\nHost: localhost\r\n"
		"Connection: close\r\n\r\n"), 1, 0, V_STATUS, 200,
	  "echo:/alive?a=1&a=1&" },
	{ "120 urlargs", ATK_L("GET /alive?"), "a=1&", 120,
	  ATK_L("a=1 HTTP/1.1\r\nHost: localhost\r\n\r\n"), 1, 0,
	  V_STATUS, HTTP_STATUS_REQ_URI_TOO_LONG, NULL },
	{ "headers never finished",
	  ATK_L("GET /alive HTTP/1.1\r\nHost: x\r\n"), NULL, 0, ATK_NONE, 1, 0,
	  V_DROPPED, 0, NULL },
	{ "headers trickled in",
	  ATK_L("GET /alive HTTP/1.1\r\nUser-Agent: "), "a", 100, ATK_NONE,
	  1, 1, V_DROPPED, 0, NULL },
};

/*
 * h2: frames built for each case.  The builder returns the stream id whose
 * outcome decides the case.
 */

struct txb {
	uint8_t		*buf;
	size_t		len;
	size_t		max;
	int		oom;	/* something wasn't added, don't send it */
};

typedef uint32_t (*h2_build_t)(struct txb *t);

struct h2_attack {
	const char	*name;
	h2_build_t	build;
	uint8_t		v;
	int		status;
	/*
	 * We send more than the server reads before it gives up on us.  It
	 * closes with our data unread, the kernel resets the connection and
	 * drops what the server had still to send, the GOAWAY included: so
	 * the connection just ending, with nothing served, is a pass too.
	 */
	uint8_t		lossy;
};

/*
 * h3: the lws client, with at most one header of our own added
 */

struct h3_attack {
	const char	*name;
	const char	*path;
	const char	*hdr_name;
	const char	*hdr_value;
	/*
	 * nonzero: the name and value are these many bytes, and go into the
	 * field section as a literal as they are, not through
	 * lws_add_http_header_by_name(), which refuses control bytes itself
	 */
	size_t		hdr_name_len;
	size_t		hdr_value_len;
	/*
	 * nonzero: add this many field lines instead, each a one-byte
	 * reference to static table row 29, an accept field
	 */
	unsigned int	static_fields;
	uint8_t		v;
};

/* a field sent as a raw literal, name and value exactly these bytes */
#define H3_LIT(n, v)	n, v, sizeof(n) - 1, sizeof(v) - 1

static const struct h3_attack h3_attacks[] = {
	/* a field named "get " once smuggled an unnormalized request path */
	{ "\"get \" field smuggling a path", "/alive", "get ",
	  "/f/../secret.txt", 0, 0, 0, V_REFUSED },
	{ "CR LF in a field value", "/alive",
	  H3_LIT("user-agent", "a\r\nb"), 0, V_REFUSED },
	{ "NUL in a raw literal value", "/alive",
	  H3_LIT("user-agent", "a\0b"), 0, V_REFUSED },
	{ "NUL in a raw literal name", "/alive",
	  H3_LIT("user-agent\0x", "a"), 0, V_REFUSED },
	/* far more fields than any request has, for almost no bytes */
	{ "1100 field lines", "/alive", NULL, NULL, 0, 0, 1100, V_REFUSED },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog, sul_trickle;
static int port_h1 = 7681, port_h2 = 7682, port_h3 = 7683, port_h1s = 7684,
	   fails;
static const char *server_addr = "127.0.0.1", *only;
static unsigned int xport_mask = (1u << XP_H1)
#if defined(LWS_WITH_HTTP2)
		| (1u << XP_H2)
#endif
#if defined(LWS_ROLE_H3)
		| (1u << XP_H3)
#endif
#if defined(LWS_WITH_TLS)
		| (1u << XP_H1S)
#endif
		;

/* which case we're on */

enum {
	PH_PATHS,
	PH_ATTACKS,
	PH_NEXT_XPORT,
};

static struct {
	int		xport;
	int		phase;
	int		idx;
	unsigned int	seq;		/* tags this case's client wsi */
	char		name[160];

	/* what to send, and what must come back */
	const char	*path;		/* request path (not raw h1) */
	const struct h1_attack	*h1a;
	const struct h2_attack	*h2a;
	const struct h3_attack	*h3a;
	uint8_t		v;
	int		status;
	const char	*expect;
	uint8_t		lossy;

	uint8_t		probe_next;	/* after an attack, a plain request */
} tc = { XP_H1, PH_PATHS, -1, 0, "", NULL, NULL, NULL, NULL, 0, 0, NULL, 0,
	 0 };

/* the client's view of the case */

static struct {
	uint8_t		*tx;
	size_t		tx_len;
	size_t		tx_pos;
	size_t		trickle_from;	/* tx_len is held back to here */

	uint8_t		rx[ATK_RX_MAX];	/* h1: raw; h2 / h3: body bytes */
	size_t		rx_len;
	uint8_t		rx_over;

	uint8_t		*fr;		/* h2 frame reassembly */
	size_t		fr_len;
	uint32_t	final_sid;
	int		status;		/* h2 / h3: of the final request */

	/* h2: a path case's first request, when the final one repeats it */
	uint8_t		first_rx[ATK_FIRST_RX_MAX];
	size_t		first_rx_len;
	uint32_t	first_sid;
	int		first_status;
	uint8_t		first_ended;
	int		goaway;		/* h2: -1, or the GOAWAY error code */
	int		rst;		/* h2: -1, or the final stream's RST */

	lws_usec_t	start;
	unsigned int	seq;		/* the case's tc.seq, 0 between cases */
	uint8_t		ended;		/* h2 / h3: the final stream ended */
	uint8_t		failed;		/* connection error */
	uint8_t		done;
} cn;

static void
next_case(lws_sorted_usec_list_t *sul);

/*
 * The server
 */

struct pss {
	char		body[1024];
	int		len;
};

/*
 * "echo:" + the path, then its urlargs rejoined by ? and &, all as lws
 * gives them to user code.  Then " ua=" and the User-Agent, if there was one,
 * to show a header after something hostile was still seen as that header.
 */

static int
echo_compose(struct lws *wsi, struct pss *pss)
{
	char arg[256], *uri;
	int ulen, n, i;

	if (lws_http_get_uri_and_method(wsi, &uri, &ulen) < 0)
		return -1;

	n = lws_snprintf(pss->body, sizeof(pss->body), "echo:%.*s", ulen, uri);
	for (i = 0; lws_hdr_copy_fragment(wsi, arg, (int)sizeof(arg),
					  WSI_TOKEN_HTTP_URI_ARGS, i) >= 0; i++)
		n += lws_snprintf(pss->body + n, sizeof(pss->body) - (size_t)n,
				  "%c%s", i ? '&' : '?', arg);
	if (lws_hdr_copy(wsi, arg, (int)sizeof(arg),
			 WSI_TOKEN_HTTP_USER_AGENT) > 0)
		n += lws_snprintf(pss->body + n, sizeof(pss->body) - (size_t)n,
				  " ua=%s", arg);
	pss->len = n;

	return 0;
}

static int
echo_respond(struct lws *wsi, struct pss *pss)
{
	uint8_t buf[LWS_PRE + 512], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	if (echo_compose(wsi, pss) ||
	    lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
					(lws_filepos_t)pss->len, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	lws_callback_on_writable(wsi);

	return 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + sizeof(pss->body)];
	char *uri;
	int ulen;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		/* a request with a body is answered once all of it is in */
		if (lws_http_get_uri_and_method(wsi, &uri, &ulen) ==
							LWSHUMETH_POST)
			return 0;

		return echo_respond(wsi, pss);

	case LWS_CALLBACK_HTTP_BODY:
		return 0;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		return echo_respond(wsi, pss);

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->len)
			break;
		memcpy(&buf[LWS_PRE], pss->body, (size_t)pss->len);
		if (lws_write(wsi, &buf[LWS_PRE], (size_t)pss->len,
			      LWS_WRITE_HTTP_FINAL) != pss->len)
			return 1;
		pss->len = 0;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * A request the file mount has no file for goes to the mount's protocol, as
 * LWS_CALLBACK_HTTP: here the dummy callback, which answers 404
 */

static const struct lws_http_mount mount_f = {
	.mountpoint		= "/f",
	.origin			= "./docroot",
	.def			= "index.html",
	.protocol		= "files",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 2,
};

/*
 * Checking what came back
 */

static const uint8_t *
find(const uint8_t *h, size_t hl, const char *needle)
{
	size_t nl = strlen(needle), n;

	for (n = 0; n + nl <= hl; n++)
		if (!memcmp(h + n, needle, nl))
			return h + n;

	return NULL;
}

struct h1_resp {
	int		status;
	const uint8_t	*body;
	size_t		body_len;
};

/*
 * Split what the h1 server sent into its responses.  lws gives every
 * response here a content-length (lowercase, as lws composes it), except
 * a close-delimited one, which runs to the end.
 */

static int
h1_parse(const uint8_t *p, size_t len, struct h1_resp *r, int max)
{
	const uint8_t *e, *cl;
	size_t hl, bl;
	int n = 0;

	while (n < max && len >= 12 && !memcmp(p, "HTTP/1.", 7)) {
		e = find(p, len, "\r\n\r\n");
		if (!e)
			break;
		hl = lws_ptr_diff_size_t(e, p) + 4;
		r[n].status = atoi((const char *)p + 9);
		bl = len - hl;
		cl = find(p, hl, "\r\ncontent-length:");
		if (cl) {
			bl = (size_t)atol((const char *)cl + 17);
			if (bl > len - hl)
				bl = len - hl;
		}
		r[n].body = p + hl;
		r[n].body_len = bl;
		n++;
		p += hl + bl;
		len -= hl + bl;
	}

	return n;
}

static int
body_is_echo(const uint8_t *b, size_t bl, const char *expect)
{
	size_t el = strlen(expect);

	return bl == el + 5 && !memcmp(b, "echo:", 5) &&
	       !memcmp(b + 5, expect, el);
}

static void
case_done(const char *why);

static void
evaluate(void)
{
	struct h1_resp r[16];
	const uint8_t *b = cn.rx;
	size_t bl = cn.rx_len;
	int status = cn.status, nr = 0, n;
	char why[160];

	if (cn.done)
		return;
	cn.done = 1;

	/* whatever else, nothing may ever have served the secret */
	if (find(cn.rx, cn.rx_len, ATK_SECRET_MARK)) {
		case_done("served the secret");
		return;
	}

	if (tc.xport == XP_H1 || tc.xport == XP_H1S) {
		nr = h1_parse(cn.rx, cn.rx_len, r, (int)LWS_ARRAY_SIZE(r));
		status = nr ? r[0].status : 0;
		b = nr ? r[0].body : NULL;
		bl = nr ? r[0].body_len : 0;
	}

	switch (tc.v) {
	case V_ECHO:
		if (status != 200 || !b || !body_is_echo(b, bl, tc.expect)) {
			lws_snprintf(why, sizeof(why),
				     "wanted 200 '%s', got %d '%.*s'",
				     tc.expect, status,
				     (int)(bl > 100 ? 100 : bl),
				     b ? (const char *)b : "");
			case_done(why);
			return;
		}
		break;

	case V_STATUS:
		if (status != tc.status ||
		    (tc.expect && (!b || !find(b, bl, tc.expect)))) {
			lws_snprintf(why, sizeof(why),
				     "wanted %d, got %d '%.*s'",
				     tc.status, status,
				     (int)(bl > 60 ? 60 : bl),
				     b ? (const char *)b : "");
			case_done(why);
			return;
		}
		break;

	case V_REFUSED:
		if ((tc.xport == XP_H1 && status != HTTP_STATUS_FORBIDDEN) ||
		    (tc.xport == XP_H2 && (cn.goaway != H2_ERR_PROTOCOL_ERROR ||
					   status)) ||
		    (tc.xport == XP_H3 && (status || cn.ended))) {
			lws_snprintf(why, sizeof(why),
				     "not refused: status %d, goaway %d, "
				     "'%.*s'", status, cn.goaway,
				     (int)(bl > 60 ? 60 : bl),
				     b ? (const char *)b : "");
			case_done(why);
			return;
		}
		break;

	case V_NO_2XX:
		for (n = 0; n < nr; n++)
			if (r[n].status >= 200 && r[n].status < 300)
				status = r[n].status;
		if (status >= 200 && status < 300) {
			lws_snprintf(why, sizeof(why), "served: %d '%.*s'",
				     status, (int)(bl > 60 ? 60 : bl),
				     b ? (const char *)b : "");
			case_done(why);
			return;
		}
		break;

	case V_GOAWAY:
		if (tc.lossy && cn.goaway < 0 && status != 200)
			break;
		if (cn.goaway != tc.status) {
			lws_snprintf(why, sizeof(why),
				     "wanted GOAWAY %d, got %d "
				     "(final stream status %d, rst %d)",
				     tc.status, cn.goaway, status, cn.rst);
			case_done(why);
			return;
		}
		break;

	case V_ALIVE_OR_CALM:
		if (cn.goaway == H2_ERR_ENHANCE_YOUR_CALM ||
		    (tc.lossy && cn.goaway < 0 && status != 200))
			break;
		if (status != 200 || !body_is_echo(b, bl, "/alive")) {
			lws_snprintf(why, sizeof(why),
				     "neither served nor calmed: status %d, "
				     "goaway %d, rst %d", status, cn.goaway,
				     cn.rst);
			case_done(why);
			return;
		}
		break;

	case V_PIPELINED:
		for (n = 0; n < nr; n++)
			if (r[n].status != 200 ||
			    !find(r[n].body, r[n].body_len, tc.expect))
				break;
		if (nr != tc.status || n != nr) {
			lws_snprintf(why, sizeof(why),
				     "wanted %d responses, got %d, %d good",
				     tc.status, nr, n);
			case_done(why);
			return;
		}
		break;

	case V_FIRST_ONLY:
		if (!nr || r[0].status != (tc.status ? tc.status : 200) ||
		    (tc.expect && !find(r[0].body, r[0].body_len,
					tc.expect))) {
			case_done("first request not served");
			return;
		}
		for (n = 1; n < nr; n++)
			if (r[n].status >= 200 && r[n].status < 300) {
				case_done("what followed it was served");
				return;
			}
		break;

	case V_THEN_ECHO:
		if (nr != 2 || r[0].status != tc.status ||
		    r[1].status != 200 ||
		    !body_is_echo(r[1].body, r[1].body_len, tc.expect)) {
			lws_snprintf(why, sizeof(why),
				     "wanted %d then 200 '%s', got %d "
				     "responses, %d then %d", tc.status,
				     tc.expect, nr, status,
				     nr > 1 ? r[1].status : 0);
			case_done(why);
			return;
		}
		break;

	case V_DROPPED:
		if (nr) {
			lws_snprintf(why, sizeof(why), "answered %d", status);
			case_done(why);
			return;
		}
		if (lws_now_usecs() - cn.start >
				(ATK_AH_IDLE_SECS + 3) * LWS_US_PER_SEC) {
			case_done("dropped, but too late");
			return;
		}
		break;
	}

	/*
	 * An h2 path case asks for the path twice, the second time by the
	 * index of the first's :path in the server's dynamic table: whatever
	 * the verdict, the two must have been answered alike
	 */
	if (tc.xport == XP_H2 && cn.first_sid && cn.goaway < 0 &&
	    (cn.first_status != status || cn.first_rx_len != bl ||
	     (bl && memcmp(cn.first_rx, b, bl)))) {
		lws_snprintf(why, sizeof(why),
			     "indexed :path got %d '%.*s', literal got %d "
			     "'%.*s'", status, (int)(bl > 50 ? 50 : bl),
			     b ? (const char *)b : "", cn.first_status,
			     (int)(cn.first_rx_len > 50 ? 50 :
				   cn.first_rx_len),
			     (const char *)cn.first_rx);
		case_done(why);
		return;
	}

	case_done(NULL);
}

static struct lws *trickle_wsi;

static void
case_done(const char *why)
{
	lws_usec_t us = lws_now_usecs() - cn.start;

	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_trickle);
	trickle_wsi = NULL;

	/* the dropped cases take the header timeout by design */
	if (tc.v != V_DROPPED && us > ATK_SLOW_CASE_MS * LWS_US_PER_MS)
		lwsl_user("%s: %s: took %dms\n", xport_names[tc.xport],
			  tc.name, (int)(us / LWS_US_PER_MS));

	if (why) {
		lwsl_err("%s: %s: FAIL: %s\n", xport_names[tc.xport], tc.name,
			 why);
		fails++;
	} else
		lwsl_user("%s: %s: PASS\n", xport_names[tc.xport], tc.name);

	/* however an attack went, the server must still serve after it */
	tc.probe_next = tc.h1a || tc.h2a || tc.h3a;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static int
rx_keep(const void *in, size_t len)
{
	if (cn.rx_len + len > sizeof(cn.rx)) {
		cn.rx_over = 1;
		len = sizeof(cn.rx) - cn.rx_len;
	}
	memcpy(cn.rx + cn.rx_len, in, len);
	cn.rx_len += len;

	return 0;
}

static void
first_keep(const void *in, size_t len)
{
	if (cn.first_rx_len + len > sizeof(cn.first_rx))
		len = sizeof(cn.first_rx) - cn.first_rx_len;
	memcpy(cn.first_rx + cn.first_rx_len, in, len);
	cn.first_rx_len += len;
}

/* only callbacks for the current case's connection are of interest */

static int
is_current(struct lws *wsi)
{
	return !cn.done && cn.seq &&
	       (unsigned int)(intptr_t)lws_get_opaque_user_data(wsi) == cn.seq;
}

static int
tx_more(struct lws *wsi)
{
	uint8_t buf[LWS_PRE + ATK_TX_CHUNK];
	size_t lim = cn.tx_len, o;

	if (cn.trickle_from && cn.trickle_from < lim)
		lim = cn.trickle_from;
	if (cn.tx_pos >= lim)
		return 0;

	o = lim - cn.tx_pos;
	if (o > ATK_TX_CHUNK)
		o = ATK_TX_CHUNK;
	memcpy(&buf[LWS_PRE], cn.tx + cn.tx_pos, o);
	if (lws_write(wsi, &buf[LWS_PRE], o, LWS_WRITE_RAW) != (int)o)
		return -1;
	cn.tx_pos += o;

	if (cn.tx_pos < lim)
		lws_callback_on_writable(wsi);

	return 0;
}

static void
trickle_cb(lws_sorted_usec_list_t *sul)
{
	if (cn.done || !trickle_wsi || cn.trickle_from >= cn.tx_len)
		return;

	cn.trickle_from++;
	lws_callback_on_writable(trickle_wsi);
	lws_sul_schedule(context, 0, &sul_trickle, trickle_cb,
			 500 * LWS_US_PER_MS);
}

/*
 * The h1 raw client: send the case's bytes, keep everything that comes
 * back until the server closes
 */

static int
callback_raw_h1(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (is_current(wsi)) {
			cn.failed = 1;
			cn.done = 1;
			case_done("could not connect");
		}
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		if (!is_current(wsi))
			return -1;
		if (tc.h1a && tc.h1a->trickle) {
			trickle_wsi = wsi;
			lws_sul_schedule(context, 0, &sul_trickle, trickle_cb,
					 500 * LWS_US_PER_MS);
		}
		return tx_more(wsi);

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!is_current(wsi))
			break;
		return tx_more(wsi);

	case LWS_CALLBACK_RAW_RX:
		if (!is_current(wsi))
			break;
		return rx_keep(in, len);

	case LWS_CALLBACK_RAW_CLOSE:
		if (is_current(wsi))
			evaluate();
		break;

	default:
		break;
	}

	return 0;
}

/*
 * h2 framing and hpack, just enough to compose the cases
 */

#define H2_DATA			0
#define H2_HEADERS		1
#define H2_RST_STREAM		3
#define H2_SETTINGS		4
#define H2_PING			6
#define H2_GOAWAY		7
#define H2_WINDOW_UPDATE	8
#define H2_CONTINUATION		9

#define H2F_END_STREAM		1
#define H2F_ACK			1
#define H2F_END_HEADERS		4

static int
tx_room(struct txb *t, size_t len)
{
	uint8_t *nb;
	size_t m;

	if (t->buf && t->len + len <= t->max)
		return 0;

	m = (t->max ? t->max * 2 : 4096) + len;
	nb = realloc(t->buf, m);
	if (!nb)
		return 1;
	t->buf = nb;
	t->max = m;

	return 0;
}

static void
tx_add(struct txb *t, const void *p, size_t len)
{
	if (!len)
		return;
	if (tx_room(t, len)) {
		t->oom = 1;
		return;
	}
	memcpy(t->buf + t->len, p, len);
	t->len += len;
}

static void
h2_frame(struct txb *t, uint8_t type, uint8_t flags, uint32_t sid,
	 const void *pl, size_t len)
{
	uint8_t h[9];

	h[0] = (uint8_t)(len >> 16);
	h[1] = (uint8_t)(len >> 8);
	h[2] = (uint8_t)len;
	h[3] = type;
	h[4] = flags;
	lws_ser_wu32be(&h[5], sid);
	tx_add(t, h, sizeof(h));
	if (len)
		tx_add(t, pl, len);
}

/* an hpack integer with an n-bit prefix, the prefix's other bits in first */

static uint8_t *
hp_int(uint8_t *p, uint8_t first, unsigned int bits, uint32_t v)
{
	uint32_t lim = (1u << bits) - 1;

	if (v < lim) {
		*p++ = (uint8_t)(first | v);
		return p;
	}
	*p++ = (uint8_t)(first | lim);
	v -= lim;
	while (v >= 128) {
		*p++ = (uint8_t)((v & 0x7f) | 0x80);
		v >>= 7;
	}
	*p++ = (uint8_t)v;

	return p;
}

/* literal without indexing, name from the static table, value not huffman */

static uint8_t *
hp_lit(uint8_t *p, unsigned int name_idx, const char *v, size_t vl)
{
	p = hp_int(p, 0, 4, name_idx);
	p = hp_int(p, 0, 7, (uint32_t)vl);
	memcpy(p, v, vl);

	return p + vl;
}

/* literal with incremental indexing, name from the static table */

static uint8_t *
hp_lit_indexing(uint8_t *p, unsigned int name_idx, const char *v, size_t vl)
{
	p = hp_int(p, 0x40, 6, name_idx);
	p = hp_int(p, 0, 7, (uint32_t)vl);
	memcpy(p, v, vl);

	return p + vl;
}

/* literal with incremental indexing, with a literal name */

static uint8_t *
hp_lit_indexing_name(uint8_t *p, const char *n, const char *v)
{
	size_t nl = strlen(n), vl = strlen(v);

	*p++ = 0x40;
	p = hp_int(p, 0, 7, (uint32_t)nl);
	memcpy(p, n, nl);
	p = hp_int(p + nl, 0, 7, (uint32_t)vl);
	memcpy(p, v, vl);

	return p + vl;
}

/* literal without indexing, with a literal name */

static uint8_t *
hp_lit_name(uint8_t *p, const char *n, const char *v)
{
	size_t nl = strlen(n), vl = strlen(v);

	*p++ = 0;
	p = hp_int(p, 0, 7, (uint32_t)nl);
	memcpy(p, n, nl);
	p = hp_int(p + nl, 0, 7, (uint32_t)vl);
	memcpy(p, v, vl);

	return p + vl;
}

#define HP_METHOD_GET		0x82
#define HP_METHOD_POST		0x83
#define HP_SCHEME_HTTP		0x86
#define HP_IDX_AUTHORITY	1
#define HP_IDX_PATH		4
#define HP_IDX_ACCEPT_ENCODING	0x90	/* accept-encoding: gzip, deflate */
#define HP_IDX_USER_AGENT	58
#define HP_IDX_DYN_NEWEST	62	/* the last dynamic table insert */

static uint8_t *
hp_request(uint8_t *p, uint8_t method, const char *path)
{
	*p++ = method;
	*p++ = HP_SCHEME_HTTP;
	p = hp_lit(p, HP_IDX_AUTHORITY, "localhost", 9);

	return hp_lit(p, HP_IDX_PATH, path, strlen(path));
}

static void
h2_get(struct txb *t, uint32_t sid, const char *path)
{
	uint8_t hb[512], *p = hp_request(hb, HP_METHOD_GET, path);

	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, sid, hb,
		 lws_ptr_diff_size_t(p, hb));
}

/*
 * The same GET, but with :path added to the server's dynamic table, and one
 * asking for that path again by its index there: what an encoder that
 * indexes :path sends when a request is repeated
 */

static void
h2_get_indexing(struct txb *t, uint32_t sid, const char *path)
{
	uint8_t hb[512], *p = hb;

	*p++ = HP_METHOD_GET;
	*p++ = HP_SCHEME_HTTP;
	p = hp_lit(p, HP_IDX_AUTHORITY, "localhost", 9);
	p = hp_lit_indexing(p, HP_IDX_PATH, path, strlen(path));
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, sid, hb,
		 lws_ptr_diff_size_t(p, hb));
}

static void
h2_get_indexed(struct txb *t, uint32_t sid)
{
	uint8_t hb[64], *p = hb;

	*p++ = HP_METHOD_GET;
	*p++ = HP_SCHEME_HTTP;
	p = hp_lit(p, HP_IDX_AUTHORITY, "localhost", 9);
	p = hp_int(p, 0x80, 7, HP_IDX_DYN_NEWEST);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, sid, hb,
		 lws_ptr_diff_size_t(p, hb));
}

static void
h2_preface(struct txb *t)
{
	tx_add(t, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
	h2_frame(t, H2_SETTINGS, 0, 0, NULL, 0);
}

/*
 * The h2 cases
 */

static uint32_t
b_bad_preface(struct txb *t)
{
	tx_add(t, "PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n", 24);
	h2_frame(t, H2_SETTINGS, 0, 0, NULL, 0);
	h2_get(t, 1, "/alive");

	return 1;
}

static uint32_t
b_continuation_flood(struct txb *t)
{
	uint8_t hb[512], *p = hp_request(hb, HP_METHOD_GET, "/alive"),
		one = HP_IDX_ACCEPT_ENCODING;
	int n;

	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM, 1, hb,
		 lws_ptr_diff_size_t(p, hb));
	for (n = 0; n < 1000; n++)
		h2_frame(t, H2_CONTINUATION, 0, 1, &one, 1);

	return 1;
}

static uint32_t
b_continuation_other_stream(struct txb *t)
{
	uint8_t hb[512], *p = hp_request(hb, HP_METHOD_GET, "/alive"),
		one = HP_IDX_ACCEPT_ENCODING;

	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM, 1, hb,
		 lws_ptr_diff_size_t(p, hb));
	h2_frame(t, H2_CONTINUATION, H2F_END_HEADERS, 3, &one, 1);

	return 1;
}

static uint32_t
b_ping_flood(struct txb *t)
{
	uint8_t ping[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	int n;

	h2_preface(t);
	for (n = 0; n < 10000; n++)
		h2_frame(t, H2_PING, 0, 0, ping, sizeof(ping));
	h2_get(t, 1, "/alive");

	return 1;
}

static uint32_t
b_settings_flood(struct txb *t)
{
	int n;

	h2_preface(t);
	for (n = 0; n < 10000; n++)
		h2_frame(t, H2_SETTINGS, 0, 0, NULL, 0);
	h2_get(t, 1, "/alive");

	return 1;
}

static uint32_t
b_rapid_reset(struct txb *t)
{
	uint8_t cancel[4] = { 0, 0, 0, 8 };
	uint32_t sid;

	h2_preface(t);
	for (sid = 1; sid < 2001; sid += 2) {
		h2_get(t, sid, "/alive");
		h2_frame(t, H2_RST_STREAM, 0, sid, cancel, sizeof(cancel));
	}
	h2_get(t, sid, "/alive");

	return sid;
}

static uint32_t
b_sid_goes_down(struct txb *t)
{
	h2_preface(t);
	h2_get(t, 5, "/alive");
	h2_get(t, 3, "/alive");

	return 3;
}

static uint32_t
b_even_sid(struct txb *t)
{
	h2_preface(t);
	h2_get(t, 2, "/alive");

	return 2;
}

static uint32_t
b_hpack_bad_index(struct txb *t)
{
	uint8_t hb[16], *p = hp_int(hb, 0x80, 7, 1000);

	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

static uint32_t
b_hpack_table_size(struct txb *t)
{
	uint8_t hb[512], *p = hp_int(hb, 0x20, 5, 1024 * 1024);

	p = hp_request(p, HP_METHOD_GET, "/alive");
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

static uint32_t
b_huffman_eos(struct txb *t)
{
	uint8_t hb[512], *p = hb;

	*p++ = HP_METHOD_GET;
	*p++ = HP_SCHEME_HTTP;
	p = hp_lit(p, HP_IDX_AUTHORITY, "localhost", 9);
	p = hp_int(p, 0, 4, HP_IDX_PATH);
	p = hp_int(p, 0x80, 7, 4);	/* huffman, 4 bytes: all 1s, the EOS */
	memset(p, 0xff, 4);
	p += 4;
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

static uint32_t
b_oversize_frame(struct txb *t)
{
	uint8_t hb[512], *p = hp_request(hb, HP_METHOD_POST, "/alive"),
		*d = calloc(1, 16385);

	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));
	if (d) {
		h2_frame(t, H2_DATA, H2F_END_STREAM, 1, d, 16385);
		free(d);
	}

	return 1;
}

static uint32_t
b_window_overflow(struct txb *t)
{
	uint8_t inc[4] = { 0x7f, 0xff, 0xff, 0xff };

	h2_preface(t);
	h2_frame(t, H2_WINDOW_UPDATE, 0, 0, inc, sizeof(inc));
	h2_get(t, 1, "/alive");

	return 1;
}

static uint32_t
b_window_zero(struct txb *t)
{
	uint8_t inc[4] = { 0, 0, 0, 0 };

	h2_preface(t);
	h2_frame(t, H2_WINDOW_UPDATE, 0, 0, inc, sizeof(inc));
	h2_get(t, 1, "/alive");

	return 1;
}

static uint32_t
b_data_sid0(struct txb *t)
{
	h2_preface(t);
	h2_frame(t, H2_DATA, 0, 0, "x", 1);
	h2_get(t, 1, "/alive");

	return 1;
}

static uint32_t
b_data_idle(struct txb *t)
{
	h2_preface(t);
	h2_frame(t, H2_DATA, H2F_END_STREAM, 7, "x", 1);

	return 7;
}

/* a request with one extra literal-named field */

static void
h2_get_with(struct txb *t, const char *name, const char *value)
{
	uint8_t hb[512], *p = hp_request(hb, HP_METHOD_GET, "/alive");

	p = hp_lit_name(p, name, value);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));
}

static uint32_t
b_get_smuggle(struct txb *t)
{
	h2_preface(t);
	h2_get_with(t, "get ", "/f/../secret.txt");

	return 1;
}

static uint32_t
b_uppercase_name(struct txb *t)
{
	h2_preface(t);
	h2_get_with(t, "X-Up", "a");

	return 1;
}

static uint32_t
b_crlf_value(struct txb *t)
{
	uint8_t hb[512], *p = hp_request(hb, HP_METHOD_GET, "/alive");

	p = hp_lit(p, HP_IDX_USER_AGENT, "a\r\nb: c", 7);
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

static uint32_t
b_no_path(struct txb *t)
{
	uint8_t hb[64], *p = hb;

	*p++ = HP_METHOD_GET;
	*p++ = HP_SCHEME_HTTP;
	p = hp_lit(p, HP_IDX_AUTHORITY, "localhost", 9);
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

static uint32_t
b_two_paths(struct txb *t)
{
	uint8_t hb[512], *p = hp_request(hb, HP_METHOD_GET, "/alive");

	p = hp_lit(p, HP_IDX_PATH, "/f/index.html", 13);
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

/* a pseudo-header may appear once, however it or its repeat is encoded */

static uint32_t
b_two_methods_literal(struct txb *t)
{
	uint8_t hb[512], *p = hp_request(hb, HP_METHOD_GET, "/alive");

	p = hp_lit_name(p, ":method", "POST");
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

static uint32_t
b_two_authorities_indexed(struct txb *t)
{
	uint8_t hb[512], *p = hb;

	*p++ = HP_METHOD_GET;
	*p++ = HP_SCHEME_HTTP;
	p = hp_lit_indexing(p, HP_IDX_AUTHORITY, "localhost", 9);
	p = hp_lit(p, HP_IDX_AUTHORITY, "other", 5);
	p = hp_lit(p, HP_IDX_PATH, "/alive", 6);
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

static uint32_t
b_pseudo_after_regular(struct txb *t)
{
	uint8_t hb[512], *p = hb;

	*p++ = HP_METHOD_GET;
	*p++ = HP_SCHEME_HTTP;
	p = hp_lit(p, HP_IDX_AUTHORITY, "localhost", 9);
	*p++ = HP_IDX_ACCEPT_ENCODING;
	p = hp_lit(p, HP_IDX_PATH, "/alive", 6);
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

static uint32_t
b_connection_header(struct txb *t)
{
	h2_preface(t);
	h2_get_with(t, "connection", "keep-alive");

	return 1;
}

static uint32_t
b_transfer_encoding(struct txb *t)
{
	h2_preface(t);
	h2_get_with(t, "transfer-encoding", "chunked");

	return 1;
}

static uint32_t
b_many_fields(struct txb *t)
{
	uint8_t hb[2048], *p = hp_request(hb, HP_METHOD_GET, "/alive");
	int n;

	for (n = 0; n < 1500; n++)
		*p++ = HP_IDX_ACCEPT_ENCODING;
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 1;
}

/*
 * A field sent with incremental indexing in a request too big for the ah
 * becomes a dynamic table entry lws could not keep, and a later request that
 * refers to it is refused with 431 too.  But trailers keep nothing anyway, so
 * a POST whose trailers refer to it must still be served.  Only the final
 * stream's body is kept, so the first one's 431 doesn't mix with it.
 */

static uint32_t
b_trailers_lost_entry(struct txb *t)
{
	static char v[5000];
	uint8_t hb[5200], *p = hp_request(hb, HP_METHOD_GET, "/alive"),
		tr = 0x80 | HP_IDX_DYN_NEWEST;

	memset(v, 'a', sizeof(v) - 1);
	p = hp_lit_indexing(p, HP_IDX_USER_AGENT, v, strlen(v));
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	p = hp_request(hb, HP_METHOD_POST, "/alive");
	h2_frame(t, H2_HEADERS, H2F_END_HEADERS, 3, hb,
		 lws_ptr_diff_size_t(p, hb));
	h2_frame(t, H2_DATA, 0, 3, "x", 1);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 3, &tr, 1);

	return 3;
}

/*
 * A dynamic table size update that shrinks the table.  The peer counts at
 * least 32 bytes an entry, lws counts a field it ignores as its name alone,
 * so lws can hold more entries than the peer: the ones it keeps must be the
 * newest, the ones the peer still has.  Here the peer keeps only the :path
 * of stream 3, and stream 5 asks for it again by index.
 */

static uint32_t
b_hpack_table_shrink(struct txb *t)
{
	uint8_t hb[512], *p = hp_request(hb, HP_METHOD_GET, "/alive");
	int n;

	for (n = 0; n < 30; n++)
		p = hp_lit_indexing_name(p, "x-f", "v");
	h2_preface(t);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 1, hb,
		 lws_ptr_diff_size_t(p, hb));

	h2_get_indexing(t, 3, "/alive");

	p = hp_int(hb, 0x20, 5, 64);
	*p++ = HP_METHOD_GET;
	*p++ = HP_SCHEME_HTTP;
	p = hp_lit(p, HP_IDX_AUTHORITY, "localhost", 9);
	p = hp_int(p, 0x80, 7, HP_IDX_DYN_NEWEST);
	h2_frame(t, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, 5, hb,
		 lws_ptr_diff_size_t(p, hb));

	return 5;
}

static const struct h2_attack h2_attacks[] = {
	{ "bad preface", b_bad_preface, V_NO_2XX, 0, 0 },
	{ "CONTINUATION flood", b_continuation_flood, V_GOAWAY,
	  H2_ERR_ENHANCE_YOUR_CALM, 1 },
	{ "CONTINUATION on another stream", b_continuation_other_stream,
	  V_GOAWAY, H2_ERR_PROTOCOL_ERROR, 0 },
	{ "PING flood", b_ping_flood, V_ALIVE_OR_CALM, 0, 1 },
	{ "SETTINGS flood", b_settings_flood, V_ALIVE_OR_CALM, 0, 1 },
	{ "rapid reset", b_rapid_reset, V_ALIVE_OR_CALM, 0, 1 },
	{ "stream id goes down", b_sid_goes_down, V_GOAWAY,
	  H2_ERR_PROTOCOL_ERROR, 0 },
	{ "even stream id", b_even_sid, V_GOAWAY, H2_ERR_PROTOCOL_ERROR, 0 },
	{ "hpack index past both tables", b_hpack_bad_index, V_GOAWAY,
	  H2_ERR_COMPRESSION_ERROR, 0 },
	/*
	 * RFC 7541 4.2 makes this a decoding error, but lws deliberately
	 * clamps it to the size it advertised, for interop with browsers
	 * (see lws_hpack_dynamic_size()): the table stays bounded
	 */
	{ "hpack table size over the limit (clamped)", b_hpack_table_size,
	  V_ECHO, 200, 0 },
	{ "hpack table shrunk below the entries lws holds",
	  b_hpack_table_shrink, V_ECHO, 200, 0 },
	{ "huffman EOS in :path", b_huffman_eos, V_GOAWAY,
	  H2_ERR_COMPRESSION_ERROR, 0 },
	{ "frame over SETTINGS_MAX_FRAME_SIZE", b_oversize_frame, V_GOAWAY,
	  H2_ERR_FRAME_SIZE_ERROR, 1 },
	{ "WINDOW_UPDATE past 2^31 - 1", b_window_overflow, V_GOAWAY,
	  H2_ERR_FLOW_CONTROL_ERROR, 0 },
	{ "WINDOW_UPDATE of 0", b_window_zero, V_GOAWAY,
	  H2_ERR_PROTOCOL_ERROR, 0 },
	{ "DATA on stream 0", b_data_sid0, V_GOAWAY, H2_ERR_PROTOCOL_ERROR, 0 },
	{ "DATA on an idle stream", b_data_idle, V_GOAWAY,
	  H2_ERR_PROTOCOL_ERROR, 0 },
	/* a field named "get " once smuggled an unnormalized request path */
	{ "\"get \" field smuggling a path", b_get_smuggle, V_GOAWAY,
	  H2_ERR_PROTOCOL_ERROR, 0 },
	{ "uppercase field name", b_uppercase_name, V_GOAWAY,
	  H2_ERR_PROTOCOL_ERROR, 0 },
	{ "CR LF in a field value", b_crlf_value, V_NO_2XX, 0, 0 },
	{ "no :path", b_no_path, V_NO_2XX, 0, 0 },
	{ "two :path", b_two_paths, V_NO_2XX, 0, 0 },
	{ "a second :method with a literal name", b_two_methods_literal,
	  V_GOAWAY, H2_ERR_PROTOCOL_ERROR, 0 },
	{ "a second :authority after an indexed one",
	  b_two_authorities_indexed, V_GOAWAY, H2_ERR_PROTOCOL_ERROR, 0 },
	{ "pseudo-header after a regular one", b_pseudo_after_regular,
	  V_NO_2XX, 0, 0 },
	{ "connection-specific field", b_connection_header, V_NO_2XX, 0, 0 },
	{ "transfer-encoding field", b_transfer_encoding, V_NO_2XX, 0, 0 },
	{ "1500 fields", b_many_fields, V_NO_2XX, 0, 0 },
	{ "trailers referring to an entry lws could not keep",
	  b_trailers_lost_entry, V_ECHO, 200, 0 },
};

/*
 * The server sends :status first, as lws composes it: a literal without
 * indexing with the name either indexed (8) or literal, the value three
 * plain digits.  Or an indexed :status from the static table.
 */

static int
h2_status(const uint8_t *p, size_t len)
{
	static const int idx_status[] = { 200, 204, 206, 304, 400, 404, 500 };

	if (!len)
		return -1;
	if ((p[0] & 0x80) && (p[0] & 0x7f) >= 8 && (p[0] & 0x7f) <= 14)
		return idx_status[(p[0] & 0x7f) - 8];
	if ((p[0] & 0xf0) == 0 || (p[0] & 0xf0) == 0x10) {
		if ((p[0] & 0x0f) == 8 && len >= 5 && p[1] == 3)
			return atoi((const char *)p + 2);
		if (!(p[0] & 0x0f) && len >= 13 && p[1] == 7 &&
		    !memcmp(p + 2, ":status", 7) && p[9] == 3)
			return ((p[10] - '0') * 100) + ((p[11] - '0') * 10) +
			       (p[12] - '0');
	}

	return -1;
}

static int
h2_rx(struct lws *wsi, const uint8_t *in, size_t len)
{
	static const uint8_t settings_ack[] = { 0, 0, 0, H2_SETTINGS,
						H2F_ACK, 0, 0, 0, 0 };
	uint8_t buf[LWS_PRE + sizeof(settings_ack)], *p, type, flags;
	size_t o = 0, flen;
	int acks = 0;
	uint32_t sid;

	if (cn.fr_len + len > ATK_H2_FRAME_MAX)
		return -1;
	memcpy(cn.fr + cn.fr_len, in, len);
	cn.fr_len += len;

	while (o + 9 <= cn.fr_len) {
		p = cn.fr + o;
		flen = ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2];
		type = p[3];
		flags = p[4];
		sid = lws_ser_ru32be(&p[5]) & 0x7fffffff;

		if (flen > ATK_H2_FRAME_MAX - 9)
			return -1;
		if (cn.fr_len - o < 9 + flen)
			break;
		p += 9;

		switch (type) {
		case H2_SETTINGS:
			if (!(flags & H2F_ACK))
				acks++;
			break;
		case H2_HEADERS:
			if (sid == cn.final_sid)
				cn.status = h2_status(p, flen);
			if (sid == cn.final_sid && (flags & H2F_END_STREAM))
				cn.ended = 1;
			if (cn.first_sid && sid == cn.first_sid) {
				cn.first_status = h2_status(p, flen);
				if (flags & H2F_END_STREAM)
					cn.first_ended = 1;
			}
			break;
		case H2_DATA:
			if (cn.first_sid && sid == cn.first_sid) {
				first_keep(p, flen);
				if (flags & H2F_END_STREAM)
					cn.first_ended = 1;
				break;
			}
			if (sid == cn.final_sid)
				rx_keep(p, flen);
			if (sid == cn.final_sid && (flags & H2F_END_STREAM))
				cn.ended = 1;
			break;
		case H2_RST_STREAM:
			if (sid == cn.final_sid && flen == 4) {
				cn.rst = (int)lws_ser_ru32be(p);
				cn.ended = 1;
			}
			if (cn.first_sid && sid == cn.first_sid)
				cn.first_ended = 1;
			break;
		case H2_GOAWAY:
			if (flen >= 8)
				cn.goaway = (int)lws_ser_ru32be(p + 4);
			break;
		default:
			break;
		}
		o += 9 + flen;
	}

	/* o is built from peer lengths, bound it before the memmove */
	if (o > cn.fr_len)
		return -1;
	cn.fr_len -= o;
	memmove(cn.fr, cn.fr + o, cn.fr_len);

	if ((cn.ended && (!cn.first_sid || cn.first_ended)) ||
	    cn.goaway >= 0) {
		evaluate();
		return -1;
	}

	/*
	 * Ack the server's SETTINGS only after all of what came is parsed:
	 * the server may already have reset the connection after sending
	 * a GOAWAY that's in this same read
	 */
	while (acks--) {
		memcpy(&buf[LWS_PRE], settings_ack, sizeof(settings_ack));
		if (lws_write(wsi, &buf[LWS_PRE], sizeof(settings_ack),
			      LWS_WRITE_RAW) != (int)sizeof(settings_ack))
			return -1;
	}

	return 0;
}

static int
callback_raw_h2(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (is_current(wsi)) {
			cn.failed = 1;
			cn.done = 1;
			case_done("could not connect");
		}
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		if (!is_current(wsi))
			return -1;
		return tx_more(wsi);

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!is_current(wsi))
			break;
		return tx_more(wsi);

	case LWS_CALLBACK_RAW_RX:
		if (!is_current(wsi))
			break;
		return h2_rx(wsi, (const uint8_t *)in, len);

	case LWS_CALLBACK_RAW_CLOSE:
		if (is_current(wsi))
			evaluate();
		break;

	default:
		break;
	}

	return 0;
}

/*
 * The h3 client
 */

static int
callback_h3(struct lws *wsi, enum lws_callback_reasons reason,
	    void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!is_current(wsi))
			return lws_callback_http_dummy(wsi, reason, user, in,
						       len);
		break;
	default:
		break;
	}

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
#if defined(LWS_ROLE_H3)
		/* the qpack encoders only exist in a build with the h3 role */
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (!tc.h3a)
			break;

		if (tc.h3a->static_fields) {
			unsigned int n;

			if ((size_t)lws_ptr_diff(end, *p) <
						tc.h3a->static_fields)
				return -1;
			for (n = 0; n < tc.h3a->static_fields; n++) {
				if (lws_qpack_encode_static(*p, 1, 29) != 1)
					return -1;
				(*p)++;
			}
			break;
		}

		if (!tc.h3a->hdr_name)
			break;

		if (tc.h3a->hdr_value_len) {
			int n = lws_qpack_encode_literal_with_literal_name(*p,
					lws_ptr_diff_size_t(end, *p),
					tc.h3a->hdr_name,
					tc.h3a->hdr_name_len,
					tc.h3a->hdr_value,
					tc.h3a->hdr_value_len);

			if (n < 0)
				return -1;
			*p += n;
			break;
		}

		if (lws_add_http_header_by_name(wsi,
				(const unsigned char *)tc.h3a->hdr_name,
				(const unsigned char *)tc.h3a->hdr_value,
				(int)strlen(tc.h3a->hdr_value), p, end))
			return -1;
#endif
		break;
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cn.status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		return rx_keep(in, len);

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		cn.ended = 1;
		evaluate();
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		cn.failed = 1;
		/* fallthru */
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		evaluate();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_srv, sizeof(struct pss), 0, 0, NULL, 0 },
	{ "files", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "raw-h1", callback_raw_h1, 0, 0, 0, NULL, 0 },
	{ "raw-h2", callback_raw_h2, 0, 0, 0, NULL, 0 },
	{ "h3", callback_h3, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * Running the cases
 */

static int
h1_compose(const struct h1_attack *a, const char *path)
{
	struct txb t = { NULL, 0, 0, 0 };
	uint32_t seed = 0x2545f491, n;
	size_t fl;
	uint8_t c;

	if (path) {
		/* a path case, as a plain HTTP/1.0 request */
		tx_add(&t, "GET ", 4);
		tx_add(&t, path, strlen(path));
		tx_add(&t, " HTTP/1.0\r\n\r\n", 13);
		goto out;
	}

	for (n = 0; n < a->repeat; n++)
		tx_add(&t, a->pre, a->pre_len);
	if (a->trickle)
		cn.trickle_from = t.len;
	fl = a->fill_str ? strlen(a->fill_str) : 1;
	for (n = 0; n < a->fill; n++) {
		if (a->fill_str) {
			tx_add(&t, a->fill_str, fl);
			continue;
		}
		/* xorshift: noise, but the same noise each run */
		seed ^= seed << 13;
		seed ^= seed >> 17;
		seed ^= seed << 5;
		c = (uint8_t)seed;
		tx_add(&t, &c, 1);
	}
	tx_add(&t, a->post, a->post_len);

out:
	cn.tx = t.buf;
	cn.tx_len = t.len;

	return !t.buf || t.oom;
}

static int
h2_compose(const struct h2_attack *a, const char *path)
{
	struct txb t = { NULL, 0, 0, 0 };

	if (path) {
		/*
		 * Twice on one connection: the first time the server adds
		 * the :path to its dynamic table, the second time we ask for
		 * it by its index there.  The second one decides the case,
		 * and must be answered as the first was.
		 */
		h2_preface(&t);
		h2_get_indexing(&t, 1, path);
		h2_get_indexed(&t, 3);
		cn.first_sid = 1;
		cn.final_sid = 3;
	} else
		cn.final_sid = a->build(&t);

	cn.tx = t.buf;
	cn.tx_len = t.len;
	cn.fr = malloc(ATK_H2_FRAME_MAX);

	return !t.buf || t.oom || !cn.fr;
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	/*
	 * Where the connection was: still sending means the server stopped
	 * reading, everything sent means the client never saw it end
	 */
	lwsl_err("%s: %s: timed out having sent %llu of %llu, received %llu\n",
		 xport_names[tc.xport], tc.name, (unsigned long long)cn.tx_pos,
		 (unsigned long long)cn.tx_len,
		 (unsigned long long)cn.rx_len);

	cn.done = 1;
	case_done("timed out");
}

/* pick the next case into tc, or return nonzero if there are none left */

static int
case_pick(void)
{
	for (;;) {
		if (tc.xport >= XP_COUNT)
			return 1;
		if (!(xport_mask & (1u << tc.xport)) ||
		    tc.phase == PH_NEXT_XPORT) {
			tc.xport++;
			tc.phase = PH_PATHS;
			tc.idx = -1;
			continue;
		}

		tc.idx++;
		tc.path = NULL;
		tc.h1a = NULL;
		tc.h2a = NULL;
		tc.h3a = NULL;
		tc.lossy = 0;

		if (tc.phase == PH_PATHS) {
			const struct path_case *pc;

			/* h1 over tls parses paths as h1 does */
			if (tc.xport == XP_H1S ||
			    tc.idx >= (int)LWS_ARRAY_SIZE(path_cases)) {
				tc.phase = PH_ATTACKS;
				tc.idx = -1;
				continue;
			}
			pc = &path_cases[tc.idx];
			/*
			 * The h3 client sends a path starting // with one
			 * of the /s taken off, so it can't send those
			 */
			if (tc.xport == XP_H3 && pc->path[0] == '/' &&
			    pc->path[1] == '/')
				continue;
			tc.path = pc->path;
			tc.v = pc->v;
			tc.status = pc->status;
			tc.expect = pc->expect;
			lws_snprintf(tc.name, sizeof(tc.name), "path '%s'",
				     pc->path);
			if (only && !strstr(tc.name, only))
				continue;
			return 0;
		}

		switch (tc.xport) {
		case XP_H1S:
			/* over tls, the cases about the request head deadline */
			if (tc.idx < (int)LWS_ARRAY_SIZE(h1_attacks) &&
			    h1_attacks[tc.idx].v != V_DROPPED)
				continue;
			/* fallthru */
		case XP_H1:
			if (tc.idx >= (int)LWS_ARRAY_SIZE(h1_attacks))
				break;
			tc.h1a = &h1_attacks[tc.idx];
			tc.v = tc.h1a->v;
			tc.status = tc.h1a->status;
			tc.expect = tc.h1a->expect;
			lws_strncpy(tc.name, tc.h1a->name, sizeof(tc.name));
			if (only && !strstr(tc.name, only))
				continue;
			return 0;
		case XP_H2:
			if (tc.idx >= (int)LWS_ARRAY_SIZE(h2_attacks))
				break;
			tc.h2a = &h2_attacks[tc.idx];
			tc.v = tc.h2a->v;
			tc.status = tc.h2a->status;
			tc.expect = "/alive";	/* what the cases ask for */
			tc.lossy = tc.h2a->lossy;
			lws_strncpy(tc.name, tc.h2a->name, sizeof(tc.name));
			if (only && !strstr(tc.name, only))
				continue;
			return 0;
		default:
			if (tc.idx >= (int)LWS_ARRAY_SIZE(h3_attacks))
				break;
			tc.h3a = &h3_attacks[tc.idx];
			tc.path = tc.h3a->path;
			tc.v = tc.h3a->v;
			tc.status = 0;
			tc.expect = NULL;
			lws_strncpy(tc.name, tc.h3a->name, sizeof(tc.name));
			if (only && !strstr(tc.name, only))
				continue;
			return 0;
		}
		tc.phase = PH_NEXT_XPORT;
	}
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	int n;

	free(cn.tx);
	free(cn.fr);
	memset(&cn, 0, sizeof(cn));
	cn.goaway = -1;
	cn.rst = -1;

	if (tc.probe_next) {
		tc.probe_next = 0;
		tc.h1a = NULL;
		tc.h2a = NULL;
		tc.h3a = NULL;
		tc.path = "/alive";
		tc.v = V_ECHO;
		tc.status = 200;
		tc.expect = "/alive";
		tc.lossy = 0;
		n = (int)strlen(tc.name);
		lws_snprintf(tc.name + n, sizeof(tc.name) - (size_t)n,
			     ", then /alive");
	} else if (case_pick()) {
		lwsl_user("--- %d failed ---\n", fails);
		lws_default_loop_exit(context);
		return;
	}
	cn.seq = ++tc.seq;
	cn.start = lws_now_usecs();

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.opaque_user_data	= (void *)(intptr_t)tc.seq;

	switch (tc.xport) {
	case XP_H1:
		if (h1_compose(tc.h1a, tc.path))
			goto oom;
		i.port = port_h1;
		i.method = "RAW";
		i.local_protocol_name = "raw-h1";
		break;
	case XP_H2:
		if (h2_compose(tc.h2a, tc.path))
			goto oom;
		i.port = port_h2;
		i.method = "RAW";
		i.local_protocol_name = "raw-h2";
		break;
	case XP_H1S:
		if (h1_compose(tc.h1a, tc.path))
			goto oom;
		i.port = port_h1s;
		i.method = "RAW";
		i.local_protocol_name = "raw-h1";
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
	default:
		i.port = port_h3;
		i.path = tc.path;
		i.method = "GET";
		i.alpn = "h3";
		i.protocol = "h3";
		i.local_protocol_name = "h3";
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 ATK_CASE_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		cn.done = 1;
		case_done("connect failed");
	}

	return;

oom:
	cn.done = 1;
	case_done("OOM");
}

#if defined(LWS_WITH_TLS)
/* a self-signed test cert does for the h3 and h1s servers */

static const char * const test_cert =
"-----BEGIN CERTIFICATE-----\n"
"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\n"
"e2Hl/7M0c/lbZ4FvXgARlex2rkgS0Ka06HE=\n"
"-----END CERTIFICATE-----\n";

static const char * const test_key =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"fBrpEY1IATtPq1taBZZogRqI3rOkkPk=\n"
"-----END PRIVATE KEY-----\n";
#endif

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* several listeners and connections: see lws_context_info_defaults() */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2-port")))
		port_h2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h3-port")))
		port_h3 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h1s-port")))
		port_h1s = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	only = lws_cmdline_option(argc, argv, "--only");
	if ((p = lws_cmdline_option(argc, argv, "--transport"))) {
		xport_mask = 0;
		for (n = 0; n < XP_COUNT; n++)
			if (!strcmp(p, xport_names[n]))
				xport_mask = 1u << n;
		if (!xport_mask) {
			lwsl_err("unknown transport %s\n", p);
			return 1;
		}
#if !defined(LWS_WITH_HTTP2)
		if (xport_mask & (1u << XP_H2)) {
			lwsl_err("h2 not in this build\n");
			return 1;
		}
#endif
#if !defined(LWS_ROLE_H3)
		if (xport_mask & (1u << XP_H3)) {
			lwsl_err("h3 not in this build\n");
			return 1;
		}
#endif
#if !defined(LWS_WITH_TLS)
		if (xport_mask & (1u << XP_H1S)) {
			lwsl_err("tls not in this build\n");
			return 1;
		}
#endif
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: hostile requests are refused\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
#if defined(LWS_WITH_TLS)
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif

	info.timeout_secs = ATK_TIMEOUT_SECS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.protocols = protocols_srv;
	info.mounts = &mount_f;
	info.timeout_secs_ah_idle = ATK_AH_IDLE_SECS;

	if (xport_mask & (1u << XP_H1)) {
		info.port = port_h1;
		info.vhost_name = "srv-h1";
		if (!lws_create_vhost(context, &info))
			goto bail;
	}

#if defined(LWS_WITH_HTTP2)
	if (xport_mask & (1u << XP_H2)) {
		info.port = port_h2;
		info.vhost_name = "srv-h2";
		info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
		if (!lws_create_vhost(context, &info))
			goto bail;
		info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	}
#endif

#if defined(LWS_WITH_TLS)
	if (xport_mask & (1u << XP_H1S)) {
		/* the same server, on h1 over tls */
		info.port = port_h1s;
		info.vhost_name = "srv-h1s";
		info.server_ssl_cert_mem = test_cert;
		info.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
		info.server_ssl_private_key_mem = test_key;
		info.server_ssl_private_key_mem_len =
					(unsigned int)strlen(test_key);
		info.alpn = "http/1.1";
		if (!lws_create_vhost(context, &info))
			goto bail;
		info.alpn = NULL;
		info.server_ssl_cert_mem = NULL;
		info.server_ssl_cert_mem_len = 0;
		info.server_ssl_private_key_mem = NULL;
		info.server_ssl_private_key_mem_len = 0;
	}
#endif

#if defined(LWS_ROLE_H3)
	if (xport_mask & (1u << XP_H3)) {
		struct lws_vhost *vh;

		info.server_ssl_cert_mem = test_cert;
		info.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
		info.server_ssl_private_key_mem = test_key;
		info.server_ssl_private_key_mem_len =
					(unsigned int)strlen(test_key);

		/* a quic listener on udp only */
		info.port = CONTEXT_PORT_NO_LISTEN_SERVER;
		info.vhost_name = "srv-h3";
		info.listen_accept_role = "quic";
		info.listen_accept_protocol = "http";
		info.alpn = "h3";
		vh = lws_create_vhost(context, &info);
		if (!vh || !lws_create_adopt_udp(vh, server_addr, port_h3,
					LWS_CAUDP_BIND, "http", NULL, NULL,
					NULL, NULL, "quic_listen"))
			goto bail;
		info.listen_accept_role = NULL;
		info.listen_accept_protocol = NULL;
		info.alpn = NULL;
		info.server_ssl_cert_mem = NULL;
		info.server_ssl_cert_mem_len = 0;
		info.server_ssl_private_key_mem = NULL;
		info.server_ssl_private_key_mem_len = 0;
	}
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.mounts = NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	n = 0;
	while (n >= 0)
		n = lws_service(context, 0);

bail:
	if (!tc.seq) {
		lwsl_err("--- setup failed ---\n");
		fails++;
	}
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_trickle);
	free(cn.tx);
	free(cn.fr);
	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
