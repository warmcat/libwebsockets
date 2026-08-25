/*
 * lws-minimal-webtransport-qir
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * WebTransport Interop Runner shim implementation.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#if defined(_WIN32)
#include <io.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
static void usleep(unsigned long l) { Sleep(l / 1000); }
/* windows has no unlink(); ISO remove() is the same thing for files */
#define qir_unlink(path) remove(path)
#else
#include <unistd.h>
#define qir_unlink(path) unlink(path)
#endif
#include <sys/stat.h>
#include <errno.h>



static int interrupted;
static int is_server;
static char testcase[64] = "";
static struct lws_context *context;
static struct lws *first_session_wsi;
static char global_endpoint[128] = "";



struct request_item {
	char url[512];
	char host[128];
	int port;
	char endpoint[128];
	char filename[128];
	struct lws *session_wsi;
	struct dgr_rx *dgr;		/* datagram rx state, NULL when done */
	int started;
	int completed;
};

static struct request_item client_requests[256];
static int client_requests_count;

struct server_request_item {
	char endpoint[128];
	char filename[128];
	struct dgr_rx *dgr;		/* datagram rx state, NULL when done */
	int started;
	int completed;
};

static struct server_request_item server_requests[256];
static int server_requests_count;

/*
 * ---------------------------------------------------------------------------
 * Datagram file transfer exchange
 * ---------------------------------------------------------------------------
 *
 * Testcase names containing "datagram" move the files over WebTransport
 * session datagrams.  QUIC datagrams are unreliable and unordered, so the
 * exchange is a receiver-driven, resumable protocol:
 *
 *   GET <name>\n                 rx -> tx: (re)request a file
 *   HDR <name> <len>\n           tx -> rx: announce the file length
 *   CH <name> <idx>\n<data>      tx -> rx: file chunk idx (0-based)
 *   MISS <name> <a>-<b>[,..]\n   rx -> tx: re-request missing chunk ranges
 *   OK <name>\n                  rx -> tx: file fully received
 *   DONE                         rx -> tx: all files received
 *
 * Chunks are self-describing (filename + index), so reassembly does not
 * depend on datagram ordering and duplicates are idempotent.  Completion
 * is receiver-side only: when every chunk of the advertised length has
 * arrived, the .part file is atomically renamed into place and OK is
 * sent.  Final paths therefore only ever hold complete files; an
 * unfinished transfer leaves the file missing, never truncated.
 *
 * The side whose testcase name contains "datagram" (the server for
 * -send, the client for -receive) is the receiver / GET initiator, so
 * it owns recovery: it re-requests anything incomplete until everything
 * has arrived, then confirms completion to the peer with a few DONE
 * datagrams so it can stop waiting without guessing.  The responder
 * only ever answers GETs and MISSes: it has no way to know what has
 * arrived at the peer, so it must not originate DONE or it would
 * truncate the exchange while files are still in flight.  A hard cap
 * keeps a stuck exchange inside the runner's own timeout.
 *
 * The runner only passes the full testcase name to the initiator's
 * container: for -send, the client container is told just "transfer",
 * with a bare endpoint URL in REQUESTS.  The responder therefore cannot
 * know from its environment that its session carries the datagram
 * exchange; it recognizes the exchange from the arriving protocol
 * datagrams instead (see dg_peer_exchange) and leaves unrelated
 * datagrams alone, so the stream transfer testcases are unaffected.
 */

/* file data bytes per CH datagram */
#define DGR_CHUNK		1024
/*
 * Datagrams must fit inside a single QUIC packet.  At the smallest MTU
 * we use (1280), ops-quic leaves ~1180 bytes for a DATAGRAM frame
 * payload; DATAGRAM frames cannot be fragmented, and lws silently wedges
 * one that can never fit, so every composed datagram is kept under this.
 */
#define DGR_MAX_DGRAM		1180
#define DGR_NAME_LEN		128	/* max filename on the wire */
#define DGR_RETRY_MS		400	/* GET / MISS retry tick */
#define DGR_DONE_COPIES		3	/* DONE copies so one survives */
#define DGR_HARDCAP_MS		20000	/* give up inside the runner timeout */
/*
 * Egress is paced under the sim's bottleneck (10Mbps) so its 25-packet
 * queue never overflows: datagrams get no retransmit, so loss here just
 * means waiting for the next MISS round.  Control datagrams are tiny and
 * coalesce into few packets, so they get a larger frame budget.
 */
#define DGR_PACE_US		20000	/* sender pace tick */
#define DGR_DATA_BURST		8	/* CH datagrams per pace tick */
#define DGR_CTL_BURST		32	/* control datagrams per pace tick */
#define DGR_RANGES_PER_MISS	64	/* range entries packed per MISS */
#define DGR_MISS_PER_TICK	4	/* MISS datagrams per file per tick */
#define DGR_CTL_RING		512	/* control ring entries */
#define DGR_RESEND_RING		1024	/* resend ring entries */

/*
 * True if this testcase uses the session datagram exchange at all.
 * The stream transfer testcases (transfer-unidirectional-{send,receive},
 * transfer-bidirectional-{send,receive}, ...) move the files over
 * WebTransport streams; only testcase names containing "datagram" use
 * datagrams.
 */
static int dg_testcase(void)
{
	return strstr(testcase, "datagram") != NULL;
}

/*
 * True if we are the GET initiator for a datagram testcase, ie, the
 * receiver of the files: the client for -receive and the server for
 * -send.  A mere "-send" / "-receive" in the testcase name is not
 * enough to match: the stream transfer testcases contain them too, and
 * if they matched, the unreliable datagram retry exchange would run
 * alongside the streams and its lossy re-sends would truncate files
 * the streams had already written complete to the same paths.
 */
static int dg_am_initiator(void)
{
	return dg_testcase() &&
	       ((strstr(testcase, "-receive") && !is_server) ||
	        (strstr(testcase, "-send") && is_server));
}

enum {
	DGR_CTL_GET,
	DGR_CTL_HDR,
	DGR_CTL_MISS,
	DGR_CTL_OK,
	DGR_CTL_DONE,
};

/* control datagram waiting to go out */
struct dgr_ctl {
	uint8_t kind;
	char name[DGR_NAME_LEN];
	uint32_t a, b;			/* MISS: chunk range; HDR: length */
};

/* sender-side per-file state */
struct dgr_tx {
	struct lws_dll2 list;
	char name[DGR_NAME_LEN];
	char srcpath[512];		/* /www<endpoint>/<name> */
	int fd;				/* -1 when closed after OK */
	size_t len;
	uint32_t chunks;
	uint32_t cursor;		/* next unsent chunk of first pass */
	int done;			/* peer sent OK */
};

/* receiver-side per-file state */
struct dgr_rx {
	char name[DGR_NAME_LEN];
	char partpath[512];		/* .part file being assembled */
	char finalpath[512];
	int fd;
	size_t len;
	uint32_t chunks;
	uint32_t got;			/* chunks received so far */
	uint8_t *bm;			/* per-chunk received bitmap */
	int req_index;			/* index into our request list */
};

static struct lws *dg_session_wsi;
static struct lws_sorted_usec_list sul_dgretry;
static struct lws_sorted_usec_list sul_dghardcap;
static struct lws_sorted_usec_list sul_dgpace;
static int dg_done_started;
static int dg_done_pumps;
static int dg_retry_armed;
static int dg_hardcap_armed;
static int dg_pace_armed;
/*
 * Set when a protocol datagram arrives on a session whose local testcase
 * name does not itself say "datagram".  The runner tells the responder of
 * the -send testcases (the client) just "transfer", so over there the
 * exchange can only be recognized from the wire.  Until then, datagrams
 * are treated as unrelated and ignored, as the stream transfer testcases
 * require.
 */
static int dg_peer_exchange;

static struct dgr_ctl dg_ctl[DGR_CTL_RING];
static int dg_ctl_head, dg_ctl_tail;

static struct dgr_resend {
	struct dgr_tx *tf;
	uint32_t idx;
} dg_resend[DGR_RESEND_RING];
static int dg_resend_head, dg_resend_tail;

static lws_dll2_owner_t dg_tx_owner;

static void dgr_kick(void);
static void dgr_repace(void);

/*
 * Test hook for local validation of the recovery paths: when set (0-99),
 * a pseudorandom sample of incoming session datagrams is dropped before
 * parsing, emulating the sim's loss without the sim.
 */
static int dg_dbg_drop_pct;
static uint32_t dg_dbg_rng = 0x12345678;

static uint32_t dg_dbg_rand(void)
{
	dg_dbg_rng ^= dg_dbg_rng << 13;
	dg_dbg_rng ^= dg_dbg_rng >> 17;
	dg_dbg_rng ^= dg_dbg_rng << 5;

	return dg_dbg_rng;
}

static void dgr_bm_set(uint8_t *bm, uint32_t idx)
{
	bm[idx >> 3] |= (uint8_t)(1u << (idx & 7));
}

static int dgr_bm_get(const uint8_t *bm, uint32_t idx)
{
	return (bm[idx >> 3] >> (idx & 7)) & 1;
}

/*
 * Wire filenames are constrained so they can never carry a path
 * component or break the header parsing.
 */
static int dgr_name_ok(const char *name)
{
	size_t n = strlen(name), i;

	if (!n || n >= DGR_NAME_LEN)
		return 0;

	for (i = 0; i < n; i++)
		if (name[i] == '/' || name[i] == ' ' || name[i] == '\n' ||
		    name[i] == '\r')
			return 0;

	return 1;
}

/* bounded decimal parse of a NUL-terminated token, no libc locale edges */
static int dgr_parse_u32(const char **pp, uint32_t *res)
{
	const char *p = *pp;
	uint32_t v = 0;
	int any = 0;

	while (*p >= '0' && *p <= '9') {
		if (v > (0xffffffffu - (uint32_t)(*p - '0')) / 10u)
			return 0;	/* overflow */
		v = (v * 10u) + (uint32_t)(*p - '0');
		p++;
		any = 1;
	}
	if (!any)
		return 0;

	*pp = p;
	*res = v;

	return 1;
}

/*
 * True if a datagram's header line opens one of our exchange protocol
 * messages.  This is how a session whose testcase name does not say
 * "datagram" recognizes that the peer has started a datagram exchange,
 * without actioning unrelated datagrams on the stream testcases.
 */
static int dgr_hdr_is_ctl(const char *hdr)
{
	return !strncmp(hdr, "GET ", 4) ||
	       !strncmp(hdr, "HDR ", 4) ||
	       !strncmp(hdr, "MISS ", 5) ||
	       !strncmp(hdr, "OK ", 3) ||
	       !strncmp(hdr, "CH ", 3) ||
	       !strcmp(hdr, "DONE");
}

static void dgr_ctl_enqueue(int kind, const char *name, uint32_t a, uint32_t b)
{
	struct dgr_ctl *e;

	if ((dg_ctl_tail + 1) % DGR_CTL_RING == dg_ctl_head) {
		lwsl_err("Datagram ctl ring overflow (kind %d)\n", kind);
		return;
	}

	e = &dg_ctl[dg_ctl_tail];
	memset(e, 0, sizeof(*e));
	e->kind = (uint8_t)kind;
	if (name)
		lws_strncpy(e->name, name, sizeof(e->name));
	e->a = a;
	e->b = b;
	dg_ctl_tail = (dg_ctl_tail + 1) % DGR_CTL_RING;
}

static void dgr_ctl_dequeue(void)
{
	if (dg_ctl_head == dg_ctl_tail)
		return;
	dg_ctl_head = (dg_ctl_head + 1) % DGR_CTL_RING;
}

static void dgr_resend_enqueue(struct dgr_tx *tf, uint32_t idx)
{
	if ((dg_resend_tail + 1) % DGR_RESEND_RING == dg_resend_head) {
		lwsl_err("Datagram resend ring overflow\n");
		return;
	}
	dg_resend[dg_resend_tail].tf = tf;
	dg_resend[dg_resend_tail].idx = idx;
	dg_resend_tail = (dg_resend_tail + 1) % DGR_RESEND_RING;
}

struct pss_qir {
	struct lws *wsi;
	int is_session;
	char endpoint[128];

	/* For child streams */
	int is_unidi;
	int is_initiator; /* 1 if we sent GET, 0 if we received GET */
	char filename[256];
	int request_index;

	/* Send state */
	int fd_in;
	size_t file_len;
	size_t sent_len;
	int header_sent;

	/* Receive state */
	int fd_out;
	char out_part[512];		/* .part path being assembled */
	char out_final[512];		/* path published on completion */
	char push_hdr[512];
	size_t push_hdr_len;
	size_t push_hdr_read;
	int push_hdr_done;
	int initialized;
	int write_completed;
};

static void init_pss(struct pss_qir *pss)
{
	if (pss && !pss->initialized) {
		pss->fd_in = -1;
		pss->fd_out = -1;
		pss->request_index = -1;
		pss->write_completed = 0;
		pss->initialized = 1;
	}
}

static int pss_is_file_sender(struct pss_qir *pss)
{
	int local_is_sender = (strstr(testcase, "-receive") && is_server) ||
			      (strstr(testcase, "-send") && !is_server) ||
			      (strcmp(testcase, "transfer") == 0 && (is_server || !client_requests_count || client_requests[0].filename[0] == '\0'));
	if (pss->is_unidi)
		return local_is_sender && !pss->is_initiator;
	return local_is_sender;
}

static int pss_is_file_receiver(struct pss_qir *pss)
{
	int local_is_receiver = (strstr(testcase, "-receive") && !is_server) ||
				(strstr(testcase, "-send") && is_server) ||
				(strcmp(testcase, "transfer") == 0 && !is_server && client_requests_count && client_requests[0].filename[0] != '\0');
	if (pss->is_unidi)
		return local_is_receiver && !pss->is_initiator;
	return local_is_receiver;
}

#if defined(LWS_WITH_CUSTOM_HEADERS)
static void print_custom_header_cb(const char *name, int nlen, void *custom)
{
	struct lws *wsi = (struct lws *)custom;
	char val[128];
	int vl = lws_hdr_custom_copy(wsi, val, sizeof(val) - 1, name, nlen);
	if (vl >= 0) {
		val[vl] = '\0';
		lwsl_user("  Custom Header: %.*s = %s\n", nlen, name, val);
	}
}
#endif


static void sigint_handler(int sig)
{
	interrupted = 1;
}
static void trim_trailing_whitespace(char *str)
{
	size_t len = strlen(str);
	while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\r' || str[len - 1] == '\n' || str[len - 1] == '\t')) {
		str[len - 1] = '\0';
		len--;
	}
}

static int parse_client_requests(void)
{
	const char *reqs = getenv("REQUESTS_CLIENT");
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	char token[512];

	if (!reqs)
		reqs = getenv("REQUESTS");
	if (!reqs)
		return 0;

	lws_tokenize_init(&ts, reqs, LWS_TOKENIZE_F_MINUS_NONTERM |
				      LWS_TOKENIZE_F_SLASH_NONTERM |
				      LWS_TOKENIZE_F_DOT_NONTERM |
				      LWS_TOKENIZE_F_COLON_NONTERM |
				      LWS_TOKENIZE_F_NO_INTEGERS |
				      LWS_TOKENIZE_F_NO_FLOATS);

	while ((e = lws_tokenize(&ts)) > 0) {
		if (e != LWS_TOKZE_TOKEN)
			continue;

		if (lws_tokenize_cstr(&ts, token, sizeof(token))) {
			lwsl_err("Client request URL too long\n");
			continue;
		}

		struct request_item *item = &client_requests[client_requests_count];
		lws_strncpy(item->url, token, sizeof(item->url));
		trim_trailing_whitespace(item->url);

		/* Parse URL: https://<host>:<port>/<endpoint>/<filename> */
		char *p = item->url;
		if (strncmp(p, "https://", 8) == 0)
			p += 8;

		char *host_start = p;
		char *slash = strchr(p, '/');
		if (!slash)
			continue;

		*slash = '\0';
		char *port_colon = strchr(host_start, ':');
		if (port_colon) {
			*port_colon = '\0';
			item->port = atoi(port_colon + 1);
		} else {
			item->port = 443;
		}
		lws_strncpy(item->host, host_start, sizeof(item->host));
		*slash = '/';

		p = slash + 1;
		char *next_slash = strchr(p, '/');
		if (next_slash) {
			*next_slash = '\0';
			lws_snprintf(item->endpoint, sizeof(item->endpoint), "/%s", p);
			*next_slash = '/';
			lws_strncpy(item->filename, next_slash + 1, sizeof(item->filename));
			trim_trailing_whitespace(item->filename);
		} else {
			lws_snprintf(item->endpoint, sizeof(item->endpoint), "/%s", p);
			item->filename[0] = '\0';
		}

		client_requests_count++;
		if (client_requests_count >= (int)LWS_ARRAY_SIZE(client_requests))
			break;
	}

	/* If we are the client and acting as the sender, we also need to parse files from REQUESTS_SERVER */
	const char *sreqs = getenv("REQUESTS_SERVER");
	if (sreqs && client_requests_count == 1 && client_requests[0].filename[0] == '\0') {
		struct lws_tokenize sts;
		lws_tokenize_elem se;
		char stoken[256];
		int first = 1;

		lws_tokenize_init(&sts, sreqs, LWS_TOKENIZE_F_MINUS_NONTERM |
					       LWS_TOKENIZE_F_SLASH_NONTERM |
					       LWS_TOKENIZE_F_DOT_NONTERM |
					       LWS_TOKENIZE_F_NO_INTEGERS |
					       LWS_TOKENIZE_F_NO_FLOATS);

		while ((se = lws_tokenize(&sts)) > 0) {
			if (se != LWS_TOKZE_TOKEN)
				continue;

			if (lws_tokenize_cstr(&sts, stoken, sizeof(stoken)))
				continue;

			/* format: <endpoint>/<filename> */
			char *slash = strchr(stoken, '/');
			if (!slash)
				continue;

			*slash = '\0';
			char filename[256];
			lws_strncpy(filename, slash + 1, sizeof(filename));
			trim_trailing_whitespace(filename);
			*slash = '/';

			if (first) {
				lws_strncpy(client_requests[0].filename, filename, sizeof(client_requests[0].filename));
				first = 0;
			} else {
				struct request_item *item = &client_requests[client_requests_count];
				item->port = client_requests[0].port;
				lws_strncpy(item->host, client_requests[0].host, sizeof(item->host));
				lws_strncpy(item->endpoint, client_requests[0].endpoint, sizeof(item->endpoint));
				lws_strncpy(item->filename, filename, sizeof(item->filename));
				client_requests_count++;
				if (client_requests_count >= (int)LWS_ARRAY_SIZE(client_requests))
					break;
			}
		}
	}

	return client_requests_count;
}

static int parse_server_requests(void)
{
	const char *reqs = getenv("REQUESTS_SERVER");
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	char token[256];

	if (!reqs)
		reqs = getenv("REQUESTS");
	if (!reqs)
		return 0;

	lws_tokenize_init(&ts, reqs, LWS_TOKENIZE_F_MINUS_NONTERM |
				      LWS_TOKENIZE_F_SLASH_NONTERM |
				      LWS_TOKENIZE_F_DOT_NONTERM |
				      LWS_TOKENIZE_F_NO_INTEGERS |
				      LWS_TOKENIZE_F_NO_FLOATS);

	while ((e = lws_tokenize(&ts)) > 0) {
		if (e != LWS_TOKZE_TOKEN)
			continue;

		if (lws_tokenize_cstr(&ts, token, sizeof(token)))
			continue;

		struct server_request_item *item = &server_requests[server_requests_count];

		/* format: <endpoint>/<filename> */
		char *slash = strchr(token, '/');
		if (!slash)
			continue;

		*slash = '\0';
		lws_snprintf(item->endpoint, sizeof(item->endpoint), "/%s", token);
		*slash = '/';
		lws_strncpy(item->filename, slash + 1, sizeof(item->filename));
		trim_trailing_whitespace(item->filename);

		server_requests_count++;
		if (server_requests_count >= (int)LWS_ARRAY_SIZE(server_requests))
			break;
	}

	return server_requests_count;
}

static void
dghardcap_sul_cb(struct lws_sorted_usec_list *sul)
{
	(void)sul;

	if (!interrupted) {
		lwsl_user("Datagram exchange hard cap reached, giving up\n");
		interrupted = 1;
	}
}

/*
 * Runs on the GET initiator only.  Each tick, anything not yet complete
 * is progressed: files with no state yet get a fresh GET, files with
 * holes in their chunk bitmap get MISS datagrams covering the missing
 * ranges.  When everything has arrived, a few DONE copies are pumped so
 * at least one survives, then we exit.
 */
static void
dgretry_sul_cb(struct lws_sorted_usec_list *sul)
{
	int i, all_done = 1, count = is_server ? server_requests_count
					       : client_requests_count;

	(void)sul;

	/* only the GET initiator owns recovery and may originate DONE */
	if (!dg_am_initiator())
		return;

	if (!dg_session_wsi) {
		/* keep waiting for the session to exist */
		lws_sul_schedule(context, 0, &sul_dgretry, dgretry_sul_cb,
				 DGR_RETRY_MS * LWS_US_PER_MS);
		return;
	}

	for (i = 0; i < count; i++) {
		struct dgr_rx *rx = is_server ? server_requests[i].dgr
					      : client_requests[i].dgr;
		int completed = is_server ? server_requests[i].completed
					  : client_requests[i].completed;
		const char *name = is_server ? server_requests[i].filename
					     : client_requests[i].filename;
		uint32_t j, a;
		int miss = 0, in_run = 0;

		if (completed)
			continue;

		all_done = 0;

		if (!rx) {
			/* no HDR yet: (re)request the whole file */
			dgr_ctl_enqueue(DGR_CTL_GET, name, 0, 0);
			continue;
		}

		/*
		 * Scan the bitmap for runs of missing chunks and ask for
		 * them, up to DGR_MISS_PER_TICK datagrams; the rest are
		 * covered by later ticks as the early ranges fill in.
		 */
		for (j = 0; j <= rx->chunks; j++) {
			int miss_bit = j < rx->chunks &&
				       !dgr_bm_get(rx->bm, j);

			if (miss_bit && !in_run) {
				in_run = 1;
				a = j;
			} else if (!miss_bit && in_run) {
				in_run = 0;
				if (miss < DGR_MISS_PER_TICK) {
					dgr_ctl_enqueue(DGR_CTL_MISS, name,
							a, j - 1);
					miss++;
				}
			}
		}
	}

	if (all_done) {
		/*
		 * Pump a few DONE copies so at least one survives, then
		 * exit.  For -send this releases the sender side, which
		 * cannot otherwise know its chunks all arrived; for
		 * -receive it lets it exit promptly instead of waiting for
		 * the hard cap when our own CONNECTION_CLOSE datagram is
		 * lost.
		 */
		if (!dg_done_started) {
			dg_done_started = 1;
			dg_done_pumps = DGR_DONE_COPIES;
		}
		if (dg_done_pumps-- > 0) {
			dgr_ctl_enqueue(DGR_CTL_DONE, NULL, 0, 0);
			dgr_kick();
			lws_sul_schedule(context, 0, &sul_dgretry,
					 dgretry_sul_cb,
					 DGR_RETRY_MS * LWS_US_PER_MS);
			return;
		}
		lwsl_user("All datagram transfers confirmed complete\n");
		interrupted = 1;
		return;
	}

	dgr_kick();
	lws_sul_schedule(context, 0, &sul_dgretry, dgretry_sul_cb,
			 DGR_RETRY_MS * LWS_US_PER_MS);
}

/*
 * Idempotent.  On the initiator (testcase name contains "datagram") this
 * starts re-request recovery; on the responder it only arms the hard cap,
 * lazily, when the first datagram arrives and we learn this is a datagram
 * exchange at all.
 */
static void
start_datagram_recovery(void)
{
	/*
	 * There is no datagram exchange to recover or cap unless this is a
	 * datagram testcase.  In particular the hard cap must not apply to
	 * the stream transfer testcases: their reliable transfers may
	 * legitimately still be in flight at 20s on a slow, lossy sim.
	 *
	 * A wire-recognized exchange (dg_peer_exchange) counts too: our
	 * testcase name may just say "transfer" although the peer is really
	 * running the datagram protocol with us.
	 */
	if (!context || (!dg_testcase() && !dg_peer_exchange))
		return;

	if (dg_am_initiator() && !dg_retry_armed) {
		dg_retry_armed = 1;
		lws_sul_schedule(context, 0, &sul_dgretry, dgretry_sul_cb,
				 DGR_RETRY_MS * LWS_US_PER_MS);
	}

	if (!dg_hardcap_armed) {
		dg_hardcap_armed = 1;
		lws_sul_schedule(context, 0, &sul_dghardcap, dghardcap_sul_cb,
				 DGR_HARDCAP_MS * LWS_US_PER_MS);
	}
}

/* --------------------------------------------------------------------
 * datagram exchange engine
 */

/*
 * Find our request-list entry for a filename.  Returns 1 and fills the
 * out params on success.
 */
static int
dgr_lookup_request(const char *name, int *idx, const char **endpoint,
		   int *completed, struct dgr_rx **prx)
{
	int i;

	if (is_server) {
		for (i = 0; i < server_requests_count; i++)
			if (!strcmp(server_requests[i].filename, name)) {
				*idx = i;
				*endpoint = server_requests[i].endpoint;
				*completed = server_requests[i].completed;
				*prx = server_requests[i].dgr;
				return 1;
			}
	} else {
		for (i = 0; i < client_requests_count; i++)
			if (!strcmp(client_requests[i].filename, name)) {
				*idx = i;
				*endpoint = client_requests[i].endpoint;
				*completed = client_requests[i].completed;
				*prx = client_requests[i].dgr;
				return 1;
			}
	}

	return 0;
}

static struct dgr_tx *
dgr_tx_find(const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
				 lws_dll2_get_head(&dg_tx_owner)) {
		struct dgr_tx *tf = lws_container_of(d, struct dgr_tx, list);

		if (!strcmp(tf->name, name))
			return tf;
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * Create sender state for a file, queue its HDR and start it at the
 * tail of the send FIFO.  Returns NULL if it cannot be served.
 */
static struct dgr_tx *
dgr_tx_create(const char *name)
{
	struct dgr_tx *tf, *found;
	char srcpath[512];
	struct stat st;
	int fd;

	if (!dgr_name_ok(name))
		return NULL;

	found = dgr_tx_find(name);
	if (found)
		return found;

	lws_snprintf(srcpath, sizeof(srcpath), "/www%s/%s",
		     global_endpoint[0] ? global_endpoint : "", name);

	fd = open(srcpath, O_RDONLY);
	if (fd < 0) {
		lwsl_info("Datagram sender cannot open %s\n", srcpath);
		return NULL;
	}
	if (fstat(fd, &st) || st.st_size < 0 ||
	    (uint64_t)st.st_size > 0x8000000ull /* 128MB sanity cap */) {
		close(fd);
		return NULL;
	}

	tf = calloc(1, sizeof(*tf));
	if (!tf) {
		close(fd);
		return NULL;
	}

	lws_strncpy(tf->name, name, sizeof(tf->name));
	lws_strncpy(tf->srcpath, srcpath, sizeof(tf->srcpath));
	tf->fd = fd;
	tf->len = (size_t)st.st_size;
	tf->chunks = (uint32_t)((tf->len + DGR_CHUNK - 1) / DGR_CHUNK);

	lws_dll2_add_tail(&tf->list, &dg_tx_owner);

	/* the peer learns the length from this before any chunk */
	dgr_ctl_enqueue(DGR_CTL_HDR, name, (uint32_t)tf->len, 0);

	return tf;
}

/* a receiver that lost everything is asking again from scratch */
static void
dgr_tx_reset(struct dgr_tx *tf)
{
	tf->done = 0;
	tf->cursor = 0;

	if (tf->fd < 0)
		tf->fd = open(tf->srcpath, O_RDONLY);

	dgr_ctl_enqueue(DGR_CTL_HDR, tf->name, (uint32_t)tf->len, 0);
}

/*
 * Create receiver state against the .part file.  The published path is
 * only ever created by rename at completion, so a transfer that never
 * finishes leaves the file missing rather than short.
 */
static struct dgr_rx *
dgr_rx_create(const char *name, size_t len, const char *endpoint, int req_index)
{
	struct dgr_rx *rx;
	char dirpath[512];

	lws_snprintf(dirpath, sizeof(dirpath), "/downloads%s",
		     endpoint[0] ? endpoint : "");
	if (mkdir(dirpath, 0777) < 0 && errno != EEXIST) { // NOSONAR
		lwsl_err("Failed to create directory %s: %d\n", dirpath, errno);
		return NULL;
	}

	rx = calloc(1, sizeof(*rx));
	if (!rx)
		return NULL;

	lws_strncpy(rx->name, name, sizeof(rx->name));
	lws_snprintf(rx->finalpath, sizeof(rx->finalpath), "%s/%s",
		     dirpath, name);
	lws_snprintf(rx->partpath, sizeof(rx->partpath), "%s/.%s.part",
		     dirpath, name);
	rx->len = len;
	rx->chunks = (uint32_t)((len + DGR_CHUNK - 1) / DGR_CHUNK);
	rx->req_index = req_index;

	{
		/* calloc(0) may legitimately return NULL: always take 1 */
		size_t bm_bytes = ((size_t)rx->chunks + 7) / 8;

		if (!bm_bytes)
			bm_bytes = 1;

		rx->bm = calloc(1, bm_bytes);
	}
	if (!rx->bm) {
		free(rx);
		return NULL;
	}

	rx->fd = open(rx->partpath, O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR
	if (rx->fd < 0) {
		lwsl_err("Failed to open %s: %d\n", rx->partpath, errno);
		free(rx->bm);
		free(rx);
		return NULL;
	}

	return rx;
}

static void
dgr_rx_destroy(struct dgr_rx *rx, int published)
{
	if (rx->fd >= 0) {
		close(rx->fd);
		rx->fd = -1;
	}
	if (!published)
		qir_unlink(rx->partpath);

	free(rx->bm);
	free(rx);
}

/* the last chunk arrived: publish the file and ack the sender */
static void
dgr_rx_complete(struct dgr_rx *rx)
{
	close(rx->fd);
	rx->fd = -1;

	if (rename(rx->partpath, rx->finalpath) < 0) {
		lwsl_err("Failed to publish %s: %d\n", rx->finalpath, errno);
		/* leave the request incomplete: the hardcap ends us */
		dgr_rx_destroy(rx, 0);
		return;
	}

	lwsl_user("Datagram file %s complete (%u chunks, %zu bytes)\n",
		  rx->name, rx->chunks, rx->len);

	if (is_server) {
		server_requests[rx->req_index].completed = 1;
		server_requests[rx->req_index].dgr = NULL;
	} else {
		client_requests[rx->req_index].completed = 1;
		client_requests[rx->req_index].dgr = NULL;
	}

	dgr_ctl_enqueue(DGR_CTL_OK, rx->name, 0, 0);
	dgr_kick();

	dgr_rx_destroy(rx, 1);
}

/*
 * Apply one chunk datagram.  Only an exactly-sized chunk for a valid
 * index is accepted, so a confused or hostile peer cannot complete a
 * file with holes in it.
 */
static void
dgr_rx_chunk(struct dgr_rx *rx, uint32_t idx, const uint8_t *data, size_t dlen)
{
	size_t expect = rx->len - (size_t)idx * DGR_CHUNK;
	off_t off = (off_t)idx * DGR_CHUNK;

	if (expect > DGR_CHUNK)
		expect = DGR_CHUNK;

	if (idx >= rx->chunks || dlen != expect || dgr_bm_get(rx->bm, idx))
		return;		/* invalid or duplicate */

	if (lseek(rx->fd, off, SEEK_SET) == (off_t)-1 ||
	    (long)write(rx->fd, data,
			LWS_POSIX_LENGTH_CAST(dlen)) != (long)dlen) {
		lwsl_err("Failed to write %s chunk %u\n", rx->name, idx);
		return;
	}

	dgr_bm_set(rx->bm, idx);
	rx->got++;

	if (rx->got == rx->chunks)
		dgr_rx_complete(rx);
}

/*
 * Send one chunk datagram.  Returns 0 on success, 1 if the chunk could
 * not be read (skip it; the receiver's MISS will try again), or -1 on a
 * write failure, which means the session is going away.
 */
static int
dgr_send_chunk(struct lws *wsi, struct dgr_tx *tf, uint32_t idx)
{
	uint8_t buf[LWS_PRE + DGR_MAX_DGRAM];
	size_t expect = tf->len - (size_t)idx * DGR_CHUNK;
	ssize_t r;
	int n;

	if (expect > DGR_CHUNK)
		expect = DGR_CHUNK;

	/*
	 * The header is capped to the datagram budget outside the fixed chunk
	 * payload, so however long the name is, header + payload can never
	 * overrun the buffer (or the QUIC DATAGRAM budget).  Validated names
	 * (<= 127 bytes) fit the cap without truncation.
	 */
	n = lws_snprintf((char *)&buf[LWS_PRE], DGR_MAX_DGRAM - DGR_CHUNK,
			 "CH %s %u\n", tf->name, idx);

	if (lseek(tf->fd, (off_t)idx * DGR_CHUNK, SEEK_SET) == (off_t)-1 ||
	    (r = read(tf->fd, &buf[LWS_PRE + n],
		      LWS_POSIX_LENGTH_CAST(expect))) < 0 ||
	    (size_t)r != expect) {
		lwsl_err("Failed reading %s chunk %u\n", tf->name, idx);
		return 1;
	}

	return lws_write(wsi, &buf[LWS_PRE], (size_t)n + (size_t)r,
			 LWS_WRITE_QUIC_DATAGRAM) < 0 ? -1 : 0;
}

/*
 * Drain queued control datagrams, packing consecutive MISS ranges for
 * the same file into shared datagrams.  Returns -1 on write failure.
 */
static int
dgr_send_ctl(struct lws *wsi, int *budget)
{
	while (*budget > 0 && dg_ctl_head != dg_ctl_tail) {
		uint8_t buf[LWS_PRE + DGR_MAX_DGRAM];
		struct dgr_ctl *e = &dg_ctl[dg_ctl_head];
		char *p = (char *)&buf[LWS_PRE];
		size_t len = 0, lim = DGR_MAX_DGRAM;

		switch (e->kind) {
		case DGR_CTL_GET:
			len = (size_t)lws_snprintf(p, lim, "GET %s\n", e->name);
			dgr_ctl_dequeue();
			break;

		case DGR_CTL_HDR:
			len = (size_t)lws_snprintf(p, lim, "HDR %s %u\n",
						   e->name, e->a);
			dgr_ctl_dequeue();
			break;

		case DGR_CTL_OK:
			len = (size_t)lws_snprintf(p, lim, "OK %s\n", e->name);
			dgr_ctl_dequeue();
			break;

		case DGR_CTL_DONE:
			len = (size_t)lws_snprintf(p, lim, "DONE\n");
			dgr_ctl_dequeue();
			break;

		case DGR_CTL_MISS:
			/* the dequeued entry itself carries the first range */
			len = (size_t)lws_snprintf(p, lim, "MISS %s %u-%u",
						   e->name, e->a, e->b);
			dgr_ctl_dequeue();
			{
				int ranges = 1;

				/* pack any consecutive ranges for the same
				 * file into the same datagram */
				while (ranges < DGR_RANGES_PER_MISS &&
				       dg_ctl_head != dg_ctl_tail) {
					struct dgr_ctl *m = &dg_ctl[dg_ctl_head];
					size_t l;

					if (m->kind != DGR_CTL_MISS ||
					    strcmp(m->name, e->name))
						break;

					l = (size_t)lws_snprintf(p + len, lim - len,
								 ",%u-%u",
								 m->a, m->b);
					if (len + l + 1 >= lim)
						break;
					len += l;
					ranges++;
					dgr_ctl_dequeue();
				}
				/* the payload always ends in a newline */
				if (len < lim)
					p[len++] = '\n';
			}
			break;

		default:
			dgr_ctl_dequeue();
			continue;
		}

		if (lws_write(wsi, &buf[LWS_PRE], len,
			      LWS_WRITE_QUIC_DATAGRAM) < 0)
			return -1;

		(*budget)--;
	}

	return 0;
}

/*
 * Called from the session WRITEABLE callback.  Sends a paced burst of
 * control datagrams, then re-requested chunks, then first-pass chunks,
 * and re-arms the pace sul if work remains.
 */
static void
dgr_pump(struct lws *wsi)
{
	int ctl_budget = DGR_CTL_BURST, data_budget = DGR_DATA_BURST;
	int work;

	if (!dg_session_wsi)
		return;

	if (dgr_send_ctl(wsi, &ctl_budget) < 0)
		return;

	/* re-requests first: they are blocking the receiver's completion */
	while (data_budget > 0 && dg_resend_head != dg_resend_tail) {
		struct dgr_tx *tf = dg_resend[dg_resend_head].tf;
		uint32_t idx = dg_resend[dg_resend_head].idx;
		int s;

		dg_resend_head = (dg_resend_head + 1) % DGR_RESEND_RING;

		if (!tf || tf->done || idx >= tf->chunks)
			continue;

		s = dgr_send_chunk(wsi, tf, idx);
		if (s < 0)
			return;		/* the session is failing */
		if (!s)
			data_budget--;
	}

	/* then the first pass over files, oldest request first */
	lws_start_foreach_dll(struct lws_dll2 *, d,
				 lws_dll2_get_head(&dg_tx_owner)) {
		struct dgr_tx *tf = lws_container_of(d, struct dgr_tx, list);

		if (!data_budget)
			break;

		while (data_budget > 0 && !tf->done && tf->cursor < tf->chunks) {
			int s = dgr_send_chunk(wsi, tf, tf->cursor);

			if (s < 0)
				return;		/* the session is failing */
			tf->cursor++;
			if (!s)
				data_budget--;
		}
	} lws_end_foreach_dll(d);

	work = dg_ctl_head != dg_ctl_tail || dg_resend_head != dg_resend_tail;
	if (!work)
		lws_start_foreach_dll(struct lws_dll2 *, d,
				 lws_dll2_get_head(&dg_tx_owner)) {
			struct dgr_tx *tf = lws_container_of(d, struct dgr_tx, list);

			if (!tf->done && tf->cursor < tf->chunks) {
				work = 1;
				break;
			}
		} lws_end_foreach_dll(d);

	if (work)
		dgr_repace();
}

static void
dgpace_sul_cb(struct lws_sorted_usec_list *sul)
{
	(void)sul;

	dg_pace_armed = 0;

	/* the sul only wakes the session; sends happen in WRITEABLE */
	if (dg_session_wsi)
		lws_callback_on_writable(dg_session_wsi);
}

/* something new to send: drain promptly if the pacer is idle */
static void
dgr_kick(void)
{
	if (!context || !dg_session_wsi || dg_pace_armed)
		return;

	dg_pace_armed = 1;
	lws_sul_schedule(context, 0, &sul_dgpace, dgpace_sul_cb, 1);
}

/* a burst was cut short: continue after the pace interval */
static void
dgr_repace(void)
{
	if (!context || !dg_session_wsi || dg_pace_armed)
		return;

	dg_pace_armed = 1;
	lws_sul_schedule(context, 0, &sul_dgpace, dgpace_sul_cb, DGR_PACE_US);
}

/* free everything at session close or exit */
static void
dgr_teardown(void)
{
	struct lws_dll2 *d, *d1;
	int i;

	for (i = 0; i < client_requests_count; i++)
		if (client_requests[i].dgr) {
			dgr_rx_destroy(client_requests[i].dgr, 0);
			client_requests[i].dgr = NULL;
		}
	for (i = 0; i < server_requests_count; i++)
		if (server_requests[i].dgr) {
			dgr_rx_destroy(server_requests[i].dgr, 0);
			server_requests[i].dgr = NULL;
		}

	d = dg_tx_owner.head;
	while (d) {
		struct dgr_tx *tf = lws_container_of(d, struct dgr_tx, list);

		d1 = lws_dll2_get_next(d);
		if (tf->fd >= 0)
			close(tf->fd);
		lws_dll2_remove(&tf->list);
		free(tf);
		d = d1;
	}

	dg_ctl_head = dg_ctl_tail = 0;
	dg_resend_head = dg_resend_tail = 0;
}

static void trigger_client_transfers(struct lws *wsi_session, const char *endpoint)
{
	int i;
	int local_is_sender = (strstr(testcase, "-receive") && is_server) ||
			      (strstr(testcase, "-send") && !is_server) ||
			      (strcmp(testcase, "transfer") == 0 && (is_server || !client_requests_count || client_requests[0].filename[0] == '\0'));
	int local_is_receiver = (strstr(testcase, "-receive") && !is_server) ||
				(strstr(testcase, "-send") && is_server) ||
				(strcmp(testcase, "transfer") == 0 && !is_server && client_requests_count && client_requests[0].filename[0] != '\0');

	lwsl_user("trigger_client_transfers called for endpoint %s, client_requests_count=%d\n", endpoint, client_requests_count);
	if (local_is_sender) {
		lwsl_user("  Local node is sender, not initiating client transfers.\n");
		return;
	}

	for (i = 0; i < client_requests_count; i++) {
		struct request_item *item = &client_requests[i];
		lwsl_user("  Client Request %d: url=%s endpoint=%s started=%d filename=%s\n", i, item->url, item->endpoint, item->started, item->filename);
		if (strcmp(item->endpoint, endpoint) == 0 && !item->started && item->filename[0]) {
			/* Start the transfer according to the testcase */
			item->started = 1;
			lwsl_user("  Triggering request %d (%s) on testcase %s\n", i, item->filename, testcase);
			if (strstr(testcase, "unidirectional")) {
				struct lws *cwsi = lws_wt_create_stream(wsi_session, 1);
				lwsl_user("  lws_wt_create_stream(unidi=1) returned wsi %p\n", cwsi);
				if (cwsi) {
					int err = lws_ensure_user_space(cwsi);
					lwsl_user("  lws_ensure_user_space returned %d\n", err);
					if (!err) {
						struct pss_qir *pss = (struct pss_qir *)lws_wsi_user(cwsi);
						lwsl_user("  pss user space: %p\n", pss);
						if (pss) {
							init_pss(pss);
							pss->is_unidi = 1;
							pss->is_initiator = 1;
							pss->request_index = i;
							lws_strncpy(pss->endpoint, item->endpoint, sizeof(pss->endpoint));
							lws_strncpy(pss->filename, item->filename, sizeof(pss->filename));
							lws_callback_on_writable(cwsi);
							lwsl_user("  Requested writable callback for client stream wsi %p\n", cwsi);
						}
					}
				}
			} else if (strstr(testcase, "bidirectional")) {
				struct lws *cwsi = lws_wt_create_stream(wsi_session, 0);
				lwsl_user("  lws_wt_create_stream(unidi=0) returned wsi %p\n", cwsi);
				if (cwsi) {
					int err = lws_ensure_user_space(cwsi);
					lwsl_user("  lws_ensure_user_space returned %d\n", err);
					if (!err) {
						struct pss_qir *pss = (struct pss_qir *)lws_wsi_user(cwsi);
						lwsl_user("  pss user space: %p\n", pss);
						if (pss) {
							init_pss(pss);
							pss->is_unidi = 0;
							pss->is_initiator = 1;
							pss->request_index = i;
							lws_strncpy(pss->endpoint, item->endpoint, sizeof(pss->endpoint));
							lws_strncpy(pss->filename, item->filename, sizeof(pss->filename));
							lws_callback_on_writable(cwsi);
							lwsl_user("  Requested writable callback for client stream wsi %p\n", cwsi);
						}
					}
				}
			} else if (strstr(testcase, "datagram")) {
				if (local_is_receiver) {
					/* the retry tick re-requests as needed */
					dgr_ctl_enqueue(DGR_CTL_GET,
							item->filename, 0, 0);
					dgr_kick();
				}
			}
		}
	}
}

static void trigger_server_transfers(struct lws *wsi_session, const char *endpoint)
{
	int i;
	int local_is_sender = (strstr(testcase, "-receive") && is_server) ||
			      (strstr(testcase, "-send") && !is_server) ||
			      (strcmp(testcase, "transfer") == 0 && (is_server || !client_requests_count || client_requests[0].filename[0] == '\0'));
	int local_is_receiver = (strstr(testcase, "-receive") && !is_server) ||
				(strstr(testcase, "-send") && is_server) ||
				(strcmp(testcase, "transfer") == 0 && !is_server && client_requests_count && client_requests[0].filename[0] != '\0');

	lwsl_user("trigger_server_transfers called for endpoint %s, server_requests_count=%d\n", endpoint, server_requests_count);
	if (local_is_sender) {
		lwsl_user("  Local node is sender, not initiating server transfers.\n");
		return;
	}

	for (i = 0; i < server_requests_count; i++) {
		struct server_request_item *item = &server_requests[i];
		lwsl_user("  Server Request %d: endpoint=%s started=%d filename=%s\n", i, item->endpoint, item->started, item->filename);
		if (strcmp(item->endpoint, endpoint) == 0 && !item->started) {
			item->started = 1;
			lwsl_user("  Triggering server request %d (%s) on testcase %s\n", i, item->filename, testcase);
			if (strstr(testcase, "unidirectional")) {
				struct lws *cwsi = lws_wt_create_stream(wsi_session, 1);
				lwsl_user("  lws_wt_create_stream(unidi=1) returned wsi %p\n", cwsi);
				if (cwsi) {
					int err = lws_ensure_user_space(cwsi);
					lwsl_user("  lws_ensure_user_space returned %d\n", err);
					if (!err) {
						struct pss_qir *pss = (struct pss_qir *)lws_wsi_user(cwsi);
						lwsl_user("  pss user space: %p\n", pss);
						if (pss) {
							init_pss(pss);
							pss->is_unidi = 1;
							pss->is_initiator = 1;
							pss->request_index = i;
							lws_strncpy(pss->endpoint, item->endpoint, sizeof(pss->endpoint));
							lws_strncpy(pss->filename, item->filename, sizeof(pss->filename));
							lws_callback_on_writable(cwsi);
							lwsl_user("  Requested writable callback for server stream wsi %p\n", cwsi);
						}
					}
				}
			} else if (strstr(testcase, "bidirectional")) {
				struct lws *cwsi = lws_wt_create_stream(wsi_session, 0);
				lwsl_user("  lws_wt_create_stream(unidi=0) returned wsi %p\n", cwsi);
				if (cwsi) {
					int err = lws_ensure_user_space(cwsi);
					lwsl_user("  lws_ensure_user_space returned %d\n", err);
					if (!err) {
						struct pss_qir *pss = (struct pss_qir *)lws_wsi_user(cwsi);
						lwsl_user("  pss user space: %p\n", pss);
						if (pss) {
							init_pss(pss);
							pss->is_unidi = 0;
							pss->is_initiator = 1;
							pss->request_index = i;
							lws_strncpy(pss->endpoint, item->endpoint, sizeof(pss->endpoint));
							lws_strncpy(pss->filename, item->filename, sizeof(pss->filename));
							lws_callback_on_writable(cwsi);
							lwsl_user("  Requested writable callback for server stream wsi %p\n", cwsi);
						}
					}
				}
			} else if (strstr(testcase, "datagram")) {
				if (local_is_receiver) {
					/* the retry tick re-requests as needed */
					dgr_ctl_enqueue(DGR_CTL_GET,
							item->filename, 0, 0);
					dgr_kick();
				}
			}
		}
	}
}

static int callback_qir(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct pss_qir *pss = (struct pss_qir *)user;
	uint8_t buf[LWS_PRE + 4096], *p;
	ssize_t r;
	int n, m;

	/*
	 * Only these reasons carry per-session storage in user.  Others
	 * (eg, PROTOCOL_INIT, OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS) pass
	 * unrelated pointers there, which must not be touched as if they
	 * were pss.
	 */
	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	/*
	 * This reason does not carry pss in user, everything it needs is
	 * in in/len.  It must be handled here, before the !pss gate, since
	 * it happens before the session exists.
	 */
	{
		unsigned char **hp = (unsigned char **)in, *end = (*hp) + len;

		/* Add sec-webtransport-http3-draft header */
		if (lws_add_http_header_by_name(wsi,
				(const unsigned char *)"sec-webtransport-http3-draft:",
				(const unsigned char *)"draft02", 7, hp, end))
			return -1;

		/* Format and send PROTOCOLS as custom headers */
		const char *env_protocols = getenv("PROTOCOLS_CLIENT");
		if (!env_protocols)
			env_protocols = getenv("PROTOCOLS");

		if (env_protocols) {
			char av_buf[512] = "";
			struct lws_tokenize ts;
			lws_tokenize_elem e;
			char tok[128];
			int first = 1;

			lws_tokenize_init(&ts, env_protocols, LWS_TOKENIZE_F_MINUS_NONTERM |
							      LWS_TOKENIZE_F_NO_INTEGERS |
							      LWS_TOKENIZE_F_NO_FLOATS);

			while ((e = lws_tokenize(&ts)) > 0) {
				if (e != LWS_TOKZE_TOKEN)
					continue;

				if (lws_tokenize_cstr(&ts, tok, sizeof(tok)))
					continue;

				if (sizeof(av_buf) - strlen(av_buf) > strlen(tok) + 5) {
					if (!first)
						strcat(av_buf, ", ");
					strcat(av_buf, "\"");
					strcat(av_buf, tok);
					strcat(av_buf, "\"");
					first = 0;
				}
			}

			if (lws_add_http_header_by_name(wsi,
					(const unsigned char *)"wt-available-protocols:",
					(const unsigned char *)av_buf, (int)strlen(av_buf), hp, end))
				return -1;
		}
		return 0;
	}

	case LWS_CALLBACK_ESTABLISHED:
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
	case LWS_CALLBACK_SERVER_WRITEABLE:
	case LWS_CALLBACK_CLIENT_WRITEABLE:
	case LWS_CALLBACK_RECEIVE:
	case LWS_CALLBACK_CLOSED:
	case LWS_CALLBACK_CLIENT_CLOSED:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (pss)
			init_pss(pss);
		break;

	default:
		/* not a per-session reason, ignore */
		return 0;
	}

	if (!pss)
		return 0;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		pss->wsi = wsi;
		pss->request_index = -1;
		if (lws_wt_is_session(wsi)) {
			if (!is_server)
				break;
			pss->is_session = 1;
			/* Extract endpoint path */
			char path[128];
			int path_len = lws_hdr_copy(wsi, path, sizeof(path) - 1, WSI_TOKEN_HTTP_COLON_PATH);
			if (path_len > 0) {
				path[path_len] = '\0';
				lws_strncpy(pss->endpoint, path, sizeof(pss->endpoint));
				lws_strncpy(global_endpoint, path, sizeof(global_endpoint));
			}
			lwsl_user("Server WebTransport session established on %s\n", pss->endpoint);

			dg_session_wsi = wsi;
			start_datagram_recovery();

			/* Save negotiated protocol to /downloads/negotiated_protocol.txt */
			{
				char client_protos[256];
				char negotiated[64] = "";
				int cp_len = lws_hdr_custom_copy(wsi, client_protos, sizeof(client_protos) - 1,
								 "wt-available-protocols:", 23);
				if (cp_len > 0) {
					const char *env_protocols = getenv("PROTOCOLS_SERVER");
					client_protos[cp_len] = '\0';
					if (!env_protocols)
						env_protocols = getenv("PROTOCOLS");

					if (env_protocols) {
						/* client_protos format: '"proto1", "proto2"' */
						struct lws_tokenize ts;
						lws_tokenize_elem e;
						char token[64];

						lws_tokenize_init(&ts, client_protos, LWS_TOKENIZE_F_COMMA_SEP_LIST |
											      LWS_TOKENIZE_F_MINUS_NONTERM |
											      LWS_TOKENIZE_F_NO_INTEGERS |
											      LWS_TOKENIZE_F_NO_FLOATS);

						while ((e = lws_tokenize(&ts)) > 0) {
							if (e != LWS_TOKZE_TOKEN && e != LWS_TOKZE_QUOTED_STRING)
								continue;

							if (lws_tokenize_cstr(&ts, token, sizeof(token)))
								continue;

							struct lws_tokenize sts;
							lws_tokenize_elem se;
							char sp_tok[64];

							lws_tokenize_init(&sts, env_protocols, LWS_TOKENIZE_F_MINUS_NONTERM |
													       LWS_TOKENIZE_F_NO_INTEGERS |
													       LWS_TOKENIZE_F_NO_FLOATS);

							while ((se = lws_tokenize(&sts)) > 0) {
								if (se != LWS_TOKZE_TOKEN)
									continue;

								if (lws_tokenize_cstr(&sts, sp_tok, sizeof(sp_tok)))
									continue;

								if (strcmp(token, sp_tok) == 0) {
									lws_strncpy(negotiated, token, sizeof(negotiated));
									break;
								}
							}
							if (negotiated[0])
								break;
						}
					}
				}

				if (negotiated[0]) {
					if (mkdir("/downloads", 0777) < 0 && errno != EEXIST) { // NOSONAR
						lwsl_err("Failed to create /downloads: %d\n", errno);
					}
					int nfd = open("/downloads/negotiated_protocol.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR
					if (nfd >= 0) {
						if (write(nfd, negotiated, LWS_POSIX_LENGTH_CAST(strlen(negotiated))) < 0) {
							lwsl_err("Failed to write negotiated protocol\n");
						}
						close(nfd);
					}
				}
			}

			/* If server needs to request files, trigger them now */
			trigger_server_transfers(wsi, pss->endpoint);
		} else {
			pss->is_session = 0;
			pss->is_unidi = lws_wt_is_unidi(wsi);
			lws_strncpy(pss->endpoint, global_endpoint, sizeof(pss->endpoint));
			lwsl_user("%s stream established (unidi=%d)\n", is_server ? "Server" : "Client", pss->is_unidi);

			if (is_server && !pss->is_unidi &&
			    lws_get_parent(wsi) && lws_wt_is_session(lws_get_parent(wsi))) {
				/* Server receives files over client-initiated bidi streams.
				 * Find first unstarted server request, assign it to this stream,
				 * and trigger writable callback to send GET <filename>. */
				int i;
				for (i = 0; i < server_requests_count; i++) {
					if (!server_requests[i].started) {
						server_requests[i].started = 1;
						pss->request_index = i;
						pss->is_initiator = 1;
						lws_strncpy(pss->filename, server_requests[i].filename, sizeof(pss->filename));
						lws_callback_on_writable(wsi);
						lwsl_user("Server assigned request %d (%s) to bidi stream %p\n", i, pss->filename, wsi);
						break;
					}
				}
			}
		}
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		if (is_server)
			break;
		pss->wsi = wsi;
		pss->request_index = -1;
		if (lws_wt_is_session(wsi)) {
			pss->is_session = 1;
			
			/* Match the endpoint from client_requests */
			int i;
			for (i = 0; i < client_requests_count; i++) {
				if (!client_requests[i].session_wsi) {
					lws_strncpy(pss->endpoint, client_requests[i].endpoint, sizeof(pss->endpoint));
					client_requests[i].session_wsi = wsi;
					lws_strncpy(global_endpoint, pss->endpoint, sizeof(global_endpoint));
					break;
				}
			}
			lwsl_user("Client WebTransport session established on %s. Listing all custom headers:\n", pss->endpoint);

			dg_session_wsi = wsi;
			start_datagram_recovery();
#if defined(LWS_WITH_CUSTOM_HEADERS)
			lws_hdr_custom_name_foreach(wsi, print_custom_header_cb, wsi);
#endif

			/* Parse and save negotiated protocol to /downloads/negotiated_protocol.txt */
			char negotiated[64];
			int nl = lws_hdr_custom_copy(wsi, negotiated, sizeof(negotiated) - 1, "wt-protocol:", 12);
			lwsl_user("wt-protocol header lookup result: %d\n", nl);
			if (nl > 0) {
				negotiated[nl] = '\0';
				/* Remove quotes */
				char *n_ptr = negotiated;
				while (*n_ptr == '"') n_ptr++;
				char *ne = n_ptr + strlen(n_ptr);
				while (ne > n_ptr && (ne[-1] == '"' || ne[-1] == '\r' || ne[-1] == '\n')) {
					ne[-1] = '\0';
					ne--;
				}
				if (mkdir("/downloads", 0777) < 0 && errno != EEXIST) { // NOSONAR
					lwsl_err("Failed to create /downloads: %d\n", errno);
				}
				int nfd = open("/downloads/negotiated_protocol.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR
				if (nfd >= 0) {
					if (write(nfd, n_ptr, LWS_POSIX_LENGTH_CAST(strlen(n_ptr))) < 0) {
						lwsl_err("Failed to write negotiated protocol\n");
					}
					close(nfd);
				}
			}

			/* If client needs to request files, trigger them now */
			trigger_client_transfers(wsi, pss->endpoint);
		} else {
			pss->is_session = 0;
			pss->is_unidi = lws_wt_is_unidi(wsi);
			lws_strncpy(pss->endpoint, global_endpoint, sizeof(pss->endpoint));
			lwsl_user("Client stream established (unidi=%d)\n", pss->is_unidi);
		}
		break;

		case LWS_CALLBACK_SERVER_WRITEABLE:
		case LWS_CALLBACK_CLIENT_WRITEABLE:
			if (pss->is_session) {
				/* datagram testcase egress is all through the pump;
				 * dg_peer_exchange covers the responder of -send,
				 * which only learns of the exchange from the wire */
				if (dg_testcase() || dg_peer_exchange)
					dgr_pump(wsi);
				break;
			}

		if (pss_is_file_sender(pss)) {
			/* Sender: write file data */
			if (!pss->filename[0] || pss->write_completed)
				break;
			if (pss->fd_in < 0) {
				char filepath[512];
				const char *endpoint = pss->endpoint[0] ? pss->endpoint : global_endpoint;
				lws_snprintf(filepath, sizeof(filepath), "/www%s/%s", endpoint, pss->filename);
				pss->fd_in = open(filepath, O_RDONLY);
				if (pss->fd_in >= 0) {
					struct stat st;
					if (fstat(pss->fd_in, &st) == 0) {
						pss->file_len = (size_t)st.st_size;
					}
					pss->sent_len = 0;
					pss->header_sent = 0;
					lwsl_user("Sender opened file %s (%zu bytes) for transmission\n", filepath, pss->file_len);
				} else {
					lwsl_err("Sender failed to open file %s\n", filepath);
					return -1;
				}
			}

			if (pss->fd_in >= 0) {
				if (!pss->is_unidi || pss->header_sent) {
					/* Read and send file chunk */
					p = &buf[LWS_PRE];
					r = read(pss->fd_in, p, LWS_POSIX_LENGTH_CAST(sizeof(buf) - LWS_PRE));
					if (r > 0) {
						pss->sent_len += (size_t)r;
						int is_final = (pss->sent_len == pss->file_len);
						m = lws_write(wsi, p, (size_t)r, LWS_WRITE_BINARY | (is_final ? LWS_WRITE_H2_STREAM_END : LWS_WRITE_NO_FIN));
						if (m < 0)
							return -1;
						if (m < r) {
							/* Seek back the unwritten bytes and retry */
							off_t diff = (off_t)(r - m);
							if (lseek(pss->fd_in, -diff, SEEK_CUR) == (off_t)-1) {
								lwsl_err("lseek failed: %d\n", errno);
								return -1;
							}
							pss->sent_len -= (size_t)diff;
							lws_callback_on_writable(wsi);
						} else {
							if (!is_final)
								lws_callback_on_writable(wsi);
							else {
								close(pss->fd_in);
								pss->fd_in = -1;
								pss->write_completed = 1;
								lwsl_user("Sender completed file write: %zu bytes\n", pss->sent_len);
								return 0;
							}
						}
					} else {
						/* EOF or error */
						close(pss->fd_in);
						pss->fd_in = -1;
						pss->write_completed = 1;
						lws_write(wsi, NULL, 0, LWS_WRITE_BINARY | LWS_WRITE_H2_STREAM_END);
						return 0;
					}
				} else {
					/* Unidirectional stream requires PUSH <filename>\n first */
					p = &buf[LWS_PRE];
					n = lws_snprintf((char *)p, sizeof(buf) - LWS_PRE, "PUSH %s\n", pss->filename);
					m = lws_write(wsi, p, (size_t)n, LWS_WRITE_BINARY | LWS_WRITE_NO_FIN);
					if (m < 0)
						return -1;
					if (m < n) {
						/* Throttled or partial, retry header next time */
						lws_callback_on_writable(wsi);
					} else {
						pss->header_sent = 1;
						lws_callback_on_writable(wsi);
						lwsl_user("Sender sent PUSH %s\\n\n", pss->filename);
					}
				}
			}
		} else {
			if (pss->is_initiator) {
				/* Initiator: write GET <filename> */
				if (!pss->header_sent) {
					p = &buf[LWS_PRE];
					n = lws_snprintf((char *)p, sizeof(buf) - LWS_PRE, "GET %s", pss->filename);
					m = lws_write(wsi, p, (size_t)n, LWS_WRITE_BINARY | LWS_WRITE_H2_STREAM_END);
					if (m < 0)
						return -1;
					pss->header_sent = 1;
					lwsl_user("Initiator sent GET %s\n", pss->filename);
				}
			}
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (pss->is_session) {
			char hdr[DGR_NAME_LEN + 64];
			const uint8_t *payload = (const uint8_t *)in;
			const uint8_t *data;
			size_t hl = 0;

			/*
			 * The header line is copied out and NUL-terminated
			 * for safe parsing; binary chunk data stays in place.
			 */
			while (hl < len && hl < sizeof(hdr) - 1 &&
			       payload[hl] != '\n')
				hl++;
			memcpy(hdr, payload, hl);
			hdr[hl] = '\0';
			trim_trailing_whitespace(hdr);
			data = payload + (hl < len ? hl + 1 : hl);

			/*
			 * Only datagram testcases have a datagram protocol.
			 * In the stream transfer testcases any datagram is
			 * unrelated and must never be actioned, in particular
			 * it must never touch the files the streams are
			 * writing to the same paths.
			 *
			 * But the responder of a -send datagram testcase is
			 * only told its testcase is "transfer": it discovers
			 * the exchange from the peer's protocol datagrams.
			 */
			if (!dg_testcase() && !dg_peer_exchange) {
				if (!dgr_hdr_is_ctl(hdr))
					break;
				dg_peer_exchange = 1;
				lwsl_user("Peer started a datagram exchange "
					  "on a non-datagram-named testcase\n");
			}

			/*
			 * Debug loss hook: drop a pseudorandom sample of
			 * incoming datagrams to exercise recovery locally.
			 */
			if (dg_dbg_drop_pct &&
			    (int)(dg_dbg_rand() % 100) < dg_dbg_drop_pct)
				break;

			/* a datagram exchange is happening, arm the safety cap */
			start_datagram_recovery();

			{
				if (!strcmp(hdr, "DONE")) {
					lwsl_user("Session WSI received datagram DONE: peer confirmed all transfers\n");
					/*
					 * Only the responder acts on DONE.  The
					 * initiator owns completion through
					 * its chunk bitmaps and its own DONE
					 * pump; a DONE that arrives while it
					 * is still missing files must not
					 * stop it retrying.
					 */
					if (!dg_am_initiator()) {
						if (!is_server) {
							int i;
							for (i = 0; i < client_requests_count; i++)
								client_requests[i].completed = 1;
						}
						interrupted = 1;
					}
				} else if (!strncmp(hdr, "GET ", 4)) {
					/* GET <name>: peer wants the file */
					const char *name = hdr + 4;
					struct dgr_tx *tf;

					if (!dgr_name_ok(name))
						break;

					tf = dgr_tx_find(name);
					if (tf) {
						/*
						 * A GET means the peer has
						 * nothing: either the whole
						 * first pass was lost after it
						 * drained, or the peer lost
						 * everything again after our
						 * OK handling.  Restart the
						 * first pass; a GET while
						 * chunks are still going out
						 * is just a duplicate.
						 */
						if (tf->done ||
						    tf->cursor >= tf->chunks)
							dgr_tx_reset(tf);
					} else
						(void)dgr_tx_create(name);
					dgr_kick();

				} else if (!strncmp(hdr, "HDR ", 4)) {
					/* HDR <name> <len>: file is incoming */
					char name[DGR_NAME_LEN];
					const char *p = hdr + 4, *sp;
					uint32_t flen;
					int ridx, completed;
					const char *endpoint;
					struct dgr_rx *rx;

					sp = strchr(p, ' ');
					if (!sp || (size_t)(sp - p) >= sizeof(name))
						break;
					memcpy(name, p, (size_t)(sp - p));
					name[sp - p] = '\0';
					p = sp + 1;
					if (!dgr_name_ok(name) ||
					    !dgr_parse_u32(&p, &flen) || *p)
						break;

					if (!dgr_lookup_request(name, &ridx,
								&endpoint, &completed, &rx))
						break;

					if (completed) {
						/* stale resend: re-ack it */
						dgr_ctl_enqueue(DGR_CTL_OK, name, 0, 0);
						dgr_kick();
						break;
					}
					if (rx) {
						if (rx->len == flen)
							break;	/* duplicate */
						/* restarted from scratch */
						if (is_server)
							server_requests[ridx].dgr = NULL;
						else
							client_requests[ridx].dgr = NULL;
						dgr_rx_destroy(rx, 0);
					}

					rx = dgr_rx_create(name, flen, endpoint, ridx);
					if (!rx)
						break;
					if (is_server)
						server_requests[ridx].dgr = rx;
					else
						client_requests[ridx].dgr = rx;

					lwsl_user("Datagram file %s incoming (%u bytes)\n",
						  name, flen);

					/* an empty file is already complete */
					if (!rx->chunks)
						dgr_rx_complete(rx);

				} else if (!strncmp(hdr, "CH ", 3)) {
					/* CH <name> <idx>\n<data> */
					char name[DGR_NAME_LEN];
					const char *p = hdr + 3, *sp;
					uint32_t idx;
					int ridx, completed;
					const char *endpoint;
					struct dgr_rx *rx;

					sp = strchr(p, ' ');
					if (!sp || (size_t)(sp - p) >= sizeof(name))
						break;
					memcpy(name, p, (size_t)(sp - p));
					name[sp - p] = '\0';
					p = sp + 1;
					if (!dgr_name_ok(name) ||
					    !dgr_parse_u32(&p, &idx) || *p)
						break;

					if (!dgr_lookup_request(name, &ridx,
								&endpoint, &completed, &rx) ||
					    completed || !rx)
						break;

					dgr_rx_chunk(rx, idx, data,
						     len - (size_t)(data - payload));

				} else if (!strncmp(hdr, "MISS ", 5)) {
					/* MISS <name> <a>-<b>[,..] */
					char name[DGR_NAME_LEN];
					const char *p = hdr + 5, *sp;
					struct dgr_tx *tf;

					sp = strchr(p, ' ');
					if (!sp || (size_t)(sp - p) >= sizeof(name))
						break;
					memcpy(name, p, (size_t)(sp - p));
					name[sp - p] = '\0';
					p = sp + 1;
					if (!dgr_name_ok(name))
						break;

					tf = dgr_tx_find(name);
					if (!tf) {
						tf = dgr_tx_create(name);
						if (!tf)
							break;
					} else if (tf->done) {
						/* our OK was lost */
						tf->done = 0;
						if (tf->fd < 0)
							tf->fd = open(tf->srcpath,
								      O_RDONLY);
					}

					for (;;) {
						uint32_t a, b;

						if (!dgr_parse_u32(&p, &a) ||
						    *p != '-')
							break;
						p++;
						if (!dgr_parse_u32(&p, &b))
							break;

						/* clamp into the file */
						if (b >= tf->chunks)
							b = tf->chunks ?
								tf->chunks - 1 : 0;
						if (tf->chunks && a <= b)
							for (; a <= b; a++)
								dgr_resend_enqueue(tf, a);

						if (*p == ',') {
							p++;
							continue;
						}
						break;
					}
					if (*p)
						lwsl_info("Trailing junk in MISS for %s\n",
							  name);
					dgr_kick();

				} else if (!strncmp(hdr, "OK ", 3)) {
					/* OK <name>: receiver has it all */
					const char *name = hdr + 3;
					struct dgr_tx *tf;

					if (!dgr_name_ok(name))
						break;

					tf = dgr_tx_find(name);
					if (tf && !tf->done) {
						tf->done = 1;
						if (tf->fd >= 0) {
							close(tf->fd);
							tf->fd = -1;
						}
						lwsl_user("Datagram sender: %s acknowledged complete\n",
							  name);
					}
				}
			}
			break;
		}

		/* Child Stream Data Received */
		{
			char *data = (char *)in;
			size_t data_len = len;
			int is_file_rec = pss_is_file_receiver(pss);

			lwsl_user("RECEIVE: wsi=%p, len=%zu, is_unidi=%d, is_initiator=%d, push_hdr_done=%d, is_file_rec=%d\n",
				wsi, data_len, pss->is_unidi, pss->is_initiator, pss->push_hdr_done, is_file_rec);

			if (is_file_rec) {
				/* Receiver of file */
				if (pss->is_unidi) {
					/* Unidirectional: parse PUSH <filename>\n first */
					if (!pss->push_hdr_done) {
						size_t i;
						for (i = 0; i < data_len; i++) {
							if (pss->push_hdr_len < sizeof(pss->push_hdr) - 1) {
								pss->push_hdr[pss->push_hdr_len++] = data[i];
								if (data[i] == '\n') {
									pss->push_hdr[pss->push_hdr_len] = '\0';
									pss->push_hdr_done = 1;
									/* Parse filename */
									if (strncmp(pss->push_hdr, "PUSH ", 5) == 0) {
										char *nl = strchr(pss->push_hdr, '\n');
										if (nl) *nl = '\0';
										lws_strncpy(pss->filename, pss->push_hdr + 5, sizeof(pss->filename));
										lwsl_user("RECEIVE: Parsed filename '%s'\n", pss->filename);
									}
								/* Open file regardless of rem.  Streams
								 * are reliable, but the file only
								 * appears at its final name when the
								 * stream completes, so a connection
								 * death leaves it missing rather than
								 * truncated. */
								char dirpath[512];
								const char *endpoint = pss->endpoint[0] ? pss->endpoint : global_endpoint;
								lws_snprintf(dirpath, sizeof(dirpath), "/downloads%s", endpoint);
								if (mkdir(dirpath, 0777) < 0 && errno != EEXIST) { // NOSONAR
									lwsl_err("Failed to create directory %s: %d\n", dirpath, errno);
								}
								lws_snprintf(pss->out_final, sizeof(pss->out_final),
									     "%s/%s", dirpath, pss->filename);
								lws_snprintf(pss->out_part, sizeof(pss->out_part),
									     "%s/.%s.part", dirpath, pss->filename);
								pss->fd_out = open(pss->out_part,
										  O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR

								size_t rem = data_len - i - 1;
								lwsl_user("RECEIVE: Opened file '%s' -> fd %d (rem=%zu bytes written)\n",
									  pss->out_final, pss->fd_out, rem);
									if (pss->fd_out >= 0 && rem > 0) {
										if (write(pss->fd_out, data + i + 1, LWS_POSIX_LENGTH_CAST(rem)) < 0) {
											lwsl_err("Failed to write stream chunk\n");
										}
									}
									break;
								}
							}
						}
					} else {
						if (pss->fd_out >= 0) {
							if (write(pss->fd_out, data, LWS_POSIX_LENGTH_CAST(data_len)) < 0) {
								lwsl_err("Failed to write stream data\n");
							}
						} else {
							lwsl_user("RECEIVE: fd_out is closed/invalid (%d) while trying to write %zu bytes\n", pss->fd_out, data_len);
						}
					}
				} else {
					/* Bidirectional: no header, just raw file contents */
					if (pss->fd_out < 0) {
						char dirpath[512];
						const char *endpoint = pss->endpoint[0] ? pss->endpoint : global_endpoint;
						lws_snprintf(dirpath, sizeof(dirpath), "/downloads%s", endpoint);
						if (mkdir(dirpath, 0777) < 0 && errno != EEXIST) { // NOSONAR
							lwsl_err("Failed to create directory %s: %d\n", dirpath, errno);
						}
						lws_snprintf(pss->out_final, sizeof(pss->out_final),
							     "%s/%s", dirpath, pss->filename);
						lws_snprintf(pss->out_part, sizeof(pss->out_part),
							     "%s/.%s.part", dirpath, pss->filename);
						pss->fd_out = open(pss->out_part,
								   O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR
						lwsl_user("RECEIVE (bidi): Opened file '%s' -> fd %d\n",
							  pss->out_final, pss->fd_out);
					}
					if (pss->fd_out >= 0) {
						if (write(pss->fd_out, data, LWS_POSIX_LENGTH_CAST(data_len)) < 0) {
							lwsl_err("Failed to write stream data\n");
						}
					}
				}
			} else {
				/* Sender (received GET <filename>) */
				if (data_len > 4 && strncmp(data, "GET ", 4) == 0) {
					char filename[256];
					size_t fn_len = data_len - 4;
					/* Remove trailing spaces or newlines if any */
					while (fn_len > 0 && (data[4 + fn_len - 1] == ' ' || data[4 + fn_len - 1] == '\r' || data[4 + fn_len - 1] == '\n'))
						fn_len--;
					if (fn_len >= sizeof(filename)) fn_len = sizeof(filename) - 1;
					memcpy(filename, data + 4, fn_len);
					filename[fn_len] = '\0';

					lws_strncpy(pss->filename, filename, sizeof(pss->filename));
					lwsl_user("Sender WSI received GET %s\n", pss->filename);

					/* Open local file from /www/<endpoint>/<filename> */
					char filepath[512];
					const char *endpoint = pss->endpoint[0] ? pss->endpoint : global_endpoint;
					lws_snprintf(filepath, sizeof(filepath), "/www%s/%s", endpoint, pss->filename);
					pss->fd_in = open(filepath, O_RDONLY);
					if (pss->fd_in >= 0) {
						struct stat st;
						if (fstat(pss->fd_in, &st) == 0) {
							pss->file_len = (size_t)st.st_size;
						}
						
						if (lws_wt_is_unidi(wsi)) {
							struct lws *cwsi = lws_wt_create_stream_from_child(wsi, 1);
							if (cwsi) {
								if (!lws_ensure_user_space(cwsi)) {
									struct pss_qir *cpss = (struct pss_qir *)lws_wsi_user(cwsi);
									if (cpss) {
										cpss->is_unidi = 1;
										cpss->is_initiator = 0;
										lws_strncpy(cpss->endpoint, endpoint, sizeof(cpss->endpoint));
										lws_strncpy(cpss->filename, filename, sizeof(cpss->filename));
										cpss->fd_in = pss->fd_in;
										pss->fd_in = -1;
										cpss->file_len = pss->file_len;
										lws_callback_on_writable(cwsi);
										lwsl_user("Created server-initiated stream %p for unidirectional file response\n", cwsi);
									} else {
										lwsl_err("Child stream user space is NULL\n");
										close(pss->fd_in);
										pss->fd_in = -1;
									}
								} else {
									lwsl_err("Failed to ensure user space for child stream\n");
									close(pss->fd_in);
									pss->fd_in = -1;
								}
							} else {
								lwsl_err("Failed to create server-initiated stream for response\n");
								close(pss->fd_in);
								pss->fd_in = -1;
							}
						} else {
							lws_callback_on_writable(wsi);
						}
					} else {
						lwsl_err("Sender WSI failed to open file %s\n", filepath);
					}
				}
			}
		}
		break;

	case LWS_CALLBACK_CLOSED:
	case LWS_CALLBACK_CLIENT_CLOSED:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
	{
		int had_out = pss->fd_out >= 0;

		if (pss->fd_in >= 0) {
			close(pss->fd_in);
			pss->fd_in = -1;
		}
		if (pss->fd_out >= 0) {
			close(pss->fd_out);
			pss->fd_out = -1;
			/*
			 * The stream carried all it had: publish what was
			 * received.  A stream that died early publishes a
			 * short file, but only at a path this exchange owns.
			 */
			if (rename(pss->out_part, pss->out_final) < 0)
				lwsl_err("Failed to publish %s: %d\n",
					 pss->out_final, errno);
		}
		if (!pss->is_session) {
			if (pss->is_unidi && pss->is_initiator) {
				lwsl_user("Initiator unidirectional GET stream closed (not marking request completed yet)\n");
				break;
			}
			/*
			 * A stream that neither received file data nor
			 * completed sending one (eg, the server-side stream
			 * that received "GET <file>" and spawned the response
			 * stream) must not complete the request; the request
			 * completes when the transfer stream itself is done.
			 */
			if (!had_out && !pss->write_completed) {
				lwsl_user("Non-transfer stream closed (not marking any request completed)\n");
				break;
			}
			if (!is_server) {
				int r_idx = -1;
				int i;
				for (i = 0; i < client_requests_count; i++) {
					if (strcmp(client_requests[i].filename, pss->filename) == 0) {
						r_idx = i;
						break;
					}
				}
				if (r_idx >= 0) {
					client_requests[r_idx].completed = 1;
					lwsl_user("Client transfer request index %d (%s) completed (stream closed)\n", r_idx, pss->filename);
				}
			} else {
				int r_idx = -1;
				int i;
				for (i = 0; i < server_requests_count; i++) {
					if (strcmp(server_requests[i].filename, pss->filename) == 0) {
						r_idx = i;
						break;
					}
				}
				if (r_idx >= 0) {
					server_requests[r_idx].completed = 1;
					lwsl_user("Server transfer request index %d (%s) completed (stream closed)\n", r_idx, pss->filename);
					
					int all_done = 1;
					for (i = 0; i < server_requests_count; i++) {
						if (!server_requests[i].completed) {
							all_done = 0;
							break;
						}
					}
					if (all_done) {
						lwsl_user("All server requests completed. Setting interrupted = 1 to exit.\n");
						interrupted = 1;
					}
				}
			}
		} else {
			lwsl_user("%s session closed. Setting interrupted = 1 to exit.\n", is_server ? "Server" : "Client");
			if (wsi == dg_session_wsi) {
				dg_session_wsi = NULL;
				lws_sul_cancel(&sul_dgretry);
				dg_retry_armed = 0;
				lws_sul_cancel(&sul_dgpace);
				dg_pace_armed = 0;
				dgr_teardown();
			}
			interrupted = 1;
		}
		lwsl_user("WSI closed\n");
		break;
	}

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "webtransport", callback_qir, sizeof(struct pss_qir), 65536, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

static struct lws_protocols *dyn_protocols = NULL;

/*
 * Keep servicing the event loop for ms milliseconds, so queued, paced
 * QUIC egress can actually be transmitted before the context is
 * destroyed.  A sul is used to make sure poll() wakes up regularly
 * even if nothing else is scheduled.
 */
static struct lws_sorted_usec_list sul_drain;
static struct lws_context *drain_ctx;
static int drain_done;

static void
drain_sul_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	drain_done = 1;

	/*
	 * The sul callbacks run before the poll wait in the same
	 * lws_service() call, so without this the loop below would sit in
	 * poll() until the next unrelated scheduled event before it could
	 * notice we are done.
	 */
	lws_cancel_service(drain_ctx);
}

static void
drain_context(struct lws_context *context, int ms)
{
	int n = 0;

	drain_done = 0;
	drain_ctx = context;
	lws_sul_schedule(context, 0, &sul_drain, drain_sul_cb,
			 (lws_usec_t)ms * LWS_US_PER_MS);

	while (n >= 0 && !drain_done)
		n = lws_service(context, 0);

	lws_sul_cancel(&sul_drain);
}

static void setup_dynamic_protocols(void)
{
	const char *env_protocols = getenv("PROTOCOLS_SERVER");
	if (!env_protocols)
		env_protocols = getenv("PROTOCOLS");

	if (!env_protocols)
		return;

	/* Count protocols */
	struct lws_tokenize ts;
	lws_tokenize_init(&ts, env_protocols, LWS_TOKENIZE_F_MINUS_NONTERM);
	lws_tokenize_elem e;
	int count = 0;

	do {
		e = lws_tokenize(&ts);
		if (e == LWS_TOKZE_TOKEN || e == LWS_TOKZE_QUOTED_STRING) {
			count++;
		}
	} while (e > 0);

	if (count == 0)
		return;

	/* Allocate count + 2 protocols: one for each protocol, plus "webtransport", plus NULL terminator */
	dyn_protocols = malloc((size_t)(count + 2) * sizeof(struct lws_protocols));
	if (!dyn_protocols) {
		lwsl_err("OOM allocating dynamic protocols\n");
		return;
	}

	memset(dyn_protocols, 0, (size_t)(count + 2) * sizeof(struct lws_protocols));

	/* Re-tokenize and copy */
	lws_tokenize_init(&ts, env_protocols, LWS_TOKENIZE_F_MINUS_NONTERM);
	int idx = 0;
	do {
		e = lws_tokenize(&ts);
		if (e == LWS_TOKZE_TOKEN || e == LWS_TOKZE_QUOTED_STRING) {
			char name[64];
			if (!lws_tokenize_cstr(&ts, name, sizeof(name))) {
				dyn_protocols[idx].name = strdup(name);
				dyn_protocols[idx].callback = callback_qir;
				dyn_protocols[idx].per_session_data_size = sizeof(struct pss_qir);
				dyn_protocols[idx].rx_buffer_size = 65536;
				idx++;
			}
		}
	} while (e > 0);

	/* Add generic "webtransport" protocol at the end of the list just in case */
	dyn_protocols[idx].name = "webtransport";
	dyn_protocols[idx].callback = callback_qir;
	dyn_protocols[idx].per_session_data_size = sizeof(struct pss_qir);
	dyn_protocols[idx].rx_buffer_size = 65536;
	idx++;

	/* Terminator is already zeroed out by memset */
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	signal(SIGINT, sigint_handler);

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	/* Determine role */
	if (argc > 1 && strcmp(argv[1], "server") == 0)
		is_server = 1;
	else
		is_server = 0;

	/* Read testcase env */
	const char *tc = getenv("TESTCASE_NAME");
	if (!tc)
		tc = getenv("TESTCASE");
	if (tc)
		lws_strncpy(testcase, tc, sizeof(testcase));

	/*
	 * Local protocol-validation hook: drop a pseudorandom sample of
	 * incoming session datagrams, emulating sim loss without the sim.
	 */
	{
		const char *drop = getenv("QIR_DBG_DROP_PERCENT");

		if (drop) {
			dg_dbg_drop_pct = atoi(drop);
			if (dg_dbg_drop_pct < 0)
				dg_dbg_drop_pct = 0;
			if (dg_dbg_drop_pct > 99)
				dg_dbg_drop_pct = 99;
			if (dg_dbg_drop_pct)
				lwsl_user("DBG: dropping %d%% of received datagrams\n",
					  dg_dbg_drop_pct);
		}
	}

	lwsl_user("LWS WebTransport QIR Tool | Role: %s | Testcase: %s\n",
		  is_server ? "server" : "client", testcase);

	/* Determine port */
	int port = 443;
	const char *port_env = getenv("PORT");
	if (port_env)
		port = atoi(port_env);

	setup_dynamic_protocols();

	memset(&info, 0, sizeof info);
	info.port = is_server ? port : CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.protocols = dyn_protocols ? dyn_protocols : protocols;
	info.alpn = "h3";

	if (is_server) {
		static char cert_path[512];
		static char key_path[512];
		int fd_check;

		/* The interop runner mounts host certificates at /certs inside the container */
		fd_check = open("/certs/cert.pem", O_RDONLY);
		if (fd_check >= 0) {
			close(fd_check);
			lws_strncpy(cert_path, "/certs/cert.pem", sizeof(cert_path));
			lws_strncpy(key_path, "/certs/priv.key", sizeof(key_path));
		} else {
			/* Fallback to local files if running outside QIR simulation */
			lws_strncpy(cert_path, "localhost-100y.cert", sizeof(cert_path));
			lws_strncpy(key_path, "localhost-100y.key", sizeof(key_path));
		}

		info.ssl_cert_filepath = cert_path;
		info.ssl_private_key_filepath = key_path;
		parse_server_requests();
	} else {
		parse_client_requests();
	}

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * A datagram testcase initiator can also get stuck before any session
	 * exists (eg, if the peer never connects), so start the recovery
	 * machinery, including the hard cap, from startup.
	 */
	start_datagram_recovery();

	/* Client connection triggering */
	if (!is_server && client_requests_count > 0) {
		int i;
		for (i = 0; i < client_requests_count; i++) {
			struct request_item *item = &client_requests[i];

			/* Connect only once per unique host/port/endpoint */
			int already_triggered = 0;
			int j;
			for (j = 0; j < i; j++) {
				if (strcmp(client_requests[j].endpoint, item->endpoint) == 0 &&
				    strcmp(client_requests[j].host, item->host) == 0 &&
				    client_requests[j].port == item->port) {
					already_triggered = 1;
					break;
				}
			}
			if (already_triggered)
				continue;

			struct lws_client_connect_info cinfo;

			memset(&cinfo, 0, sizeof(cinfo));
			cinfo.context = context;
			cinfo.address = item->host;
			cinfo.port = item->port;
			cinfo.path = item->endpoint;
			cinfo.host = item->host;
			cinfo.origin = item->host;
			cinfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
			cinfo.protocol = "webtransport";
			cinfo.alpn = "h3";

			if (first_session_wsi) {
				/* Force multiplexing on the same QUIC network connection */
				cinfo.parent_wsi = first_session_wsi;
			}

			struct lws *wsi = lws_client_connect_via_info(&cinfo);
			if (!wsi) {
				lwsl_err("Failed to initiate WebTransport client connection to %s\n", item->url);
			} else {
				if (!first_session_wsi) {
					first_session_wsi = wsi;
				}
			}
		}
	}

	while (n >= 0 && !interrupted) {
		n = lws_service(context, 0);

		/* Check if all client requests are done and exit */
		if (!is_server && client_requests_count > 0) {
			int all_done = 1;
			int i;
			for (i = 0; i < client_requests_count; i++) {
				if (!client_requests[i].completed)
					all_done = 0;
			}
			if (all_done && strcmp(testcase, "handshake") != 0 &&
			    !strstr(testcase, "datagram")) {
				lwsl_user("All client requests completed. Draining before exiting.\n");
				drain_context(context, 500);
				break;
			}
			/* Handshake testcase does not download files, just wait a bit and exit */
			if (strcmp(testcase, "handshake") == 0) {
				char client_proto_path[512];
				lws_snprintf(client_proto_path, sizeof(client_proto_path), "/downloads/negotiated_protocol.txt");
				int fd = open(client_proto_path, O_RDONLY);
				if (fd >= 0) {
					close(fd);
					lwsl_user("Handshake verification file found, client exiting successfully.\n");
					break;
				}
			}
		}
	}

	/*
	 * QUIC egress is paced; anything still queued is dropped if we
	 * destroy the context immediately, truncating downloads at the
	 * peer.  Keep the event loop serviced for a grace period so it
	 * can all leave before we go.
	 */
	if (n >= 0)
		drain_context(context, 1000);

	/* free datagram exchange state and drop any .part leftovers */
	dgr_teardown();

	lws_context_destroy(context);

	if (dyn_protocols) {
		int idx = 0;
		while (dyn_protocols[idx].name) {
			if (strcmp(dyn_protocols[idx].name, "webtransport") != 0) {
				free((void *)dyn_protocols[idx].name);
			}
			idx++;
		}
		free(dyn_protocols);
	}

	return 0;
}
