/*
 * lws-api-test-ota
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Runs lws_ota against a fake platform OTA layer (the lws_ota_ops_t a real
 * platform, like esp32, provides) and a small raw socket http server in the
 * same process, and confirms that however an update ends, lws_ota leaves the
 * platform, the system state and the periodic checks the way they should be:
 *
 *  - complete: the whole image is written and finalized, and reboot() called
 *  - cut: the image connection closes partway through; the platform op is
 *    aborted promptly, not after the 45s drain timeout
 *  - stall-timeout: the stream times out while a flash write is in flight;
 *    the lws_ota_t must stay alive until the write completes and the ABORT
 *    after it is acknowledged (the write completion reads g->buf)
 *  - refuse-modal: user code refuses to enter MODAL_UPDATING until lws_ota
 *    gives up
 *  - context-destroy: the context is destroyed while a flash write is in
 *    flight; the platform must be told to let go synchronously (ota_detach)
 *
 * After each of the first four, the system must be back in OPERATIONAL, the
 * periodic update check rescheduled, and the platform holding nothing.  The
 * platform must never be given an op while one is in flight, or after ABORT or
 * FINALIZE.
 *
 * The OTA manifest is signed at runtime with ota-test.private.jwk, so the test
 * is only built when lws was configured with LWS_OTA_PUBLIC_JWK_FILE pointing
 * at ota-test.public.jwk in this directory (see README.md).
 *
 * The fake platform needs the layout of struct lws_ota, which is private,
 * as the platform implementations inside lws do.
 */

#include <libwebsockets.h>
#include "private-lib-core.h"

#include <string.h>

enum {
	LWS_SW_PORT,
	LWS_SW_SERVER,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	= { "-p",	"Port for the test update server "
					"(default 7681)" },
	[LWS_SW_SERVER]	= { "--server",	"Address the client connects to "
					"(default localhost)" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

typedef enum {
	OTC_COMPLETE,
	OTC_CUT,
	OTC_STALL_TIMEOUT,
	OTC_REFUSE_MODAL,
	OTC_CONTEXT_DESTROY,

	OTC_COUNT
} ota_case_t;

static const char * const case_names[] = {
	"complete", "cut", "stall-timeout", "refuse-modal", "context-destroy"
};

#define IMG_LEN		20000
#define CASE_DEADLINE	(20 * LWS_US_PER_SEC)

static uint8_t img[IMG_LEN], img_hash[64];
static uint8_t gz[(IMG_LEN * 9) / 8 + 32];
static size_t gz_len;
static char manifest[2048];
static size_t manifest_len;

static struct lws_context *context;
static lws_state_notify_link_t nl;
static lws_sorted_usec_list_t sul_poll;
static lws_usec_t case_start;
static ota_case_t cur_case;
static int failed, refusals, reboots, case_triggered, case_seen_ss;

/*
 * The fake platform OTA layer.  Like a real one, it does its ops "elsewhere"
 * and reports each completion later, by setting async_r / async_completed and
 * waking the event loop with lws_cancel_service().  Flash writes read g->buf
 * when they complete, like a write that is in flight on another task would.
 */

static struct {
	struct lws_ota			*g;	/* what the platform holds */
	lws_sorted_usec_list_t		sul;	/* completes the op in flight */
	struct lws_genhash_ctx		hash;
	lws_ota_async_t			op;	/* op in flight, or 0 */
	size_t				written;
	int				starts, writes, aborts, finalizes,
					detaches, errors;
	char				hold_writes;
	char				hash_inited;
	char				hash_ok;
} fp;

static void
fp_error(const char *what)
{
	lwsl_err("%s: platform: %s\n", case_names[cur_case], what);
	fp.errors++;
}

static void
fp_hash_drop(void)
{
	if (fp.hash_inited) {
		lws_genhash_destroy(&fp.hash, NULL);
		fp.hash_inited = 0;
	}
}

static void
fp_complete_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_ota *g = fp.g;
	uint8_t digest[64];
	lws_ota_async_t op = fp.op;

	if (!g || !op) {
		fp_error("completion with nothing in flight");
		return;
	}

	switch (op) {
	case LWS_OTA_ASYNC_WRITE:
		/* this is where an in-flight write would read g->buf */
		if (g->buf_len > sizeof(g->buf) ||
		    fp.written + g->buf_len > IMG_LEN) {
			fp_error("write overflows the image");
			break;
		}
		if (fp.hash_inited &&
		    lws_genhash_update(&fp.hash, g->buf, g->buf_len))
			fp_error("hash update");
		fp.written += g->buf_len;
		break;

	case LWS_OTA_ASYNC_FINALIZE:
		if (fp.hash_inited) {
			lws_genhash_destroy(&fp.hash, digest);
			fp.hash_inited = 0;
			fp.hash_ok = fp.written == IMG_LEN &&
				     !memcmp(digest, img_hash, sizeof(digest));
		}
		break;

	case LWS_OTA_ASYNC_ABORT:
		fp_hash_drop();
		break;

	default:
		break;
	}

	fp.op = 0;
	g->async_r = LWSOTARET_OK;
	g->async_completed = 1;

	if (op == LWS_OTA_ASYNC_ABORT || op == LWS_OTA_ASYNC_FINALIZE)
		/* the platform lets go of g */
		fp.g = NULL;

	lws_cancel_service(context);
}

static void
fp_ota_queue(struct lws_ota *g, lws_ota_async_t a)
{
	if (g != fp.g) {
		fp_error("op for an lws_ota the platform does not hold");
		return;
	}
	if (fp.op) {
		fp_error("op queued while another is in flight");
		return;
	}

	g->async_last = a; /* as the esp32 implementation does */
	fp.op = a;

	switch (a) {
	case LWS_OTA_ASYNC_WRITE:
		fp.writes++;
		if (fp.hold_writes)
			/* the test decides when this write completes */
			return;
		break;
	case LWS_OTA_ASYNC_ABORT:
		fp.aborts++;
		break;
	case LWS_OTA_ASYNC_FINALIZE:
		fp.finalizes++;
		break;
	default:
		break;
	}

	/* an erase at START takes a while */
	lws_sul_schedule(context, 0, &fp.sul, fp_complete_cb,
			 a == LWS_OTA_ASYNC_START ? 50 * LWS_US_PER_MS :
						    LWS_US_PER_MS);
}

static int
fp_ota_start(struct lws_ota *g)
{
	if (fp.g) {
		fp_error("start while already holding an lws_ota");
		return 1;
	}

	fp.g = g;
	fp.starts++;
	fp.written = 0;
	if (lws_genhash_init(&fp.hash, LWS_GENHASH_TYPE_SHA512)) {
		fp_error("hash init");
		return 1;
	}
	fp.hash_inited = 1;

	fp_ota_queue(g, LWS_OTA_ASYNC_START);

	return 0;
}

static void
fp_ota_detach(struct lws_ota *g)
{
	fp.detaches++;

	if (!fp.g)
		/* already let go of it */
		return;

	if (g != fp.g) {
		fp_error("detach of an lws_ota the platform does not hold");
		return;
	}

	/* abort whatever is in flight, synchronously */
	lws_sul_cancel(&fp.sul);
	fp_hash_drop();
	fp.op = 0;
	fp.g = NULL;
}

static int
fp_ota_get_last_fw_unixtime(uint64_t *fw_unixtime)
{
	return 1; /* nothing known, so any update is newer */
}

static int
fp_ota_progress(lws_ota_ret_t state, int percent)
{
	return 0;
}

static int
fp_reboot(void)
{
	reboots++;

	return 0;
}

static lws_system_ops_t system_ops = {
	.reboot					= fp_reboot,
	.ota_ops = {
		.ota_start			= fp_ota_start,
		.ota_queue			= fp_ota_queue,
		.ota_detach			= fp_ota_detach,
		.ota_progress			= fp_ota_progress,
		.ota_get_last_fw_unixtime	= fp_ota_get_last_fw_unixtime,
		/* the next check comes soon after one ends */
		.ota_periodic_check_secs	= 1,
	},
};

/*
 * The update server, a raw socket server speaking just enough http/1.1
 */

typedef struct srv_pss {
	char			req[1024];
	size_t			req_len;
	char			responded;
	char			hold;
} srv_pss_t;

static uint8_t txb[LWS_PRE + sizeof(gz) + 256];

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	srv_pss_t *pss = (srv_pss_t *)user;
	const uint8_t *body;
	size_t body_len;
	char *p, *start;
	int n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss->responded)
			break;

		if (len > sizeof(pss->req) - 1 - pss->req_len) {
			lwsl_err("%s: request too large\n", __func__);
			return -1;
		}
		memcpy(pss->req + pss->req_len, in, len);
		pss->req_len += len;
		pss->req[pss->req_len] = '\0';

		if (strstr(pss->req, "\r\n\r\n"))
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pss->responded) {
			if (pss->hold)
				/* say nothing more, until the client gives up */
				break;
			return -1;
		}

		if (strstr(pss->req, " /ota/") &&
		    strstr(pss->req, "/manifest.jws ")) {
			body = (const uint8_t *)manifest;
			body_len = manifest_len;
		} else if (strstr(pss->req, " /ota/") &&
			   strstr(pss->req, "/image.gz ")) {
			body = gz;
			body_len = gz_len;
			switch (cur_case) {
			case OTC_COMPLETE:
				break;
			case OTC_CUT:
				/* half of it, then close */
				body_len = gz_len / 2;
				break;
			default:
				/* half of it, then hold the connection */
				body_len = gz_len / 2;
				pss->hold = 1;
				break;
			}
		} else {
			lwsl_err("%s: unexpected request\n", __func__);
			return -1;
		}

		/* Content-Length always says the whole thing */

		start = p = (char *)txb + LWS_PRE;
		p += lws_snprintf(p, 256, "HTTP/1.1 200 OK\r\n"
				  "Content-Type: application/octet-stream\r\n"
				  "Content-Length: %u\r\n"
				  "Connection: close\r\n\r\n",
				  (unsigned int)(body == gz ? gz_len : body_len));
		memcpy(p, body, body_len);
		p += body_len;

		n = lws_ptr_diff(p, start);
		if (lws_write(wsi, (uint8_t *)start, (size_t)n,
			      LWS_WRITE_RAW) != n)
			return -1;

		pss->responded = 1;
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "ota-srv", callback_srv, sizeof(srv_pss_t), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The test sequencing
 */

static void
finish(int fail)
{
	if (fail)
		failed = 1;
	lws_default_loop_exit(context);
}

static int
check(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAIL: %s\n", case_names[cur_case], what);
		failed = 1;
	}

	return !cond;
}

/* what must be true when any check / update has ended */

static void
check_ended(void)
{
	lws_state_manager_t *mgr = lws_system_get_state_manager(context);

	check(mgr->state == LWS_SYSTATE_OPERATIONAL,
	      "system state not back to OPERATIONAL");
	check(!lws_dll2_is_detached(&context->sul_ota_periodic.list),
	      "periodic update check not scheduled");
	check(!fp.g, "platform still holds the lws_ota");
	check(!fp.op, "platform op still in flight");
	check(!fp.errors, "platform saw bad op sequencing");
}

static void
case_ended(void)
{
	lwsl_user("--- %s: ended: starts %d, writes %d, written %u, "
		  "aborts %d, finalizes %d, detaches %d, reboots %d\n",
		  case_names[cur_case], fp.starts, fp.writes,
		  (unsigned int)fp.written, fp.aborts, fp.finalizes,
		  fp.detaches, reboots);

	check_ended();

	switch (cur_case) {
	case OTC_COMPLETE:
		check(fp.starts == 1 && fp.finalizes == 1 && !fp.aborts,
		      "not started once and finalized");
		check(fp.hash_ok, "written image differs");
		check(reboots == 1, "no reboot");
		break;
	case OTC_CUT:
	case OTC_STALL_TIMEOUT:
		check(fp.starts == 1 && fp.writes && fp.aborts == 1 &&
		      !fp.finalizes, "not started, written and aborted");
		check(!reboots, "reboot");
		break;
	case OTC_REFUSE_MODAL:
		check(refusals > 0, "modal was not asked for");
		check(!fp.starts, "platform ota started without modal");
		break;
	default:
		check(0, "unexpected end");
		break;
	}

	if (failed) {
		finish(1);
		return;
	}

	lwsl_user("--- %s: ok\n", case_names[cur_case]);

	/* the periodic check starts the next one */

	cur_case++;
	lws_sul_cancel(&fp.sul);
	fp_hash_drop();
	memset(&fp, 0, sizeof(fp));
	reboots = refusals = case_triggered = case_seen_ss = 0;
	fp.hold_writes = cur_case == OTC_STALL_TIMEOUT ||
			 cur_case == OTC_CONTEXT_DESTROY;
	case_start = lws_now_usecs();
	lwsl_user("--- %s ---\n", case_names[cur_case]);
}

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	if (lws_now_usecs() - case_start > CASE_DEADLINE) {
		lwsl_err("%s: FAIL: timed out\n", case_names[cur_case]);
		finish(1);
		return;
	}

	if (context->ota_ss)
		case_seen_ss = 1;
	else
		if (case_seen_ss) {
			case_ended();
			if (failed)
				return;
		}

	switch (cur_case) {
	case OTC_STALL_TIMEOUT:
		if (!case_triggered && context->ota_ss &&
		    fp.op == LWS_OTA_ASYNC_WRITE) {
			/*
			 * The transfer is stalled and a flash write is in
			 * flight: make the stream time out now, as if the
			 * download had stalled for long enough.  Then let the
			 * write complete a bit later.
			 */
			lwsl_user("%s: timing out with write in flight\n",
				  __func__);
			case_triggered = 1;
			lws_ss_start_timeout(context->ota_ss, 1);
			lws_sul_schedule(context, 0, &fp.sul, fp_complete_cb,
					 200 * LWS_US_PER_MS);
		}
		break;

	case OTC_REFUSE_MODAL:
		if (!case_triggered && context->ota_ss && refusals) {
			/* stand in for lws_ota's 30s limit on waiting */
			case_triggered = 1;
			lws_ss_start_timeout(context->ota_ss, 1);
		}
		break;

	case OTC_CONTEXT_DESTROY:
		if (!case_triggered && context->ota_ss &&
		    fp.op == LWS_OTA_ASYNC_WRITE) {
			lwsl_user("%s: destroying context with write in "
				  "flight\n", __func__);
			case_triggered = 1;
			finish(0);
			return;
		}
		break;

	default:
		break;
	}

	lws_sul_schedule(context, 0, &sul_poll, poll_cb, 20 * LWS_US_PER_MS);
}

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	if (current != target && target == LWS_SYSTATE_MODAL_UPDATING &&
	    cur_case == OTC_REFUSE_MODAL) {
		lwsl_user("%s: refusing MODAL_UPDATING\n", __func__);
		refusals++;

		return 1;
	}

	if (current == LWS_SYSTATE_OPERATIONAL &&
	    target == LWS_SYSTATE_OPERATIONAL && !case_start) {
		/* the first time we get to OPERATIONAL */
		case_start = lws_now_usecs();
		lwsl_user("--- %s ---\n", case_names[cur_case]);
		lws_sul_schedule(context, 0, &sul_poll, poll_cb,
				 20 * LWS_US_PER_MS);
	}

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

/*
 * The update image: IMG_LEN bytes of noise, gzipped as one deflate block of
 * literals using the fixed huffman codes, and a manifest describing it, signed
 * by the test key
 */

typedef struct {
	uint8_t		*p;
	uint32_t	acc;
	int		nbits;
} bitw_t;

static void
bw_put(bitw_t *bw, uint32_t v, int n) /* lsb-first */
{
	bw->acc |= v << bw->nbits;
	bw->nbits += n;
	while (bw->nbits >= 8) {
		*bw->p++ = (uint8_t)bw->acc;
		bw->acc >>= 8;
		bw->nbits -= 8;
	}
}

static void
bw_put_huff(bitw_t *bw, uint32_t code, int n) /* huffman codes are msb-first */
{
	while (n--)
		bw_put(bw, (code >> n) & 1, 1);
}

static int
make_update(void)
{
	char hex[129], temp[4096];
	struct lws_genhash_ctx hc;
	struct lws_jwk jwk;
	uint32_t crc, x = 0x12345678;
	bitw_t bw;
	size_t n;
	uint8_t *p = gz;

	for (n = 0; n < IMG_LEN; n++) {
		x = x * 1103515245u + 12345u;
		img[n] = (uint8_t)(x >> 16);
	}

	if (lws_genhash_init(&hc, LWS_GENHASH_TYPE_SHA512) ||
	    lws_genhash_update(&hc, img, sizeof(img)) ||
	    lws_genhash_destroy(&hc, img_hash))
		return 1;

	lws_hex_from_byte_array(img_hash, sizeof(img_hash), hex, sizeof(hex));

	/* gzip header: deflate, no flags, no mtime, unknown OS */
	*p++ = 0x1f; *p++ = 0x8b; *p++ = 8; *p++ = 0;
	*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
	*p++ = 0; *p++ = 0xff;

	/* one final block, fixed huffman codes, all literals */
	memset(&bw, 0, sizeof(bw));
	bw.p = p;
	bw_put(&bw, 1, 1);	/* BFINAL */
	bw_put(&bw, 1, 2);	/* BTYPE 01 */
	for (n = 0; n < IMG_LEN; n++)
		if (img[n] < 144)
			bw_put_huff(&bw, 0x30u + img[n], 8);
		else
			bw_put_huff(&bw, 0x190u + img[n] - 144u, 9);
	bw_put_huff(&bw, 0, 7);	/* end of block */
	if (bw.nbits)
		bw_put(&bw, 0, 8 - bw.nbits);
	p = bw.p;

	crc = lws_crc32(0, img, IMG_LEN);
	for (n = 0; n < 4; n++)
		*p++ = (uint8_t)(crc >> (8 * n));
	for (n = 0; n < 4; n++)
		*p++ = (uint8_t)((uint32_t)IMG_LEN >> (8 * n));

	gz_len = lws_ptr_diff_size_t(p, gz);

	if (lws_jwk_load(&jwk, "ota-test.private.jwk", NULL, NULL)) {
		lwsl_err("%s: unable to load ota-test.private.jwk\n", __func__);
		return 1;
	}

	manifest_len = sizeof(manifest);
	n = (size_t)lws_jwt_sign_compact(context, &jwk, "ES512", manifest,
				&manifest_len, temp, sizeof(temp),
				"{\"variant\":\"%s\",\"path\":\"image.gz\","
				"\"size\":%u,\"unixtime\":%llu,"
				"\"sha512\":\"%s\"}", lws_ota_variant_name(),
				IMG_LEN, (unsigned long long)lws_now_secs(),
				hex);
	lws_jwk_destroy(&jwk);
	if (n) {
		lwsl_err("%s: unable to sign manifest\n", __func__);
		return 1;
	}

	return 0;
}

int
main(int argc, const char **argv)
{
	const char *p, *server_ads = "localhost";
	struct lws_context_creation_info info;
	char policy[1024];
	int port = 7681;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw)))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw)))
		server_ads = p;

	lwsl_user("LWS API selftest: lws_ota lifecycle\n");

	lws_snprintf(policy, sizeof(policy),
		"{\"release\":\"01234567\",\"product\":\"myproduct\","
		 "\"schema-version\":1,"
		 "\"retry\":[{\"default\":{\"backoff\":[1000,2000,3000],"
			"\"conceal\":3,\"jitterpc\":20,"
			"\"svalidping\":30,\"svalidhup\":35}}],"
		 "\"s\":[{\"ota\":{"
			"\"endpoint\":\"%s\",\"port\":%d,\"protocol\":\"h1\","
			"\"http_method\":\"GET\","
			"\"http_url\":\"ota/${ota_variant}/${file}\","
			"\"metadata\":[{\"ota_variant\":\"\",\"file\":\"\"}],"
			"\"opportunistic\":true,"
			"\"retry\":\"default\",\"tls\":false}}]}",
		server_ads, port);

	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;

	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pss_policies_json		= policy;
	info.register_notifier_list	= app_notifier_list;
	info.system_ops			= &system_ops;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (make_update())
		goto bail;

	/* the update server vhost */

	info.vhost_name	= "ota-srv";
	info.port	= port;
	info.protocols	= protocols_srv;
	info.options	= LWS_SERVER_OPTION_ONLY_RAW;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	lws_context_default_loop_run_destroy(context);

	/* the context, and the ota stream with it, is gone now */

	fp_hash_drop();

	if (!failed) {
		if (cur_case != OTC_CONTEXT_DESTROY)
			check(0, "did not get to the last case");
		check(fp.detaches == 1, "platform not detached at destroy");
		check(!fp.g, "platform still holds the destroyed lws_ota");
		check(!fp.errors, "platform saw bad op sequencing");
	}

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;

bail:
	lws_context_destroy(context);

	return 1;
}
