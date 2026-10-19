/*
 * lws-api-test-dht-dnssec-fetch-opaque
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A zone fetch's completion is the only thing that knows how to release the
 * opaque its caller gave it (the plugin's own NOTIFY fetches give it a heap
 * strike tracker), so the fetch_zone() op calls it exactly once on every
 * path that is not a cancel, and never for a cancel (G-202).  This checks,
 * with the lws-dht-dnssec plugin built in and driven through its ops:
 *
 *  - a fetch refused at once (malformed hash token, no domain) completes
 *    as aborted before fetch_zone() returns, which returns nonzero
 *  - a pending fetch, and one merged into it, complete once between them,
 *    as aborted, when the vhost goes away unfinished
 *  - a cancelled fetch never completes: its opaque is the caller's again
 *  - a cancel with no domain takes back every fetch with that opaque, of
 *    any domain, and only those, as auth-dns does when its vhost goes,
 *    since fetches outlive the queries that started them (G-220)
 *
 * Each opaque is heap allocated and released only by its completion, so
 * one never released also shows as a leak under LSan.
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define FOT_STORE	"./fetch-opaque-store"

enum {
	FOT_MALFORMED,
	FOT_NO_DOMAIN,
	FOT_PENDING,
	FOT_CANCELLED,
	FOT_CANCEL_ALL,

	FOT_COUNT
};

static const char * const fot_names[] = {
	"refused for a malformed hash token",
	"refused for no domain",
	"pending, and a request merged into it",
	"cancelled",
	"cancelled with every domain of its opaque",
};

static int fot_calls[FOT_COUNT], fot_status[FOT_COUNT], fails;

struct fot_opaque {
	int		which;
};

static void
fot_fetch_cb(void *opaque, const char *domain, int status)
{
	struct fot_opaque *o = (struct fot_opaque *)opaque;

	fot_calls[o->which]++;
	fot_status[o->which] = status;
	free(o);
}

static struct fot_opaque *
fot_opaque_create(int which)
{
	struct fot_opaque *o = malloc(sizeof(*o));

	if (o)
		o->which = which;

	return o;
}

static int
fot_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);
		fails++;

		return 1;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);

	return 0;
}

static int
fot_fetch(const struct lws_dht_dnssec_ops *ops, struct lws_context *cx,
	  struct lws_vhost *vh, const char *domain, void *opaque,
	  int is_cancel)
{
	struct lws_dht_dnssec_fetch_zone_args args;

	memset(&args, 0, sizeof(args));
	args.vhost		= vh;
	args.domain		= domain;
	args.cb			= fot_fetch_cb;
	args.opaque		= opaque;
	args.is_cancel		= is_cancel;
	args.force_network	= 1;

	return ops->fetch_zone(cx, &args);
}

int
main(int argc, const char **argv)
{
	static const struct lws_protocols *pprotocols[] = {
		&lws_dht_dnssec_protocols[0], NULL
	};
	struct lws_protocol_vhost_options pvo[5], pvo_wrap;
	const struct lws_dht_dnssec_ops *ops = NULL;
	struct fot_opaque *o_pending, *o_cancel, *o_all;
	struct lws_context_creation_info info;
	const struct lws_protocols *pcol;
	const char *port, *tport;
	struct lws_vhost *vh = NULL;
	struct lws_context *cx;
	lws_usec_t t_start;
	int n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: dht-dnssec fetch opaque ownership\n");

	port = lws_cmdline_option(argc, argv, "--port");
	tport = lws_cmdline_option(argc, argv, "--target-port");
	if (!port || !tport || atoi(port) <= 0 || atoi(port) > 65535 ||
	    atoi(tport) <= 0 || atoi(tport) > 65535) {
		lwsl_err("%s: --port and --target-port <udp port> are required\n",
			 __func__);

		return 1;
	}

	lws_dir(FOT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(FOT_STORE);
	if (mkdir(FOT_STORE, 0700) && errno != EEXIST) {
		lwsl_err("%s: unable to create %s\n", __func__, FOT_STORE);

		return 1;
	}

	memset(pvo, 0, sizeof(pvo));
	pvo[0].name = "dht-storage-path";
	pvo[0].value = FOT_STORE;
	pvo[0].next = &pvo[1];
	pvo[1].name = "dht-port";
	pvo[1].value = port;
	pvo[1].next = &pvo[2];
	pvo[2].name = "dht-allow-private";
	pvo[2].value = "1";
	pvo[2].next = &pvo[3];
	pvo[3].name = "target-ip";
	pvo[3].value = "127.0.0.1";
	pvo[3].next = &pvo[4];
	pvo[4].name = "target-port";
	pvo[4].value = tport;

	memset(&pvo_wrap, 0, sizeof(pvo_wrap));
	pvo_wrap.name = "lws-dht-dnssec";
	pvo_wrap.value = "";
	pvo_wrap.options = pvo;

	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: lws init failed\n", __func__);

		return 1;
	}

	/* the plugin, on a vhost of its own */

	info.vhost_name = "fetcher";
	info.pprotocols = pprotocols;
	info.pvo = &pvo_wrap;
	vh = lws_create_vhost(cx, &info);
	pcol = vh ? lws_vhost_name_to_protocol(vh, "lws-dht-dnssec") : NULL;
	if (pcol)
		ops = (const struct lws_dht_dnssec_ops *)pcol->user;

	/* the vhost's protocols are initialized once the loop runs */
	t_start = lws_now_usecs();
	while (ops && !lws_protocol_vh_priv_get(vh, pcol) &&
	       lws_now_usecs() - t_start < 5 * LWS_US_PER_SEC)
		if (lws_service(cx, 0) < 0)
			break;

	if (fot_expect(ops && ops->fetch_zone &&
		       lws_protocol_vh_priv_get(vh, pcol),
		       "plugin instantiated"))
		goto bail;

	/* refused before anything was queued: completed before returning */

	n = fot_fetch(ops, cx, vh, "dht-hash-NOT-HEX",
		      fot_opaque_create(FOT_MALFORMED), 0);
	fot_expect(n && fot_calls[FOT_MALFORMED] == 1 &&
		   fot_status[FOT_MALFORMED] == LWS_DHT_DNSSEC_FETCH_ABORTED,
		   "malformed hash token refused and completed as aborted");

	n = fot_fetch(ops, cx, vh, NULL, fot_opaque_create(FOT_NO_DOMAIN), 0);
	fot_expect(n && fot_calls[FOT_NO_DOMAIN] == 1 &&
		   fot_status[FOT_NO_DOMAIN] == LWS_DHT_DNSSEC_FETCH_ABORTED,
		   "no domain refused and completed as aborted");

	/* pending: nobody answers, so it completes only at destroy */

	o_pending = fot_opaque_create(FOT_PENDING);
	n = fot_fetch(ops, cx, vh, "pending.example", o_pending, 0);
	fot_expect(!n && !fot_calls[FOT_PENDING], "fetch pending");
	n = fot_fetch(ops, cx, vh, "pending.example", o_pending, 0);
	fot_expect(!n && !fot_calls[FOT_PENDING],
		   "same fetch merged into the pending one");

	/* cancelled: the opaque comes back to us */

	o_cancel = fot_opaque_create(FOT_CANCELLED);
	n = fot_fetch(ops, cx, vh, "cancel.example", o_cancel, 0);
	fot_expect(!n, "fetch to cancel pending");
	n = fot_fetch(ops, cx, vh, "cancel.example", o_cancel, 1);
	fot_expect(!n && !fot_calls[FOT_CANCELLED],
		   "cancel does not complete the fetch");
	free(o_cancel);

	/* one opaque for two domains, taken back by one cancel naming none */

	o_all = fot_opaque_create(FOT_CANCEL_ALL);
	n = fot_fetch(ops, cx, vh, "all-1.example", o_all, 0);
	n |= fot_fetch(ops, cx, vh, "all-2.example", o_all, 0);
	fot_expect(!n, "two fetches with one opaque pending");
	n = fot_fetch(ops, cx, vh, NULL, o_all, 1);
	fot_expect(!n && !fot_calls[FOT_CANCEL_ALL],
		   "cancel with no domain does not complete them");
	free(o_all);

	/* a little service, so the fetches really went out */

	for (n = 0; n < 5; n++)
		if (lws_service(cx, 0) < 0)
			break;

bail:
	lws_context_destroy(cx);

	fot_expect(fot_calls[FOT_PENDING] == 1 &&
		   fot_status[FOT_PENDING] == LWS_DHT_DNSSEC_FETCH_ABORTED,
		   "pending fetch completed once, as aborted, at destroy");
	fot_expect(!fot_calls[FOT_CANCELLED],
		   "cancelled fetch never completed");
	fot_expect(!fot_calls[FOT_CANCEL_ALL],
		   "fetches cancelled with no domain never completed");

	for (n = 0; n < FOT_COUNT; n++)
		lwsl_user("%s: %s: %d completion(s), status %d\n", __func__,
			  fot_names[n], fot_calls[n], fot_status[n]);

	lws_dir(FOT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(FOT_STORE);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
