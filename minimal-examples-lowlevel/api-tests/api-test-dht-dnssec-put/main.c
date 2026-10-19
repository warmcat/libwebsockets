/*
 * lws-api-test-dht-dnssec-put
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A node running the lws-dht-dnssec plugin reassembles each zone a peer PUTs
 * to it in a temp file, and the zone's key, SHA256("lws-dnssec-dht-" +
 * domain), is public.  The plugin is built into this test, and its PUT and
 * RSP handlers are driven directly with chunks from made-up senders, so many
 * hosts can be had without a network:
 *
 *  - one host, opening reassemblies for many hashes from several ports, or
 *    from several IPv6 addresses of one /64, only gets a few of the slots,
 *    and another host can still PUT
 *  - a host that opens a reassembly for a zone's key first does not stop the
 *    real publisher, at another address, from PUTting the same key
 *  - nor does it stop our own fetch of that key: the responder's first RSP
 *    starts a fetch reassembly of its own
 *  - but only a host our fetch's GET went to can start it: an RSP from any
 *    other host is refused, one from another port of the host we asked is
 *    not (G-153)
 *  - however long a sender keeps a reassembly making progress, it is reaped
 *    at a fixed time after it started
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define PUTT_STORE	"./put-store"
#define PUTT_TOTAL	100
/* a JWS starts "ey...": the plugin only takes PUTs that look like one */
#define PUTT_CHUNK	"eyJhbGciOi"

static struct lws_context *context;
static lws_sorted_usec_list_t sul_wait;
static lws_usec_t t_start;
static int fails;

static int
putt_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);
		fails++;

		return 1;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);

	return 0;
}

static void
putt_v4(lws_sockaddr46 *sa46, uint8_t last, uint16_t port)
{
	memset(sa46, 0, sizeof(*sa46));
	sa46->sa4.sin_family = AF_INET;
	/* TEST-NET-3: never routed, so what the plugin sends back goes nowhere */
	sa46->sa4.sin_addr.s_addr = htonl(0xcb007100u | last);
	sa46->sa4.sin_port = htons(port);
}

/* a zone key: 64 hex chars, all c but the last two, which are n */

static void
putt_hash(char *hash, unsigned int n)
{
	memset(hash, 'c', 62);
	lws_snprintf(hash + 62, 3, "%02x", n & 0xff);
}

static int
putt_chunk(struct vhd_dht_dnssec *vhd, int rsp, const char *hash,
	   unsigned long long offset, const lws_sockaddr46 *from)
{
	struct lws_dht_verb_dispatch_args args;
	struct lws_dht_msg msg;

	memset(&msg, 0, sizeof(msg));
	lws_strncpy(msg.verb, rsp ? "RSP" : "PUT", sizeof(msg.verb));
	lws_strncpy(msg.hash, hash, sizeof(msg.hash));
	msg.offset	= offset;
	msg.len		= PUTT_TOTAL;
	msg.payload	= PUTT_CHUNK;
	msg.payload_len	= strlen(PUTT_CHUNK);

	memset(&args, 0, sizeof(args));
	args.ctx	= vhd->dht;
	args.msg	= &msg;
	args.from	= (const struct sockaddr *)from;
	args.fromlen	= from->sa4.sin_family == AF_INET ?
				sizeof(struct sockaddr_in) :
				sizeof(struct sockaddr_in6);

	return rsp ? verb_rsp_handler(vhd, &args) :
		     verb_put_handler(vhd, &args);
}

/* the reassembly of hash from the host of from, PUT or fetch, or NULL */

static struct dht_fragment *
putt_frag(struct vhd_dht_dnssec *vhd, const char *hash,
	  const lws_sockaddr46 *from, int inbound)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->fragments)) {
		struct dht_fragment *f = lws_container_of(d,
					struct dht_fragment, list);

		if (f->inbound == inbound && !strcmp(f->safe_hash, hash) &&
		    !lws_sa46_compare_ads((const lws_sockaddr46 *)&f->from_sa,
					  from))
			return f;
	} lws_end_foreach_dll(d);

	return NULL;
}

/* how many PUT reassemblies the host of from has */

static int
putt_count(struct vhd_dht_dnssec *vhd, const lws_sockaddr46 *from)
{
	int n = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->fragments)) {
		struct dht_fragment *f = lws_container_of(d,
					struct dht_fragment, list);

		if (f->inbound &&
		    lws_dht_same_host((const struct sockaddr *)&f->from_sa,
				      (const struct sockaddr *)from))
			n++;
	} lws_end_foreach_dll(d);

	return n;
}

static void
putt_run(struct vhd_dht_dnssec *vhd)
{
	struct lws_dht_dnssec_fetch_req *req;
	lws_sockaddr46 h1, h2, h3, h4, resp, stranger;
	char get[128];
	struct dht_fragment *f;
	char hash[65], victim[65];
	lws_usec_t left;
	int n;

	/* one host, many hashes, from several ports */

	for (n = 0; n < 2 * LWS_DHT_DNSSEC_MAX_FRAGMENTS_PER_SRC; n++) {
		putt_v4(&h1, 1, (uint16_t)(1000 + n));
		putt_hash(hash, (unsigned int)n);
		putt_chunk(vhd, 0, hash, 0, &h1);
	}
	putt_expect(putt_count(vhd, &h1) == LWS_DHT_DNSSEC_MAX_FRAGMENTS_PER_SRC,
		    "one IPv4 host gets its share of reassemblies, no more");

#if defined(LWS_WITH_IPV6)
	{
		lws_sockaddr46 h6;

		/* 2001:db8:1:2::n, all in one /64 */
		for (n = 0; n < 2 * LWS_DHT_DNSSEC_MAX_FRAGMENTS_PER_SRC; n++) {
			memset(&h6, 0, sizeof(h6));
			h6.sa6.sin6_family = AF_INET6;
			h6.sa6.sin6_port = htons(2000);
			h6.sa6.sin6_addr.s6_addr[0] = 0x20;
			h6.sa6.sin6_addr.s6_addr[1] = 0x01;
			h6.sa6.sin6_addr.s6_addr[2] = 0x0d;
			h6.sa6.sin6_addr.s6_addr[3] = 0xb8;
			h6.sa6.sin6_addr.s6_addr[5] = 1;
			h6.sa6.sin6_addr.s6_addr[7] = 2;
			h6.sa6.sin6_addr.s6_addr[15] = (uint8_t)(1 + n);
			putt_hash(hash, (unsigned int)(0x40 + n));
			putt_chunk(vhd, 0, hash, 0, &h6);
		}
		putt_expect(putt_count(vhd, &h6) ==
					LWS_DHT_DNSSEC_MAX_FRAGMENTS_PER_SRC,
			    "one IPv6 /64 gets one host's share, no more");
	}
#endif

	putt_v4(&h2, 2, 1000);
	putt_hash(hash, 0x80);
	putt_chunk(vhd, 0, hash, 0, &h2);
	putt_expect(putt_count(vhd, &h2) == 1, "another host can still PUT");

	/*
	 * h3 opens the victim zone's key first; the real publisher h4 must
	 * still get a reassembly of its own for it
	 */

	putt_hash(victim, 0xee);
	putt_v4(&h3, 3, 1000);
	putt_chunk(vhd, 0, victim, 0, &h3);
	putt_v4(&h4, 4, 1000);
	putt_chunk(vhd, 0, victim, 0, &h4);
	putt_expect(putt_frag(vhd, victim, &h3, 1) &&
		    putt_frag(vhd, victim, &h4, 1),
		    "a PUT of a key does not lock other publishers out of it");

	/*
	 * ... and our own fetch of it, whose GET went to resp: the
	 * responder's first RSP must start a fetch reassembly, not be refused
	 * as a stranger to h3's PUT.  But a host the GET did not go to must
	 * not start it, racing the responder.
	 */

	req = calloc(1, sizeof(*req));
	if (putt_expect(!!req, "fetch request"))
		return;
	lws_strncpy(req->domain, "victim.example", sizeof(req->domain));
	lws_strncpy(req->target_hash, victim, sizeof(req->target_hash));
	req->vhd = vhd;
	lws_dll2_add_tail(&req->list, &vhd->fetch_reqs);

	putt_v4(&resp, 5, 1000);
	lws_dht_msg_gen(get, sizeof(get), "GET", victim, 0, 1024);
	dht_dnssec_fetch_req_send(vhd, req, (const struct sockaddr *)&resp,
				  get);

	putt_v4(&stranger, 6, 1000);
	putt_chunk(vhd, 1, victim, 0, &stranger);
	putt_expect(!dht_dnssec_find_fragment(vhd, victim),
		    "an RSP from a host our GET did not go to is refused");

	/* the host we asked, answering from another of its ports */
	putt_v4(&resp, 5, 1001);
	putt_chunk(vhd, 1, victim, 0, &resp);
	putt_expect(!!putt_frag(vhd, victim, &resp, 0),
		    "an inbound PUT of a key does not block our fetch of it");

	lws_dll2_remove(&req->list);
	free(req);

	/*
	 * A reassembly that keeps making progress still ends a fixed time
	 * after it started: make h2's look nearly that old, then send it more
	 */

	putt_hash(hash, 0x80);
	f = putt_frag(vhd, hash, &h2, 1);
	if (putt_expect(!!f, "h2's reassembly"))
		return;
	f->created = lws_now_usecs() -
		     (LWS_DHT_DNSSEC_FRAGMENT_MAX_SECS - 5) * LWS_US_PER_SEC;
	putt_chunk(vhd, 0, hash, strlen(PUTT_CHUNK), &h2);
	f = putt_frag(vhd, hash, &h2, 1);
	left = f ? f->sul_stale.us - lws_now_usecs() : 0;
	putt_expect(f && f->received_len == 2 * strlen(PUTT_CHUNK) &&
		    left > 0 && left <= 5 * LWS_US_PER_SEC,
		    "progress does not extend a reassembly past its lifetime");
}

/* the plugin makes its DHT once the system is up: wait for that */

static void
putt_wait_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_dht_dnssec *vhd = get_dnssec_vhd(context,
			lws_get_vhost_by_name(context, "default"));

	if (!vhd || !vhd->dht) {
		if (lws_now_usecs() - t_start < 10 * LWS_US_PER_SEC) {
			lws_sul_schedule(context, 0, &sul_wait, putt_wait_cb,
					 50 * LWS_US_PER_MS);
			return;
		}
		putt_expect(0, "plugin instantiated");
	} else
		putt_run(vhd);

	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	static const struct lws_protocols *pprotocols[] = {
		&lws_dht_dnssec_protocols[0], NULL
	};
	struct lws_protocol_vhost_options pvo[3], pvo_wrap;
	struct lws_context_creation_info info;
	const char *port;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: dht-dnssec PUT reassemblies\n");

	port = lws_cmdline_option(argc, argv, "--port");
	if (!port || atoi(port) <= 0 || atoi(port) > 65535) {
		lwsl_err("%s: --port <udp port> is required\n", __func__);

		return 1;
	}

	lws_dir(PUTT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(PUTT_STORE);
	if (mkdir(PUTT_STORE, 0700) && errno != EEXIST) {
		lwsl_err("%s: unable to create %s\n", __func__, PUTT_STORE);

		return 1;
	}

	memset(pvo, 0, sizeof(pvo));
	pvo[0].name = "dht-storage-path";
	pvo[0].value = PUTT_STORE;
	pvo[0].next = &pvo[1];
	pvo[1].name = "dht-port";
	pvo[1].value = port;
	pvo[1].next = &pvo[2];
	pvo[2].name = "dht-allow-private";
	pvo[2].value = "1";

	memset(&pvo_wrap, 0, sizeof(pvo_wrap));
	pvo_wrap.name = "lws-dht-dnssec";
	pvo_wrap.value = "";
	pvo_wrap.options = pvo;

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.pprotocols = pprotocols;
	info.pvo = &pvo_wrap;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: lws init failed\n", __func__);

		return 1;
	}

	t_start = lws_now_usecs();
	lws_sul_schedule(context, 0, &sul_wait, putt_wait_cb,
			 50 * LWS_US_PER_MS);

	while (lws_service(context, 0) >= 0)
		;

	lws_sul_cancel(&sul_wait);
	lws_context_destroy(context);

	lws_dir(PUTT_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(PUTT_STORE);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
