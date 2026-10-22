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
 *
 * and, once a zone's signature is confirmed, what is done with it:
 *
 *  - a PUT of the version we already hold is taken as held, not refused, so
 *    the publisher is not sent an ERR and does not retry it for ever, and
 *    our fetch of it completes OK; nothing new is stored
 *  - an older version is refused
 *  - a newer one is stored in place of what we held, and handed to auth-dns
 *    only once auth-dns serves the zone: until then it is a sponge copy
 *  - once that one's payload is gone, its high-water mark still refuses the
 *    older version; a mark that can't be read refuses any version and is
 *    left as it is, and only with no mark at all is a version taken (G-533)
 *
 * and the plugin runs once per context: lwsws conf giving its DHT pvos to a
 * second vhost does not start another instance on the same DHT port, which
 * would have the kernel split the PUTs between them.  auth-dns on that vhost
 * registers with the instance that is running, and so hears of each zone a
 * PUT stores.
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define PUTT_STORE	"./put-store"
#define PUTT_TOTAL	100
/* a JWS starts "ey...": the plugin only takes PUTs that look like one */
#define PUTT_CHUNK	"eyJhbGciOi"

#define PUTT_HELD_DOMAIN	"held.example"
#define PUTT_HELD_SERIAL	2026102201u

static struct lws_context *context;
static struct lws_vhost *vh_second;
static char auth_path[512];
static int auth_calls;
static lws_sorted_usec_list_t sul_wait;
static lws_usec_t t_start;
static int fails, fetch_status = 99;

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

/* RRSIG validity as zone text, YYYYMMDDHHMMSS */

static void
putt_time(char *buf, size_t len, time_t t)
{
	struct tm tm;

	gmtime_r(&t, &tm);
	lws_snprintf(buf, len, "%04d%02d%02d%02d%02d%02d", tm.tm_year + 1900,
		     tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
		     tm.tm_sec);
}

/* PUTT_HELD_DOMAIN's zone at serial, signed and in date, written to path */

static int
putt_zone(const char *path, uint32_t serial)
{
	char z[512], exp[16], inc[16];
	time_t now = time(NULL);
	int fd, n;

	putt_time(exp, sizeof(exp), now + 30 * 86400);
	putt_time(inc, sizeof(inc), now - 3600);
	n = lws_snprintf(z, sizeof(z), "$ORIGIN " PUTT_HELD_DOMAIN ".\n"
		"@ IN SOA ns1." PUTT_HELD_DOMAIN ". host." PUTT_HELD_DOMAIN
		". ( %u 3600 1800 604800 60 )\n"
		"@ IN RRSIG SOA 8 2 60 %s %s 12345 " PUTT_HELD_DOMAIN ". AAAA\n"
		"www IN A 127.0.0.1\n", serial, exp, inc);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return 1;
	if (write(fd, z, (size_t)n) != n) {
		close(fd);
		return 1;
	}
	close(fd);

	return 0;
}

/* what auth-dns is told of each zone the plugin stores */

static void
putt_auth_cb(void *opaque, const char *domain, const char *payload_path)
{
	if (!strcmp(domain, PUTT_HELD_DOMAIN))
		lws_strncpy(auth_path, payload_path, sizeof(auth_path));
	auth_calls++;
}

static void
putt_fetch_cb(void *opaque, const char *domain, int status)
{
	fetch_status = status;
}

/*
 * A PUT of hash from h whose signature was confirmed, carrying the zone at
 * serial: what dht_dnssec_frag_take() makes of it
 */

static enum dht_dnssec_taken
putt_take(struct vhd_dht_dnssec *vhd, const char *hash,
	  const lws_sockaddr46 *h, uint32_t serial, int *tmp_left)
{
	enum dht_dnssec_taken r = DHT_DNSSEC_REFUSED;
	char path[256], ppath[256];
	struct dht_fragment *frag;

	frag = calloc(1, sizeof(*frag));
	if (!frag)
		return r;

	frag->vhd		= vhd;
	frag->dht_ctx		= vhd->dht;
	frag->inbound		= 1;
	frag->fd		= -1;
	frag->temp_token	= serial;
	frag->last_len		= strlen(PUTT_CHUNK);
	memcpy(&frag->from_sa, h, sizeof(h->sa4));
	frag->from_salen	= sizeof(h->sa4);
	lws_strncpy(frag->safe_hash, hash, sizeof(frag->safe_hash));
	lws_strncpy(frag->domain, PUTT_HELD_DOMAIN, sizeof(frag->domain));

	/* the JWS, which is not looked at again, and its payload */
	lws_snprintf(path, sizeof(path), PUTT_STORE "/tmp/%s.%08X", hash,
		     frag->temp_token);
	lws_snprintf(ppath, sizeof(ppath), "%s.payload", path);
	if (!putt_zone(path, serial) && !putt_zone(ppath, serial))
		r = dht_dnssec_frag_take(vhd, frag);

	*tmp_left = !access(path, F_OK) || !access(ppath, F_OK);
	unlink(path);
	unlink(ppath);
	free(frag);

	return r;
}

/* the newest serial stored for hash, or 0 if none */

static uint32_t
putt_stored_serial(const char *hash)
{
	struct lws_dir_args da;

	memset(&da, 0, sizeof(da));
	da.prefix = hash;
	lws_dir(PUTT_STORE "/cc/cc", &da, dht_dnssec_find_highest_serial_cb);

	return da.is_outdated ? (uint32_t)da.new_serial : 0;
}

static void
putt_take_cases(struct vhd_dht_dnssec *vhd)
{
	struct lws_dht_dnssec_subscribed_domain *sub;
	struct lws_dht_dnssec_fetch_req *req;
	char hash[65], held[512], mark[512];
	lws_sockaddr46 pub;
	int tmp_left, fd;
	struct stat st;

	putt_hash(hash, 0xa0);
	putt_v4(&pub, 7, 1000);

	/* the version we hold, as stored by an earlier PUT */
	lws_snprintf(held, sizeof(held), PUTT_STORE "/cc/cc/%s_%llu_%llu_%u"
		     ".payload", hash, (unsigned long long)time(NULL) + 3600,
		     (unsigned long long)time(NULL) + 30 * 86400,
		     PUTT_HELD_SERIAL);
	if (putt_expect((mkdir(PUTT_STORE "/cc", 0700) == 0 ||
			 errno == EEXIST) &&
			(mkdir(PUTT_STORE "/cc/cc", 0700) == 0 ||
			 errno == EEXIST) &&
			(mkdir(PUTT_STORE "/tmp", 0700) == 0 ||
			 errno == EEXIST) &&
			!putt_zone(held, PUTT_HELD_SERIAL), "a held zone"))
		return;

	/*
	 * auth-dns lives on the vhost that was refused its own instance, as on
	 * a node whose conf gave the DHT pvos to two vhosts
	 */
	putt_expect(vh_second && !lws_protocol_vh_priv_get(vh_second,
				lws_vhost_name_to_protocol(vh_second,
							   "lws-dht-dnssec")),
		    "a second vhost with a dht-port gets no instance of its own");
	putt_expect(!dht_dnssec_register_auth_cb(vh_second, putt_auth_cb,
						 NULL) &&
		    vhd->auth_cb == putt_auth_cb,
		    "auth-dns on it registers with the running instance");

	/* and a fetch of ours for it, that a holder answers */
	req = calloc(1, sizeof(*req));
	if (putt_expect(!!req, "fetch request"))
		return;
	lws_strncpy(req->domain, PUTT_HELD_DOMAIN, sizeof(req->domain));
	lws_strncpy(req->target_hash, hash, sizeof(req->target_hash));
	req->cb = putt_fetch_cb;
	req->vhd = vhd;
	lws_dll2_add_tail(&req->list, &vhd->fetch_reqs);

	putt_expect(putt_take(vhd, hash, &pub, PUTT_HELD_SERIAL, &tmp_left) ==
						DHT_DNSSEC_HELD && !tmp_left &&
		    !access(held, F_OK) &&
		    putt_stored_serial(hash) == PUTT_HELD_SERIAL,
		    "the version we hold is taken as held, not refused");
	putt_expect(fetch_status == LWS_DHT_DNSSEC_FETCH_OK &&
		    !dht_dnssec_find_fetch_req(vhd, hash),
		    "and our fetch of it completes OK");
	putt_expect(!auth_calls, "auth-dns is not told of the held version "
				 "again");

	putt_expect(putt_take(vhd, hash, &pub, PUTT_HELD_SERIAL - 1,
			      &tmp_left) == DHT_DNSSEC_REFUSED &&
		    putt_stored_serial(hash) == PUTT_HELD_SERIAL,
		    "an older version is refused");

	putt_expect(putt_take(vhd, hash, &pub, PUTT_HELD_SERIAL + 1,
			      &tmp_left) == DHT_DNSSEC_STORED && !tmp_left &&
		    access(held, F_OK) &&
		    putt_stored_serial(hash) == PUTT_HELD_SERIAL + 1,
		    "a newer version is stored in place of the held one");
	putt_expect(!auth_calls, "auth-dns, which doesn't serve the zone, "
				 "is not told of it");

	/*
	 * auth-dns subscribes to the zones it serves, by name: the zone's key
	 * here is made up, so give it the subscription that would be
	 */
	sub = calloc(1, sizeof(*sub));
	if (putt_expect(sub && lws_hex_to_byte_array(hash, sub->hash, 32) == 32,
			"a subscription")) {
		free(sub);
		return;
	}
	sub->vhd = vhd;
	lws_strncpy(sub->domain, PUTT_HELD_DOMAIN, sizeof(sub->domain));
	lws_dll2_add_tail(&sub->list, &vhd->subscribed_domains);

	putt_expect(putt_take(vhd, hash, &pub, PUTT_HELD_SERIAL + 2,
			      &tmp_left) == DHT_DNSSEC_STORED &&
		    auth_calls == 1 && strstr(auth_path, hash) &&
		    !access(auth_path, F_OK),
		    "once it subscribes to the zone, it is told of the next");

	/*
	 * Once the newer version's payload is gone (expired, swept), only its
	 * high-water mark stands between an older one and the store (G-505)
	 */
	unlink(auth_path);
	putt_expect(!putt_stored_serial(hash) &&
		    putt_take(vhd, hash, &pub, PUTT_HELD_SERIAL, &tmp_left) ==
						DHT_DNSSEC_REFUSED &&
		    !putt_stored_serial(hash) && auth_calls == 1,
		    "an older version is refused by the mark of a newer one "
		    "no longer held");

	/*
	 * A mark that can't be read fails closed, and is not replaced by the
	 * version offered (G-533); only one that is not there admits it
	 */
	lws_snprintf(mark, sizeof(mark), PUTT_STORE "/cc/cc/%s.hwm", hash);
	fd = open(mark, O_WRONLY | O_TRUNC);
	if (!putt_expect(fd >= 0 && write(fd, "x", 1) == 1, "garble the mark")) {
		putt_expect(putt_take(vhd, hash, &pub, PUTT_HELD_SERIAL + 2,
				      &tmp_left) == DHT_DNSSEC_REFUSED &&
			    !putt_stored_serial(hash) && auth_calls == 1 &&
			    !stat(mark, &st) && st.st_size == 1,
			    "a garbled mark refuses even a newer version, and "
			    "is left as it is");
		unlink(mark);
		putt_expect(putt_take(vhd, hash, &pub, PUTT_HELD_SERIAL + 2,
				      &tmp_left) == DHT_DNSSEC_STORED &&
			    putt_stored_serial(hash) == PUTT_HELD_SERIAL + 2 &&
			    auth_calls == 2,
			    "with no mark, the version is stored");
	}
	if (fd >= 0)
		close(fd);

	vhd->auth_cb = NULL;
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

	putt_take_cases(vhd);
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

	/* the same DHT pvos on a second vhost, as a misconfigured node has */
	info.vhost_name = "second";
	vh_second = lws_create_vhost(context, &info);

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
