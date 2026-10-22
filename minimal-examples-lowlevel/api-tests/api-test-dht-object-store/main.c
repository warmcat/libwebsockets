/*
 * lws-api-test-dht-object-store
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The lws-dht-object-store plugin reassembles each object a peer PUTs to it
 * (or sends in RSP to a GET of ours) in a partial file, and has a fixed
 * number of slots for those transfers.  The plugin is built into this test,
 * and its PUT handler is driven directly with chunks from made-up senders,
 * so many hosts can be had without a network:
 *
 *  - one host, opening transfers for many keys from several ports, only gets
 *    a few of the slots, and another host can still PUT an object
 *  - a transfer that keeps sending, but falls behind the minimum rate, is
 *    dropped, and progress never moves its deadline past that rate
 *  - what transfers in flight declared counts against the store quota
 *  - only an offset 0 chunk can open a transfer
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_object_store/protocol_lws_dht_object_store.c"

#define OST_STORE	"./ost-store"
#define OST_TOTAL	1000
#define OST_OBJECT	"an object a second host puts while the first trickles"

static struct lws_context *context;
static lws_sorted_usec_list_t sul_wait;
static lws_usec_t t_start;
static int fails;

static int
ost_expect(int cond, const char *what)
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
ost_v4(lws_sockaddr46 *sa46, uint8_t last, uint16_t port)
{
	memset(sa46, 0, sizeof(*sa46));
	sa46->sa4.sin_family = AF_INET;
	/* TEST-NET-3: never routed, so what the plugin sends back goes nowhere */
	sa46->sa4.sin_addr.s_addr = htonl(0xcb007100u | last);
	sa46->sa4.sin_port = htons(port);
}

/* a made-up object key: 64 hex chars, all a but the last two, which are n */

static void
ost_hash(char *hash, unsigned int n)
{
	memset(hash, 'a', 62);
	lws_snprintf(hash + 62, 3, "%02x", n & 0xff);
}

static int
ost_chunk(struct vhd_dht_store *vhd, const char *hash, unsigned long long len,
	  unsigned long long offset, const void *payload, size_t payload_len,
	  const lws_sockaddr46 *from)
{
	struct lws_dht_msg msg;

	memset(&msg, 0, sizeof(msg));
	lws_strncpy(msg.verb, "PUT", sizeof(msg.verb));
	lws_strncpy(msg.hash, hash, sizeof(msg.hash));
	msg.offset	= offset;
	msg.len		= len;
	msg.payload	= payload;
	msg.payload_len	= payload_len;

	return verb_put_handler(vhd->dht, vhd, &msg,
				(const struct sockaddr *)from,
				from->sa4.sin_family == AF_INET ?
					sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6));
}

/* how many transfers the host of from has in flight */

static int
ost_count(struct vhd_dht_store *vhd, const lws_sockaddr46 *from)
{
	int n = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->fragments)) {
		struct dht_fragment *f = lws_container_of(d,
					struct dht_fragment, list);

		if (lws_dht_same_host((const struct sockaddr *)&f->from_sa,
				      (const struct sockaddr *)from))
			n++;
	} lws_end_foreach_dll(d);

	return n;
}

static void
ost_run(struct vhd_dht_store *vhd)
{
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hctx;
	char hash[65], obj[65], path[256];
	lws_sockaddr46 h1, h2, h3;
	struct dht_fragment *f;
	struct stat st;
	lws_usec_t left;
	int n;

	/* h1 tries to open a transfer in every slot, from several ports */

	for (n = 0; n < LWS_DHT_STORE_MAX_INFLIGHT; n++) {
		ost_v4(&h1, 1, (uint16_t)(1000 + n));
		ost_hash(hash, (unsigned int)n);
		ost_chunk(vhd, hash, OST_TOTAL, 0, "x", 1, &h1);
	}
	ost_expect(ost_count(vhd, &h1) == LWS_DHT_STORE_MAX_INFLIGHT_PER_SRC,
		   "one host gets its share of the transfer slots, no more");

	/* h2 can still PUT a whole object, under its real key */

	if (lws_genhash_init(&hctx, LWS_DHT_STORE_GENHASH) ||
	    lws_genhash_update(&hctx, OST_OBJECT, strlen(OST_OBJECT)) ||
	    lws_genhash_destroy(&hctx, digest)) {
		ost_expect(0, "hash the object");
		return;
	}
	lws_hex_from_byte_array(digest,
				(size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH),
				obj, sizeof(obj));

	ost_v4(&h2, 2, 1000);
	ost_expect(!ost_chunk(vhd, obj, strlen(OST_OBJECT), 0, OST_OBJECT,
			      strlen(OST_OBJECT), &h2) &&
		   !dht_obj_store_path(vhd, obj, 0, path, sizeof(path)) &&
		   !stat(path, &st) && st.st_size == (off_t)strlen(OST_OBJECT),
		   "another host's PUT commits while the first holds slots");

	/*
	 * h1 keeps its first transfer moving a byte at a time: once that is
	 * behind the minimum rate, its next byte loses it
	 */

	ost_hash(hash, 0);
	f = dht_obj_store_find_fragment(vhd, hash);
	if (ost_expect(!!f, "h1's first transfer"))
		return;
	f->created = lws_now_usecs() - LWS_DHT_STORE_XFER_GRACE_US -
		     LWS_US_PER_SEC;
	ost_v4(&h1, 1, 1000);
	ost_chunk(vhd, hash, OST_TOTAL, 1, "x", 1, &h1);
	ost_expect(!dht_obj_store_find_fragment(vhd, hash),
		   "a trickling transfer behind the minimum rate is dropped");

	/*
	 * ... and while it is not yet behind, progress does not move its
	 * deadline past where the minimum rate puts it
	 */

	ost_hash(hash, 1);
	f = dht_obj_store_find_fragment(vhd, hash);
	if (ost_expect(!!f, "h1's second transfer"))
		return;
	f->created = lws_now_usecs() - LWS_DHT_STORE_XFER_GRACE_US +
		     5 * LWS_US_PER_SEC;
	ost_v4(&h1, 1, 1001);
	ost_chunk(vhd, hash, OST_TOTAL, 1, "x", 1, &h1);
	f = dht_obj_store_find_fragment(vhd, hash);
	left = f ? f->sul_timeout.us - lws_now_usecs() : 0;
	ost_expect(f && f->received_len == 2 && left > 0 &&
		   left <= 5 * LWS_US_PER_SEC + 2 * LWS_US_PER_SEC /
						LWS_DHT_STORE_XFER_MIN_RATE,
		   "progress does not extend a transfer past the minimum rate");

	/* a transfer can only be opened at offset 0 */

	ost_v4(&h3, 3, 1000);
	ost_hash(hash, 0x80);
	ost_chunk(vhd, hash, OST_TOTAL, 1, "x", 1, &h3);
	ost_expect(!dht_obj_store_find_fragment(vhd, hash),
		   "a chunk at a nonzero offset opens nothing");

	/* what transfers in flight declared is reserved against the quota */

	vhd->quota = vhd->store_bytes + vhd->inflight_bytes + OST_TOTAL / 2;
	ost_chunk(vhd, hash, OST_TOTAL, 0, "x", 1, &h3);
	ost_expect(!dht_obj_store_find_fragment(vhd, hash),
		   "in-flight transfers' declared lengths count to the quota");
	ost_chunk(vhd, hash, OST_TOTAL / 4, 0, "x", 1, &h3);
	ost_expect(!!dht_obj_store_find_fragment(vhd, hash),
		   "a transfer within the remaining quota opens");
}

/* the plugin makes its DHT at protocol init: wait for that */

static void
ost_wait_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_vhost *vh = lws_get_vhost_by_name(context, "default");
	struct vhd_dht_store *vhd = vh ? (struct vhd_dht_store *)
		lws_protocol_vh_priv_get(vh,
				&lws_dht_object_store_protocols[0]) : NULL;

	if (!vhd || !vhd->dht) {
		if (lws_now_usecs() - t_start < 10 * LWS_US_PER_SEC) {
			lws_sul_schedule(context, 0, &sul_wait, ost_wait_cb,
					 50 * LWS_US_PER_MS);
			return;
		}
		ost_expect(0, "plugin instantiated");
	} else
		ost_run(vhd);

	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	static const struct lws_protocols *pprotocols[] = {
		&lws_dht_object_store_protocols[0], NULL
	};
	struct lws_protocol_vhost_options pvo[4], pvo_wrap;
	struct lws_context_creation_info info;
	const char *port;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: dht-object-store transfer slots\n");

	port = lws_cmdline_option(argc, argv, "--port");
	if (!port || atoi(port) <= 0 || atoi(port) > 65535) {
		lwsl_err("%s: --port <udp port> is required\n", __func__);

		return 1;
	}

	lws_dir(OST_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(OST_STORE);
	if (mkdir(OST_STORE, 0700) && errno != EEXIST) {
		lwsl_err("%s: unable to create %s\n", __func__, OST_STORE);

		return 1;
	}

	memset(pvo, 0, sizeof(pvo));
	pvo[0].name = "dht-storage-path";
	pvo[0].value = OST_STORE;
	pvo[0].next = &pvo[1];
	pvo[1].name = "dht-port";
	pvo[1].value = port;
	pvo[1].next = &pvo[2];
	pvo[2].name = "dht-allow-private";
	pvo[2].value = "1";
	pvo[2].next = &pvo[3];
	pvo[3].name = "dht-jwk";
	pvo[3].value = OST_STORE "/node.jwk";

	memset(&pvo_wrap, 0, sizeof(pvo_wrap));
	pvo_wrap.name = "lws-dht-object-store";
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
	lws_sul_schedule(context, 0, &sul_wait, ost_wait_cb,
			 50 * LWS_US_PER_MS);

	while (lws_service(context, 0) >= 0)
		;

	lws_sul_cancel(&sul_wait);
	lws_context_destroy(context);

	lws_dir(OST_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(OST_STORE);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
