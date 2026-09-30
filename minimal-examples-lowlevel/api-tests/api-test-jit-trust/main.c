/*
 * lws-api-test-jit-trust
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An lws JIT Trust client and three lws tls servers in one process confirm
 * the real JIT Trust flow end to end, with no internet and no self-signed
 * allowances: the client's own vhost trusts only the app's own CA, and it has
 * a trust blob holding one other test root CA to answer its jit_trust_query()
 * from.
 *
 * The servers' chains are shaped like real ones:
 *
 *  - "trusted" serves a leaf and three intermediates, as many as JIT Trust
 *    collects, leaf first as tls requires.  The top intermediate is issued by
 *    the root in the trust blob, and the leaf, like a Let's Encrypt leaf, has
 *    no Subject Key Id, only an Authority Key Id naming its issuer.  That is
 *    the shape warmcat.com's chain had when JIT Trust could not handle it
 *
 *  - "untrusted" serves a leaf of the same shape issued directly by a root
 *    that is not in the trust blob
 *
 *  - "app CA" serves a leaf of the same shape issued directly by the app's
 *    own CA, which the client's vhost trusts and the trust blob doesn't have
 *
 * The steps, each a client GET, retried from CLIENT_CONNECTION_ERROR up to
 * MAX_ATTEMPTS as an app using JIT Trust does:
 *
 *  - untrusted: every attempt fails.  JIT Trust asks about the root the leaf
 *    names, the blob doesn't have it, and nothing is made to trust it
 *
 *  - cold: the first attempt fails, JIT Trust asks about each of the four
 *    AKIDs in the chain, gets the root from the blob and makes a vhost
 *    trusting it, the retry binds to that and completes
 *
 *  - warm: the JIT Trust vhost is still there, the first attempt binds to it
 *    and completes, with no queries
 *
 *  - cached: the JIT Trust vhost has idled out, but the trust cache still
 *    knows which CA the endpoint needs: the first attempt regenerates the
 *    vhost from the cache, asking only for that CA, and completes
 *
 *  - other port: "app CA", on the same address as "trusted" but another
 *    port, completes on the client's own vhost at the first attempt.  What
 *    JIT Trust learned about "trusted" is not about this server, and must not
 *    move its connections to a vhost that trusts only the blob's root
 *
 *  - rotated: "trusted" now serves the "app CA" leaf.  The first attempt
 *    is bound to the JIT Trust vhost by the cache, and fails.  That forgets
 *    the cache entry, so the retry is on the client's own vhost and completes
 *
 *  - rotated, later: after the JIT Trust vhost idled out, the first attempt
 *    completes on the client's own vhost, with no queries: there was nothing
 *    left in the cache to regenerate the JIT Trust vhost from
 *
 * The JIT Trust vhost is named after the CAs it trusts, which here is just the
 * test root, so the test can also check it by name.
 *
 * The test fails if any step does not see what it expects, or does not finish
 * inside the watchdog period.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define MAX_ATTEMPTS	3
#define STEP_TIMEOUT_S	20
#define VH_GRACE_MS	1500	/* comfortably longer than warm step takes */
#define POLL_MS		100

#define ANY		-1	/* the count depends on the timing or tls lib */

enum {
	SRV_TRUSTED,
	SRV_UNTRUSTED,
	SRV_APPCA,

	SRV_COUNT
};

enum {
	ON_JITT,	/* completes on the JIT Trust vhost */
	ON_DEFAULT,	/* completes on the client's own vhost */
};

static const struct step {
	const char	*name;
	int		srv;
	char		completes;	/* else all attempts fail */
	char		on;		/* ON_JITT or ON_DEFAULT */
	int		failed;		/* attempts that failed */
	int		queries;	/* jit_trust_query() calls */
	int		found;		/* ...that the trust blob answered */
	char		vh_gone_first;	/* wait for the jitt vhost to idle out */
	char		rotate_first;	/* "trusted" serves the app CA leaf */
} steps[] = {
	{ "untrusted root: never trusted",	SRV_UNTRUSTED,	0, ON_JITT,
	  MAX_ATTEMPTS, MAX_ATTEMPTS, 0, 0, 0 },
	{ "cold: sacrificial attempt, then JIT Trust vhost",
				SRV_TRUSTED,	1, ON_JITT,	1, 4, 1, 0, 0 },
	{ "warm: JIT Trust vhost still there",
				SRV_TRUSTED,	1, ON_JITT,	0, 0, 0, 0, 0 },
	{ "cached: JIT Trust vhost regenerated from the trust cache",
				SRV_TRUSTED,	1, ON_JITT,	0, 1, 1, 1, 0 },
	{ "other port: app CA server on the same address keeps its own trust",
				SRV_APPCA,	1, ON_DEFAULT,	0, 0, 0, 0, 0 },
	{ "rotated: JIT Trust vhost fails once, its cache entry is forgotten",
				SRV_TRUSTED,	1, ON_DEFAULT,	1, ANY, ANY, 0, 1 },
	{ "rotated, later: nothing left to regenerate a JIT Trust vhost from",
				SRV_TRUSTED,	1, ON_DEFAULT,	0, 0, 0, 1, 0 },
};

/*
 * The test PKI, made with openssl as README.md describes.  The servers' certs
 * and keys are files in this directory, the client only knows the DER of the
 * trusted root, and its SKID, which is what the trust blob indexes it by, and
 * the DER of the app's own CA.
 */

static const uint8_t root_der[] = {
	0x30, 0x82, 0x01, 0xc5, 0x30, 0x82, 0x01, 0x6a, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x14, 0x24, 0xe7, 0xad, 0x93, 0x35, 0x39, 0x9f, 0xf3, 0x04,
	0x22, 0xf0, 0x88, 0xed, 0xb6, 0xfc, 0x81, 0x5d, 0xc3, 0xa1, 0x4a, 0x30,
	0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
	0x3f, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x12,
	0x6c, 0x69, 0x62, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74,
	0x73, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03,
	0x55, 0x04, 0x03, 0x0c, 0x17, 0x6c, 0x77, 0x73, 0x20, 0x6a, 0x69, 0x74,
	0x20, 0x74, 0x72, 0x75, 0x73, 0x74, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20,
	0x72, 0x6f, 0x6f, 0x74, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x31,
	0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x32,
	0x31, 0x32, 0x35, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35,
	0x39, 0x5a, 0x30, 0x3f, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04,
	0x0a, 0x0c, 0x12, 0x6c, 0x69, 0x62, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63,
	0x6b, 0x65, 0x74, 0x73, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x20, 0x30,
	0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x6c, 0x77, 0x73, 0x20,
	0x6a, 0x69, 0x74, 0x20, 0x74, 0x72, 0x75, 0x73, 0x74, 0x20, 0x74, 0x65,
	0x73, 0x74, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06,
	0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x07, 0x71,
	0x34, 0xe9, 0x95, 0x8d, 0x15, 0x22, 0xe6, 0x40, 0x28, 0xf1, 0x1a, 0x17,
	0x9a, 0xe8, 0x8b, 0x7d, 0x33, 0x43, 0x32, 0x26, 0xb3, 0xa8, 0x08, 0xf5,
	0xcd, 0x2a, 0x6a, 0x88, 0xd7, 0x42, 0x18, 0x1d, 0x46, 0x10, 0x1a, 0x25,
	0xcd, 0x41, 0x33, 0xac, 0xf6, 0x75, 0xb0, 0x8f, 0x35, 0x7b, 0x71, 0x59,
	0x03, 0x0c, 0xd3, 0xce, 0xeb, 0xbc, 0x00, 0x81, 0x06, 0xb4, 0x6c, 0xd9,
	0x51, 0x71, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
	0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
	0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
	0x02, 0x01, 0x06, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
	0x04, 0x14, 0x6b, 0xa5, 0x5d, 0x42, 0x4a, 0x57, 0x6e, 0xd5, 0x82, 0x12,
	0x12, 0x79, 0xb6, 0xa8, 0x48, 0x68, 0x3d, 0x05, 0xea, 0x94, 0x30, 0x0a,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49,
	0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0x88, 0xe3, 0x0d, 0x1e, 0x6c, 0xa4,
	0x1a, 0x33, 0x53, 0xa7, 0x2b, 0xea, 0xf6, 0x12, 0x87, 0x26, 0x65, 0x45,
	0xd4, 0x24, 0x31, 0x3a, 0x58, 0x96, 0x7f, 0x95, 0xa9, 0xc8, 0x25, 0x4a,
	0x80, 0x10, 0x02, 0x21, 0x00, 0xfa, 0x0b, 0x06, 0xc9, 0xf5, 0xf0, 0xe3,
	0xa1, 0xad, 0xd7, 0xe7, 0xcd, 0x3b, 0xcb, 0x04, 0x66, 0x37, 0x08, 0x58,
	0x55, 0x90, 0x41, 0x65, 0x2d, 0x99, 0x95, 0x63, 0x58, 0x12, 0x48, 0xd1,
	0x6d
};

static const uint8_t root_skid[] = {
	0x6b, 0xa5, 0x5d, 0x42, 0x4a, 0x57, 0x6e, 0xd5, 0x82, 0x12,
	0x12, 0x79, 0xb6, 0xa8, 0x48, 0x68, 0x3d, 0x05, 0xea, 0x94
};

/*
 * The app's own CA, that the client's vhost trusts itself, the way an app
 * trusts its own backend's private CA.  It is not in the trust blob.
 */

static const uint8_t app_root_der[] = {
	0x30, 0x82, 0x01, 0xcc, 0x30, 0x82, 0x01, 0x72, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x14, 0x6d, 0x76, 0x3f, 0x78, 0x80, 0xa6, 0xe7, 0xc5, 0x32,
	0xaa, 0xdf, 0xb7, 0x62, 0x4d, 0x85, 0xea, 0x46, 0x2d, 0x1c, 0x72, 0x30,
	0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
	0x43, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x12,
	0x6c, 0x69, 0x62, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74,
	0x73, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03,
	0x55, 0x04, 0x03, 0x0c, 0x1b, 0x6c, 0x77, 0x73, 0x20, 0x6a, 0x69, 0x74,
	0x20, 0x74, 0x72, 0x75, 0x73, 0x74, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20,
	0x61, 0x70, 0x70, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x30, 0x20, 0x17, 0x0d,
	0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x35, 0x31, 0x32, 0x33, 0x31, 0x32,
	0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x43, 0x31, 0x1b, 0x30, 0x19,
	0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x12, 0x6c, 0x69, 0x62, 0x77, 0x65,
	0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x2d, 0x74, 0x65, 0x73,
	0x74, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1b,
	0x6c, 0x77, 0x73, 0x20, 0x6a, 0x69, 0x74, 0x20, 0x74, 0x72, 0x75, 0x73,
	0x74, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x61, 0x70, 0x70, 0x20, 0x72,
	0x6f, 0x6f, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
	0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
	0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x29, 0x80, 0x50, 0x68, 0x6d, 0x46,
	0xac, 0x87, 0x05, 0x44, 0x99, 0x95, 0xad, 0x16, 0xf5, 0x99, 0xd9, 0xd5,
	0xb6, 0x3a, 0x40, 0x79, 0xc1, 0x1b, 0xd7, 0x4c, 0x5e, 0xa4, 0x5c, 0xcc,
	0xa8, 0x45, 0x5a, 0x23, 0x9b, 0xa6, 0x0c, 0x1d, 0x5e, 0x85, 0xa6, 0x72,
	0x7b, 0x8c, 0xeb, 0x76, 0xdf, 0x15, 0xbd, 0x72, 0x99, 0x1d, 0x37, 0x81,
	0xf2, 0x17, 0xad, 0x71, 0x03, 0x5d, 0xed, 0x0d, 0xc1, 0x91, 0xa3, 0x42,
	0x30, 0x40, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
	0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55,
	0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30,
	0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa9, 0xdf,
	0xe7, 0x90, 0xa7, 0x1a, 0x16, 0x05, 0x97, 0x41, 0xf7, 0xb9, 0x98, 0x3e,
	0x1b, 0xc6, 0xef, 0xdd, 0xfc, 0x67, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02,
	0x21, 0x00, 0x93, 0x7d, 0x5b, 0x7f, 0x14, 0xf2, 0xff, 0xc0, 0xd8, 0x86,
	0x7b, 0xe1, 0x23, 0xb0, 0xe1, 0xe4, 0x8f, 0x9b, 0xb6, 0xe9, 0xdb, 0xe7,
	0x1c, 0x07, 0xd4, 0x70, 0x6c, 0x72, 0xb4, 0x27, 0xbf, 0xa2, 0x02, 0x20,
	0x61, 0x88, 0xbb, 0x5d, 0xd1, 0x11, 0xcd, 0xdb, 0xcc, 0x5c, 0xbd, 0xb9,
	0xd2, 0x93, 0x64, 0x68, 0xe2, 0x94, 0xeb, 0xf6, 0x36, 0x22, 0x10, 0xb9,
	0xf9, 0x8f, 0xbd, 0xe7, 0xfe, 0xaa, 0xb2, 0xb9
};

static const char * const srv_certs[SRV_COUNT][2] = {
	[SRV_TRUSTED]	= { "trusted-chain.pem",	"trusted-leaf.key" },
	[SRV_UNTRUSTED]	= { "untrusted-leaf.pem",	"untrusted-leaf.key" },
	[SRV_APPCA]	= { "app-leaf.pem",		"app-leaf.key" },
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_step, sul_watchdog;
static uint8_t *blob;
static size_t blob_len;
static const char *server_addr = "127.0.0.1";
static char jitt_vh_name[32];
static int ports[SRV_COUNT] = { 7681, 7682, 7683 }, cur = -1, result = 1,
	   failures;

static struct {
	int		attempts;
	int		failed;
	int		queries;
	int		found;
	int		status;
	char		completed;
	char		on;		/* the vhost the completing attempt was on */
} st;

/*
 * A trust blob holding only the test root, laid out as
 * READMEs/README.jit-trust.md describes... a real one would be made by
 * scripts/mozilla-trust-gen.sh, but this is all a device that only trusts one
 * CA needs.
 */

static int
make_trust_blob(void)
{
	size_t ofs_derlen = 0x1c + sizeof(root_der);
	uint8_t *p;

	blob_len = ofs_derlen + 2 + 1 + sizeof(root_skid);
	blob = malloc(blob_len);
	if (!blob)
		return 1;

	p = blob;
	memcpy(p, "TBLB", 4);
	lws_ser_wu16be(p + 4, 1);			/* layout version */
	lws_ser_wu16be(p + 6, 1);			/* count of certs */
	lws_ser_wu32be(p + 8, 0);			/* generation time */
	lws_ser_wu32be(p + 0xc, (uint32_t)ofs_derlen);	/* DER lengths */
	lws_ser_wu32be(p + 0x10, (uint32_t)ofs_derlen + 2); /* SKID lengths */
	lws_ser_wu32be(p + 0x14, (uint32_t)ofs_derlen + 3); /* SKIDs */
	lws_ser_wu32be(p + 0x18, (uint32_t)blob_len);

	memcpy(p + 0x1c, root_der, sizeof(root_der));
	p += ofs_derlen;
	lws_ser_wu16be(p, (uint16_t)sizeof(root_der));
	p[2] = (uint8_t)sizeof(root_skid);
	memcpy(p + 3, root_skid, sizeof(root_skid));

	return 0;
}

static int
jit_trust_query(struct lws_context *cx, const uint8_t *skid,
		size_t skid_len, void *got_opaque)
{
	const uint8_t *der = NULL;
	size_t der_len = 0;

	st.queries++;

	lws_tls_jit_trust_blob_queury_skid(blob, blob_len, skid, skid_len,
					   &der, &der_len);
	if (der)
		st.found++;

	lwsl_user("%s: query %d: %s\n", __func__, st.queries,
		  der ? "trusted" : "not trusted");

	return lws_tls_jit_trust_got_cert_cb(cx, got_opaque, skid, skid_len,
					     der, der_len);
}

static lws_system_ops_t system_ops = {
	.jit_trust_query		= jit_trust_query
};

static void
next_step(lws_sorted_usec_list_t *sul);

static int
check_step(void)
{
	const struct step *s = &steps[cur];
	int bad = 0;

	if (st.completed != s->completes) {
		lwsl_err("%s: %s, expected %s\n", s->name,
			 st.completed ? "completed" : "never completed",
			 s->completes ? "to complete" : "never to complete");
		bad = 1;
	}
	if (st.completed && st.status != HTTP_STATUS_OK) {
		lwsl_err("%s: http status %d\n", s->name, st.status);
		bad = 1;
	}
	if (st.completed && st.on != s->on) {
		lwsl_err("%s: did not complete on the %s vhost\n", s->name,
			 s->on == ON_JITT ? "JIT Trust" : "client's own");
		bad = 1;
	}
	if (st.failed != s->failed) {
		lwsl_err("%s: %d attempts failed, expected %d\n", s->name,
			 st.failed, s->failed);
		bad = 1;
	}
	if ((s->queries != ANY && st.queries != s->queries) ||
	    (s->found != ANY && st.found != s->found)) {
		lwsl_err("%s: %d queries, %d trusted, expected %d, %d\n",
			 s->name, st.queries, st.found, s->queries, s->found);
		bad = 1;
	}
	if (s->completes && s->on == ON_JITT &&
	    !lws_get_vhost_by_name(context, jitt_vh_name)) {
		lwsl_err("%s: no JIT Trust vhost %s\n", s->name, jitt_vh_name);
		bad = 1;
	}

	lwsl_user("%s: step %d: %s\n", bad ? "FAIL" : "PASS", cur, s->name);

	return bad;
}

static void
step_done(void)
{
	lws_sul_cancel(&sul_watchdog);

	if (check_step())
		failures++;

	lws_sul_schedule(context, 0, &sul_step, next_step, 1);
}

static void
watchdog(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: step %d timed out\n", __func__, cur);
	failures++;
	lws_default_loop_exit(context);
}

static void
try_connect(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	st.attempts++;

	memset(&i, 0, sizeof i);
	i.context		= context;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= ports[steps[cur].srv];
	i.path			= "/";
	i.method		= "GET";
	i.alpn			= "http/1.1";
	i.protocol		= "jitt-client";
	/*
	 * No i.vhost: that is what lets lws bind the connection to the JIT
	 * Trust vhost for the address, when there is one.  Validation is
	 * wholly normal, there is no ALLOW_SELFSIGNED or the like.
	 */
	i.ssl_connection	= LCCSCF_USE_SSL;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: client creation failed\n", __func__);
		st.failed++;
		step_done();
	}
}

/*
 * "trusted" renews its certificate, from the app's own CA this time, the way
 * a server's certificate changes under a client that learned its trust
 */

static int
rotate_trusted(void)
{
	static char cert[2048], key[512];
	int cl, kl;

	cl = lws_plat_read_file(srv_certs[SRV_APPCA][0], cert, sizeof(cert) - 1);
	kl = lws_plat_read_file(srv_certs[SRV_APPCA][1], key, sizeof(key) - 1);
	if (cl <= 0 || kl <= 0) {
		lwsl_err("%s: unable to read the app CA leaf\n", __func__);
		return 1;
	}
	cert[cl] = '\0';
	key[kl] = '\0';

	return lws_tls_cert_updated(context, srv_certs[SRV_TRUSTED][0],
				    srv_certs[SRV_TRUSTED][1],
				    cert, (size_t)cl, key, (size_t)kl);
}

static void
next_step(lws_sorted_usec_list_t *sul)
{
	static int polls;

	if (cur + 1 == (int)LWS_ARRAY_SIZE(steps)) {
		result = !!failures;
		lws_default_loop_exit(context);
		return;
	}

	if (steps[cur + 1].vh_gone_first &&
	    lws_get_vhost_by_name(context, jitt_vh_name)) {
		/* the JIT Trust vhost has to idle out first, check back */
		if (++polls > (STEP_TIMEOUT_S * 1000) / POLL_MS) {
			lwsl_err("%s: %s never idled out\n", __func__,
				 jitt_vh_name);
			failures++;
			lws_default_loop_exit(context);
			return;
		}
		lws_sul_schedule(context, 0, &sul_step, next_step,
				 POLL_MS * LWS_US_PER_MS);
		return;
	}

	polls = 0;
	cur++;
	memset(&st, 0, sizeof(st));
	lwsl_user("%s: step %d: %s\n", __func__, cur, steps[cur].name);

	if (steps[cur].rotate_first && rotate_trusted()) {
		failures++;
		lws_default_loop_exit(context);
		return;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog,
			 STEP_TIMEOUT_S * LWS_US_PER_SEC);
	try_connect(NULL);
}

static int
callback_client(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	const char *vhn;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: attempt %d failed: %s\n", __func__, st.attempts,
			  in ? (const char *)in : "(null)");
		st.failed++;
		if (st.attempts < MAX_ATTEMPTS)
			lws_sul_schedule(context, 0, &sul_step, try_connect, 1);
		else
			step_done();
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		st.status = (int)lws_http_client_http_response(wsi);
		vhn = lws_get_vhost_name(lws_get_vhost(wsi));
		st.on = vhn && !strcmp(vhn, jitt_vh_name) ? ON_JITT :
			(vhn && !strcmp(vhn, "default") ? ON_DEFAULT : -1);
		lwsl_user("%s: attempt %d: http %d on vhost %s\n", __func__,
			  st.attempts, st.status, vhn ? vhn : "?");
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char buf[256 + LWS_PRE], *px = buf + LWS_PRE;
			int lenx = sizeof(buf) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		st.completed = 1;
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (st.completed)
			step_done();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_cli[] = {
	{ "jitt-client", callback_client, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

struct pss {
	uint8_t		resp[LWS_PRE + 16];
	size_t		resp_len;
};

static int
callback_server(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	struct pss *pss = (struct pss *)user;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->resp_len = (size_t)lws_snprintf(
					(char *)&pss->resp[LWS_PRE],
					sizeof(pss->resp) - LWS_PRE, "ok\n");

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						(lws_filepos_t)pss->resp_len,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->resp_len)
			break;
		if (lws_write(wsi, &pss->resp[LWS_PRE], pss->resp_len,
			      LWS_WRITE_HTTP_FINAL) != (int)pss->resp_len)
			return -1;
		pss->resp_len = 0;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "jitt-server", callback_server, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* three listeners (v4 + v6 each), and both ends of the connections */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		ports[SRV_TRUSTED] = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--untrusted-port")))
		ports[SRV_UNTRUSTED] = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--appca-port")))
		ports[SRV_APPCA] = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: JIT Trust\n");

	if (make_trust_blob())
		return 1;

	/* the vhost JIT Trust makes is named after the CA SKIDs it trusts */
	lws_snprintf(jitt_vh_name, sizeof(jitt_vh_name), "jitt-%08X",
		     (unsigned int)lws_ser_ru32be(root_skid));

	/*
	 * The context's default vhost is the client one.  It trusts only the
	 * app's own CA, and the JIT Trust vhosts inherit the context options,
	 * so they don't resume a session instead of validating the server
	 * chain either.
	 */

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS |
		       LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols_cli;
	info.system_ops = &system_ops;
	info.vh_idle_grace_ms = VH_GRACE_MS;
	info.client_ssl_ca_mem = app_root_der;
	info.client_ssl_ca_mem_len = (unsigned int)sizeof(app_root_der);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		goto bail;
	}

	info.client_ssl_ca_mem = NULL;
	info.client_ssl_ca_mem_len = 0;

	/*
	 * The servers.  Their alpn leaves out h3, so they do not also listen
	 * on quic and advertise it by alt-svc for a later attempt to race
	 */

	info.protocols = protocols_srv;
	info.system_ops = NULL;
	info.alpn = "http/1.1";

	for (n = 0; n < SRV_COUNT; n++) {
		static const char * const srv_names[SRV_COUNT] = {
			[SRV_TRUSTED]	= "srv-trusted",
			[SRV_UNTRUSTED]	= "srv-untrusted",
			[SRV_APPCA]	= "srv-appca",
		};

		info.vhost_name = srv_names[n];
		info.port = ports[n];
		info.ssl_cert_filepath = srv_certs[n][0];
		info.ssl_private_key_filepath = srv_certs[n][1];

		if (!lws_create_vhost(context, &info)) {
			lwsl_err("Failed to create server vhost %s\n",
				 info.vhost_name);
			goto bail;
		}
	}

	lws_sul_schedule(context, 0, &sul_step, next_step, 1);

	n = 0;
	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);
	free(blob);

	lwsl_user("Completed: %s (%d of %d steps failed)\n",
		  result ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(steps));

	return result;
}
