/*
 * lws-api-test-auth-dns-zonedir
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain
 *
 * F-055 fence: the local zone-dir trust policy in protocol-lws-auth-dns.
 *
 * Everything the plugin loads from its zone dir is served as authoritative
 * data, so the dir must be exclusively controlled by the service uid.  The
 * test plants zones the pre-fix plugin happily served, and asserts they are
 * now refused:
 *
 * | phase | arrangement | pre-fix behavior | post-fix behavior |
 * |-------|-------------|------------------|-------------------|
 * | 1 | service-owned dir + properly decorated zone file | served | served (control) |
 * | 2 | no "zone-dir" pvo at all | defaults to shared /tmp/lws-auth-dns and starts | protocol init refused, no listener |
 * | 3 | world-writable zone dir with planted zone | planted zone served | protocol init refused, no listener |
 * | 4 | zone-dir that is a symlink to a valid dir | followed, zone served | protocol init refused, no listener |
 * | 5 | good dir, but undecorated / short-suffix / group-writable / symlinked zone files | all loaded and served | only the properly shaped file loads, the rest answer REFUSED |
 * | 6 | zones handed over by lws-dht-dnssec as verified for a domain (G-117) | installed under their last $ORIGIN, replacing that zone | installed only if exactly the zone of the domain handed over with them, and signed and in date (G-505) |
 * | 7 | a query for a zone nobody serves times out (G-224) | its zone fetch left running | the fetch given up, completed once as timed out |
 * | 7b | queries for 10 zones nobody serves, and another for the first (G-508) | a fetch started for each query | a fetch for each of the first 8 zones, the rest REFUSED, the other query waits on the first fetch |
 * | 8 | a zone with a delegation (G-246) | names at / below the cut answered authoritatively from the zone text | referred: no AA, the cut's NS in authority; only the DS at the cut answered |
 * | 9 | more zone files than cache-max-zones (G-290) | the surplus evicted at startup and its files unlinked | all served, every file still there |
 * | 10 | cache-max-zones 1, an operator zone and DHT-handed zones (G-290) | the operator zone evicted for a DHT zone and its file unlinked | the operator zone served and its file kept, the DHT zones evicting each other |
 * | 11 | (root only) zone file or dir owned by another uid | loaded / started | file ignored (REFUSED) / init refused |
 *
 * Phase 6 stands in for lws-dht-dnssec with a protocol of that name whose
 * ops only collect the callback auth-dns registers for verified zones.  The
 * test then hands it payloads as the plugin does after checking their
 * signature against a domain's keys: one carrying a second $ORIGIN for a
 * zone the dir serves, and one that is wholly another zone, must both be
 * refused, leaving the served zone as it was.  Its stand-in refuses the
 * first registrations, as lws-dht-dnssec does when it isn't started on the
 * vhost yet: auth-dns must register again later, not lose it.
 *
 * Phase 7's stand-in also takes zone fetches, keeping their completion and
 * opaque as the plugin does, and never answers them.  When auth-dns' query
 * times out (5s) and is answered REFUSED, nothing is waiting for the zone any
 * more: the fetch must have been given up, its completion called exactly
 * once, as timed out, leaving nothing holding auth-dns' opaque.
 *
 * Phase 8 serves a zone delegating a subdomain, with glue and with data
 * occluded by the delegation in the zone text: the zone is not
 * authoritative for any of it, so every name at or below the cut must be
 * referred to the child's name servers, except the DS at the cut, which is
 * the parent's own.
 *
 * "No listener" is observed two ways: queries stay unanswered, and the UDP
 * port is bindable by the test itself afterwards (the plugin only creates
 * its UDP listeners once protocol init succeeded).
 */

#include <libwebsockets.h>
#include <libwebsockets/lws-dht-dnssec.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TICK_US			(50 * LWS_US_PER_MS)
#define RESP_US			(2 * LWS_US_PER_SEC)  /* wait for expected replies */
/* auth-dns answers a query waiting on a zone fetch after 5s */
#define RESP_FETCH_US		(7 * LWS_US_PER_SEC)
#define QUIET_US		(700 * LWS_US_PER_MS)  /* prove silence */
#define DEADLINE_US		(8 * LWS_US_PER_SEC)

#define BASE_DIR		"zones-f055"

/* decorated filename fields: far-future ttl / sig expiry (2033), serial 1 */
#define DECOR			"_2000000000_2000000000_1.zone"

extern const struct lws_protocols lws_auth_dns_protocols[];

static struct lws_context *context;

static int ports[2];
static int cli_fd = -1;
static struct sockaddr_in auth_sa;

static int test_ok = 1;
static int phase_idx, phase_done, phase_failed;

/* per-phase state */

struct qexp {
	const char	*name;
	uint16_t	id;
	int		expect_rcode;	/* -1: no response at all */
	int		expect_anc;
	int		got_rcode;
	int		got_anc;
	int		sent;
	uint16_t	qtype;		/* 0: A */
	int		expect_ref;	/* 1: a referral, 2: an AA answer */
	int		got_aa;
	int		got_nsc;
};

#define MAX_Q		12

struct phase {
	const char	*name;
	const char	*zdir;		/* NULL: no zone-dir pvo */
	int		check_port_free;
	int		dht;		/* hand zones over as lws-dht-dnssec */
	int		fetch;		/* take zone fetches as lws-dht-dnssec:
					 * 1: one, given up with its query
					 * 2: many, rate limited (G-508) */
	const char	*cache_max;	/* "cache-max-zones" pvo, if any */
	const char	*keep[4];	/* zdir files that must survive */
	struct qexp	q[MAX_Q];
};

static struct phase *cur;

/*
 * Standing in for lws-dht-dnssec: auth-dns finds the ops by the protocol
 * name and registers its callback for zones the plugin verified
 */

typedef void (*zd_auth_cb_t)(void *opaque, const char *domain,
			     const char *payload_path);

static zd_auth_cb_t dht_auth_cb;
static void *dht_auth_opaque;
/*
 * The protocols on a vhost start in no fixed order: like a lws-dht-dnssec
 * that isn't started yet, refuse the first registrations, so auth-dns has to
 * try again, and the zones are still handed over
 */
#define ZD_REG_REFUSALS		2
static int zd_reg_refused, zd_reg_waits;

static int
zd_register_auth_cb(struct lws_vhost *vh, zd_auth_cb_t cb, void *opaque)
{
	(void)vh;
	if (zd_reg_refused++ < ZD_REG_REFUSALS)
		return 1;

	dht_auth_cb = cb;
	dht_auth_opaque = opaque;

	return 0;
}

static struct lws_dht_dnssec_ops zd_dht_ops = {
	.register_auth_cb = zd_register_auth_cb,
};

/*
 * Phase 7 stands in for the zone fetches as well, keeping to the fetch_zone()
 * contract in lws-dht-dnssec.h: a request merged by domain, cb and opaque, a
 * cancel dropping it without completing it, a fail completing it once, as
 * timed out.  Nobody ever answers, so a request only ends by those.
 */

static struct {
	char				domain[256];
	lws_dht_dnssec_fetch_cb_t	cb;
	void				*opaque;
	int				pending;
} zd_fetch;

static int zd_fetch_starts, zd_fetch_completions, zd_fetch_status,
	   zd_fetch_calls;

/*
 * auth-dns starts at most a burst of this many zone fetches at once
 * (LWS_AUTH_DNS_DHT_FETCH_BURST), then one per 500ms
 */
#define ZD_FETCH_BURST		8

static void
zd_fetch_reset(void)
{
	memset(&zd_fetch, 0, sizeof(zd_fetch));
	zd_fetch_starts = zd_fetch_completions = zd_fetch_calls = 0;
	zd_fetch_status = -100;
}

static int
zd_fetch_matches(const struct lws_dht_dnssec_fetch_zone_args *a)
{
	return zd_fetch.pending && a->opaque == zd_fetch.opaque &&
	       (!a->domain || !strcmp(a->domain, zd_fetch.domain));
}

static int
zd_fetch_zone(struct lws_context *cx, struct lws_dht_dnssec_fetch_zone_args *a)
{
	(void)cx;

	if (a->is_cancel) {
		if (zd_fetch_matches(a))
			zd_fetch.pending = 0;

		return 0;
	}

	if (a->is_fail) {
		if (zd_fetch_matches(a)) {
			zd_fetch.pending = 0;
			zd_fetch_completions++;
			zd_fetch_status = LWS_DHT_DNSSEC_FETCH_TIMEOUT;
			zd_fetch.cb(zd_fetch.opaque, zd_fetch.domain,
				    LWS_DHT_DNSSEC_FETCH_TIMEOUT);
		}

		return 0;
	}

	zd_fetch_calls++;

	if (!a->domain)
		goto refuse;

	if (zd_fetch.pending) {
		if (!strcmp(a->domain, zd_fetch.domain) &&
		    a->cb == zd_fetch.cb && a->opaque == zd_fetch.opaque)
			return 0; /* merged */

		/* the phase only asks for one zone */
		goto refuse;
	}

	lws_strncpy(zd_fetch.domain, a->domain, sizeof(zd_fetch.domain));
	zd_fetch.cb = a->cb;
	zd_fetch.opaque = a->opaque;
	zd_fetch.pending = 1;
	zd_fetch_starts++;

	return 0;

refuse:
	zd_fetch_completions++;
	zd_fetch_status = LWS_DHT_DNSSEC_FETCH_ABORTED;
	if (a->cb)
		a->cb(a->opaque, a->domain ? a->domain : "",
		      LWS_DHT_DNSSEC_FETCH_ABORTED);

	return 1;
}

static struct lws_dht_dnssec_ops zd_dht_fetch_ops = {
	.fetch_zone = zd_fetch_zone,
	.register_auth_cb = zd_register_auth_cb,
};

/* what is handed over, and the domain it was verified for */

/*
 * lws-dht-dnssec only hands over zones that are signed and in date, and
 * auth-dns refuses any other (G-505).  The RRSIG's times are what is looked
 * at, not its signature, which the JWS over the zone stands for: a period
 * from 2020 to 2035 is valid while the test runs.
 */
#define ZD_SOA_RRSIG(_z) "@ IN RRSIG SOA 8 2 86400 20350101000000 " \
			 "20200101000000 12345 " _z ".example. AAAA\n"

static const struct {
	const char	*file;
	const char	*domain;
	const char	*text;
} zd_handed[] = {
	{	/* a zone of its own, as it should be */
		"handed-ok3.zone", "ok3.example",
		"$ORIGIN ok3.example.\n"
		"$TTL 86400\n"
		"@ IN SOA ns1.ok3.example. hostmaster.ok3.example. "
			"( 2026090101 3600 1800 604800 86400 )\n"
		ZD_SOA_RRSIG("ok3")
		"www IN A 127.0.0.77\n"
	}, {	/* signed for a.example, with victim.example's records after */
		"handed-trailing.zone", "a.example",
		"$ORIGIN a.example.\n"
		"$TTL 86400\n"
		"@ IN SOA ns1.a.example. hostmaster.a.example. "
			"( 2026090199 3600 1800 604800 86400 )\n"
		"www IN A 127.0.0.65\n"
		"$ORIGIN victim.example.\n"
		"@ IN SOA ns1.victim.example. hostmaster.victim.example. "
			"( 2026090199 3600 1800 604800 86400 )\n"
		"evil IN A 127.0.0.66\n"
	}, {	/* signed for a2.example, wholly victim.example's */
		"handed-foreign.zone", "a2.example",
		"$ORIGIN victim.example.\n"
		"$TTL 86400\n"
		"@ IN SOA ns1.victim.example. hostmaster.victim.example. "
			"( 2026090199 3600 1800 604800 86400 )\n"
		"evil2 IN A 127.0.0.66\n"
	}, {	/* another of its own, handed over after ok3.example */
		"handed-ok4.zone", "ok4.example",
		"$ORIGIN ok4.example.\n"
		"$TTL 86400\n"
		"@ IN SOA ns1.ok4.example. hostmaster.ok4.example. "
			"( 2026090101 3600 1800 604800 86400 )\n"
		ZD_SOA_RRSIG("ok4")
		"www IN A 127.0.0.78\n"
	}, {	/* its domain's, but not signed (G-505) */
		"handed-unsigned.zone", "ok5.example",
		"$ORIGIN ok5.example.\n"
		"$TTL 86400\n"
		"@ IN SOA ns1.ok5.example. hostmaster.ok5.example. "
			"( 2026090101 3600 1800 604800 86400 )\n"
		"www IN A 127.0.0.79\n"
	}, {	/* its domain's, but its signatures expired (G-505) */
		"handed-expired.zone", "ok6.example",
		"$ORIGIN ok6.example.\n"
		"$TTL 86400\n"
		"@ IN SOA ns1.ok6.example. hostmaster.ok6.example. "
			"( 2026090101 3600 1800 604800 86400 )\n"
		"@ IN RRSIG SOA 8 2 86400 20210101000000 "
			"20200101000000 12345 ok6.example. AAAA\n"
		"www IN A 127.0.0.80\n"
	},
};

static lws_sorted_usec_list_t sul_drive;
static lws_usec_t t0;

/* build a DNS query for "name" into buf, returning the packet length */

static size_t
mk_query(uint8_t *buf, size_t bufsize, uint16_t id, const char *name,
	 uint16_t qtype)
{
	const char *p = name;
	size_t o = 12;

	memset(buf, 0, bufsize >= 12 ? 12 : bufsize);
	buf[0] = (uint8_t)(id >> 8);
	buf[1] = (uint8_t)(id & 0xff);
	buf[2] = 0x01;			/* RD */
	buf[5] = 1;			/* QDCOUNT = 1 */

	while (*p) {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);

		if (!l || l > 63 || o + 1 + l + 4 > bufsize)
			return 0;

		buf[o++] = (uint8_t)l;
		memcpy(&buf[o], p, l);
		o += l;

		p = dot ? dot + 1 : p + l;
	}
	buf[o++] = 0;			/* root */

	buf[o++] = (uint8_t)(qtype >> 8);
	buf[o++] = (uint8_t)(qtype & 0xff);
	buf[o++] = 0;			/* IN */
	buf[o++] = 1;

	return o;
}

/*
 * Fixture creation.  Everything lives under a per-run scratch dir so runs
 * as different uids cannot trip over each other's leftovers, and every
 * created object is chmod'd explicitly so the arrangement does not depend
 * on the process umask.
 */

static char run_dir[512];

static int
mk_zone_dir(const char *path, mode_t mode)
{
	struct stat st;

	if (mkdir(path, 0700) < 0 && errno != EEXIST) {
		lwsl_err("%s: mkdir %s failed errno %d\n", __func__, path,
				errno);
		return 1;
	}

	if (chmod(path, mode) == 0)
		return 0;

	/*
	 * chmod can fail on something another uid left behind; what matters
	 * is the effective mode is the one this phase needs
	 */
	if (stat(path, &st) == 0 && (st.st_mode & 07777) == mode)
		return 0;

	lwsl_err("%s: chmod %s to %o failed\n", __func__, path,
			(unsigned int)mode);

	return 1;
}

static int
write_zone_text(const char *dir, const char *fname, const char *text,
		mode_t mode)
{
	size_t l = strlen(text);
	char path[1024];
	int fd, n;

	lws_snprintf(path, sizeof(path), "%s/%s", dir, fname);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		lwsl_err("%s: open %s failed\n", __func__, path);
		return 1;
	}
	n = (write(fd, text, l) == (ssize_t)l);
	close(fd);

	if (!n || chmod(path, mode)) {
		lwsl_err("%s: write/chmod %s failed\n", __func__, path);
		return 1;
	}

	return 0;
}

static int
write_zone(const char *dir, const char *fname, const char *origin,
	   const char *ip, mode_t mode)
{
	char buf[2048];

	lws_snprintf(buf, sizeof(buf),
			"$ORIGIN %s.\n"
			"$TTL 86400\n"
			"@	IN	SOA	ns1.%s. hostmaster.%s. (\n"
			"			2026090101 ; serial\n"
			"			3600 1800 604800 86400 )\n"
			"@	IN	NS	ns1.%s.\n"
			"www	IN	A	%s\n",
			origin, origin, origin, origin, ip);

	return write_zone_text(dir, fname, buf, mode);
}

/*
 * phase 8: sub.dl.example is delegated, with glue, and the zone text also
 * has an A record below the cut that the zone cannot be authoritative for
 */

static const char *zone_deleg =
	"$ORIGIN dl.example.\n"
	"$TTL 86400\n"
	"@	IN	SOA	ns1.dl.example. hostmaster.dl.example. "
		"( 2026090101 3600 1800 604800 86400 )\n"
	"@	IN	NS	ns1.dl.example.\n"
	"ns1	IN	A	127.0.0.1\n"
	"www	IN	A	127.0.0.77\n"
	"sub	IN	NS	ns.sub.dl.example.\n"
	"sub	IN	DS	12345 13 2 0123456789abcdef0123456789abcdef"
		"0123456789abcdef0123456789abcdef\n"
	"ns.sub	IN	A	127.0.0.53\n"
	"www.sub	IN	A	127.0.0.66\n";

static int
plant_fixtures(void)
{
	char dir[512], target[512], link[512];

	if (mk_zone_dir(BASE_DIR, 0755))
		return 1;

	/* the per-run scratch dir */

	if (mk_zone_dir(run_dir, 0755))
		return 1;

	/* phase 1: a clean, service-owned arrangement */

	lws_snprintf(dir, sizeof(dir), "%s/good", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "ok.example" DECOR, "ok.example", "127.0.0.77", 0644))
		return 1;

	/* phase 3: world-writable dir with a planted zone */

	lws_snprintf(dir, sizeof(dir), "%s/ww", run_dir);
	if (mk_zone_dir(dir, 0777) ||
	    write_zone(dir, "pwn.example" DECOR, "pwn.example", "127.0.0.66", 0644))
		return 1;

	/*
	 * phase 4: a valid arrangement reached through a symlinked zone-dir
	 * path
	 */

	lws_snprintf(dir, sizeof(dir), "%s/real", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "via.example" DECOR, "via.example", "127.0.0.65", 0644))
		return 1;

	lws_snprintf(link, sizeof(link), "%s/symlink", run_dir);
	unlink(link);
	if (symlink(dir, link)) {
		lwsl_err("%s: symlink %s failed errno %d\n", __func__, link,
				errno);
		return 1;
	}

	/*
	 * phase 5: good dir, but only one file of the lot is admissible
	 */

	lws_snprintf(dir, sizeof(dir), "%s/files", run_dir);
	if (mk_zone_dir(dir, 0700))
		return 1;

	if (write_zone(dir, "ok2.example" DECOR, "ok2.example", "127.0.0.77", 0644))
		return 1;

	/* undecorated name: valid content, foreign shape */
	if (write_zone(dir, "plain.example.zone", "plain.example", "127.0.0.66", 0644))
		return 1;

	/* only two numeric suffix fields */
	if (write_zone(dir, "short.example_2000000000_2000000000.zone",
			"short.example", "127.0.0.66", 0644))
		return 1;

	/* right shape and content, but group-writable */
	if (write_zone(dir, "badmode.example" DECOR, "badmode.example",
			"127.0.0.66", 0666))
		return 1;

	/* right shape, but a symlink to a valid zone file */
	lws_snprintf(target, sizeof(target), "%s/%s", dir, "ok2.example" DECOR);
	lws_snprintf(link, sizeof(link), "%s/linked.example" DECOR, dir);
	unlink(link);
	if (symlink(target, link)) {
		lwsl_err("%s: symlink %s failed errno %d\n", __func__, link,
				errno);
		return 1;
	}

	/* phase 6: the zone the handed-over payloads go after */

	lws_snprintf(dir, sizeof(dir), "%s/dht", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "victim.example" DECOR, "victim.example",
		       "127.0.0.77", 0644))
		return 1;

	{
		size_t i;

		for (i = 0; i < LWS_ARRAY_SIZE(zd_handed); i++) {
			char path[768];
			size_t l = strlen(zd_handed[i].text);
			int fd;

			lws_snprintf(path, sizeof(path), "%s/%s", run_dir,
				     zd_handed[i].file);
			fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
			if (fd < 0)
				return 1;
			if (write(fd, zd_handed[i].text, l) != (ssize_t)l) {
				close(fd);
				return 1;
			}
			close(fd);
		}
	}

	/* phase 8: a zone with a delegation */

	lws_snprintf(dir, sizeof(dir), "%s/deleg", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone_text(dir, "dl.example" DECOR, zone_deleg, 0644))
		return 1;

	/* phase 9: three operator zones, with cache-max-zones 1 */

	lws_snprintf(dir, sizeof(dir), "%s/pressure", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "p1.example" DECOR, "p1.example", "127.0.0.71", 0644) ||
	    write_zone(dir, "p2.example" DECOR, "p2.example", "127.0.0.72", 0644) ||
	    write_zone(dir, "p3.example" DECOR, "p3.example", "127.0.0.73", 0644))
		return 1;

	/* phase 10: one operator zone, then DHT zones, cache-max-zones 1 */

	lws_snprintf(dir, sizeof(dir), "%s/dhtpress", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "loc.example" DECOR, "loc.example", "127.0.0.74", 0644))
		return 1;

	/*
	 * phases 9+10 (root only): another uid's file in an otherwise good
	 * dir, and another uid's dir
	 */

	lws_snprintf(dir, sizeof(dir), "%s/rootfile", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "okroot.example" DECOR, "okroot.example", "127.0.0.77", 0644) ||
	    write_zone(dir, "foreign.example" DECOR, "foreign.example", "127.0.0.66", 0644))
		return 1;

	lws_snprintf(dir, sizeof(dir), "%s/rootdir", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "another.example" DECOR, "another.example", "127.0.0.66", 0644))
		return 1;

	if (!geteuid()) {
		char path[512];

		lws_snprintf(path, sizeof(path), "%s/rootfile/foreign.example" DECOR, run_dir);
		if (chown(path, 1, (gid_t)-1)) {
			lwsl_err("%s: chown %s failed\n", __func__, path);
			return 1;
		}

		if (chown(dir, 1, (gid_t)-1)) {
			lwsl_err("%s: chown rootdir failed\n", __func__);
			return 1;
		}
	}

	return 0;
}

/* best-effort removal of this run's scratch dir (known contents) */

static void
unplant_fixtures(void)
{
	static const char *const subdirs[] = {
		"good", "ww", "real", "files", "dht", "deleg", "pressure",
		"dhtpress", "rootfile", "rootdir"
	};
	static const char *const zones[] = {
		"ok", "pwn", "via", "ok2", "badmode", "linked", "okroot",
		"foreign", "another", "victim", "dl", "p1", "p2", "p3", "loc"
	};
	size_t i;

	for (i = 0; i < LWS_ARRAY_SIZE(zd_handed); i++) {
		char fpath[768];

		lws_snprintf(fpath, sizeof(fpath), "%s/%s", run_dir,
			     zd_handed[i].file);
		unlink(fpath);
	}

	for (i = 0; i < LWS_ARRAY_SIZE(subdirs); i++) {
		char dpath[600], fpath[768];
		size_t z;

		lws_snprintf(dpath, sizeof(dpath), "%s/%s", run_dir, subdirs[i]);

		lws_snprintf(fpath, sizeof(fpath), "%s/symlink", run_dir);
		unlink(fpath);

		for (z = 0; z < LWS_ARRAY_SIZE(zones); z++) {
			lws_snprintf(fpath, sizeof(fpath), "%s/%s.example" DECOR,
				     dpath, zones[z]);
			unlink(fpath);
		}
		lws_snprintf(fpath, sizeof(fpath), "%s/plain.example.zone", dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath),
				"%s/short.example_2000000000_2000000000.zone", dpath);
		unlink(fpath);

		rmdir(dpath);
	}

	rmdir(run_dir);
}

static int
udp_port_free(int port)
{
	struct sockaddr_in sa;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return 0;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		close(fd);
		return 0;
	}

	close(fd);

	return 1;
}

static void
drive_cb(lws_sorted_usec_list_t *sul)
{
	lws_usec_t now = lws_now_usecs();
	int n, still_waiting = 0, window;
	ssize_t r;
	uint8_t buf[2048];

	(void)sul;

	/* harvest any responses */

	do {
		struct qexp *q = NULL;
		int i;

		r = recv(cli_fd, buf, sizeof(buf), 0);
		if (r < 12)
			break;

		for (i = 0; i < MAX_Q; i++) {
			if (!cur->q[i].name)
				break;
			if (cur->q[i].id == (uint16_t)((buf[0] << 8) | buf[1])) {
				q = &cur->q[i];
				break;
			}
		}

		if (!q) {
			lwsl_err("%s: stray packet id %02x%02x\n", __func__,
					buf[0], buf[1]);
			phase_failed = 1;
			phase_done = 1;
			return;
		}

		if (!(buf[2] & 0x80)) {
			lwsl_err("%s: not a response\n", __func__);
			phase_failed = 1;
			phase_done = 1;
			return;
		}

		q->got_rcode = buf[3] & 0xf;
		q->got_anc = (buf[6] << 8) | buf[7];
		q->got_aa = !!(buf[2] & 0x04);
		q->got_nsc = (buf[8] << 8) | buf[9];
	} while (1);

	/* first tick after the listeners should be up: send the queries */

	if (!phase_failed && !cur->q[0].sent) {
		if (cur->dht) {
			size_t i;

			/* it registers again a little later, after refusals */
			if (!dht_auth_cb && ++zd_reg_waits < 40)
				goto again;
			if (!dht_auth_cb) {
				lwsl_err("%s: auth-dns registered no callback "
					 "for verified zones\n", __func__);
				phase_failed = 1;
				phase_done = 1;
				return;
			}

			/* as lws-dht-dnssec does, once it verified each */

			for (i = 0; i < LWS_ARRAY_SIZE(zd_handed); i++) {
				char path[768];

				lws_snprintf(path, sizeof(path), "%s/%s",
					     run_dir, zd_handed[i].file);
				dht_auth_cb(dht_auth_opaque,
					    zd_handed[i].domain, path);
			}
		}

		for (n = 0; n < MAX_Q && cur->q[n].name; n++) {
			size_t ql = mk_query(buf, sizeof(buf), cur->q[n].id,
					     cur->q[n].name,
					     cur->q[n].qtype ? cur->q[n].qtype :
							LWS_ADNS_RECORD_A);

			if (!ql ||
			    sendto(cli_fd, buf, ql, 0,
				   (struct sockaddr *)&auth_sa,
				   sizeof(auth_sa)) < 0) {
				lwsl_err("%s: query %d sendto failed errno %d\n",
						__func__, n, errno);
				phase_failed = 1;
				break;
			}
			cur->q[n].sent = 1;
		}
		if (phase_failed) {
			phase_done = 1;
			return;
		}

		lwsl_user("phase '%s': %d queries sent\n", cur->name, n);
	}

	for (n = 0; n < MAX_Q && cur->q[n].name; n++) {
		if (cur->q[n].expect_rcode < 0) {
			/* no response must ever arrive for this one */
			if (cur->q[n].got_rcode != -1)
				continue; /* handled as failure below */
		} else if (cur->q[n].got_rcode != cur->q[n].expect_rcode ||
			   cur->q[n].got_anc < cur->q[n].expect_anc)
			still_waiting++;
	}

	window = still_waiting ? (cur->fetch ? RESP_FETCH_US : RESP_US) :
				 QUIET_US;

	if (now - t0 >= (lws_usec_t)window || now - t0 >= DEADLINE_US) {
		int i;

		for (i = 0; i < MAX_Q && cur->q[i].name; i++) {
			if (cur->q[i].expect_rcode < 0) {
				if (cur->q[i].got_rcode != -1) {
					lwsl_err("phase '%s': FAIL %s was "
						 "answered (rcode %d)\n",
						 cur->name, cur->q[i].name,
						 cur->q[i].got_rcode);
					phase_failed = 1;
				} else
					lwsl_user("phase '%s': %s stayed "
						  "unanswered\n", cur->name,
						  cur->q[i].name);
				continue;
			}
			/*
			 * a referral: not authoritative, no answer, the cut's
			 * NS RRset in the authority section
			 */
			if (cur->q[i].expect_ref == 1 &&
			    (cur->q[i].got_aa || cur->q[i].got_anc ||
			     cur->q[i].got_nsc < 1)) {
				lwsl_err("phase '%s': FAIL %s not referred: "
					 "aa %d anc %d nsc %d\n", cur->name,
					 cur->q[i].name, cur->q[i].got_aa,
					 cur->q[i].got_anc, cur->q[i].got_nsc);
				phase_failed = 1;
				continue;
			}
			if (cur->q[i].expect_ref == 2 && !cur->q[i].got_aa) {
				lwsl_err("phase '%s': FAIL %s not answered "
					 "authoritatively\n", cur->name,
					 cur->q[i].name);
				phase_failed = 1;
				continue;
			}
			if (cur->q[i].got_rcode != cur->q[i].expect_rcode ||
			    cur->q[i].got_anc < cur->q[i].expect_anc) {
				lwsl_err("phase '%s': FAIL %s rcode %d/%d "
					 "anc %d/%d\n", cur->name,
					 cur->q[i].name,
					 cur->q[i].got_rcode,
					 cur->q[i].expect_rcode,
					 cur->q[i].got_anc,
					 cur->q[i].expect_anc);
				phase_failed = 1;
			} else
				lwsl_user("phase '%s': %s rcode %d anc %d "
					  "ok\n", cur->name,
					  cur->q[i].name,
					  cur->q[i].got_rcode,
					  cur->q[i].got_anc);
		}

		/*
		 * the query was answered after its timeout: nothing waits for
		 * the zone, so its fetch must be over, completed once
		 */
		if (cur->fetch == 2) {
			/*
			 * each zone asked for once, the first queries' up to
			 * the burst, the rest refused; a query for a zone
			 * already being fetched waits on that fetch
			 */
			if (zd_fetch_calls < ZD_FETCH_BURST ||
			    zd_fetch_calls > ZD_FETCH_BURST + 1) {
				lwsl_err("phase '%s': FAIL %d fetches started, "
					 "wanted %d\n", cur->name,
					 zd_fetch_calls, ZD_FETCH_BURST);
				phase_failed = 1;
			} else
				lwsl_user("phase '%s': %d fetches started\n",
					  cur->name, zd_fetch_calls);
		} else if (cur->fetch) {
			if (zd_fetch_starts != 1 || zd_fetch.pending ||
			    zd_fetch_completions != 1 ||
			    zd_fetch_status != LWS_DHT_DNSSEC_FETCH_TIMEOUT) {
				lwsl_err("phase '%s': FAIL fetch started %d, "
					 "still pending %d, completed %d "
					 "(status %d), wanted 1, 0, 1 (%d)\n",
					 cur->name, zd_fetch_starts,
					 zd_fetch.pending, zd_fetch_completions,
					 zd_fetch_status,
					 LWS_DHT_DNSSEC_FETCH_TIMEOUT);
				phase_failed = 1;
			} else
				lwsl_user("phase '%s': fetch given up and "
					  "completed once, as timed out\n",
					  cur->name);
		}

		if (cur->check_port_free && !udp_port_free(ports[phase_idx & 1])) {
			lwsl_err("phase '%s': FAIL udp port %d is still bound, "
				 "protocol init did not refuse\n", cur->name,
				 ports[phase_idx & 1]);
			phase_failed = 1;
		}

		phase_done = 1;

		return;
	}

again:
	lws_sul_schedule(context, 0, &sul_drive, drive_cb, TICK_US);
}

static void
sigint_handler(int sig)
{
	(void)sig;

	lws_default_loop_exit(context);
}

static int
run_phase(struct phase *p, int idx)
{
	struct lws_context_creation_info info;
	const struct lws_protocols my_protocols[] = {
		lws_auth_dns_protocols[0],
		{ NULL, NULL, 0, 0, 0, NULL, 0 }
	}, my_protocols_dht[] = {
		lws_auth_dns_protocols[0],
		{ "lws-dht-dnssec", lws_callback_http_dummy, 0, 0, 0,
		  &zd_dht_ops, 0 },
		{ NULL, NULL, 0, 0, 0, NULL, 0 }
	}, my_protocols_fetch[] = {
		lws_auth_dns_protocols[0],
		{ "lws-dht-dnssec", lws_callback_http_dummy, 0, 0, 0,
		  &zd_dht_fetch_ops, 0 },
		{ NULL, NULL, 0, 0, 0, NULL, 0 }
	};
	struct lws_protocol_vhost_options pvo_extra = {
		NULL, NULL, "cache-max-zones", "499"
	};
	struct lws_protocol_vhost_options pvo_cache_max = {
		NULL, NULL, "cache-max-zones", ""
	};
	struct lws_protocol_vhost_options pvo_zonedir = {
		NULL, NULL, "zone-dir", ""
	};
	struct lws_protocol_vhost_options pvo = {
		NULL, NULL, "protocol-lws-auth-dns", ""
	};
	char zd[512] = "";
	int n = 0;

	cur = p;
	phase_idx = idx;
	phase_done = phase_failed = 0;
	t0 = lws_now_usecs();

	/* discard anything left over from the previous phase */

	{
		uint8_t dbuf[2048];

		while (recv(cli_fd, dbuf, sizeof(dbuf), 0) >= 0)
			;
	}

	lws_context_info_defaults(&info, NULL);
	/* a server: size the fds tables to the process limit */
	info.fd_limit_per_thread = 0;
	info.port = ports[idx & 1];
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "protocol-lws-auth-dns";
	info.protocols = p->fetch ? my_protocols_fetch :
			 (p->dht ? my_protocols_dht : my_protocols);
	dht_auth_cb = NULL;
	zd_reg_refused = zd_reg_waits = 0;
	zd_fetch_reset();

	if (p->zdir) {
		lws_snprintf(zd, sizeof(zd), "%s/%s", run_dir, p->zdir);
		pvo_zonedir.value = zd;
		pvo.options = &pvo_zonedir;
		if (p->cache_max) {
			pvo_cache_max.value = p->cache_max;
			pvo_zonedir.next = &pvo_cache_max;
		}
	} else
		/*
		 * some pvo content is needed so the plugin actually runs its
		 * init refusal path rather than the !in early exit
		 */
		pvo.options = &pvo_extra;
	info.pvo = &pvo;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("phase '%s': lws init failed\n", p->name);
		return 1;
	}

	lws_sul_schedule(context, 0, &sul_drive, drive_cb, TICK_US);

	while (n >= 0 && !phase_done)
		n = lws_service(context, 0);

	if (n < 0) /* loop exit requested */
		phase_failed = 1;

	lws_context_destroy(context);
	context = NULL;

	/* the operator's zone files are still where they put them */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(p->keep) && p->keep[n]; n++) {
		char path[768];
		struct stat st;

		lws_snprintf(path, sizeof(path), "%s/%s", zd, p->keep[n]);
		if (stat(path, &st)) {
			lwsl_err("phase '%s': FAIL zone file %s is gone\n",
				 p->name, p->keep[n]);
			phase_failed = 1;
		} else
			lwsl_user("phase '%s': zone file %s kept\n", p->name,
				  p->keep[n]);
	}

	if (phase_failed)
		test_ok = 0;

	return phase_failed;
}

int
main(int argc, const char **argv)
{
	struct phase tbl[] = {
		{
			.name		= "good dir serves decorated zone",
			.zdir		= "good",
			.q		= {
				{ "www.ok.example", 0x1101, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "missing zone-dir pvo refused",
			.zdir		= NULL,
			.check_port_free = 1,
			.q		= {
				{ "www.any.example", 0x1102, -1, 0, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "world-writable zone dir refused",
			.zdir		= "ww",
			.check_port_free = 1,
			.q		= {
				{ "www.pwn.example", 0x1103, -1, 0, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "symlinked zone dir refused",
			.zdir		= "symlink",
			.check_port_free = 1,
			.q		= {
				{ "www.via.example", 0x1104, -1, 0, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "foreign files in good dir ignored",
			.zdir		= "files",
			.q		= {
				{ "www.ok2.example", 0x1105, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.plain.example", 0x2105, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.short.example", 0x3105, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.badmode.example", 0x4105, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.linked.example", 0x5105, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "zones handed over by dht-dnssec",
			.zdir		= "dht",
			.dht		= 1,
			.q		= {
				/* the served zone is still the dir's own */
				{ "www.victim.example", 0x1108, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
				/* nothing from either payload was installed */
				{ "evil.victim.example", 0x2108, 3, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "evil2.victim.example", 0x3108, 3, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.a.example", 0x4108, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				/* while a zone that is its domain's is */
				{ "www.ok3.example", 0x5108, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
				/* unless it is unsigned or out of date */
				{ "www.ok5.example", 0x6108, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.ok6.example", 0x7108, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "zone fetch given up with its query",
			.zdir		= "good",
			.fetch		= 1,
			.q		= {
				/* REFUSED once its 5s wait for the zone ends */
				{ "www.unserved.example", 0x1109, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			/*
			 * G-508: a spoofed query stream for zones nobody
			 * serves must not start a DHT fetch each.  All are
			 * REFUSED: those past the burst at once, the rest
			 * when their wait for the zone ends.
			 */
			.name		= "query-driven zone fetches rate limited",
			.zdir		= "good",
			.fetch		= 2,
			.q		= {
				{ "www.rl1.example", 0x110d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.rl2.example", 0x120d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.rl3.example", 0x130d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.rl4.example", 0x140d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.rl5.example", 0x150d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.rl6.example", 0x160d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.rl7.example", 0x170d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.rl8.example", 0x180d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.rl9.example", 0x190d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.rl10.example", 0x1a0d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				/* waits on the fetch the first one started */
				{ "ftp.rl1.example", 0x1b0d, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "names at or below a zone cut referred",
			.zdir		= "deleg",
			.q		= {
				/* the zone's own data, as before */
				{ "www.dl.example", 0x110a, 0, 1, -1, -1, 0,
				  0, 2, 0, 0 },
				/* data occluded by the cut */
				{ "www.sub.dl.example", 0x210a, 0, 0, -1, -1, 0,
				  0, 1, 0, 0 },
				/* glue */
				{ "ns.sub.dl.example", 0x310a, 0, 0, -1, -1, 0,
				  0, 1, 0, 0 },
				/* a name the zone text does not have */
				{ "x.sub.dl.example", 0x410a, 0, 0, -1, -1, 0,
				  0, 1, 0, 0 },
				/* but the DS at the cut is the parent's */
				{ "sub.dl.example", 0x510a, 0, 1, -1, -1, 0,
				  43, 2, 0, 0 },
			}
		}, {
			.name		= "operator zones over cache-max-zones",
			.zdir		= "pressure",
			.cache_max	= "1",
			.keep		= { "p1.example" DECOR, "p2.example" DECOR,
					    "p3.example" DECOR },
			.q		= {
				{ "www.p1.example", 0x110b, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.p2.example", 0x210b, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.p3.example", 0x310b, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "operator zone under DHT cache pressure",
			.zdir		= "dhtpress",
			.dht		= 1,
			.cache_max	= "1",
			.keep		= { "loc.example" DECOR },
			.q		= {
				/* the operator's zone is still served */
				{ "www.loc.example", 0x110c, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
				/* the DHT zones are bounded: ok4 evicted ok3 */
				{ "www.ok3.example", 0x210c, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.ok4.example", 0x310c, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "another uid's file ignored",
			.zdir		= "rootfile",
			.q		= {
				{ "www.okroot.example", 0x1106, 0, 1, -1, -1, 0, 0, 0, 0, 0 },
				{ "www.foreign.example", 0x2106, 5, 0, -1, -1, 0, 0, 0, 0, 0 },
			}
		}, {
			.name		= "another uid's zone dir refused",
			.zdir		= "rootdir",
			.check_port_free = 1,
			.q		= {
				{ "www.another.example", 0x1107, -1, 0, -1, -1, 0, 0, 0, 0, 0 },
			}
		},
	};
	int nph = 10, i, ret;

	const char *p;

	signal(SIGINT, sigint_handler);

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);

	if ((p = lws_cmdline_option(argc, argv, "-p"))) {
		ports[0] = atoi(p);
		if (ports[0] <= 0 || ports[0] > 65535) {
			lwsl_err("Bad port %s\n", p);
			return 1;
		}
	}

	if ((p = lws_cmdline_option(argc, argv, "-b"))) {
		ports[1] = atoi(p);
		if (ports[1] <= 0 || ports[1] > 65535) {
			lwsl_err("Bad port %s\n", p);
			return 1;
		}
	}

	if (!ports[0] || !ports[1]) {
		lwsl_err("usage: %s -p <auth dns port a> -b <auth dns port b>\n",
				argv[0]);
		return 1;
	}

	if (geteuid())
		lwsl_user("not running as root: uid-based phases skipped\n");
	else
		nph = (int)LWS_ARRAY_SIZE(tbl);

	lws_snprintf(run_dir, sizeof(run_dir), "%s/%d", BASE_DIR,
			(int)getpid());

	if (plant_fixtures()) {
		lwsl_err("fixture planting failed\n");
		return 1;
	}

	cli_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (cli_fd < 0) {
		lwsl_err("client socket failed\n");
		unplant_fixtures();
		return 1;
	}

	if (fcntl(cli_fd, F_SETFL, O_NONBLOCK) < 0) {
		lwsl_err("client socket fcntl failed\n");
		close(cli_fd);
		unplant_fixtures();
		return 1;
	}

	lwsl_user("LWS API selftest: auth dns zone dir trust (F-055)\n");

	for (i = 0; i < nph; i++) {
		lwsl_user("--- phase %d: %s\n", i + 1, tbl[i].name);

		memset(&auth_sa, 0, sizeof(auth_sa));
		auth_sa.sin_family = AF_INET;
		auth_sa.sin_port = htons((uint16_t)ports[i & 1]);
		auth_sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		if (run_phase(&tbl[i], i)) {
			lwsl_err("phase %d (%s) FAILED\n", i + 1, tbl[i].name);
			break;
		}
	}

	ret = i != nph;

	lwsl_user("Completed: %s\n", test_ok && !ret ? "PASS" : "FAIL");

	close(cli_fd);
	unplant_fixtures();

	return !test_ok || ret;
}
