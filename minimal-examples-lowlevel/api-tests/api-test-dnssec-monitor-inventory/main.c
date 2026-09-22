/*
 * lws-api-test-dnssec-monitor-inventory
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Exercises the dnssec-monitor plugin's Server IP Inventory directly:
 * zonefiles are laid into a throwaway <base-dir>/domains corpus, and the
 * get_ip_inventory request handler is driven across all of its pages.
 *
 * Covered behaviours:
 *
 *  - every kind of record in a zonefile is cached as a row, and the
 *    rolled-up server list is derived from those rows at read time
 *  - v4 and v6 address records on one owner name come out as one server
 *  - an address shared by a nameserver name and a host name is marked
 *    ns without ns_only ("our infrastructure"), while an address only
 *    bound to an NS target is ns_only ("may not be our infrastructure")
 *  - a LOC record for an addressed name comes out on its server, but a
 *    LOC-only name produces no server
 *  - an NS target with no address records in any zonefile produces no
 *    server
 *  - a changed zonefile is rescanned into the cache and a removed
 *    domain's rows are dropped
 *  - cursor pagination covers every server exactly once
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "private.h"

/* the translation unit under test */
void handle_req_get_ip_inventory(struct vhd *vhd, struct pss *root_pss,
				  struct monitor_req_args *a);

#define T_MAX_SERVERS	4096
#define T_MAX_IPS	8
#define T_NAME_SZ	256

struct t_ip {
	char	ip[46];
	int	v6, ns, ns_only;
};

struct t_srv {
	char	name[T_NAME_SZ];
	char	loc[128];
	int	ns, has_v4, has_v6;
	struct t_ip	ips[T_MAX_IPS];
	int	nips;
};

struct t_inv {
	struct t_srv	servers[T_MAX_SERVERS];
	int		nsrv;
	int		total, more, next;
	int		oops;
};

static const char * const t_paths[] = {
	"servers[].name",
	"servers[].loc",
	"servers[].ns",
	"servers[].v4",
	"servers[].v6",
	"servers[].ips[].ip",
	"servers[].ips[].v6",
	"servers[].ips[].ns",
	"servers[].ips[].ns_only",
	"total",
	"more",
	"next"
};

enum {
	TP_S_NAME,
	TP_S_LOC,
	TP_S_NS,
	TP_S_V4,
	TP_S_V6,
	TP_I_IP,
	TP_I_V6,
	TP_I_NS,
	TP_I_NS_ONLY,
	TP_TOTAL,
	TP_MORE,
	TP_NEXT
};

/*
 * The handler composes "name" first in each server object and "ip" first
 * in each ip object, so the start of those strings opens a new entry.
 * Arrays are not distinguished in lejp paths, so the current entry is
 * simply the last one started.
 */

static signed char
t_cb(struct lejp_ctx *ctx, char reason)
{
	struct t_inv *ti = (struct t_inv *)ctx->user;
	struct t_srv *ts = ti->nsrv ? &ti->servers[ti->nsrv - 1] : NULL;
	int m = ctx->path_match - 1;

	if (reason == LEJPCB_VAL_STR_END) {
		switch (m) {
		case TP_S_NAME:
			if (ti->nsrv == T_MAX_SERVERS) {
				ti->oops = 1;
				break;
			}
			ts = &ti->servers[ti->nsrv++];
			memset(ts, 0, sizeof(*ts));
			lws_strncpy(ts->name, ctx->buf, sizeof(ts->name));
			break;
		case TP_S_LOC:
			if (ts)
				lws_strncpy(ts->loc, ctx->buf, sizeof(ts->loc));
			break;
		case TP_I_IP:
			if (ts && ts->nips < T_MAX_IPS)
				lws_strncpy(ts->ips[ts->nips++].ip, ctx->buf,
					    sizeof(ts->ips[0].ip));
			break;
		default:
			break;
		}

		return 0;
	}

	if (reason == LEJPCB_VAL_NUM_INT || reason == LEJPCB_VAL_TRUE ||
	    reason == LEJPCB_VAL_FALSE) {
		int v = atoi(ctx->buf);

		if (reason == LEJPCB_VAL_TRUE)
			v = 1;
		if (reason == LEJPCB_VAL_FALSE)
			v = 0;

		switch (m) {
		case TP_S_NS:	if (ts) ts->ns = v;	break;
		case TP_S_V4:	if (ts) ts->has_v4 = v;	break;
		case TP_S_V6:	if (ts) ts->has_v6 = v;	break;
		case TP_I_V6:
		case TP_I_NS:
		case TP_I_NS_ONLY:
			if (ts && ts->nips) {
				struct t_ip *ti_ =
					&ts->ips[ts->nips - 1];
				if (m == TP_I_V6)		ti_->v6 = v;
				else if (m == TP_I_NS)		ti_->ns = v;
				else				ti_->ns_only = v;
			}
			break;
		case TP_TOTAL:	ti->total = v;		break;
		case TP_MORE:	ti->more = v;		break;
		case TP_NEXT:	ti->next = v;		break;
		}
	}

	return 0;
}

/* fetch every page of the inventory into \p ti; returns 0 if it worked */

static int
t_fetch(struct vhd *vhd, struct t_inv *ti)
{
	struct monitor_req_args a;
	int cursor = 0, pages = 0;

	memset(ti, 0, sizeof(*ti));

	do {
		struct pss pss;
		struct lejp_ctx jctx;
		char *line;

		memset(&pss, 0, sizeof(pss));
		memset(&a, 0, sizeof(a));
		lws_strncpy(a.req, "get_ip_inventory", sizeof(a.req));
		a.cursor = cursor;

		handle_req_get_ip_inventory(vhd, &pss, &a);

		if (!pss.tx_len) {
			lwsl_err("%s: no response\n", __func__);

			return 1;
		}

		line = (char *)&pss.tx[LWS_PRE];
		/* strip the newline frame */
		line[pss.tx_len - 1] = '\0';

		if (strstr(line, "\"status\":\"error\"")) {
			lwsl_err("%s: error response: %s\n", __func__, line);

			return 1;
		}

		lejp_construct(&jctx, t_cb, ti, t_paths,
			       LWS_ARRAY_SIZE(t_paths));
		if (lejp_parse(&jctx, (const uint8_t *)line,
			       (int)strlen(line)) < 0 || ti->oops) {
			lejp_destruct(&jctx);
			lwsl_err("%s: parse failed\n", __func__);

			return 1;
		}
		lejp_destruct(&jctx);

		cursor = ti->next;
		pages++;
	} while (ti->more && pages < 500);

	return ti->more ? 1 : 0;
}

static struct t_srv *
t_find(struct t_inv *ti, const char *name)
{
	for (int n = 0; n < ti->nsrv; n++)
		if (!strcmp(ti->servers[n].name, name))
			return &ti->servers[n];

	return NULL;
}

static int
t_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);

		return 1;
	}

	return 0;
}

static int
t_write_file(const char *path, const char *content)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	size_t l = strlen(content);

	if (fd < 0)
		return 1;
	if (write(fd, content, l) != (ssize_t)l) {
		close(fd);

		return 1;
	}
	close(fd);

	return 0;
}

static int
t_mkdir(const char *path)
{
	if (mkdir(path, 0700) && errno != EEXIST)
		return 1;

	return 0;
}

static const char *z_example =
	"$ORIGIN example.com.\n"
	"$TTL 3600\n"
	"@ IN SOA ns1.example.com. admin.example.com. ("
	" 2026092201 7200 900 1209600 3600 )\n"
	"@ IN NS ns1\n"
	"@ IN NS ns2.example.com.\n"
	"ns1 IN A 192.0.2.1\n"
	"ns1 IN AAAA 2001:db8::1\n"
	"ns1 IN LOC 42 21 54 N 71 6 18 W -24m 30m 200m 15m\n"
	"www IN A 192.0.2.1\n"
	"www IN AAAA 2001:db8::1\n"
	"mail IN A 192.0.2.9\n"
	"lonely IN LOC 1 2 3 N 4 5 6 E 10m\n"
	"@ IN TXT \"v=spf1 -all\"\n";

static const char *z_other =
	"$ORIGIN other.com.\n"
	"$TTL 3600\n"
	"@ IN SOA ns1.other.com. admin.other.com. ("
	" 2026092201 7200 900 1209600 3600 )\n"
	"@ IN NS ns1.example.com.\n"
	"@ IN NS ns3\n"
	"ns3 IN A 198.51.100.3\n";

/* large enough that it must live in .bss, not on the stack */
static struct t_inv ti;

int main(void)
{
	struct vhd vhd;
	struct t_srv *s;
	char path[512];
	int fails = 0, n;

	unlink("./ip-inventory.sqlite3");
	lws_dir("./inv-corpus", NULL, lws_dir_rm_rf_cb);
	rmdir("./inv-corpus");

	if (t_mkdir("./inv-corpus") ||
	    t_mkdir("./inv-corpus/domains") ||
	    t_mkdir("./inv-corpus/domains/example.com") ||
	    t_mkdir("./inv-corpus/domains/other.com") ||
	    t_write_file("./inv-corpus/domains/example.com/example.com.zone",
			 z_example) ||
	    t_write_file("./inv-corpus/domains/other.com/other.com.zone",
			 z_other)) {
		lwsl_err("%s: unable to lay down corpus\n", __func__);

		return 1;
	}

	memset(&vhd, 0, sizeof(vhd));
	vhd.base_dir = "./inv-corpus";

	/* initial rollup */

	if (t_fetch(&vhd, &ti)) {
		lwsl_err("%s: fetch failed\n", __func__);

		return 1;
	}

	fails += t_expect(ti.nsrv == 4, "four servers: ns1, www, mail, ns3");
	fails += t_expect(ti.total == 4, "total matches");

	s = t_find(&ti, "ns1.example.com.");
	fails += t_expect(!!s, "ns1 present");
	if (s) {
		fails += t_expect(s->ns, "ns1 is an NS target");
		fails += t_expect(s->has_v4 && s->has_v6, "ns1 has v4 and v6");
		fails += t_expect(s->nips == 2, "ns1 has both addresses");
		fails += t_expect(!!strstr(s->loc, "42 21 54 N"),
				  "ns1 carries its LOC record");
		/*
		 * its addresses are also bound to www, so they are ns but
		 * not ns_only: the nameserver is our infrastructure
		 */
		for (n = 0; n < s->nips; n++)
			fails += t_expect(s->ips[n].ns && !s->ips[n].ns_only,
					  "ns1 address is ns, not ns_only");
	}

	s = t_find(&ti, "www.example.com.");
	fails += t_expect(!!s, "www present");
	if (s) {
		fails += t_expect(!s->ns, "www is not an NS target");
		for (n = 0; n < s->nips; n++)
			fails += t_expect(s->ips[n].ns && !s->ips[n].ns_only,
					  "www address shared with nameserver");
	}

	s = t_find(&ti, "ns3.other.com.");
	fails += t_expect(!!s, "ns3 present");
	if (s)
		fails += t_expect(s->nips == 1 && s->ips[0].ns &&
				  s->ips[0].ns_only,
				  "ns3 address is NS glue only");

	fails += t_expect(!!t_find(&ti, "mail.example.com."),
			  "mail present");
	fails += t_expect(!t_find(&ti, "ns2.example.com."),
			  "NS target with no address records absent");
	fails += t_expect(!t_find(&ti, "lonely.example.com."),
			  "LOC-only name absent");

	/*
	 * A changed zonefile is rescanned: extend example.com's zone with
	 * one more host record and require it to appear alongside the rest
	 */

	{
		char bigger[1024];

		lws_snprintf(bigger, sizeof(bigger), "%snewhost IN A 203.0.113.99\n",
			     z_example);

		fails += t_expect(!t_write_file(
			"./inv-corpus/domains/example.com/example.com.zone",
			bigger) &&
			!t_fetch(&vhd, &ti) &&
			ti.nsrv == 5 &&
			!!t_find(&ti, "newhost.example.com."),
			"appended record appears after rescan");
	}

	/* a removed domain's rows are dropped */

	lws_dir("./inv-corpus/domains/other.com", NULL, lws_dir_rm_rf_cb);
	rmdir("./inv-corpus/domains/other.com");

	fails += t_expect(!t_fetch(&vhd, &ti) &&
			  !t_find(&ti, "ns3.other.com.") &&
			  ti.nsrv == 4,
			  "removed domain rows dropped");

	/*
	 * enough zones to need real pagination: two servers each, so this
	 * overflows the first page's room-based budget
	 */

	for (n = 0; n < 400; n++) {
		char zone[256];

		lws_snprintf(path, sizeof(path),
			     "./inv-corpus/domains/z%d.example", n);
		if (t_mkdir(path))
			goto page_fail;
		lws_snprintf(zone, sizeof(zone),
			     "$ORIGIN z%d.example.\n"
			     "@ IN SOA ns.z%d.example. a.z%d.example."
			     " ( 1 2 3 4 5 )\n"
			     "@ IN NS ns\n"
			     "ns IN A 10.50.%d.%d\n"
			     "www IN AAAA 2001:db8:%x::1\n",
			     n, n, n, n / 256, n % 256, n);
		lws_snprintf(path + strlen(path), sizeof(path) - strlen(path),
			     "/z%d.example.zone", n);
		if (t_write_file(path, zone))
			goto page_fail;

		continue;
page_fail:
		lwsl_err("%s: corpus page build failed\n", __func__);

		return 1;
	}

	if (t_fetch(&vhd, &ti)) {
		lwsl_err("%s: paged fetch failed\n", __func__);

		return 1;
	}

	/* every server exactly once, and the same set the total promised */
	{
		int i, j, dups = 0;

		for (i = 0; i < ti.nsrv; i++)
			for (j = i + 1; j < ti.nsrv; j++)
				if (!strcmp(ti.servers[i].name,
					    ti.servers[j].name))
					dups++;

		fails += t_expect(!dups, "no duplicate servers across pages");
		fails += t_expect(ti.nsrv == ti.total,
				  "paginated count matches total");
		fails += t_expect(ti.total == 804,
				  "400 zones produced 800 servers");
	}

	/* tidy the build-tree corpus away */

	lws_dir("./inv-corpus", NULL, lws_dir_rm_rf_cb);
	rmdir("./inv-corpus");
	unlink("./ip-inventory.sqlite3");

	if (fails) {
		lwsl_err("%s: %d failures\n", __func__, fails);

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
