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
 *    rolled-up interface list is derived from those rows at read time
 *  - the rows list network interfaces, not names: a name binding both a
 *    v4 and a v6 address proves they are addresses of the same
 *    interface, and all names pointing at any of those addresses are
 *    collected as evidence on that one interface
 *  - dynamic-address records (${MHWC_DYNAMIC} / ${MHWC6_DYNAMIC})
 *    resolve to the DHT-detected addresses passed with the request
 *  - an address shared by a nameserver name and a host name is marked
 *    ns without ns_only ("our infrastructure"), while an address only
 *    bound to an NS target is ns_only ("may not be our infrastructure")
 *  - a LOC record comes out on the name that carries it, but a LOC-only
 *    name produces no interface, nor does an NS target with no address
 *    records
 *  - a changed zonefile is rescanned into the cache and a removed
 *    domain's rows are dropped
 *  - cursor pagination covers every interface exactly once
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

#define T_MAX_IFACES	4096
#define T_MAX_IPS	8
#define T_MAX_NAMES	16
#define T_MAX_NSZ	8
#define T_NAME_SZ	256

struct t_ip {
	char	ip[46];
	int	v6, ns, ns_only;
};

struct t_name {
	char	name[T_NAME_SZ];
	char	loc[128];
	int	ns;
};

struct t_iface {
	struct t_ip	ips[T_MAX_IPS];
	int		nips;
	struct t_name	names[T_MAX_NAMES];
	int		nnames;
	char		ns_zones[T_MAX_NSZ][T_NAME_SZ];
	int		nnsz;
	int		has_v4, has_v6;
};

struct t_inv {
	struct t_iface	ifaces[T_MAX_IFACES];
	int		nif;
	int		total, more, next;
	int		oops;
};

/* large enough that it must live in .bss, not on the stack */
static struct t_inv ti;

static const char * const t_paths[] = {
	"ifaces[].ips[].ip",
	"ifaces[].ips[].v6",
	"ifaces[].ips[].ns",
	"ifaces[].ips[].ns_only",
	"ifaces[].names[].name",
	"ifaces[].names[].loc",
	"ifaces[].names[].ns",
	"ifaces[].ns_zones[].z",
	"ifaces[].v4",
	"ifaces[].v6",
	"total",
	"more",
	"next"
};

enum {
	TP_I_IP,
	TP_I_V6,
	TP_I_NS,
	TP_I_NS_ONLY,
	TP_N_NAME,
	TP_N_LOC,
	TP_N_NS,
	TP_NSZ,
	TP_F_V4,
	TP_F_V6,
	TP_TOTAL,
	TP_MORE,
	TP_NEXT
};

/*
 * The handler composes "ips" first in each interface object and "ip"
 * first in each ip object, and "names" with "name" first in each name
 * object, so the start of those strings opens a new entry.  Arrays are
 * not distinguished in lejp paths, so the current entry is simply the
 * last one started.
 */

static signed char
t_cb(struct lejp_ctx *ctx, char reason)
{
	struct t_inv *tv = (struct t_inv *)ctx->user;
	struct t_iface *tf = tv->nif ? &tv->ifaces[tv->nif - 1] : NULL;
	int m = ctx->path_match - 1;

	if (reason == LEJPCB_VAL_STR_END) {
		switch (m) {
		case TP_I_IP: {
			struct t_iface *cur =
				tv->nif ? &tv->ifaces[tv->nif - 1] : NULL;

			/*
			 * "ips" comes first in each interface object, so
			 * an ip arriving on an interface that already has
			 * names opens the next interface
			 */
			if (cur && cur->nnames)
				cur = NULL;
			if (!cur) {
				if (tv->nif == T_MAX_IFACES) {
					tv->oops = 1;
					break;
				}
				cur = &tv->ifaces[tv->nif++];
				memset(cur, 0, sizeof(*cur));
			}

			if (cur->nips == T_MAX_IPS) {
				tv->oops = 1;
				break;
			}
			lws_strncpy(cur->ips[cur->nips++].ip, ctx->buf,
				    sizeof(cur->ips[0].ip));
			break;
		}
		case TP_N_NAME:
			if (!tf)
				break;
			if (tf->nnames == T_MAX_NAMES) {
				tv->oops = 1;
				break;
			}
			lws_strncpy(tf->names[tf->nnames].name, ctx->buf,
				    T_NAME_SZ);
			tf->nnames++;
			break;
		case TP_N_LOC:
			if (tf && tf->nnames)
				lws_strncpy(tf->names[tf->nnames - 1].loc,
					    ctx->buf,
					    sizeof(tf->names[0].loc));
			break;
		case TP_NSZ:
			if (tf && tf->nnsz < T_MAX_NSZ) {
				lws_strncpy(tf->ns_zones[tf->nnsz++],
					    ctx->buf, T_NAME_SZ);
			}
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
		case TP_F_V4:	if (tf) tf->has_v4 = v;	break;
		case TP_F_V6:	if (tf) tf->has_v6 = v;	break;
		case TP_I_V6:
			if (tf && tf->nips)
				tf->ips[tf->nips - 1].v6 = v;
			break;
		case TP_I_NS:
			if (tf && tf->nips)
				tf->ips[tf->nips - 1].ns = v;
			break;
		case TP_I_NS_ONLY:
			if (tf && tf->nips)
				tf->ips[tf->nips - 1].ns_only = v;
			break;
		case TP_N_NS:
			if (tf && tf->nnames)
				tf->names[tf->nnames - 1].ns = v;
			break;
		case TP_TOTAL:	tv->total = v;	break;
		case TP_MORE:	tv->more = v;	break;
		case TP_NEXT:	tv->next = v;	break;
		}
	}

	return 0;
}

/* fetch every page of the inventory into ti; returns 0 if it worked */

static int
t_fetch(struct vhd *vhd)
{
	struct monitor_req_args a;
	int cursor = 0, pages = 0;

	memset(&ti, 0, sizeof(ti));

	do {
		struct pss pss;
		struct lejp_ctx jctx;
		char *line;

		memset(&pss, 0, sizeof(pss));
		memset(&a, 0, sizeof(a));
		lws_strncpy(a.req, "get_ip_inventory", sizeof(a.req));
		a.cursor = cursor;

		/*
		 * the DHT-detected addresses for the dynamic-address
		 * records, as the UI passes them
		 */
		lws_strncpy(a.ip4, "203.0.113.7", sizeof(a.ip4));
		lws_strncpy(a.ip6, "2001:db8:ffff::1", sizeof(a.ip6));

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

		lejp_construct(&jctx, t_cb, &ti, t_paths,
			       LWS_ARRAY_SIZE(t_paths));
		if (lejp_parse(&jctx, (const uint8_t *)line,
			       (int)strlen(line)) < 0 || ti.oops) {
			lejp_destruct(&jctx);
			lwsl_err("%s: parse failed\n", __func__);

			return 1;
		}
		lejp_destruct(&jctx);

		cursor = ti.next;
		pages++;
	} while (ti.more && pages < 500);

	return ti.more ? 1 : 0;
}

/* find the interface carrying the given address */

static struct t_iface *
t_find_ip(struct t_inv *tv, const char *ip)
{
	for (int n = 0; n < tv->nif; n++)
		for (int m = 0; m < tv->ifaces[n].nips; m++)
			if (!strcmp(tv->ifaces[n].ips[m].ip, ip))
				return &tv->ifaces[n];

	return NULL;
}

static struct t_name *
t_find_name(struct t_iface *tf, const char *name)
{
	for (int n = 0; n < tf->nnames; n++)
		if (!strcmp(tf->names[n].name, name))
			return &tf->names[n];

	return NULL;
}

static int
t_ip_flag(struct t_iface *tf, const char *ip, const char *flag)
{
	for (int n = 0; n < tf->nips; n++)
		if (!strcmp(tf->ips[n].ip, ip))
			return !strcmp(flag, "ns") ? tf->ips[n].ns
						   : tf->ips[n].ns_only;

	return -1;
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
	"dyn IN A MHWC_DYNAMIC\n"
	"dyn IN AAAA MHWC6_DYNAMIC\n"
	"dyn2 IN A MHWC_DYNAMIC\n"
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

int main(void)
{
	struct vhd vhd;
	struct t_iface *f;
	struct t_name *nm;
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

	if (t_fetch(&vhd)) {
		lwsl_err("%s: fetch failed\n", __func__);

		return 1;
	}

	fails += t_expect(ti.nif == 4, "four interfaces");
	fails += t_expect(ti.total == 4, "total matches");

	/*
	 * ns1 and www point at the same v4 + v6 pair, so they are one
	 * interface; its shared addresses are ns (via ns1) but not ns_only
	 * (www binds them too): the nameserver is our infrastructure
	 */

	f = t_find_ip(&ti, "192.0.2.1");
	fails += t_expect(!!f, "shared-address interface present");
	if (f) {
		fails += t_expect(f->nips == 2 &&
				  t_find_ip(&ti, "2001:db8::1") == f,
				  "v4 and v6 of one name are one interface");
		fails += t_expect(f->nnames == 2, "both names on it");
		nm = t_find_name(f, "ns1.example.com.");
		fails += t_expect(!!nm && nm->ns, "ns1 name is an NS target");
		fails += t_expect(nm && !!strstr(nm->loc, "42 21 54 N"),
				  "ns1 name carries its LOC record");
		fails += t_expect(!!t_find_name(f, "www.example.com."),
				  "www name on the same interface");
		fails += t_expect(t_ip_flag(f, "192.0.2.1", "ns") == 1 &&
				  t_ip_flag(f, "192.0.2.1", "ns_only") == 0 &&
				  t_ip_flag(f, "2001:db8::1", "ns") == 1 &&
				  t_ip_flag(f, "2001:db8::1", "ns_only") == 0,
				  "shared addresses are ns, not ns_only");
		fails += t_expect(f->nnsz == 2, "delegated from both zones");
	}

	f = t_find_ip(&ti, "192.0.2.9");
	fails += t_expect(!!f && f->nnames == 1 &&
			  !!t_find_name(f, "mail.example.com."),
			  "mail alone on its address");

	/*
	 * the dynamic-address records resolve against the detected
	 * addresses; dyn binds both families, so one interface carries the
	 * detected pair with dyn and dyn2 on it
	 */

	f = t_find_ip(&ti, "203.0.113.7");
	fails += t_expect(!!f, "dynamic v4 resolved");
	if (f) {
		fails += t_expect(f->nips == 2, "detected v4 + v6 together");
		fails += t_expect(f->nnames == 2 &&
				  !!t_find_name(f, "dyn.example.com.") &&
				  !!t_find_name(f, "dyn2.example.com."),
				  "both dynamic names on the detected pair");
	}

	f = t_find_ip(&ti, "198.51.100.3");
	fails += t_expect(!!f, "ns3 present");
	if (f) {
		fails += t_expect(f->nnames == 1 &&
				  !!t_find_name(f, "ns3.other.com."),
				  "ns3 alone on its address");
		fails += t_expect(t_ip_flag(f, "198.51.100.3", "ns") == 1 &&
				  t_ip_flag(f, "198.51.100.3", "ns_only") == 1,
				  "ns3 address is NS glue only");
	}

	/* no interface for the addressless NS target or the LOC-only name */
	for (n = 0; n < ti.nif; n++) {
		fails += t_expect(!t_find_name(&ti.ifaces[n],
					 "ns2.example.com."),
					 "addressless NS target absent");
		fails += t_expect(!t_find_name(&ti.ifaces[n],
					 "lonely.example.com."),
					 "LOC-only name absent");
	}

	/*
	 * A changed zonefile is rescanned: extend example.com's zone with
	 * one more host record and require a new interface to appear
	 */

	{
		char bigger[2048];

		lws_snprintf(bigger, sizeof(bigger), "%snewhost IN A 203.0.113.99\n",
			     z_example);

		fails += t_expect(!t_write_file(
			"./inv-corpus/domains/example.com/example.com.zone",
			bigger) &&
			!t_fetch(&vhd) &&
			ti.nif == 5 &&
			!!t_find_ip(&ti, "203.0.113.99"),
			"appended record appears after rescan");
	}

	/* a removed domain's interfaces are dropped */

	lws_dir("./inv-corpus/domains/other.com", NULL, lws_dir_rm_rf_cb);
	rmdir("./inv-corpus/domains/other.com");

	fails += t_expect(!t_fetch(&vhd) &&
			  !t_find_ip(&ti, "198.51.100.3") &&
			  ti.nif == 4,
			  "removed domain rows dropped");

	/*
	 * enough zones to need real pagination: each zone's ns and www
	 * share both addresses, so one interface with two names each, and
	 * this overflows the first page's room-based budget
	 */

	for (n = 0; n < 400; n++) {
		char zone[512];

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
			     "ns IN AAAA 2001:db8:1:%x::1\n"
			     "www IN A 10.50.%d.%d\n"
			     "www IN AAAA 2001:db8:1:%x::1\n",
			     n, n, n, n / 256, n % 256, n,
			     n / 256, n % 256, n);
		lws_snprintf(path + strlen(path), sizeof(path) - strlen(path),
			     "/z%d.example.zone", n);
		if (t_write_file(path, zone))
			goto page_fail;

		continue;
page_fail:
		lwsl_err("%s: corpus page build failed\n", __func__);

		return 1;
	}

	if (t_fetch(&vhd)) {
		lwsl_err("%s: paged fetch failed\n", __func__);

		return 1;
	}

	/* every interface exactly once, and the promised count */
	{
		int i, j, dups = 0;

		for (i = 0; i < ti.nif; i++)
			for (j = i + 1; j < ti.nif; j++)
				if (!strcmp(ti.ifaces[i].ips[0].ip,
					    ti.ifaces[j].ips[0].ip))
					dups++;

		fails += t_expect(!dups, "no duplicate interfaces across pages");
		fails += t_expect(ti.nif == ti.total,
				  "paginated count matches total");
		fails += t_expect(ti.total == 404,
				  "400 zones produced 400 interfaces");
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
