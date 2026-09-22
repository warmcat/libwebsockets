/*
 * libwebsockets - protocol - dht_dnssec_monitor
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * Server IP inventory for the monitor UI
 *
 * Every zonefile under <base-dir>/domains is parsed into a row-per-record
 * sqlite3 cache, so the corpus is only re-read when a zonefile's mtime or
 * size changed since it was last scanned.  The interface view shown in the
 * UI is rolled up from those rows at read time: a name binding both a v4
 * and a v6 address is evidence they are addresses of the same network
 * interface on one server, so addresses are equivalence classes joined by
 * the names that bind them, and every name pointing at any of them is
 * listed as further evidence about that interface.  Each address also
 * tracks the kinds of names that point at it, so an address that only
 * exists as NS glue can be told apart from one that is also used by host
 * records.  Dynamic-address records (${MHWC_DYNAMIC} / ${MHWC6_DYNAMIC})
 * resolve to the DHT-detected addresses the UI passes with the request.
 */

#if !defined(LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#if defined(WIN32) || defined(_WIN32)
#else
#include <arpa/inet.h>
#endif

#include "private.h"

#if defined(LWS_WITH_SQLITE3)
#include <sqlite3.h>

/*
 * Bump when the cache layout changes: an existing cache with any other
 * version is deleted and rebuilt from the zonefiles
 */
#define INV_DB_VERSION		1

/* refuse to parse zonefiles larger than the signer is willing to read */
#define INV_ZONE_MAX_BYTES	(1024 * 1024)

/* longest rdata we cache per record row */
#define INV_RDATA_MAX		1023

/*
 * Stop starting another server entry into the response when less than this
 * much room is left in the IPC tx buffer; the rest is sent by the next page
 * instead.  Comfortably larger than the largest single entry composed below
 */
#define INV_EMIT_ROOM		24576

/* one composed interface entry never exceeds this */
#define INV_ENTRY_MAX		12288

/* per-entry caps so one pathological interface cannot outgrow INV_ENTRY_MAX */
#define INV_MAX_IPS		16
#define INV_MAX_NAMES		96
#define INV_MAX_ZONES		4
#define INV_MAX_NS_ZONES	8

struct inv_stmts {
	sqlite3_stmt		*seen;		/* INSERT OR REPLACE INTO seen */
	sqlite3_stmt		*stamp;		/* SELECT mtime,size FROM zones */
	sqlite3_stmt		*del_recs;	/* DELETE FROM recs WHERE domain */
	sqlite3_stmt		*del_zones;	/* DELETE FROM zones WHERE domain */
	sqlite3_stmt		*put_zone;	/* INSERT INTO zones */
	sqlite3_stmt		*ins_rec;	/* INSERT INTO recs */
};

/*
 * The inventory lists network interfaces, not DNS names: a name binding
 * both a v4 and a v6 address is evidence those are addresses of the same
 * interface, and every name that points at any of those addresses is more
 * evidence about the same interface.  So addresses are equivalence classes
 * joined by the names that bind them together, and each row shows the
 * addresses with the names that point at them.
 */

/* one unique address (or unresolved dynamic macro, see inv_rollup()) */

struct inv_addr {
	lws_dll2_t		list;		/* inv_ctx.addrs */
	char			ip[46];		/* canonical text form */
	int			is_v6;
	int			idx;		/* position in the fold arrays */
	/* set once every name is attached, see inv_fold() */
	int			bindings;	/* names pointing at it */
	int			ns_bindings;	/* ...that are NS targets */
	int			ns;		/* some name binding it is an NS target */
	int			ns_only;	/* ...and no name binding it is not */
};

/* one zonefile the name was seen mentioned by */

struct inv_zmention {
	lws_dll2_t		list;		/* inv_name.zones / iface.ns_zones */
	char			*zone;
};

/* one edge of the bipartite name <-> address graph */

struct inv_naddr {
	lws_dll2_t		list;		/* inv_name.addrs */
	char			ip[46];		/* resolved address text */
	int			is_v6;
	struct inv_addr		*a;		/* set by inv_fold() */
};

/* one fully-qualified name pointing at one or more addresses */

struct inv_name {
	lws_dll2_t		list;		/* inv_ctx.names, in name order */
	char			*name;
	char			*loc;		/* first LOC rdata seen for the name */
	lws_dll2_owner_t	addrs;
	lws_dll2_owner_t	zones;		/* zones with records for the name */
	int			ns;		/* some zone delegates to this name */
	struct inv_iface	*iface;		/* set by inv_fold() */
};

struct inv_iaddr {
	lws_dll2_t		list;		/* inv_iface.addrs */
	struct inv_addr		*a;
};

struct inv_iname {
	lws_dll2_t		list;		/* inv_iface.names */
	struct inv_name		*n;
};

/* one network interface: a connected set of addresses and their names */

struct inv_iface {
	lws_dll2_t		list;		/* inv_ctx.ifaces, sorted */
	lws_dll2_owner_t	addrs;
	lws_dll2_owner_t	names;		/* in name order */
	lws_dll2_owner_t	ns_zones;	/* zones delegating to any name here */
	char			*sort_key;	/* smallest address text */
	int			has_v4, has_v6;
};

struct inv_ctx {
	struct lwsac		*lwsac;
	lws_dll2_owner_t	addrs;		/* every unique address */
	lws_dll2_owner_t	names;		/* every name, in name order */
	lws_dll2_owner_t	ifaces;		/* emitted order */
};

static int
inv_exec(sqlite3 *db, const char *sql)
{
	char *err = NULL;

	if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
		lwsl_notice("%s: '%s' failed: %s\n", __func__, sql,
			    err ? err : "?");
		sqlite3_free(err);

		return 1;
	}

	return 0;
}

static void
inv_db_path(struct vhd *vhd, char *buf, size_t len)
{
	lws_snprintf(buf, len, "%s/ip-inventory.sqlite3", vhd->base_dir);
}

/* lay in the cache schema */

static int
inv_db_schema(sqlite3 *db)
{
	char setver[64];

	lws_snprintf(setver, sizeof(setver), "PRAGMA user_version = %d",
		     INV_DB_VERSION);

	return inv_exec(db, "CREATE TABLE IF NOT EXISTS zones("
			    " domain TEXT PRIMARY KEY,"
			    " mtime INTEGER NOT NULL,"
			    " size INTEGER NOT NULL)") ||
	       inv_exec(db, "CREATE TABLE IF NOT EXISTS recs("
			    " domain TEXT NOT NULL,"
			    " name TEXT NOT NULL,"
			    " rtype INTEGER NOT NULL,"
			    " rdata TEXT NOT NULL)") ||
	       inv_exec(db, "CREATE INDEX IF NOT EXISTS idx_recs_name"
			    " ON recs(name)") ||
	       inv_exec(db, "CREATE INDEX IF NOT EXISTS idx_recs_type"
			    " ON recs(rtype)") ||
	       inv_exec(db, setver);
}

/*
 * Open the cache, discarding and recreating it if it belongs to any other
 * cache generation.  The cache is entirely expendable: anything about it we
 * cannot understand is deleted and rebuilt from the zonefiles.
 */

static sqlite3 *
inv_db_open(struct vhd *vhd)
{
	char path[1024];
	sqlite3 *db = NULL;
	sqlite3_stmt *ver = NULL;
	int ok = 0;

	inv_db_path(vhd, path, sizeof(path));

	if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE |
					 SQLITE_OPEN_CREATE, NULL)
	    != SQLITE_OK) {
		lwsl_notice("%s: unable to open %s\n", __func__, path);
		if (db)
			sqlite3_close(db);

		return NULL;
	}

	/* it is a cache: trade durability for scan cost */
	inv_exec(db, "PRAGMA synchronous = OFF");

	if (sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &ver,
			       NULL) == SQLITE_OK) {
		ok = sqlite3_step(ver) == SQLITE_ROW &&
		     sqlite3_column_int(ver, 0) == INV_DB_VERSION &&
		     !inv_db_schema(db);
		sqlite3_finalize(ver);
	}

	if (ok)
		return db;

	lwsl_notice("%s: rebuilding stale or damaged inventory cache %s\n",
		    __func__, path);

	sqlite3_close(db);
	unlink(path);
	lws_snprintf(path + strlen(path), sizeof(path) - strlen(path),
		     "-journal");
	unlink(path);

	db = NULL;
	inv_db_path(vhd, path, sizeof(path));
	if (sqlite3_open_v2(path, &db,
			    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
			    NULL) != SQLITE_OK || !db) {
		if (db)
			sqlite3_close(db);

		return NULL;
	}

	inv_exec(db, "PRAGMA synchronous = OFF");

	if (inv_db_schema(db)) {
		sqlite3_close(db);

		return NULL;
	}

	return db;
}

static int
inv_prep(sqlite3 *db, sqlite3_stmt **st, const char *sql)
{
	if (sqlite3_prepare_v2(db, sql, -1, st, NULL) != SQLITE_OK) {
		lwsl_notice("%s: prepare '%s' failed: %s\n", __func__, sql,
			    sqlite3_errmsg(db));

		return 1;
	}

	return 0;
}

static int
inv_stmts_prep(sqlite3 *db, struct inv_stmts *s)
{
	if (inv_prep(db, &s->seen, "INSERT OR REPLACE INTO seen(domain)"
				   " VALUES(?)"))
		return 1;
	if (inv_prep(db, &s->stamp, "SELECT mtime,size FROM zones"
				   " WHERE domain=?"))
		return 1;
	if (inv_prep(db, &s->del_recs, "DELETE FROM recs WHERE domain=?"))
		return 1;
	if (inv_prep(db, &s->del_zones, "DELETE FROM zones WHERE domain=?"))
		return 1;
	if (inv_prep(db, &s->put_zone, "INSERT INTO zones(domain,mtime,size)"
				       " VALUES(?,?,?)"))
		return 1;
	if (inv_prep(db, &s->ins_rec, "INSERT INTO recs(domain,name,rtype,rdata)"
				      " VALUES(?,?,?,?)"))
		return 1;

	return 0;
}

static void
inv_stmts_destroy(struct inv_stmts *s)
{
	sqlite3_finalize(s->seen);
	sqlite3_finalize(s->stamp);
	sqlite3_finalize(s->del_recs);
	sqlite3_finalize(s->del_zones);
	sqlite3_finalize(s->put_zone);
	sqlite3_finalize(s->ins_rec);
	memset(s, 0, sizeof(*s));
}

static void
inv_bind_text(sqlite3_stmt *st, int idx, const char *s)
{
	sqlite3_bind_text(st, idx, s, -1, SQLITE_STATIC);
}

/*
 * Bring one rdata target name to the same fully-qualified, lowercased form
 * the parser already gives owner names, so an NS target and an address
 * record owner can be matched up across zonefiles
 */

static void
inv_qualify(char *out, size_t outlen, const char *tok, const char *origin)
{
	if (!strcmp(tok, "@") && origin[0])
		lws_strncpy(out, origin, outlen);
	else if (tok[0] && tok[strlen(tok) - 1] == '.')
		lws_strncpy(out, tok, outlen);
	else if (origin[0] && strcmp(origin, "."))
		lws_snprintf(out, outlen, "%s.%s", tok, origin);
	else
		lws_strncpy(out, tok, outlen);

	for (char *c = out; *c; c++)
		*c = (char)tolower((unsigned char)*c);
}

/* copy the first whitespace-delimited token out of an rdata string */

static void
inv_first_tok(const char *rdata, char *tok, size_t toklen)
{
	const char *p = rdata;
	size_t n = 0;

	while (*p == ' ' || *p == '\t')
		p++;

	while (p[n] && p[n] != ' ' && p[n] != '\t' && n < toklen - 1)
		n++;

	memcpy(tok, p, n);
	tok[n] = '\0';
}

/*
 * Does the buffer carry any $ORIGIN control line?  The library parser
 * qualifies relative names against $ORIGIN, so a zonefile without one gets
 * an explicit origin matching the domain implied by its location, the same
 * assumption the signer's zone discovery makes.
 */

static int
inv_buf_has_origin(const char *buf)
{
	if (!strncmp(buf, "$ORIGIN", 7))
		return 1;

	return strstr(buf, "\n$ORIGIN") != NULL;
}

/*
 * Parse one zonefile into recs rows for its domain.  Every kind of record
 * found gets a row; A / AAAA rdata is canonicalised through inet_pton so
 * grouping does not depend on how the address was written, and NS rdata is
 * qualified and lowercased for the same reason.  The zone's stamp row is
 * laid in last, so a zone that only half-scanned is retried next time.
 *
 * The caller has already deleted the domain's old rows inside the open
 * transaction.  Returns nonzero if the zone could not be read at all.
 */

static int
inv_scan_zone(struct inv_stmts *s, const char *domains_path,
	      const char *domain, time_t mtime, off_t size)
{
	char path[1024], pfx[320], origin[300], tok[512], qual[512], ip[46];
	struct auth_dns_zone zone;
	struct stat st;
	uint8_t stack_buf[4096];
	uint8_t *buf = NULL;
	size_t alloc;
	ssize_t n;
	int fd, pl, ret = 1;

	lws_snprintf(path, sizeof(path), "%s/%s/%s.zone", domains_path,
		     domain, domain);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 1;

	if (fstat(fd, &st) || st.st_size <= 0 ||
	    (off_t)st.st_size > INV_ZONE_MAX_BYTES)
		goto bail;

	n = (ssize_t)st.st_size;
	pl = lws_snprintf(pfx, sizeof(pfx), "$ORIGIN %s.\n", domain);
	if (pl < 0)
		goto bail;

	alloc = (size_t)n + (size_t)pl + 1;

	if (alloc <= sizeof(stack_buf))
		buf = stack_buf;
	else
		buf = malloc(alloc);

	if (!buf)
		goto bail;

	if (read(fd, buf, (size_t)n) != n)
		goto bail;
	buf[n] = '\0';

	if (!inv_buf_has_origin((const char *)buf)) {
		memmove(buf + pl, buf, (size_t)n + 1);
		memcpy(buf, pfx, (size_t)pl);
		n += pl;
	}

	memset(&zone, 0, sizeof(zone));

	if (lws_auth_dns_parse_zone_buf((const char *)buf, (size_t)n, &zone,
					NULL, NULL)) {
		/*
		 * An unparseable zone still gets its stamp, so it is not
		 * rescanned on every request until it is fixed
		 */
		memset(&zone, 0, sizeof(zone));
	}

	lws_strncpy(origin, zone.origin[0] ? zone.origin : domain,
		    sizeof(origin));
	if (origin[strlen(origin) - 1] != '.')
		lws_snprintf(origin + strlen(origin),
			     sizeof(origin) - strlen(origin) - 1, ".");

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&zone.rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d,
						struct auth_dns_rrset, list);

		lws_start_foreach_dll(struct lws_dll2 *, d2,
				      lws_dll2_get_head(&rs->rr_list)) {
			struct auth_dns_rr *rr = lws_container_of(d2,
						struct auth_dns_rr, list);
			char stored[INV_RDATA_MAX + 1];
			int step;

			if (!rr->rdata)
				continue;

			inv_first_tok(rr->rdata, tok, sizeof(tok));

			if (!tok[0]) {
				/* record with empty rdata: keep it literally */
				lws_strncpy(stored, rr->rdata, sizeof(stored));
			} else if (rs->type == 1 || rs->type == 28) {
				unsigned char ad[16];
				int fam = rs->type == 1 ? AF_INET : AF_INET6;

				/*
				 * Only well-formed addresses can group,
				 * but keep whatever was written as the row
				 */
				if (inet_pton(fam, tok, ad) == 1 &&
				    inet_ntop(fam, ad, ip, sizeof(ip)))
					lws_strncpy(stored, ip, sizeof(stored));
				else
					lws_strncpy(stored, tok, sizeof(stored));
			} else if (rs->type == 2) {
				inv_qualify(qual, sizeof(qual), tok, origin);
				lws_strncpy(stored, qual, sizeof(stored));
			} else
				lws_strncpy(stored, rr->rdata, sizeof(stored));

			inv_bind_text(s->ins_rec, 1, domain);
			inv_bind_text(s->ins_rec, 2, rs->name);
			sqlite3_bind_int(s->ins_rec, 3, rs->type);
			inv_bind_text(s->ins_rec, 4, stored);

			step = sqlite3_step(s->ins_rec);
			sqlite3_reset(s->ins_rec);

			if (step != SQLITE_DONE)
				goto bail_zone;

		} lws_end_foreach_dll(d2);
	} lws_end_foreach_dll(d);

	inv_bind_text(s->put_zone, 1, domain);
	sqlite3_bind_int64(s->put_zone, 2, (sqlite3_int64)mtime);
	sqlite3_bind_int64(s->put_zone, 3, (sqlite3_int64)size);

	if (sqlite3_step(s->put_zone) == SQLITE_DONE)
		ret = 0;

	sqlite3_reset(s->put_zone);

bail_zone:
	lws_auth_dns_free_zone(&zone);

bail:
	if (buf && buf != stack_buf)
		free(buf);
	close(fd);

	return ret;
}

/*
 * lws_dir() walk over <base-dir>/domains: stat each domain's zonefile and
 * rescan it into fresh rows when its stamp no longer matches.  A zone that
 * cannot be read now just stays unstamped, so it is retried on the next
 * request; only sql-level failures stop the walk early.
 */

struct inv_walk {
	struct inv_stmts	*s;
	const char		*domains_path;
	int			failed;
};

static int
inv_walk_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct inv_walk *w = (struct inv_walk *)user;
	struct inv_stmts *s = w->s;
	struct stat st;
	char zone_path[1024];
	sqlite3_int64 mtime, size;
	int rescan = 1, step;

	if (lde->type != LDOT_DIR && lde->type != LDOT_UNKNOWN)
		return 0;

	if (lde->name[0] == '.' || strlen(lde->name) >= 200)
		return 0;

	lws_snprintf(zone_path, sizeof(zone_path), "%s/%s/%s.zone",
		     w->domains_path, lde->name, lde->name);

	if (stat(zone_path, &st))
		return 0; /* no zonefile for this domain */

	mtime = (sqlite3_int64)st.st_mtime;
	size  = (sqlite3_int64)st.st_size;

	inv_bind_text(s->seen, 1, lde->name);
	step = sqlite3_step(s->seen);
	sqlite3_reset(s->seen);
	if (step != SQLITE_DONE)
		goto fail;

	inv_bind_text(s->stamp, 1, lde->name);
	if (sqlite3_step(s->stamp) == SQLITE_ROW &&
	    sqlite3_column_int64(s->stamp, 0) == mtime &&
	    sqlite3_column_int64(s->stamp, 1) == size)
		rescan = 0;
	sqlite3_reset(s->stamp);

	if (!rescan)
		return 0;

	inv_bind_text(s->del_recs, 1, lde->name);
	step = sqlite3_step(s->del_recs);
	sqlite3_reset(s->del_recs);
	if (step != SQLITE_DONE)
		goto fail;

	inv_bind_text(s->del_zones, 1, lde->name);
	step = sqlite3_step(s->del_zones);
	sqlite3_reset(s->del_zones);
	if (step != SQLITE_DONE)
		goto fail;

	inv_scan_zone(s, w->domains_path, lde->name, (time_t)mtime,
		      (off_t)size);

	return 0;

fail:
	w->failed = 1;

	/* stop the walk early */

	return 1;
}

/*
 * Bring the cache up to date with the zonefiles on disk.  Returns an open
 * db when the cache is usable (whether or not anything needed rescanning),
 * or NULL.
 */

static sqlite3 *
inv_db_ensure(struct vhd *vhd)
{
	char domains_path[1024];
	int retry;

	lws_snprintf(domains_path, sizeof(domains_path), "%s/domains",
		     vhd->base_dir);

	for (retry = 0; retry < 2; retry++) {
		struct inv_stmts s;
		struct inv_walk w;
		sqlite3 *db;
		int failed = 0;

		/* finalize-safe whatever path we leave by */
		memset(&s, 0, sizeof(s));

		if (retry) {
			char path[1024];

			lwsl_notice("%s: cache unusable, retrying on a wiped"
				    " cache\n", __func__);
			inv_db_path(vhd, path, sizeof(path));
			unlink(path);
		}

		db = inv_db_open(vhd);
		if (!db)
			return NULL;

		/*
		 * The temp table has to exist before any statement naming
		 * it is prepared
		 */
		if (inv_exec(db, "CREATE TEMP TABLE IF NOT EXISTS seen"
				   "(domain TEXT PRIMARY KEY)"))
			failed = 1;

		if (!failed && inv_stmts_prep(db, &s)) {
			inv_stmts_destroy(&s);
			sqlite3_close(db);

			return NULL;
		}

		if (!failed)
			failed = inv_exec(db, "BEGIN IMMEDIATE");

		if (!failed) {
			struct stat st;

			/*
			 * lws_dir() reports an unopenable directory the
			 * same as an empty one, but an empty walk would
			 * drop every cached row below; check it is really
			 * there first
			 */
			if (stat(domains_path, &st) || !S_ISDIR(st.st_mode)) {
				lwsl_notice("%s: cannot open %s\n", __func__,
					    domains_path);
				failed = 1;
			}
		}

		if (!failed) {
			memset(&w, 0, sizeof(w));
			w.s = &s;
			w.domains_path = domains_path;

			if (!lws_dir(domains_path, &w, inv_walk_cb))
				failed = w.failed;
		}

		if (!failed)
			failed = inv_exec(db, "DELETE FROM recs WHERE domain"
						     " NOT IN (SELECT domain FROM"
						     " seen)") ||
				 inv_exec(db, "DELETE FROM zones WHERE domain"
						     " NOT IN (SELECT domain FROM"
						     " seen)");

		if (inv_exec(db, failed ? "ROLLBACK" : "COMMIT"))
			failed = 1;

		inv_stmts_destroy(&s);

		if (!failed)
			return db;

		sqlite3_close(db);

		/* one more attempt on a wiped cache, then give up */
	}

	return NULL;
}

static struct inv_name *
inv_name_new(struct inv_ctx *ic, const char *name)
{
	struct inv_name *nm = lwsac_use_zero(&ic->lwsac, sizeof(*nm) +
					      strlen(name) + 1, 0);

	if (!nm)
		return NULL;

	nm->name = (char *)&nm[1];
	memcpy(nm->name, name, strlen(name) + 1);
	lws_dll2_add_tail(&nm->list, &ic->names);

	return nm;
}

static struct inv_zmention *
inv_zm_add(struct inv_ctx *ic, lws_dll2_owner_t *owner, const char *zone)
{
	struct inv_zmention *zm;

	/* one mention per zone is enough for either list */
	lws_start_foreach_dll(struct lws_dll2 *, z, lws_dll2_get_head(owner)) {
		zm = lws_container_of(z, struct inv_zmention, list);
		if (!strcmp(zm->zone, zone))
			return zm;
	} lws_end_foreach_dll(z);

	zm = lwsac_use_zero(&ic->lwsac, sizeof(*zm) + strlen(zone) + 1, 0);
	if (!zm)
		return NULL;

	zm->zone = (char *)&zm[1];
	memcpy(zm->zone, zone, strlen(zone) + 1);
	lws_dll2_add_tail(&zm->list, owner);

	return zm;
}

static int
inv_cmp_edgeip(const void *a, const void *b)
{
	const struct inv_naddr *ea = *(const struct inv_naddr * const *)a;
	const struct inv_naddr *eb = *(const struct inv_naddr * const *)b;

	return strcmp(ea->ip, eb->ip);
}

static int
inv_cmp_namep(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

static int
inv_cmp_iface(const void *a, const void *b)
{
	const struct inv_iface *fa = *(const struct inv_iface * const *)a;
	const struct inv_iface *fb = *(const struct inv_iface * const *)b;

	return strcmp(fa->sort_key, fb->sort_key);
}

/* union-find over the address array, joined by the names binding them */

static int
inv_find(int *parent, int i)
{
	while (parent[i] != i) {
		parent[i] = parent[parent[i]];
		i = parent[i];
	}

	return i;
}

/*
 * Canonicalise one rdata value into \p out as a real address, honouring
 * the dynamic-address macros the signer substitutes at sign time.  Without
 * a detected address for the family, the macro itself becomes the address
 * text, so the names using it still group together.  Returns 0 if the
 * value is not any address we can use.
 */

static int
inv_resolve_rdata(const char *rdata, int is_v6, const char *ip4,
		  const char *ip6, char *out, size_t outlen)
{
	const char *subst = is_v6 ? ip6 : ip4;
	unsigned char ad[16];
	int fam = is_v6 ? AF_INET6 : AF_INET;

	if (!strcmp(rdata, is_v6 ? "MHWC6_DYNAMIC" : "MHWC_DYNAMIC")) {
		/*
		 * subst is either empty or already canonical, see
		 * handle_req_get_ip_inventory()
		 */
		if (subst && subst[0]) {
			lws_strncpy(out, subst, outlen);

			return 1;
		}

		lws_strncpy(out, rdata, outlen);

		return 1;
	}

	if (inet_pton(fam, rdata, ad) != 1)
		return 0;

	if (!inet_ntop(fam, ad, out, (socklen_t)outlen))
		return 0;

	return 1;
}

/*
 * Fold the collected name -> address edges into interfaces:
 *
 *  - the edges are sorted by address text and deduplicated into the set of
 *    unique addresses
 *  - each name joins all the addresses it binds into one equivalence
 *    class (union-find), so a name with both a v4 and a v6 address merges
 *    them as one interface, and an address shared between names merges
 *    their classes
 *  - every address learns what kinds of names point at it
 *  - interfaces come out sorted by their smallest address text
 */

static int
inv_fold(struct inv_ctx *ic, size_t nedges)
{
	struct inv_naddr **sorted, *edge;
	struct inv_addr **addrs;
	struct inv_iaddr *ia;
	struct inv_iname *in;
	struct inv_iface **ifaces, **byroot;
	struct inv_name *nm;
	int *parent;
	size_t n = 0, naddrs = 0, nifaces = 0, i;

	sorted = lwsac_use(&ic->lwsac, nedges * sizeof(*sorted), 0);
	addrs  = lwsac_use(&ic->lwsac, nedges * sizeof(*addrs), 0);
	parent = lwsac_use(&ic->lwsac, nedges * sizeof(*parent), 0);
	byroot = lwsac_use_zero(&ic->lwsac, nedges * sizeof(*byroot), 0);
	ifaces = lwsac_use(&ic->lwsac, nedges * sizeof(*ifaces), 0);
	if (!sorted || !addrs || !parent || !byroot || !ifaces)
		return 1;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ic->names)) {
		nm = lws_container_of(d, struct inv_name, list);
		lws_start_foreach_dll(struct lws_dll2 *, e,
				      lws_dll2_get_head(&nm->addrs)) {
			sorted[n++] = lws_container_of(e, struct inv_naddr,
						       list);
		} lws_end_foreach_dll(e);
	} lws_end_foreach_dll(d);

	qsort(sorted, nedges, sizeof(*sorted), inv_cmp_edgeip);

	/* deduplicate the address texts into the unique address set */

	for (i = 0; i < nedges; i++) {
		struct inv_addr *a;

		if (i && !strcmp(sorted[i - 1]->ip, sorted[i]->ip)) {
			sorted[i]->a = addrs[naddrs - 1];

			continue;
		}

		a = lwsac_use_zero(&ic->lwsac, sizeof(*a), 0);
		if (!a)
			return 1;

		lws_strncpy(a->ip, sorted[i]->ip, sizeof(a->ip));
		a->is_v6 = sorted[i]->is_v6;
		a->idx = (int)naddrs;
		parent[naddrs] = (int)naddrs;
		lws_dll2_add_tail(&a->list, &ic->addrs);

		addrs[naddrs++] = a;
		sorted[i]->a = a;
	}

	/*
	 * Join every name's addresses into one class: the first address is
	 * the anchor, the rest union onto it, so a v4 / v6 pair used by one
	 * name becomes one interface however many names also point at either
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ic->names)) {
		struct inv_naddr *first = NULL;

		nm = lws_container_of(d, struct inv_name, list);
		lws_start_foreach_dll(struct lws_dll2 *, e,
				      lws_dll2_get_head(&nm->addrs)) {
			edge = lws_container_of(e, struct inv_naddr, list);
			if (!first) {
				first = edge;

				continue;
			}

			{
				int r1 = inv_find(parent, first->a->idx);
				int r2 = inv_find(parent, edge->a->idx);

				if (r1 != r2)
					parent[r2] = r1;
			}
		} lws_end_foreach_dll(e);
	} lws_end_foreach_dll(d);

	/*
	 * Bucket the addresses on their class root, and each name onto the
	 * bucket of any of its addresses; names arrive in name order, so the
	 * per-interface name lists keep that order
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ic->addrs)) {
		struct inv_addr *a = lws_container_of(d, struct inv_addr,
						      list);
		int root = inv_find(parent, a->idx);

		if (!byroot[root]) {
			struct inv_iface *f = lwsac_use_zero(&ic->lwsac,
							     sizeof(*f), 0);

			if (!f)
				return 1;

			byroot[root] = f;
			ifaces[nifaces++] = f;
		}

		ia = lwsac_use_zero(&ic->lwsac, sizeof(*ia), 0);
		if (!ia)
			return 1;
		ia->a = a;
		lws_dll2_add_tail(&ia->list, &byroot[root]->addrs);

		if (a->is_v6)
			byroot[root]->has_v6 = 1;
		else
			byroot[root]->has_v4 = 1;
	} lws_end_foreach_dll(d);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ic->names)) {
		nm = lws_container_of(d, struct inv_name, list);

		lws_start_foreach_dll(struct lws_dll2 *, e,
				      lws_dll2_get_head(&nm->addrs)) {
			edge = lws_container_of(e, struct inv_naddr, list);
			nm->iface = byroot[inv_find(parent, edge->a->idx)];

			break;
		} lws_end_foreach_dll(e);

		if (!nm->iface)
			continue; /* no addresses: no interface evidence */

		in = lwsac_use_zero(&ic->lwsac, sizeof(*in), 0);
		if (!in)
			return 1;
		in->n = nm;
		lws_dll2_add_tail(&in->list, &nm->iface->names);

		/* count what kinds of names point at each address */
		lws_start_foreach_dll(struct lws_dll2 *, e,
				      lws_dll2_get_head(&nm->addrs)) {
			edge = lws_container_of(e, struct inv_naddr, list);
			edge->a->bindings++;
			if (nm->ns)
				edge->a->ns_bindings++;
		} lws_end_foreach_dll(e);
	} lws_end_foreach_dll(d);

	/*
	 * An address bound to several names is ns_only when every one of
	 * them is an NS target: absent anything more specific, it may not be
	 * our infrastructure
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ic->addrs)) {
		struct inv_addr *a = lws_container_of(d, struct inv_addr,
						      list);

		if (a->bindings) {
			a->ns = a->ns_bindings > 0;
			a->ns_only = a->ns_bindings == a->bindings;
		}
	} lws_end_foreach_dll(d);

	/* deterministic emission order: smallest address text first */

	for (i = 0; i < nifaces; i++) {
		lws_start_foreach_dll(struct lws_dll2 *, ad,
				      lws_dll2_get_head(&ifaces[i]->addrs)) {
			ia = lws_container_of(ad, struct inv_iaddr, list);

			if (!ifaces[i]->sort_key ||
			    strcmp(ia->a->ip, ifaces[i]->sort_key) < 0)
				ifaces[i]->sort_key = ia->a->ip;
		} lws_end_foreach_dll(ad);
	}

	qsort(ifaces, nifaces, sizeof(*ifaces), inv_cmp_iface);

	for (i = 0; i < nifaces; i++) {
		lws_dll2_remove(&ifaces[i]->list);
		lws_dll2_add_tail(&ifaces[i]->list, &ic->ifaces);
	}

	return 0;
}

/*
 * Build the interface list from the cached rows.
 *
 * Address and LOC rows are collected per fully-qualified owner name (the
 * parser already qualified them), and the sorted set of NS targets from
 * all zonefiles classifies each name.  Then the names are folded away:
 * every name that binds several addresses joins those addresses into one
 * network interface, all names land on the interface of their addresses,
 * and each address learns what kinds of names point at it.  The interface
 * list comes out sorted by its smallest address, which is what makes
 * cursor pagination over it deterministic.
 */

static int
inv_rollup(sqlite3 *db, struct inv_ctx *ic, const char *ip4, const char *ip6)
{
	sqlite3_stmt *nst = NULL, *rows = NULL, *nsz = NULL;
	struct inv_name *cur = NULL;
	char **targets = NULL;
	size_t talloc = 0, tcount = 0, nedges = 0;
	int ret = 1;

	memset(ic, 0, sizeof(*ic));

	/* pass 1: the sorted set of NS target names across all zonefiles */

	if (sqlite3_prepare_v2(db, "SELECT DISTINCT rdata FROM recs"
				  " WHERE rtype=2 ORDER BY rdata", -1,
				  &nst, NULL))
		goto bail;

	while (sqlite3_step(nst) == SQLITE_ROW) {
		const char *t = (const char *)
					sqlite3_column_text(nst, 0);

		if (!t)
			continue;

		if (tcount == talloc) {
			size_t na = talloc ? talloc * 2 : 32;
			char **nt = realloc(targets, na * sizeof(*nt));

			if (!nt)
				goto bail;
			targets = nt;
			talloc = na;
		}

		targets[tcount] = strdup(t);
		if (!targets[tcount])
			goto bail;
		tcount++;
	}

	/* pass 2: address and LOC rows, grouped by owner name */

	if (sqlite3_prepare_v2(db, "SELECT domain,name,rtype,rdata FROM recs"
				  " WHERE rtype IN (1,28,29) ORDER BY name",
			  -1, &rows, NULL))
		goto bail;

	while (sqlite3_step(rows) == SQLITE_ROW) {
		const char *domain = (const char *)
					sqlite3_column_text(rows, 0);
		const char *name = (const char *)
					sqlite3_column_text(rows, 1);
		const char *rdata = (const char *)
					sqlite3_column_text(rows, 3);
		int rtype = sqlite3_column_int(rows, 2);

		if (!domain || !name || !rdata)
			continue;

		if (!cur || strcmp(cur->name, name)) {
			char *key = (char *)name;

			cur = inv_name_new(ic, name);
			if (!cur)
				goto bail;

			/*
			 * Is this name the target of NS records anywhere?
			 * Bsearching the sorted target array decides; the
			 * key is passed by address like the elements, so
			 * the comparator sees char ** on both sides
			 */
			cur->ns = targets && bsearch(&key, targets, tcount,
						sizeof(*targets),
						inv_cmp_namep) != NULL;
		}

		if (rtype == 29) {
			if (!cur->loc) {
				cur->loc = lwsac_use(&ic->lwsac,
						strlen(rdata) + 1, 0);
				if (!cur->loc)
					goto bail;
				memcpy(cur->loc, rdata, strlen(rdata) + 1);
			}
			if (!inv_zm_add(ic, &cur->zones, domain))
				goto bail;

			continue;
		}

		/* rtype 1 or 28: an address binding for this name */

		{
			struct inv_naddr *edge;
			char ip[64];
			int is_v6 = rtype == 28;

			/*
			 * Unresolvable rdata (kept as-written in the cache)
			 * cannot group, and names it leaves with no address
			 * at all simply produce no interface
			 */
			if (!inv_resolve_rdata(rdata, is_v6, ip4, ip6,
					       ip, sizeof(ip)))
				continue;

			/* one binding per address is enough per name */
			lws_start_foreach_dll(struct lws_dll2 *, e,
					lws_dll2_get_head(&cur->addrs)) {
				edge = lws_container_of(e,
						struct inv_naddr, list);
				if (!strcmp(edge->ip, ip))
					goto next_row;
			} lws_end_foreach_dll(e);

			edge = lwsac_use_zero(&ic->lwsac, sizeof(*edge), 0);
			if (!edge)
				goto bail;
			lws_strncpy(edge->ip, ip, sizeof(edge->ip));
			edge->is_v6 = is_v6;
			lws_dll2_add_tail(&edge->list, &cur->addrs);
			nedges++;

			if (!inv_zm_add(ic, &cur->zones, domain))
				goto bail;
		}
next_row:
		;
	}

	/* pass 3: fold the names away into interfaces */

	if (nedges && inv_fold(ic, nedges))
		goto bail;

	/* pass 4: which zones delegate to each nameserver-ish name */

	if (sqlite3_prepare_v2(db, "SELECT DISTINCT domain FROM recs"
				  " WHERE rtype=2 AND rdata=?", -1,
				  &nsz, NULL))
		goto bail;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ic->names)) {
		struct inv_name *nm = lws_container_of(d, struct inv_name,
						       list);

		if (!nm->ns || !nm->iface)
			continue;

		inv_bind_text(nsz, 1, nm->name);
		while (sqlite3_step(nsz) == SQLITE_ROW) {
			const char *dom = (const char *)
						sqlite3_column_text(nsz, 0);

			if (dom && !inv_zm_add(ic, &nm->iface->ns_zones, dom))
				goto bail;
		}
		sqlite3_reset(nsz);
	} lws_end_foreach_dll(d);

	ret = 0;

bail:
	sqlite3_finalize(nst);
	sqlite3_finalize(rows);
	sqlite3_finalize(nsz);

	for (size_t n = 0; n < tcount; n++)
		free(targets[n]);
	free(targets);

	if (ret)
		lwsac_free(&ic->lwsac);

	return ret;
}

static size_t
inv_rem(char *tx, char *tx_end)
{
	size_t rem = lws_ptr_diff_size_t(tx_end, tx);

	/* lws_snprintf() must always see room for at least the NUL */
	return rem ? rem - 1 : 0;
}

/*
 * One server entry is composed into a bounded scratch buffer first: a
 * newline-framed IPC stream cannot survive an entry that saturates mid-way
 * through the tx buffer, so an entry that cannot fit whole is degraded to
 * a stub rather than truncated into the stream.
 */

struct inv_emit {
	char			buf[INV_ENTRY_MAX];
	size_t			len;
	int			saturated;
};

static void
inv_emit(struct inv_emit *e, const char *fmt, ...) LWS_FORMAT(2);

static void
inv_emit(struct inv_emit *e, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (e->saturated)
		return;

	va_start(ap, fmt);
	n = vsnprintf(e->buf + e->len, sizeof(e->buf) - e->len, fmt, ap);
	va_end(ap);

	if (n < 0 || (size_t)n >= sizeof(e->buf) - e->len) {
		e->saturated = 1;

		return;
	}

	e->len += (size_t)n;
}

/* canonicalise the request's detected-address hints, or drop them */

static void
inv_canon_hint(char *out, size_t outlen, const char *in, int is_v6)
{
	unsigned char ad[16];

	out[0] = '\0';

	if (!in[0] || inet_pton(is_v6 ? AF_INET6 : AF_INET, in, ad) != 1 ||
	    !inet_ntop(is_v6 ? AF_INET6 : AF_INET, ad, out,
		       (socklen_t)outlen))
		out[0] = '\0';
}

/*
 * One page of the rolled-up interface list, newline-framed like every
 * monitor response.  \p cursor says how many interfaces were already sent
 * by earlier pages; "next" hands the client the cursor for the following
 * page.
 */

void
handle_req_get_ip_inventory(struct vhd *vhd, struct pss *root_pss,
			     struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = (char *)root_pss->tx + sizeof(root_pss->tx);
	char ip4[64], ip6[64];
	sqlite3 *db;
	struct inv_ctx ic;
	unsigned long total, pos = 0, emitted = 0;
	long cursor = a->cursor > 0 ? a->cursor : 0;
	int more;

	db = inv_db_ensure(vhd);
	if (!db) {
		tx += lws_snprintf(tx, inv_rem(tx, tx_end),
				"{\"req\":\"%s\",\"status\":\"error\","
				"\"msg\":\"Inventory cache unavailable\"}\n",
				a->req);
		root_pss->tx_len = lws_ptr_diff_size_t(tx,
					(char *)&root_pss->tx[LWS_PRE]);

		return;
	}

	inv_canon_hint(ip4, sizeof(ip4), a->ip4, 0);
	inv_canon_hint(ip6, sizeof(ip6), a->ip6, 1);

	if (inv_rollup(db, &ic, ip4, ip6)) {
		sqlite3_close(db);
		tx += lws_snprintf(tx, inv_rem(tx, tx_end),
				"{\"req\":\"%s\",\"status\":\"error\","
				"\"msg\":\"Inventory rollup failed\"}\n",
				a->req);
		root_pss->tx_len = lws_ptr_diff_size_t(tx,
					(char *)&root_pss->tx[LWS_PRE]);

		return;
	}

	total = lws_dll2_count(&ic.ifaces);

	tx += lws_snprintf(tx, inv_rem(tx, tx_end),
			"{\"req\":\"%s\",\"status\":\"ok\",\"total\":%lu,"
			"\"cursor\":%ld,\"ifaces\":[",
			a->req, total, cursor);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ic.ifaces)) {
		struct inv_iface *f = lws_container_of(d, struct inv_iface,
						       list);
		struct inv_emit e;
		char esc_name[MON_ESC_DOMAIN_SZ];
		char esc_loc[6 * (INV_RDATA_MAX + 1) + 8];
		char esc_zone[MON_ESC_DOMAIN_SZ];
		int n;

		if (pos++ < (unsigned long)cursor ||
		    inv_rem(tx, tx_end) < INV_EMIT_ROOM)
			continue;

		memset(&e, 0, sizeof(e));

		/* the addresses, with what kinds of names point at them */
		inv_emit(&e, "{\"ips\":[");
		n = 0;
		lws_start_foreach_dll(struct lws_dll2 *, p,
				      lws_dll2_get_head(&f->addrs)) {
			struct inv_iaddr *ia = lws_container_of(p,
					struct inv_iaddr, list);

			if (n == INV_MAX_IPS)
				break;

			inv_emit(&e, "%s{\"ip\":\"%s\",\"v6\":%d,"
					"\"ns\":%d,\"ns_only\":%d}",
					n ? "," : "", ia->a->ip, ia->a->is_v6,
					ia->a->ns ? 1 : 0,
					ia->a->ns_only ? 1 : 0);
			n++;
		} lws_end_foreach_dll(p);
		inv_emit(&e, "]");

		/* the names pointing at this interface, in name order */
		inv_emit(&e, ",\"names\":[");
		n = 0;
		lws_start_foreach_dll(struct lws_dll2 *, m,
				      lws_dll2_get_head(&f->names)) {
			struct inv_iname *inm = lws_container_of(m,
					struct inv_iname, list);
			struct inv_name *nm = inm->n;

			if (n == INV_MAX_NAMES)
				break;

			inv_emit(&e, "%s{\"name\":\"%s\",\"ns\":%d",
					n ? "," : "",
					json_escape(esc_name, sizeof(esc_name),
						    nm->name),
					nm->ns ? 1 : 0);

			if (nm->loc)
				inv_emit(&e, ",\"loc\":\"%s\"",
					 json_escape(esc_loc,
						     sizeof(esc_loc), nm->loc));

			inv_emit(&e, ",\"zones\":[");
			{
				int zn = 0;

				lws_start_foreach_dll(struct lws_dll2 *, z,
						lws_dll2_get_head(&nm->zones)) {
					struct inv_zmention *zm =
						lws_container_of(z,
							struct inv_zmention,
							list);

					if (zn == INV_MAX_ZONES)
						break;

					inv_emit(&e, "%s{\"z\":\"%s\"}",
						 zn ? "," : "",
						 json_escape(esc_zone,
							     sizeof(esc_zone),
							     zm->zone));
					zn++;
				} lws_end_foreach_dll(z);
			}
			inv_emit(&e, "]}");
			n++;
		} lws_end_foreach_dll(m);
		inv_emit(&e, "]");

		/* the zonefiles delegating to any name on this interface */
		inv_emit(&e, ",\"ns_zones\":[");
		n = 0;
		lws_start_foreach_dll(struct lws_dll2 *, z,
				      lws_dll2_get_head(&f->ns_zones)) {
			struct inv_zmention *zm = lws_container_of(z,
					struct inv_zmention, list);

			if (n == INV_MAX_NS_ZONES)
				break;

			inv_emit(&e, "%s{\"z\":\"%s\"}", n ? "," : "",
				 json_escape(esc_zone, sizeof(esc_zone),
					     zm->zone));
			n++;
		} lws_end_foreach_dll(z);
		inv_emit(&e, "],\"v4\":%d,\"v6\":%d}",
			 f->has_v4 ? 1 : 0, f->has_v6 ? 1 : 0);

		if (e.saturated) {
			/*
			 * Absurdly wide entry: fall back to a stub that
			 * cannot outgrow the scratch buffer, so pagination
			 * can always make progress past it
			 */
			struct inv_iaddr *first = lws_container_of(
					lws_dll2_get_head(&f->addrs),
					struct inv_iaddr, list);
			struct inv_iname *fname = lws_container_of(
					lws_dll2_get_head(&f->names),
					struct inv_iname, list);

			memset(&e, 0, sizeof(e));
			inv_emit(&e, "{\"ips\":[{\"ip\":\"%s\","
					"\"v6\":%d,\"ns\":%d,"
					"\"ns_only\":%d}],"
					"\"names\":[{\"name\":\"%s\","
					"\"ns\":%d,\"zones\":[]}],"
					"\"ns_zones\":[],\"v4\":%d,"
					"\"v6\":%d,\"trunc\":1}",
					first->a->ip, first->a->is_v6,
					first->a->ns ? 1 : 0,
					first->a->ns_only ? 1 : 0,
					json_escape(esc_name, sizeof(esc_name),
						    fname->n->name),
					fname->n->ns ? 1 : 0,
					f->has_v4 ? 1 : 0,
					f->has_v6 ? 1 : 0);
		}

		if (!e.saturated) {
			if (emitted)
				*tx++ = ',';
			memcpy(tx, e.buf, e.len);
			tx += e.len;
		}

		/*
		 * Count the position as consumed even in the (practically
		 * unreachable) case the stub itself saturated, so the next
		 * cursor always advances past this entry
		 */
		emitted++;
	} lws_end_foreach_dll(d);

	more = cursor + (long)emitted < (long)total;

	tx += lws_snprintf(tx, inv_rem(tx, tx_end),
			"],\"more\":%d,\"next\":%ld}\n", more ? 1 : 0,
			cursor + (long)emitted);

	root_pss->tx_len = lws_ptr_diff_size_t(tx,
					(char *)&root_pss->tx[LWS_PRE]);

	lwsac_free(&ic.lwsac);
	sqlite3_close(db);
}

#else /* !LWS_WITH_SQLITE3 */

void
handle_req_get_ip_inventory(struct vhd *vhd, struct pss *root_pss,
			     struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = (char *)root_pss->tx + sizeof(root_pss->tx);

	(void)vhd;

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx),
			"{\"req\":\"%s\",\"status\":\"error\","
			"\"msg\":\"Built without sqlite3 support\"}\n", a->req);
	root_pss->tx_len = lws_ptr_diff_size_t(tx,
				(char *)&root_pss->tx[LWS_PRE]);
}

#endif
