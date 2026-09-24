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
 * Country-level geolocation for the inventory's world map.
 *
 * Zonefiles can place a server exactly with a LOC record; addresses
 * without one are placed at their country's centroid, resolved through
 * dbip-country CSVs (from sapics/ip-location-db, CC-BY-4.0 data via
 * DB-IP lite) that the root process downloads into <base-dir>/geo and
 * refreshes when they are older than a month.
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
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#if defined(WIN32) || defined(_WIN32)
#else
#include <arpa/inet.h>
#endif

#include "private.h"

/* refresh the downloaded CSVs when older than this */
#define INV_GEO_MAX_AGE_SECS	(30 * 24 * 3600)

/* sanity caps on what we are willing to parse */
#define INV_GEO_CSV_MAX_BYTES	(256 * 1024 * 1024)
#define INV_GEO_CSV_MAX_ROWS	(8 * 1024 * 1024)

static const char * const inv_geo_host = "github.com";

static const char * const inv_geo_url_path[2] = {
	"/sapics/ip-location-db/releases/download/latest/"
					"dbip-country-ipv4-cidr.csv",
	"/sapics/ip-location-db/releases/download/latest/"
					"dbip-country-ipv6-cidr.csv",
};

static const char * const inv_geo_file[2] = {
	"dbip-country-ipv4-cidr.csv",
	"dbip-country-ipv6-cidr.csv",
};

/*
 * Country centroids derived from Natural Earth 1:110m admin-0
 * (public domain, https://www.naturalearthdata.com/), computed as
 * the area centroid of each country's largest polygon at that scale.
 * lat / lon stored as degrees x 100.
 */
static const struct inv_ccent {
	char	cc[3];
	int16_t	latx100;
	int16_t	lonx100;
} inv_ccents[] = {
	{ "AE", 2387, 5421 },
	{ "AF", 3386, 6609 },
	{ "AL", 4114, 2003 },
	{ "AM", 4022, 4500 },
	{ "AO", -1229, 1750 },
	{ "AQ", -8052, 2128 },
	{ "AR", -3522, -6515 },
	{ "AT", 4761, 1408 },
	{ "AU", -2556, 13438 },
	{ "AZ", 4028, 4768 },
	{ "BA", 4418, 1782 },
	{ "BD", 2384, 9027 },
	{ "BE", 5065, 458 },
	{ "BF", 1231, -178 },
	{ "BG", 4275, 2520 },
	{ "BI", -338, 2991 },
	{ "BJ", 965, 234 },
	{ "BN", 469, 11492 },
	{ "BO", -1673, -6464 },
	{ "BR", -1081, -5305 },
	{ "BS", 2451, -7792 },
	{ "BT", 2743, 9047 },
	{ "BW", -2210, 2377 },
	{ "BY", 5351, 2798 },
	{ "BZ", 1720, -8870 },
	{ "CA", 5775, -10157 },
	{ "CD", -285, 2358 },
	{ "CF", 654, 2037 },
	{ "CG", -84, 1513 },
	{ "CH", 4679, 812 },
	{ "CI", 755, -561 },
	{ "CL", -3734, -7167 },
	{ "CM", 566, 1261 },
	{ "CN", 3661, 10387 },
	{ "CO", 393, -7308 },
	{ "CR", 997, -8418 },
	{ "CU", 2163, -7896 },
	{ "CY", 3491, 3304 },
	{ "CZ", 4978, 1533 },
	{ "DE", 5113, 1029 },
	{ "DJ", 1177, 4250 },
	{ "DK", 5622, 931 },
	{ "DO", 1888, -7046 },
	{ "DZ", 2819, 260 },
	{ "EC", -145, -7838 },
	{ "EE", 5864, 2582 },
	{ "EG", 2651, 2984 },
	{ "EH", 2429, -1214 },
	{ "ER", 1543, 3868 },
	{ "ES", 4035, -362 },
	{ "ET", 865, 3955 },
	{ "FI", 6450, 2621 },
	{ "FJ", -1783, 17800 },
	{ "FK", -5171, -5942 },
	{ "FR", 4661, 234 },
	{ "GA", -65, 1169 },
	{ "GB", 5388, -266 },
	{ "GE", 4216, 4348 },
	{ "GH", 793, -124 },
	{ "GL", 7477, -4150 },
	{ "GM", 1348, -1543 },
	{ "GN", 1045, -1106 },
	{ "GQ", 165, 1037 },
	{ "GR", 3934, 2256 },
	{ "GT", 1570, -9037 },
	{ "GW", 1202, -1511 },
	{ "GY", 479, -5897 },
	{ "HN", 1482, -8659 },
	{ "HR", 4502, 1657 },
	{ "HT", 1890, -7266 },
	{ "HU", 4720, 1936 },
	{ "ID", -25, 11402 },
	{ "IE", 5318, -801 },
	{ "IL", 3148, 3500 },
	{ "IN", 2293, 7959 },
	{ "IQ", 3304, 4376 },
	{ "IR", 3252, 5429 },
	{ "IS", 6507, -1876 },
	{ "IT", 4347, 1222 },
	{ "JM", 1814, -7732 },
	{ "JO", 3125, 3678 },
	{ "JP", 3602, 13688 },
	{ "KE", 60, 3779 },
	{ "KG", 4151, 7462 },
	{ "KH", 1268, 10488 },
	{ "KP", 4014, 12717 },
	{ "KR", 3643, 12782 },
	{ "KW", 2931, 4760 },
	{ "KZ", 4819, 6728 },
	{ "LA", 1844, 10375 },
	{ "LB", 3391, 3587 },
	{ "LK", 770, 8067 },
	{ "LR", 643, -941 },
	{ "LS", -2963, 2817 },
	{ "LT", 5528, 2388 },
	{ "LU", 4977, 597 },
	{ "LV", 5681, 2483 },
	{ "LY", 2700, 1797 },
	{ "MA", 2989, -842 },
	{ "MD", 4720, 2841 },
	{ "ME", 4279, 1929 },
	{ "MG", -1936, 4669 },
	{ "MK", 4161, 2170 },
	{ "ML", 1727, -354 },
	{ "MM", 2102, 9651 },
	{ "MN", 4682, 10295 },
	{ "MR", 2021, -1033 },
	{ "MW", -1317, 3419 },
	{ "MX", 2394, -10258 },
	{ "MY", 355, 11468 },
	{ "MZ", -1723, 3547 },
	{ "NA", -2210, 1716 },
	{ "NC", -2126, 16553 },
	{ "NE", 1735, 932 },
	{ "NG", 955, 800 },
	{ "NI", 1285, -8502 },
	{ "NL", 5230, 551 },
	{ "NO", 6454, 1424 },
	{ "NP", 2824, 8401 },
	{ "NZ", -4399, 17051 },
	{ "OM", 2058, 5610 },
	{ "PA", 853, -8011 },
	{ "PE", -919, -7439 },
	{ "PG", -665, 14433 },
	{ "PH", 1575, 12154 },
	{ "PK", 2997, 6941 },
	{ "PL", 5215, 1931 },
	{ "PR", 1824, -6648 },
	{ "PS", 3194, 3527 },
	{ "PT", 3963, -806 },
	{ "PY", -2325, -5839 },
	{ "QA", 2532, 5118 },
	{ "RO", 4586, 2494 },
	{ "RS", 4423, 2082 },
	{ "RU", 6169, 9922 },
	{ "RW", -201, 2992 },
	{ "SA", 2412, 4452 },
	{ "SB", -790, 15910 },
	{ "SD", 1599, 2986 },
	{ "SE", 6281, 1660 },
	{ "SI", 4613, 1494 },
	{ "SK", 4873, 1951 },
	{ "SL", 853, -1180 },
	{ "SN", 1435, -1451 },
	{ "SO", 475, 4573 },
	{ "SR", 412, -5591 },
	{ "SS", 729, 3020 },
	{ "SV", 1373, -8887 },
	{ "SY", 3501, 3854 },
	{ "SZ", -2649, 3140 },
	{ "TD", 1533, 1858 },
	{ "TF", -4931, 6953 },
	{ "TG", 844, 100 },
	{ "TH", 1502, 10101 },
	{ "TJ", 3858, 7103 },
	{ "TL", -877, 12597 },
	{ "TM", 3909, 5928 },
	{ "TN", 3417, 953 },
	{ "TR", 3899, 3539 },
	{ "TT", 1043, -6133 },
	{ "TW", 2374, 12097 },
	{ "TZ", -626, 3475 },
	{ "UA", 4915, 3123 },
	{ "UG", 130, 3236 },
	{ "US", 3950, -9906 },
	{ "UY", -3278, -5600 },
	{ "UZ", 4175, 6320 },
	{ "VE", 716, -6616 },
	{ "VN", 1666, 10629 },
	{ "VU", -1522, 16691 },
	{ "XK", 4258, 2090 },
	{ "YE", 1591, 4754 },
	{ "ZA", -2896, 2512 },
	{ "ZM", -1340, 2773 },
	{ "ZW", -1891, 2979 },
};

static int
inv_geo_cmp_cc(const void *a, const void *b)
{
	return strcmp((const char *)a, ((const struct inv_ccent *)b)->cc);
}

int
inv_geo_centroid(const char *cc, double *lat, double *lon)
{
	const struct inv_ccent *c;

	if (!cc || !cc[0])
		return 1;

	c = bsearch(cc, inv_ccents, LWS_ARRAY_SIZE(inv_ccents),
		    sizeof(*c), inv_geo_cmp_cc);
	if (!c)
		return 1;

	*lat = c->latx100 / 100.0;
	*lon = c->lonx100 / 100.0;

	return 0;
}

/*
 * Parse the leading coordinates out of a LOC rdata as stored in the
 * inventory cache, eg "42 21 54 N 71 6 18 W -24m 30m 200m 15m": up to
 * three numbers then a direction letter, twice.  Returns 0 with the
 * signed angles in degrees.
 */

static const char *
inv_geo_num(const char *p, double *v)
{
	char *e;
	double d = strtod(p, &e);

	if (e == p)
		return NULL;

	*v = d;

	return e;
}

static const char *
inv_geo_dms(const char *p, double *degrees)
{
	double v[3] = { 0, 0, 0 };
	int n = 0;
	char dir;

	while (*p == ' ' || *p == '\t')
		p++;

	while (n < 3) {
		const char *e = inv_geo_num(p, &v[n]);

		if (!e)
			break;
		p = e;
		while (*p == ' ' || *p == '\t')
			p++;
		n++;
	}

	if (!n || !isalpha((unsigned char)*p))
		return NULL;

	dir = (char)toupper((unsigned char)*p);
	p++;

	if (dir != 'N' && dir != 'S' && dir != 'E' && dir != 'W')
		return NULL;

	if ((n == 2 && v[1] >= 60.0) || (n == 3 && (v[1] >= 60.0 ||
						 v[2] >= 60.0)))
		return NULL;

	*degrees = v[0] + (n > 1 ? v[1] / 60.0 : 0) +
		   (n > 2 ? v[2] / 3600.0 : 0);

	if (dir == 'S' || dir == 'W')
		*degrees = -*degrees;

	return p;
}

int
inv_geo_loc_parse(const char *rdata, double *lat, double *lon)
{
	const char *p = inv_geo_dms(rdata, lat);

	if (!p)
		return 1;

	p = inv_geo_dms(p, lon);

	return p ? 0 : 1;
}

static void
inv_geo_path(struct vhd *vhd, char *buf, size_t len, int is_v6)
{
	lws_snprintf(buf, len, "%s/geo/%s", vhd->base_dir,
		     inv_geo_file[!!is_v6]);
}

static int
inv_geo_cmp_r4(const void *a, const void *b)
{
	const struct inv_grange4 *x = a, *y = b;

	if (x->start != y->start)
		return x->start < y->start ? -1 : 1;

	return 0;
}

static int
inv_geo_cmp_r6(const void *a, const void *b)
{
	return memcmp(((const struct inv_grange6 *)a)->start,
		      ((const struct inv_grange6 *)b)->start, 16);
}

/* bsearch comparator where the key is the address inside its range */

struct inv_geo_key4 {
	uint32_t ip;
};

static int
inv_geo_cmp_ip4(const void *k, const void *r)
{
	const struct inv_geo_key4 *key = k;
	const struct inv_grange4 *row = r;

	if (key->ip < row->start)
		return -1;
	if (key->ip > row->end)
		return 1;

	return 0;
}

struct inv_geo_key6 {
	const unsigned char *ip;
};

static int
inv_geo_cmp_ip6(const void *k, const void *r)
{
	const struct inv_geo_key6 *key = k;
	const struct inv_grange6 *row = r;

	if (memcmp(key->ip, row->start, 16) < 0)
		return -1;
	if (memcmp(key->ip, row->end, 16) > 0)
		return 1;

	return 0;
}

/*
 * Parse one "cidr,CC" line into the caller's row.  Returns 0 if the
 * line is a usable range.
 */

static int
inv_geo_row(struct inv_grange4 *r4, struct inv_grange6 *r6,
	    char *line, int is_v6)
{
	char *cc, *slash;
	struct in_addr a4;
	struct in6_addr a6;

	cc = (char *)strchr(line, ',');
	if (!cc)
		return 1;
	*cc++ = '\0';

	slash = (char *)strchr(line, '/');
	if (!slash)
		return 1;
	*slash++ = '\0';

	if (cc[0] && cc[1] && cc[2])
		return 1; /* over-long cc */

	if (is_v6) {
		int plen = atoi(slash), pre;

		if (plen < 0 || plen > 128 ||
		    inet_pton(AF_INET6, line, &a6) != 1)
			return 1;

		pre = plen / 8;
		memcpy(r6->start, &a6, 16);
		memcpy(r6->end, &a6, 16);

		if (pre < 16) {
			/*
			 * Keep the top plen % 8 bits of the partial byte;
			 * with no partial bits the whole byte is host bits
			 */
			uint8_t m = (uint8_t)(plen % 8 ?
				((0xff00 >> (plen % 8)) & 0xff) : 0);

			r6->start[pre] &= m;
			memset(r6->start + pre + 1, 0, (size_t)(15 - pre));
			r6->end[pre] |= (uint8_t)~m;
			memset(r6->end + pre + 1, 0xff, (size_t)(15 - pre));
		}

		r6->cc[0] = cc[0];
		r6->cc[1] = cc[1];
		r6->cc[2] = '\0';

		return 0;
	}

	{
		int plen = atoi(slash);
		uint32_t mask;

		if (plen < 0 || plen > 32 ||
		    inet_pton(AF_INET, line, &a4) != 1)
			return 1;

		mask = plen ? (uint32_t)(0xffffffffU << (32 - plen)) : 0;

		r4->start = ntohl(a4.s_addr) & mask;
		r4->end   = r4->start | ~mask;
		r4->cc[0] = cc[0];
		r4->cc[1] = cc[1];
		r4->cc[2] = '\0';

		return 0;
	}
}

/*
 * (Re)parse one of the CSV caches if its file changed since the last
 * parse.  Runs synchronously on the first address lookup after a
 * download, which is a couple of times a month.
 */

static int
inv_geo_maybe_load(struct vhd *vhd, int is_v6)
{
	struct inv_geo *g = &vhd->geo;
	struct inv_grange4 *r4 = NULL;
	struct inv_grange6 *r6 = NULL;
	size_t used = 0, alloc = 0;
	time_t *mt = is_v6 ? &g->mt6 : &g->mt4;
	char path[1024], *buf = NULL;
	struct stat st;
	size_t size;
	int fd, ret = 1;

	inv_geo_path(vhd, path, sizeof(path), is_v6);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 1;

	if (fstat(fd, &st) || st.st_size <= 0 ||
	    (size_t)st.st_size > INV_GEO_CSV_MAX_BYTES)
		goto bail;

	if (st.st_mtime == *mt) {
		/* already parsed this exact file */
		ret = 0;
		goto bail;
	}

	size = (size_t)st.st_size;
	buf = malloc(size + 1);
	if (!buf)
		goto bail;

	if (read(fd, buf, size) != (ssize_t)size)
		goto bail;
	buf[size] = '\0';

	alloc = 4096;
	if (is_v6) {
		r6 = malloc(alloc * sizeof(*r6));
		if (!r6)
			goto bail;
	} else {
		r4 = malloc(alloc * sizeof(*r4));
		if (!r4)
			goto bail;
	}

	{
		char *p = buf, *line;

		while ((line = p) && *p) {
			char *nl = (char *)strchr(p, '\n');
			struct inv_grange4 t4;
			struct inv_grange6 t6;

			if (nl)
				*nl = '\0';

			p = nl ? nl + 1 : (char *)buf + size;

			if (!inv_geo_row(&t4, &t6, line, is_v6)) {
				if (used == alloc) {
					size_t na;
					void *nb;

					if (alloc >= INV_GEO_CSV_MAX_ROWS)
						goto bail;

					na = alloc * 2;
					nb = is_v6 ? realloc(r6, na * sizeof(*r6))
						   : realloc(r4, na * sizeof(*r4));
					if (!nb)
						goto bail;

					if (is_v6)
						r6 = nb;
					else
						r4 = nb;
					alloc = na;
				}

				if (is_v6)
					r6[used] = t6;
				else
					r4[used] = t4;
				used++;
			}
		}
	}

	if (is_v6) {
		qsort(r6, used, sizeof(*r6), inv_geo_cmp_r6);
		free(g->r6);
		g->r6 = r6;
		g->n6 = used;
		r6 = NULL;
	} else {
		qsort(r4, used, sizeof(*r4), inv_geo_cmp_r4);
		free(g->r4);
		g->r4 = r4;
		g->n4 = used;
		r4 = NULL;
	}

	*mt = st.st_mtime;

	lwsl_notice("%s: loaded %zu %s ranges from %s\n", __func__, used,
		    is_v6 ? "ipv6" : "ipv4", path);

	ret = 0;

bail:
	free(buf);
	free(r4);
	free(r6);
	close(fd);

	return ret;
}

const char *
inv_geo_cc(struct vhd *vhd, const char *ip, int is_v6)
{
	struct inv_geo *g = &vhd->geo;

	if (!ip || !ip[0])
		return NULL;

	if (inv_geo_maybe_load(vhd, is_v6))
		return NULL;

	if (is_v6) {
		const struct inv_grange6 *r;
		struct in6_addr a6;
		struct inv_geo_key6 key;

		if (inet_pton(AF_INET6, ip, &a6) != 1 || !g->n6)
			return NULL;

		key.ip = (const unsigned char *)&a6;

		r = bsearch(&key, g->r6, g->n6, sizeof(*g->r6),
			    inv_geo_cmp_ip6);

		return r ? r->cc : NULL;
	}

	{
		const struct inv_grange4 *r;
		struct in_addr a4;
		struct inv_geo_key4 key;

		if (inet_pton(AF_INET, ip, &a4) != 1 || !g->n4)
			return NULL;

		key.ip = ntohl(a4.s_addr);

		r = bsearch(&key, g->r4, g->n4, sizeof(*g->r4),
			    inv_geo_cmp_ip4);

		return r ? r->cc : NULL;
	}
}

/*
 * The downloader: GET the CSV to a temp file next to its final name and
 * rename over it on completion.  The HTTP body streams back through the
 * plugin's main callback, keyed on the opaque magic.
 */

struct inv_geo_dl *
inv_geo_dl_create(struct vhd *vhd, int is_v6)
{
	struct lws_client_connect_info i;
	struct inv_geo_dl *g;
	char dir[1024];

	g = calloc(1, sizeof(*g));
	if (!g)
		return NULL;

	g->magic = INV_GEO_DL_MAGIC;
	g->vhd = vhd;
	g->is_v6 = !!is_v6;

	lws_snprintf(dir, sizeof(dir), "%s/geo", vhd->base_dir);
	if (mkdir(dir, 0700) && errno != EEXIST)
		goto bail;

	inv_geo_path(vhd, g->final, sizeof(g->final), g->is_v6);
	lws_snprintf(g->tmp, sizeof(g->tmp), "%s.tmp", g->final);

	g->fd = open(g->tmp, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (g->fd < 0)
		goto bail;

	memset(&i, 0, sizeof(i));
	i.context	= vhd->context;
	{
		struct lws_vhost *vh = lws_get_vhost_by_name(vhd->context,
							     "default");
		i.vhost = vh ? vh : vhd->vhost;
	}
	i.address	= inv_geo_host;
	i.port		= 443;
	i.ssl_connection = LCCSCF_USE_SSL;
	i.method	= "GET";
	i.path		= inv_geo_url_path[g->is_v6];
	i.host		= inv_geo_host;
	i.origin	= inv_geo_host;
	i.protocol	= "lws-dht-dnssec-monitor";
	i.opaque_user_data = g;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_notice("%s: connect for %s failed\n", __func__,
			    inv_geo_file[g->is_v6]);
		goto bail2;
	}

	lwsl_notice("%s: downloading %s\n", __func__, inv_geo_file[g->is_v6]);

	return g;

bail2:
	close(g->fd);
	unlink(g->tmp);

bail:
	free(g);

	return NULL;
}

int
inv_geo_dl_rx(struct inv_geo_dl *g, const char *in, size_t len)
{
	if (!g || g->magic != INV_GEO_DL_MAGIC)
		return 1;

	if (g->got + len > INV_GEO_CSV_MAX_BYTES)
		return 1;

	if (write(g->fd, in, len) != (ssize_t)len)
		return 1;

	g->got += len;

	return 0;
}

void
inv_geo_dl_complete(struct inv_geo_dl *g)
{
	if (!g || g->magic != INV_GEO_DL_MAGIC)
		return;

	close(g->fd);
	g->fd = -1;

	if (g->got < 1024) {
		/* not a plausible CSV: keep the previous one */
		lwsl_notice("%s: %s download too small, discarded\n",
			    __func__, inv_geo_file[g->is_v6]);
		unlink(g->tmp);
	} else {
		rename(g->tmp, g->final);
		lwsl_notice("%s: %s updated (%zu bytes)\n", __func__,
			    inv_geo_file[g->is_v6], g->got);
	}

	if (g->is_v6)
		g->vhd->geo.dl6 = NULL;
	else
		g->vhd->geo.dl4 = NULL;

	g->magic = 0;
	free(g);
}

void
inv_geo_dl_fail(struct inv_geo_dl *g)
{
	if (!g || g->magic != INV_GEO_DL_MAGIC)
		return;

	if (g->fd >= 0)
		close(g->fd);
	unlink(g->tmp);

	if (g->is_v6)
		g->vhd->geo.dl6 = NULL;
	else
		g->vhd->geo.dl4 = NULL;

	g->magic = 0;
	free(g);
}

/*
 * Re-download any missing or stale CSV, daily (and once shortly after
 * the root process starts).
 */

static void
inv_geo_refresh(struct vhd *vhd)
{
	time_t now = time(NULL);
	int n;

	for (n = 0; n < 2; n++) {
		struct stat st;
		char path[1024];

		if (n ? vhd->geo.dl6 : vhd->geo.dl4)
			continue; /* already in flight */

		inv_geo_path(vhd, path, sizeof(path), n);

		if (!stat(path, &st) &&
		    now - st.st_mtime < INV_GEO_MAX_AGE_SECS)
			continue;

		if (!n) {
			vhd->geo.dl4 = inv_geo_dl_create(vhd, 0);
		} else {
			vhd->geo.dl6 = inv_geo_dl_create(vhd, 1);
		}
	}
}

void
inv_geo_timer_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_geo);

	inv_geo_refresh(vhd);

	lws_sul_schedule(vhd->context, 0, &vhd->sul_geo, inv_geo_timer_cb,
			 24 * 3600 * LWS_US_PER_SEC);
}

void
inv_geo_destroy(struct vhd *vhd)
{
	lws_sul_cancel(&vhd->sul_geo);
	inv_geo_dl_fail((struct inv_geo_dl *)vhd->geo.dl4);
	inv_geo_dl_fail((struct inv_geo_dl *)vhd->geo.dl6);
	free(vhd->geo.r4);
	free(vhd->geo.r6);
	memset(&vhd->geo, 0, sizeof(vhd->geo));
}
