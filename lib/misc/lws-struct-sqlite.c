/*
 * libwebsockets - lws_struct JSON serialization helpers
 *
 * Copyright (C) 2019 Andy Green <andy@warmcat.com>
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
 */

#include <libwebsockets.h>
#include <core/private.h>

#include <sqlite3.h>

/*
 * we get one of these per matching result from the query
 */

static int
lws_struct_sq3_deser_cb(void *priv, int cols, char **cv, char **cn)
{
	lws_struct_args_t *a = (lws_struct_args_t *)priv;
	const lws_struct_map_t *map = a->map_st[0];
	int n, mems = a->map_entries_st[0];
	lws_dll2_owner_t *o = (lws_dll2_owner_t *)a->cb_arg;
	char *u = lwsac_use_zero(&a->ac, a->dest_len, a->ac_block_size);
	long long li;
	size_t lim;
	char **pp;
	char *s;

	if (!u) {
		lwsl_err("OOM\n");

		return 1;
	}

	lws_dll2_add_tail((lws_dll2_t *)((char *)u + a->toplevel_dll2_ofs), o);

	while (mems--) {
		for (n = 0; n < cols; n++) {
			if (!cv[n] || strcmp(cn[n], map->colname))
				continue;

			switch (map->type) {
			case LSMT_SIGNED:
				if (map->aux == sizeof(signed char)) {
					signed char *pc;
					pc = (signed char *)(u + map->ofs);
					*pc = atoi(cv[n]);
					break;
				}
				if (map->aux == sizeof(int)) {
					int *pi;
					pi = (int *)(u + map->ofs);
					*pi = atoi(cv[n]);
					break;
				}
				if (map->aux == sizeof(long)) {
					long *pl;
					pl = (long *)(u + map->ofs);
					*pl = atol(cv[n]);
					break;
				}
				{
					long long *pll;
					pll = (long long *)(u + map->ofs);
					*pll = atoll(cv[n]);
				}
				break;

			case LSMT_UNSIGNED:
				if (map->aux == sizeof(unsigned char)) {
					unsigned char *pc;
					pc = (unsigned char *)(u + map->ofs);
					*pc = atoi(cv[n]);
					break;
				}
				if (map->aux == sizeof(unsigned int)) {
					unsigned int *pi;
					pi = (unsigned int *)(u + map->ofs);
					*pi = atoi(cv[n]);
					break;
				}
				if (map->aux == sizeof(unsigned long)) {
					unsigned long *pl;
					pl = (unsigned long *)(u + map->ofs);
					*pl = atol(cv[n]);
					break;
				}
				{
					unsigned long long *pll;
					pll = (unsigned long long *)(u + map->ofs);
					*pll = atoll(cv[n]);
				}
				break;

			case LSMT_BOOLEAN:
				li = 0;
				if (!strcmp(cv[n], "true") ||
				    !strcmp(cv[n], "TRUE") || cv[n][0] == '1')
					li = 1;
				if (map->aux == sizeof(char)) {
					char *pc;
					pc = (char *)(u + map->ofs);
					*pc = (char)li;
					break;
				}
				if (map->aux == sizeof(int)) {
					int *pi;
					pi = (int *)(u + map->ofs);
					*pi = (int)li;
				} else {
					uint64_t *p64;
					p64 = (uint64_t *)(u + map->ofs);
					*p64 = li;
				}
				break;

			case LSMT_STRING_CHAR_ARRAY:
				s = (char *)(u + map->ofs);
				lim = map->aux - 1;
				lws_strncpy(s, cv[n], lim);
				break;

			case LSMT_STRING_PTR:
				pp = (char **)(u + map->ofs);
				lim = strlen(cv[n]);
				s = lwsac_use(&a->ac, lim + 1, a->ac_block_size);
				if (!s)
					return 1;
				*pp = s;
				memcpy(s, cv[n], lim);
				s[lim] = '\0';
				break;
			default:
				break;
			}
		}
		map++;
	}

	return 0;
}

/*
 * Call this with an LSM_SCHEMA map, its colname is the table name and its
 * type information describes the toplevel type.  Schema is dereferenced and
 * put in args before the actual sq3 query, which is given the child map.
 */

int
lws_struct_sq3_deserialize(sqlite3 *pdb, const lws_struct_map_t *schema,
			   lws_dll2_owner_t *o, struct lwsac **ac,
			   uint64_t start, int limit)
{
	char s[150], where[32];
	lws_struct_args_t a;

	memset(&a, 0, sizeof(a));
	a.cb_arg = o; /* lws_dll2_owner tracking query result objects */
	a.map_st[0]  = schema->child_map;
	a.map_entries_st[0] = schema->child_map_size;
	a.dest_len = schema->aux; /* size of toplevel object to allocate */
	a.toplevel_dll2_ofs = schema->ofs;

	lws_dll2_owner_clear(o);

	where[0] = '\0';
	if (start)
		lws_snprintf(where, sizeof(where), " where when < %llu ",
				(unsigned long long)start);

	lws_snprintf(s, sizeof(s) - 1, "select * "
		     "from %s %s order by created desc limit %d;",
		     schema->colname, where, limit);

	if (sqlite3_exec(pdb, s, lws_struct_sq3_deser_cb, &a, NULL) != SQLITE_OK) {
		lwsl_err("%s: fail\n", sqlite3_errmsg(pdb));
		lwsac_free(&a.ac);
		return -1;
	}

	*ac = a.ac;

	return 0;
}

int
lws_struct_sq3_create_table(sqlite3 *pdb, const lws_struct_map_t *schema)
{
	const lws_struct_map_t *map = schema->child_map;
	int map_size = schema->child_map_size, subsequent = 0;
	char s[2048], *p = s, *end = &s[sizeof(s) - 1], *pri = "primary key";

	p += lws_snprintf(p, end - p, "create table if not exists %s (",
			  schema->colname);

	while (map_size--) {
		if (map->type > LSMT_STRING_PTR) {
			map++;
			continue;
		}
		if (subsequent && (end - p) > 3)
			*p++ = ',';
		subsequent = 1;
		if (map->type < LSMT_STRING_CHAR_ARRAY)
			p += lws_snprintf(p, end - p, "%s integer %s",
					  map->colname, pri);
		else
			p += lws_snprintf(p, end - p, "%s varchar %s",
					  map->colname, pri);
		pri = "";
		map++;
	}

	p += lws_snprintf(p, end - p, ");");

	if (sqlite3_exec(pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s: fail\n", __func__, sqlite3_errmsg(pdb));

		return -1;
	}

	return 0;
}

int
lws_struct_sq3_open(struct lws_context *context, const char *sqlite3_path,
		    sqlite3 **pdb)
{
	int uid = 0, gid = 0;

	if (sqlite3_open_v2(sqlite3_path, pdb,
			    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
			    NULL) != SQLITE_OK) {
		lwsl_err("%s: Unable to open db %s: %s\n",
			 __func__, sqlite3_path, sqlite3_errmsg(*pdb));

		return 1;
	}

	lws_get_effective_uid_gid(context, &uid, &gid);
	if (uid)
		chown(sqlite3_path, uid, gid);
	chmod(sqlite3_path, 0600);

	lwsl_notice("%s: created %s owned by %u:%u mode 0600\n", __func__,
			sqlite3_path, (unsigned int)uid, (unsigned int)gid);

	sqlite3_extended_result_codes(*pdb, 1);

	return 0;
}

int
lws_struct_sq3_close(sqlite3 **pdb)
{
	if (!*pdb)
		return 0;

	sqlite3_close(*pdb);
	*pdb = NULL;

	return 0;
}
