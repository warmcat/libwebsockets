/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <libwebsockets.h>
#include <private-lib-core.h>

#include <sqlite3.h>

/*
 * we get one of these per matching result from the query
 */

static int
lws_struct_sq3_deser_cb(void *priv, int cols, char **cv, char **cn)
{
	lws_struct_args_t *a = (lws_struct_args_t *)priv;
	char *u = lwsac_use_zero(&a->ac, a->dest_len, a->ac_block_size);
	lws_dll2_owner_t *o = (lws_dll2_owner_t *)a->cb_arg;
	const lws_struct_map_t *map = a->map_st[0];
	int n, mems = (int)(ssize_t)a->map_entries_st[0];
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
					*pc = (signed char)atoi(cv[n]);
					break;
				}
				if (map->aux == sizeof(short)) {
					short *ps;
					ps = (short *)(u + map->ofs);
					*ps = (short)atoi(cv[n]);
					break;
				}
				if (map->aux == sizeof(int)) {
					int *pi;
					pi = (int *)(u + map->ofs);
					*pi = (int)atoll(cv[n]); /* 32-bit OS */
					break;
				}
				if (map->aux == sizeof(long)) {
					long *pl;
					pl = (long *)(u + map->ofs);
					*pl = (long)atoll(cv[n]); /* 32-bit OS */
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
					*pc = (unsigned char)(unsigned int)atoi(cv[n]);
					break;
				}
				if (map->aux == sizeof(unsigned short)) {
					unsigned short *ps;
					ps = (unsigned short *)(u + map->ofs);
					*ps = (unsigned short)atoi(cv[n]);
					break;
				}
				if (map->aux == sizeof(unsigned int)) {
					unsigned int *pi;
					pi = (unsigned int *)(u + map->ofs);
					*pi = (unsigned int)atoi(cv[n]);
					break;
				}
				if (map->aux == sizeof(unsigned long)) {
					unsigned long *pl;
					pl = (unsigned long *)(u + map->ofs);
					*pl = (unsigned long)atol(cv[n]);
					break;
				}
				{
					unsigned long long *pll;
					pll = (unsigned long long *)(u + map->ofs);
					*pll = (unsigned long long)atoll(cv[n]);
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
					*p64 = (uint64_t)li;
				}
				break;

			case LSMT_STRING_CHAR_ARRAY:
				s = (char *)(u + map->ofs);
				lim = map->aux;
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
lws_struct_sq3_deserialize(sqlite3 *pdb, const char *filter, const char *order,
			   const lws_struct_map_t *schema, lws_dll2_owner_t *o,
			   struct lwsac **ac, int start, int _limit)
{
	int limit = _limit < 0 ? -_limit : _limit, subsequent = 0;
	char *s, *p, *end;
	lws_struct_args_t a;
	size_t n, len;

	lws_dll2_owner_clear(o);

	if (!order)
		order = "_lws_idx";

	/*
	 * The statement is as long as the schema's column list and the
	 * caller's filter make it, eg, a filter matching a long builder name,
	 * so size it from its parts rather than limit it to a fixed buffer.
	 * The constant parts and the two ints fit in the 128 bytes headroom.
	 */

	len = strlen(schema->colname) + strlen(order) + 128;
	if (filter)
		len += strlen(filter);
	for (n = 0; n < schema->child_map_size; n++)
		len += strlen(schema->child_map[n].colname) + 2;

	s = malloc(len);
	if (!s)
		return -1;

	p = s;
	end = s + len;

	/*
	 * Explicitly list the columns instead of use *, so we can skip blobs
	 */

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "select ");
	for (n = 0; n < schema->child_map_size; n++)
		if (!schema->child_map[n].json_only) {
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "%s%s", subsequent ? ", " : "",
					  schema->child_map[n].colname);
			subsequent = 1;
		}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), " from %s",
			  schema->colname);
	if (filter)
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  " WHERE 1=1 %s", filter);
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  " order by %s %slimit %d OFFSET %d;", order,
			  _limit < 0 ? "desc " : "", limit, start);

	/*
	 * It was sized to fit, but a statement truncated at a clause boundary
	 * is still valid SQL with the row restriction quietly removed, so
	 * never run one we could not write in full.
	 */

	if (p >= end - 1) {
		lwsl_err("%s: statement too long\n", __func__);
		free(s);

		return -1;
	}

	memset(&a, 0, sizeof(a));
	a.ac = *ac;
	a.cb_arg = o; /* lws_dll2_owner tracking query result objects */
	a.map_st[0]  = schema->child_map;
	a.map_entries_st[0] = schema->child_map_size;
	a.dest_len = schema->aux; /* size of toplevel object to allocate */
	a.toplevel_dll2_ofs = schema->ofs;

	if (sqlite3_exec(pdb, s, lws_struct_sq3_deser_cb, &a, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s: fail %s\n", __func__, sqlite3_errmsg(pdb), s);
		free(s);
		lwsac_free(&a.ac);
		return -1;
	}

	free(s);
	*ac = a.ac;

	return 0;
}

/*
 * The writers below never splice member values into the SQL text.  The text
 * holds only the table and column names from the map, which are program
 * constants, and a ? placeholder for each value; the values are bound to
 * the prepared statement.  So a value needs no escaping, can't change the
 * statement and isn't limited in length.
 *
 * This is how long the text of a statement naming every column of the map
 * up to three times can be, plus the table name, the conflict / where column
 * and the constant parts.  Each writer still checks it fit.
 */

static size_t
ls_sq3_sql_len(const char *table, const lws_struct_map_t *map,
	       size_t map_entries, const char *where_col)
{
	size_t n, len = strlen(table) + 128;

	if (where_col)
		len += strlen(where_col);

	for (n = 0; n < map_entries; n++)
		len += (3 * strlen(map[n].colname)) + 16;

	return len;
}

/*
 * Bind one member as the value of parameter \p col of \p st.  Integer
 * members are read at their real width (map->aux is sizeof(member)), like
 * the JSON serializer does, and an unrecognized width is a hard fail.  A NULL
 * string pointer is bound as SQL NULL, which lws_struct_sq3_deserialize()
 * gives back as a NULL member.
 */

static int
ls_sq3_bind_col(sqlite3 *pdb, sqlite3_stmt *st, int col, const void *memb,
		const lws_struct_map_t *map)
{
	unsigned long long ull;
	const char *s, *z;
	long long ll;
	size_t len;
	int n;

	switch (map->type) {
	case LSMT_SIGNED:
		if (map->aux == sizeof(signed char))
			ll = *(const signed char *)memb;
		else if (map->aux == sizeof(short))
			ll = *(const short *)memb;
		else if (map->aux == sizeof(int))
			ll = *(const int *)memb;
		else if (map->aux == sizeof(long))
			ll = *(const long *)memb;
		else if (map->aux == sizeof(long long))
			ll = *(const long long *)memb;
		else
			goto bad_width;

		n = sqlite3_bind_int64(st, col, (sqlite3_int64)ll);
		break;

	case LSMT_UNSIGNED:
	case LSMT_BOOLEAN:
		if (map->aux == sizeof(unsigned char))
			ull = *(const unsigned char *)memb;
		else if (map->aux == sizeof(unsigned short))
			ull = *(const unsigned short *)memb;
		else if (map->aux == sizeof(unsigned int))
			ull = *(const unsigned int *)memb;
		else if (map->aux == sizeof(unsigned long))
			ull = *(const unsigned long *)memb;
		else if (map->aux == sizeof(unsigned long long))
			ull = *(const unsigned long long *)memb;
		else
			goto bad_width;

		if (map->type == LSMT_BOOLEAN)
			ull = !!ull;

		/*
		 * sqlite integers are signed 64-bit: a value with the top bit
		 * set is stored as the negative number with the same bits,
		 * which the deserializer's conversion back to the unsigned
		 * member restores.  As text it became a lossy REAL.
		 */
		n = sqlite3_bind_int64(st, col, (sqlite3_int64)ull);
		break;

	case LSMT_STRING_CHAR_ARRAY:
		/* the member may fill its array without a terminating NUL */
		z = memchr(memb, '\0', map->aux);
		len = z ? (size_t)((const char *)z - (const char *)memb) :
			    map->aux;
		if (len > INT_MAX)
			goto too_long;

		n = sqlite3_bind_text(st, col, (const char *)memb, (int)len,
				      SQLITE_STATIC);
		break;

	case LSMT_STRING_PTR:
		s = *(const char * const *)memb;
		if (!s) {
			n = sqlite3_bind_null(st, col);
			break;
		}

		len = strlen(s);
		if (len > INT_MAX)
			goto too_long;

		n = sqlite3_bind_text(st, col, s, (int)len, SQLITE_STATIC);
		break;

	default:
		lwsl_err("%s: '%s': unsupported type %d\n", __func__,
			 map->colname, (int)map->type);

		return 1;
	}

	if (n != SQLITE_OK) {
		lwsl_err("%s: '%s': %s\n", __func__, map->colname,
			 sqlite3_errmsg(pdb));

		return 1;
	}

	return 0;

bad_width:
	lwsl_err("%s: '%s': bad member width %d\n", __func__, map->colname,
		 (int)map->aux);

	return 1;

too_long:
	lwsl_err("%s: '%s': value too long\n", __func__, map->colname);

	return 1;
}

static int
ls_sq3_prepare(sqlite3 *pdb, const char *sql, sqlite3_stmt **st)
{
	if (sqlite3_prepare_v2(pdb, sql, -1, st, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s: %s\n", __func__, sqlite3_errmsg(pdb), sql);

		return 1;
	}

	return 0;
}

/* run the bound statement to completion and finalize it either way */

static int
ls_sq3_step_finalize(sqlite3 *pdb, sqlite3_stmt *st, const char *sql)
{
	int n = sqlite3_step(st);

	if (n != SQLITE_DONE)
		lwsl_warn("%s: %s: %s\n", __func__, sqlite3_errmsg(pdb), sql);

	sqlite3_finalize(st);

	return n != SQLITE_DONE;
}

/*
 * This takes a struct and turns it into an sqlite3 INSERT, using the given
 * schema... which has one LSM_SCHEMA_DLL2 entry wrapping the actual schema
 */

static int
_lws_struct_sq3_ser_one(sqlite3 *pdb, const lws_struct_map_t *schema,
			uint32_t idx, void *st)
{
	const lws_struct_map_t *map = schema->child_map;
	size_t n, nentries = schema->child_map_size, len;
	const uint8_t *stb = (const uint8_t *)st;
	char *sql, *p, *end;
	sqlite3_stmt *stmt;
	int pk, col;

	/*
	 * The first UNSIGNED is the hidden primary key autoincrement, and
	 * isn't specified.  Blobs are not handled by lws_struct except to
	 * create the column in the schema.
	 */

	len = ls_sq3_sql_len(schema->colname, map, nentries, NULL);
	sql = malloc(len);
	if (!sql)
		return -1;

	p = sql;
	end = sql + len;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "insert into %s(_lws_idx", schema->colname);

	pk = 0;
	for (n = 0; n < nentries; n++) {
		if (map[n].json_only)
			continue;
		if (!pk && map[n].type == LSMT_UNSIGNED) {
			pk = 1;
			continue;
		}
		if (map[n].type == LSMT_BLOB_PTR)
			continue;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ", %s",
				  map[n].colname);
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ") values(?");

	pk = 0;
	for (n = 0; n < nentries; n++) {
		if (map[n].json_only)
			continue;
		if (!pk && map[n].type == LSMT_UNSIGNED) {
			pk = 1;
			continue;
		}
		if (map[n].type == LSMT_BLOB_PTR)
			continue;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ", ?");
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ");");

	if (p >= end - 1) {
		lwsl_err("%s: statement too long\n", __func__);
		goto bail;
	}

	if (ls_sq3_prepare(pdb, sql, &stmt))
		goto bail;

	col = 1;
	if (sqlite3_bind_int64(stmt, col++, (sqlite3_int64)idx) != SQLITE_OK)
		goto bail_stmt;

	pk = 0;
	for (n = 0; n < nentries; n++) {
		if (map[n].json_only)
			continue;
		if (!pk && map[n].type == LSMT_UNSIGNED) {
			pk = 1;
			continue;
		}
		if (map[n].type == LSMT_BLOB_PTR)
			continue;

		if (ls_sq3_bind_col(pdb, stmt, col++, stb + map[n].ofs, &map[n]))
			goto bail_stmt;
	}

	if (ls_sq3_step_finalize(pdb, stmt, sql))
		goto bail;

	free(sql);

	return 0;

bail_stmt:
	sqlite3_finalize(stmt);
bail:
	free(sql);

	return -1;
}

int
lws_struct_sq3_serialize(sqlite3 *pdb, const lws_struct_map_t *schema,
			 lws_dll2_owner_t *owner, uint32_t manual_idx)
{
	uint32_t idx = manual_idx;

	lws_start_foreach_dll(struct lws_dll2 *, p, lws_dll2_get_head(owner)) {
		void *item = (void *)((uint8_t *)p - schema->ofs_clist);
		if (_lws_struct_sq3_ser_one(pdb, schema, idx++, item))
			return 1;

	} lws_end_foreach_dll(p);

	return 0;
}

/*
 * Is map[i] a column update / upsert writes?  Not the primary key, nor a
 * blob, nor, when where_col is given, the column that selects the row.
 */

static int
ls_sq3_writes_col(const lws_struct_map_t *map, size_t i, const char *where_col)
{
	if (map[i].json_only || map[i].type == LSMT_BLOB_PTR ||
	    (i == 0 && map[i].type == LSMT_UNSIGNED))
		return 0;

	return !where_col || strcmp(map[i].colname, where_col);
}

/*
 * UPDATE ... SET ... WHERE
 */

int
lws_struct_sq3_update(sqlite3 *pdb, const char *table,
		      const lws_struct_map_t *map, size_t map_entries, const void *data,
		      const char *where_col)
{
	size_t i, len, wi = map_entries;
	char *q, *p, *end, subsequent = 0;
	sqlite3_stmt *st;
	int col;

	for (i = 0; i < map_entries; i++)
		if (!map[i].json_only && !strcmp(map[i].colname, where_col)) {
			wi = i;
			break;
		}

	if (wi == map_entries) {
		lwsl_err("%s: no member for where column %s\n", __func__,
			 where_col);

		return 1;
	}

	len = ls_sq3_sql_len(table, map, map_entries, where_col);
	q = malloc(len);
	if (!q)
		return 1;

	p = q;
	end = q + len;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "UPDATE %s SET ", table);

	for (i = 0; i < map_entries; i++) {
		if (!ls_sq3_writes_col(map, i, where_col))
			continue;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s%s=?",
				  subsequent ? "," : "", map[i].colname);
		subsequent = 1;
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), " WHERE %s=?;",
			  where_col);

	/*
	 * It was sized to fit, but lws_snprintf() saturates p at end when it
	 * truncates, and a statement cut short before its WHERE can still be
	 * valid SQL: an UPDATE that applies to every row in the table.
	 */

	if (p >= end - 1 || !subsequent) {
		lwsl_err("%s: statement too long or nothing to set\n", __func__);
		goto bail;
	}

	if (ls_sq3_prepare(pdb, q, &st))
		goto bail;

	col = 1;
	for (i = 0; i < map_entries; i++) {
		if (!ls_sq3_writes_col(map, i, where_col))
			continue;

		if (ls_sq3_bind_col(pdb, st, col++,
				    (const uint8_t *)data + map[i].ofs, &map[i]))
			goto bail_st;
	}

	if (ls_sq3_bind_col(pdb, st, col, (const uint8_t *)data + map[wi].ofs,
			    &map[wi]))
		goto bail_st;

	if (ls_sq3_step_finalize(pdb, st, q))
		goto bail;

	free(q);

	return sqlite3_changes(pdb) == 0;

bail_st:
	sqlite3_finalize(st);
bail:
	free(q);

	return 1;
}

/*
 * INSERT ... ON CONFLICT DO UPDATE
 */

int
lws_struct_sq3_upsert(sqlite3 *pdb, const char *table,
		      const lws_struct_map_t *map, size_t map_entries, const void *data,
		      const char *where_col)
{
	char *q, *p, *end, subsequent = 0;
	sqlite3_stmt *st;
	size_t i, len;
	int col;

	len = ls_sq3_sql_len(table, map, map_entries, where_col);
	q = malloc(len);
	if (!q)
		return 1;

	p = q;
	end = q + len;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "INSERT INTO %s (", table);

	for (i = 0; i < map_entries; i++) {
		if (!ls_sq3_writes_col(map, i, NULL))
			continue;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s%s",
				  subsequent ? "," : "", map[i].colname);
		subsequent = 1;
	}

	if (!subsequent) {
		lwsl_err("%s: no columns to insert\n", __func__);
		goto bail;
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ") VALUES (");
	subsequent = 0;

	for (i = 0; i < map_entries; i++) {
		if (!ls_sq3_writes_col(map, i, NULL))
			continue;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s?",
				  subsequent ? "," : "");
		subsequent = 1;
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  ") ON CONFLICT(%s) DO ", where_col);
	subsequent = 0;

	/*
	 * On conflict, the row takes the values we tried to insert, apart
	 * from the conflict column itself.  "excluded" is the row that was
	 * refused, so the values are bound only once.
	 */

	for (i = 0; i < map_entries; i++) {
		if (!ls_sq3_writes_col(map, i, where_col))
			continue;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  "%s%s=excluded.%s",
				  subsequent ? "," : "UPDATE SET ",
				  map[i].colname, map[i].colname);
		subsequent = 1;
	}

	if (!subsequent)
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "NOTHING");

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ";");

	/* same truncation hazard as lws_struct_sq3_update() above */

	if (p >= end - 1) {
		lwsl_err("%s: statement too long for buffer\n", __func__);
		goto bail;
	}

	if (ls_sq3_prepare(pdb, q, &st))
		goto bail;

	col = 1;
	for (i = 0; i < map_entries; i++) {
		if (!ls_sq3_writes_col(map, i, NULL))
			continue;

		if (ls_sq3_bind_col(pdb, st, col++,
				    (const uint8_t *)data + map[i].ofs, &map[i])) {
			sqlite3_finalize(st);
			goto bail;
		}
	}

	if (ls_sq3_step_finalize(pdb, st, q))
		goto bail;

	free(q);

	return 0;

bail:
	free(q);

	return 1;
}

int
lws_struct_sq3_create_table(sqlite3 *pdb, const lws_struct_map_t *schema)
{
	const lws_struct_map_t *map = schema->child_map;
	int map_size = (int)(ssize_t)schema->child_map_size, subsequent = 0;
	char s[2048], *p = s, *end = &s[sizeof(s) - 1],
	     *pri = " primary key autoincrement", *use;
	int pk_done = 0;

	p += lws_snprintf(p, (unsigned int)lws_ptr_diff(end, p),
			  /* The _lws_idx is for ordering, not a real key */
			  "create table if not exists %s (_lws_idx integer, ",
			  schema->colname);

	while (map_size--) {
		if (map->json_only ||
		    (map->type > LSMT_STRING_PTR && map->type != LSMT_BLOB_PTR)) {
			map++;
			continue;
		}
		if (subsequent && (end - p) > 4) {
			*p++ = ',';
			*p++ = ' ';
		}
		subsequent = 1;
		if (map->type == LSMT_BLOB_PTR) {

			p += lws_snprintf(p, (unsigned int)lws_ptr_diff(end, p), "%s blob", map->colname);

		} else {
			if (map->type < LSMT_STRING_CHAR_ARRAY) {
				/* This is an integer-type column */
				use = "";
				if (!pk_done) {
					use = pri;
					pk_done = 1;
				}
				p += lws_snprintf(p, (unsigned int)lws_ptr_diff(end, p), "%s integer%s",
						map->colname, use);
			} else
				p += lws_snprintf(p, (unsigned int)lws_ptr_diff(end, p), "%s varchar",
						map->colname);
		}
		map++;
	}

	p += lws_snprintf(p, (unsigned int)lws_ptr_diff(end, p), ");");

	if (sqlite3_exec(pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s: fail: %s\n", __func__, sqlite3_errmsg(pdb), s);

		return -1;
	}

	/* Ensure the UNIQUE constraint for upserts exists */
	p = s;
	p += lws_snprintf(p, (unsigned int)lws_ptr_diff(end, p),
		"CREATE UNIQUE INDEX IF NOT EXISTS name_idx ON %s (name)",
		schema->colname);
	sqlite3_exec(pdb, s, NULL, NULL, NULL);

	return 0;
}

int
lws_struct_sq3_open(struct lws_context *context, const char *sqlite3_path,
		    char create_if_missing, sqlite3 **pdb)
{
#if !defined(WIN32)
	uid_t uid = 0;
	gid_t gid = 0;
#endif

	if (sqlite3_open_v2(sqlite3_path, pdb,
			    SQLITE_OPEN_READWRITE |
			    (create_if_missing ? SQLITE_OPEN_CREATE : 0),
			    NULL) != SQLITE_OK) {
		lwsl_info("%s: Unable to open db %s: %s\n",
			 __func__, sqlite3_path, sqlite3_errmsg(*pdb));

		return 1;
	}

#if !defined(WIN32)
	lws_get_effective_uid_gid(context, &uid, &gid);
	if (uid)
		if (chown(sqlite3_path, uid, gid))
			lwsl_err("%s: failed to chown %s\n", __func__, sqlite3_path);
	if (chmod(sqlite3_path, 0600))
		lwsl_err("%s: failed to chmod %s\n", __func__, sqlite3_path);

	lwsl_debug("%s: created %s owned by %u:%u mode 0600\n", __func__,
			sqlite3_path, (unsigned int)uid, (unsigned int)gid);
#else
	lwsl_debug("%s: created %s\n", __func__, sqlite3_path);
#endif
	sqlite3_extended_result_codes(*pdb, 1);

	return 0;
}

int
lws_struct_sq3_close(sqlite3 **pdb)
{
	int n;

	if (!*pdb)
		return 0;

	n = sqlite3_close(*pdb);
	if (n != SQLITE_OK) {
		/*
		 * trouble...
		 */
		lwsl_err("%s: failed to close: %d\n", __func__, n);
		return 1;
	}
	*pdb = NULL;

	return 0;
}
