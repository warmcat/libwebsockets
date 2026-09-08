/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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

#include <assert.h>

/*
 * Drop any collated string chunks.  Nothing outside this file owns the
 * ac_chunks lwsac, so it has to be released whenever we are done with the
 * pending chunks: after every consumed value, and again when the parse ends
 * (a document truncated in the middle of a string value leaves chunks on the
 * list, and the callers only ever lwsac_free() args->ac).
 */

static void
lws_struct_args_chunks_free(lws_struct_args_t *args)
{
	lwsac_free(&args->ac_chunks);
	lws_dll2_owner_clear(&args->chunks_owner);
	args->chunks_length = 0;
}

signed char
lws_struct_schema_only_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	lws_struct_args_t *a = (lws_struct_args_t *)ctx->user;
	const lws_struct_map_t *map = a->map_st[ctx->pst_sp];
	size_t n = a->map_entries_st[ctx->pst_sp], imp = 0;
	lejp_callback cb = map->lejp_cb;
	void *v;

	if (reason == LEJPCB_COMPLETE || reason == LEJPCB_FAILED ||
	    reason == LEJPCB_DESTRUCTED) {
		lws_struct_args_chunks_free(a);

		return 0;
	}

	if (reason == LEJPCB_PAIR_NAME && strcmp(ctx->path, "schema")) {
		/*
		 * If not "schema", the schema is implicit rather than
		 * explicitly given, ie, he just goes ahead and starts using
		 * member names that imply a particular type.  For example, he
		 * may have an implicit type normally, and a different one for
		 * exceptions that just starts using "error-message" or whatever
		 * and we can understand that's the exception type now.
		 *
		 * Let's look into each of the maps in the top level array
		 * and match the first one that mentions the name he gave here,
		 * and bind to the associated type / create a toplevel object
		 * of that type.
		 */

		while (n--) {
			int m, child_members = (int)map->child_map_size;

			for (m = 0; m < child_members; m++) {
				const lws_struct_map_t *child = &map->child_map[m];
				if (!strcmp(ctx->path, child->colname)) {
					/*
					 * We matched on him... map is pointing
					 * to the right toplevel type, let's
					 * just pick up from there as if we
					 * matched the explicit schema name...
					 */
					ctx->path_match = 1;
					imp = 1;
					goto matched;
				}
			}
			map++;
		}
		lwsl_notice("%s: can't match implicit schema %s\n",
			    __func__, ctx->path);

		return -1;
	}

	if (reason != LEJPCB_VAL_STR_END || ctx->path_match != 1)
		return 0;

	/* If "schema", then look for a matching name in the map array */

	while (n--) {
		if (strcmp(ctx->buf, map->colname)) {
			map++;
			continue;
		}

matched:

		v = lwsac_use_zero(&a->ac, map->aux, a->ac_block_size);
		if (!v) {
			lwsl_err("%s: OOT\n", __func__);

			return 1;
		}
		if (!a->dest) {
			a->dest = v;
			a->dest_len = map->aux;

			a->top_schema_index = (int)(map - a->map_st[ctx->pst_sp]);
		}
		if (!cb)
			cb = lws_struct_default_lejp_cb;

		lejp_parser_push(ctx, v, &map->child_map[0].colname,
				 (uint8_t)map->child_map_size, cb);
		a->map_st[ctx->pst_sp] = map->child_map;
		a->map_entries_st[ctx->pst_sp] = map->child_map_size;

		if (imp)
			return cb(ctx, reason);

		return 0;
	}

	lwsl_notice("%s: unknown schema %s\n", __func__, ctx->buf);

	return 1;
}

static int
lws_struct_lejp_push(struct lejp_ctx *ctx, lws_struct_args_t *args,
		     const lws_struct_map_t *map, uint8_t *ch)
{
	lejp_callback cb = map->lejp_cb;

	if (!cb)
		cb = lws_struct_default_lejp_cb;

	/*
	 * If the parsing stack is full, lejp_parser_push() fails without
	 * changing ctx->pst_sp.  We must not then bind the child map over the
	 * current level's entry: ctx->pst[] would still be matching against
	 * the parent's paths while map_st[] pointed at the (possibly shorter)
	 * child map, and ctx->path_match - 1 could index past its end.
	 */

	if (lejp_parser_push(ctx, ch, (const char * const*)map->child_map,
			     (uint8_t)map->child_map_size, cb)) {
		lwsl_err("%s: parsing stack overflow at '%s'\n", __func__,
			 map->colname);

		return 1;
	}

	args->map_st[ctx->pst_sp] = map->child_map;
	args->map_entries_st[ctx->pst_sp] = map->child_map_size;

	return 0;
}

signed char
lws_struct_default_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	lws_struct_args_t *args = (lws_struct_args_t *)ctx->user;
	const lws_struct_map_t *map, *pmap = NULL;
	uint8_t *ch;
	size_t n;
	char *u;

	if (reason == LEJPCB_ARRAY_END)
		return 0;

	if (reason == LEJPCB_COMPLETE || reason == LEJPCB_FAILED ||
	    reason == LEJPCB_DESTRUCTED) {
		lws_struct_args_chunks_free(args);

		return 0;
	}

	if (reason == LEJPCB_ARRAY_START) {
		if (!ctx->path_match) {
			lwsl_info("%s: ARRAY_START with ctx->path_match 0\n", __func__);
			return 0;
		}
		map = &args->map_st[ctx->pst_sp][ctx->path_match - 1];

		if (map->type == LSMT_LIST &&
		    lws_struct_lejp_push(ctx, args, map, NULL))
			return 1;

		return 0;
	}

	if (ctx->pst_sp)
		pmap = &args->map_st[ctx->pst_sp - 1]
	                 [ctx->pst[ctx->pst_sp - 1].path_match - 1];

	if (reason == LEJPCB_OBJECT_START) {

		if (!ctx->path_match) {
			ctx->pst[ctx->pst_sp].user = NULL;

			return 0;
		}

		map = &args->map_st[ctx->pst_sp][ctx->path_match - 1];
		n = args->map_entries_st[ctx->pst_sp];

		if (map->type != LSMT_CHILD_PTR && map->type != LSMT_LIST) {
			ctx->pst[ctx->pst_sp].user = NULL;

			return 0;
		}
		pmap = map;

		if (lws_struct_lejp_push(ctx, args, map, NULL))
			return 1;
	}

	if (reason == LEJPCB_OBJECT_END && pmap) {
		if (pmap->type == LSMT_CHILD_PTR)
			lejp_parser_pop(ctx);

		if (ctx->pst_sp)
			pmap = &args->map_st[ctx->pst_sp - 1]
		                 [ctx->pst[ctx->pst_sp - 1].path_match - 1];
	}

	if (!ctx->path_match)
		return 0;

	map = &args->map_st[ctx->pst_sp][ctx->path_match - 1];
	n = args->map_entries_st[ctx->pst_sp];

	if (map->type == LSMT_SCHEMA) {

		/*
		 * Only the *value* names the schema, and ctx->buf / ctx->npos
		 * are only meaningful for it at VAL_STR_END (lejp NUL-
		 * terminates ctx->buf there).  We used to arrive here for any
		 * reason and strncmp() against a stale ctx->npos, which at
		 * PAIR_NAME time is typically 0 -- and strncmp(a, b, 0) is 0,
		 * so the first schema in the array was selected whatever the
		 * document actually said.  Compare the whole name.
		 */

		if (reason != LEJPCB_VAL_STR_END)
			return 0;

		while (n--) {
			if (strcmp(map->colname, ctx->buf)) {
				map++;
				continue;
			}

			/* instantiate the correct toplevel object */

			ch = lwsac_use_zero(&args->ac, map->aux,
					    args->ac_block_size);
			if (!ch) {
				lwsl_err("OOM\n");

				return 1;
			}

			if (lws_struct_lejp_push(ctx, args, map, ch))
				return 1;

			return 0;
		}
		lwsl_notice("%s: unknown schema %.*s, tried %d\n", __func__,
				ctx->npos, ctx->buf,
				(int)args->map_entries_st[ctx->pst_sp]);

		goto cleanup;
	}

	if (!ctx->pst[ctx->pst_sp].user) {
		struct lws_dll2_owner *owner;
		struct lws_dll2 *list;

		/* create list item object if none already */

		if (!ctx->path_match || !pmap)
			return 0;

		if (!ctx->pst_sp)
			return 0;

		map = &args->map_st[ctx->pst_sp - 1][ctx->path_match - 1];
		n = args->map_entries_st[ctx->pst_sp - 1];

		if (pmap->type != LSMT_LIST && pmap->type != LSMT_CHILD_PTR)
			return 1;

		/* we need to create a child or array item object */

		owner = (struct lws_dll2_owner *)
			(((char *)ctx->pst[ctx->pst_sp - 1].user) + pmap->ofs);

		assert(pmap->aux);

		/* instantiate one of the child objects */

		ctx->pst[ctx->pst_sp].user = lwsac_use_zero(&args->ac,
						pmap->aux, args->ac_block_size);
		if (!ctx->pst[ctx->pst_sp].user) {
			lwsl_err("OOM\n");

			return 1;
		}
		lwsl_info("%s: created '%s' object size %d\n", __func__,
				pmap->colname, (int)pmap->aux);

		switch (pmap->type) {
		case LSMT_LIST:
			list = (struct lws_dll2 *)
				 ((char *)ctx->pst[ctx->pst_sp].user +
				 pmap->ofs_clist);

			lws_dll2_add_tail(list, owner);
			break;
		case LSMT_CHILD_PTR:
			*((void **)owner) = ctx->pst[ctx->pst_sp].user;
			break;
		default:
			assert(0);
			break;
		}
	}

	if (!ctx->path_match)
		return 0;

	if (reason == LEJPCB_VAL_STR_CHUNK || reason == LEJPCB_VAL_STR_END) {
		lejp_collation_t *coll;

		/* don't cache stuff we are going to ignore */

		if (map->type != LSMT_STRING_CHAR_ARRAY ||
		    args->chunks_length < map->aux) {
			coll = lwsac_use_zero(&args->ac_chunks, sizeof(*coll),
					      sizeof(*coll));
			if (!coll) {
				lwsl_err("%s: OOT\n", __func__);

				return 1;
			}
			lws_dll2_clear(&coll->chunks);

			coll->len = ctx->npos;
			lws_dll2_add_tail(&coll->chunks, &args->chunks_owner);

			memcpy(coll->buf, ctx->buf, ctx->npos);

			args->chunks_length += ctx->npos;
		}
		if (reason == LEJPCB_VAL_STR_CHUNK)
			return 0;

		ctx->npos = 0;
	}

	if (reason != LEJPCB_VAL_STR_END && reason != LEJPCB_VAL_NUM_INT &&
	    reason != LEJPCB_VAL_TRUE && reason != LEJPCB_VAL_FALSE)
		return 0;

	/* this is the end of the string */

	if (ctx->pst[ctx->pst_sp].user && pmap && pmap->type == LSMT_CHILD_PTR) {
		void **pp = (void **)
			(((char *)ctx->pst[ctx->pst_sp - 1].user) + pmap->ofs);

		*pp = ctx->pst[ctx->pst_sp].user;
	}

	u = (char *)ctx->pst[ctx->pst_sp].user;
	if (!u)
		u = (char *)ctx->pst[ctx->pst_sp - 1].user;

	{
		char **pp, *s;
		size_t lim, b;
		long long li;

		switch (map->type) {
		case LSMT_SIGNED:
			/*
			 * These have to be selected on the member's real width
			 * (map->aux is sizeof(member)).  There was no 2-byte
			 * arm and the final else was unguarded, so a 16-bit
			 * member was written with an 8-byte store, 6 bytes past
			 * its end.  An unrecognized width is now a hard fail.
			 */
			if (map->aux == sizeof(signed char)) {
				signed char *pc;
				pc = (signed char *)(u + map->ofs);
				*pc = (signed char)atoi(ctx->buf);
				break;
			}
			if (map->aux == sizeof(short)) {
				short *ps;
				ps = (short *)(u + map->ofs);
				*ps = (short)atoi(ctx->buf);
				break;
			}
			if (map->aux == sizeof(int)) {
				int *pi;
				pi = (int *)(u + map->ofs);
				*pi = atoi(ctx->buf);
				break;
			}
			if (map->aux == sizeof(long)) {
				long *pl;
				pl = (long *)(u + map->ofs);
				*pl = atol(ctx->buf);
				break;
			}
			if (map->aux == sizeof(long long)) {
				long long *pll;
				pll = (long long *)(u + map->ofs);
				*pll = atoll(ctx->buf);
				break;
			}
			goto bad_width;

		case LSMT_UNSIGNED:
			/* see the note on member widths above */
			if (map->aux == sizeof(unsigned char)) {
				unsigned char *pc;
				pc = (unsigned char *)(u + map->ofs);
				*pc = (unsigned char)(unsigned int)atoi(ctx->buf);
				break;
			}
			if (map->aux == sizeof(unsigned short)) {
				unsigned short *ps;
				ps = (unsigned short *)(u + map->ofs);
				*ps = (unsigned short)(unsigned long)atol(ctx->buf);
				break;
			}
			if (map->aux == sizeof(unsigned int)) {
				unsigned int *pi;
				pi = (unsigned int *)(u + map->ofs);
				*pi = (unsigned int)atoi(ctx->buf);
				break;
			}
			if (map->aux == sizeof(unsigned long)) {
				unsigned long *pl;
				pl = (unsigned long *)(u + map->ofs);
				*pl = (unsigned long)atol(ctx->buf);
				break;
			}
			if (map->aux == sizeof(unsigned long long)) {
				unsigned long long *pll;
				pll = (unsigned long long *)(u + map->ofs);
				*pll = (unsigned long long)atoll(ctx->buf);
				break;
			}
			goto bad_width;

		case LSMT_BOOLEAN:
			/* see the note on member widths above */
			li = reason == LEJPCB_VAL_TRUE;
			if (map->aux == sizeof(char)) {
				char *pc;
				pc = (char *)(u + map->ofs);
				*pc = (char)li;
				break;
			}
			if (map->aux == sizeof(short)) {
				short *ps;
				ps = (short *)(u + map->ofs);
				*ps = (short)li;
				break;
			}
			if (map->aux == sizeof(int)) {
				int *pi;
				pi = (int *)(u + map->ofs);
				*pi = (int)li;
				break;
			}
			if (map->aux == sizeof(uint64_t)) {
				uint64_t *p64;
				p64 = (uint64_t *)(u + map->ofs);
				*p64 = (uint64_t)li;
				break;
			}
			goto bad_width;

		case LSMT_STRING_CHAR_ARRAY:
			s = (char *)(u + map->ofs);
			lim = map->aux - 1;
			goto chunk_copy_l;

		case LSMT_STRING_PTR:
			pp = (char **)(u + map->ofs);
			lim = args->chunks_length + ctx->npos;
			s = lwsac_use(&args->ac, lim + 1, args->ac_block_size);
			if (!s)
				goto cleanup;
			*pp = s;

chunk_copy_l:
			s[lim] = '\0';
			/* copy up to lim from the string chunk ac first */
			lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
						lws_dll2_get_head(&args->chunks_owner)) {
				lejp_collation_t *coll = (lejp_collation_t *)p;

				if (lim) {
					b = (unsigned int)coll->len;
					if (b > lim)
						b = lim;
					memcpy(s, coll->buf, b);
					s += b;
					lim -= b;
				}
			} lws_end_foreach_dll_safe(p, p1);

			if (lim) {
				b = ctx->npos;
				if (b > lim)
					b = lim;
				memcpy(s, ctx->buf, b);
				s[b] = '\0';
			}
			break;
		default:
			break;
		}
	}

	/*
	 * The value is consumed... drop any collated string chunks
	 * unconditionally.  Only the two string cases used to clear them, so
	 * a string value landing on eg an LSMT_UNSIGNED member left its bytes
	 * on the list to be silently prepended to the *next* string member's
	 * value.
	 */

	lws_struct_args_chunks_free(args);

	if (args->cb)
		args->cb(args->dest, args->cb_arg);

	return 0;

bad_width:
	lwsl_err("%s: '%s': bad member width %d\n", __func__, map->colname,
		 (int)map->aux);

cleanup:
	lwsl_notice("%s: cleanup\n", __func__);
	lws_struct_args_chunks_free(args);

	return 1;
}

static const char * schema[] = { "schema" };

int
lws_struct_json_init_parse(struct lejp_ctx *ctx, lejp_callback cb, void *user)
{
	/*
	 * By default we are looking to match on a toplevel member called
	 * "schema", against an LSM_SCHEMA
	 */
	if (!cb)
		cb = lws_struct_schema_only_lejp_cb;
	lejp_construct(ctx, cb, user, schema, 1);

	ctx->path_stride = sizeof(lws_struct_map_t);

	return 0;
}

lws_struct_serialize_t *
lws_struct_json_serialize_create(const lws_struct_map_t *map,
				 size_t map_entries, int flags,
				 const void *ptoplevel)
{
	lws_struct_serialize_t *js = lws_zalloc(sizeof(*js), __func__);
	lws_struct_serialize_st_t *j;

	if (!js)
		return NULL;

	js->flags = flags;

	j = &js->st[0];
	j->map = map;
	j->map_entries = map_entries;
	j->obj = ptoplevel;
	j->idt = 0;

	return js;
}

void
lws_struct_json_serialize_destroy(lws_struct_serialize_t **pjs)
{
	if (!*pjs)
		return;

	lws_free(*pjs);

	*pjs = NULL;
}

/*
 * Returns nonzero (and writes nothing) if the indent does not fit in what is
 * left of the caller's buffer.  One byte is always kept spare for the NUL we
 * write after the official end.
 */

static int
lws_struct_pretty(lws_struct_serialize_t *js, uint8_t **pbuf, size_t *plen)
{
	if (js->flags & LSSERJ_FLAG_PRETTY) {
		int n, idt = js->st[js->sp].idt;

		if (idt < 0)
			idt = 0;

		if (*plen < (size_t)idt + 2)
			return 1;

		*(*pbuf)++ = '\n';
		(*plen)--;
		for (n = 0; n < idt; n++) {
			*(*pbuf)++ = ' ';
			(*plen)--;
		}
	}

	return 0;
}

/*
 * Emit one byte, keeping one byte spare for the NUL we always write after the
 * official end.  `len` is a size_t and these stores used to be unguarded: a
 * string that consumed the loop's headroom exactly could take len to 0 and
 * then wrap it to SIZE_MAX during the check_up: unwinding, after which the
 * emit loop happily continued past the end of the caller's buffer.  There is
 * no way to resume from a half-emitted structural token, so fail closed.
 */

#define ser_emit(_c) \
	do { \
		if (len < 2) \
			return LSJS_RESULT_ERROR; \
		*buf++ = (uint8_t)(_c); \
		len--; \
	} while (0)

lws_struct_json_serialize_result_t
lws_struct_json_serialize(lws_struct_serialize_t *js, uint8_t *buf,
			  size_t len, size_t *written)
{
	lws_struct_serialize_st_t *j;
	const lws_struct_map_t *map;
	size_t budget = 0, olen = len, m;
	struct lws_dll2_owner *o;
	unsigned long long uli;
	char dbuf[72] = {};
	const char *q;
	const void *p;
	long long li;
	int n, used = 0;

	*written = 0;

	if (!len) /* we always write a NUL at *buf */
		return LSJS_RESULT_ERROR;

	*buf = '\0';

	while (len > sizeof(dbuf) + 20) {
		int do_up = 0;
		j = &js->st[js->sp];
		map = &j->map[j->map_entry];
		q = j->obj + map->ofs;

		/* early check if the entry should be elided */
		switch (map->type) {
		case LSMT_STRING_CHAR_ARRAY:
			break;
		case LSMT_STRING_PTR:
		case LSMT_CHILD_PTR:
			q = (char *)*(char **)q;
			if (!q) {
				do_up = 1;
				goto check_up;
			}
			break;

		case LSMT_LIST:
			o = (struct lws_dll2_owner *)q;
			p = j->dllpos = lws_dll2_get_head(o);
			if (!p) {
				do_up = 1;
				goto check_up;
			}
			break;

		case LSMT_BLOB_PTR:
			do_up = 1;
			goto check_up;

		default:
			break;
		}

		if (j->subsequent && !js->offset) {
			ser_emit(',');
			if (lws_struct_pretty(js, &buf, &len))
				return LSJS_RESULT_ERROR;
		}
		j->subsequent = 1;

		if (map->type != LSMT_SCHEMA && !js->offset) {
			n = lws_snprintf((char *)buf, len, "\"%s\":",
					    map->colname);
			/*
			 * lws_snprintf() returns the size it was given when it
			 * truncated, so a long colname can consume the whole
			 * remaining buffer here
			 */
			if ((size_t)n + 1 >= len)
				return LSJS_RESULT_ERROR;
			buf += n;
			len = len - (unsigned int)n;
			if (js->flags & LSSERJ_FLAG_PRETTY) {
				ser_emit(' ');
			}
		}

		switch (map->type) {
		case LSMT_BOOLEAN:
		case LSMT_UNSIGNED:
			/*
			 * Take the member's real width... a 2-byte member used
			 * to fall through to the unsigned long long arm and be
			 * read 8 bytes wide.  Anything we don't recognize is a
			 * hard fail, not a widened access.
			 */
			if (map->aux == sizeof(char))
				uli = *(unsigned char *)q;
			else if (map->aux == sizeof(unsigned short))
				uli = *(unsigned short *)q;
			else if (map->aux == sizeof(unsigned int))
				uli = *(unsigned int *)q;
			else if (map->aux == sizeof(unsigned long))
				uli = *(unsigned long *)q;
			else if (map->aux == sizeof(unsigned long long))
				uli = *(unsigned long long *)q;
			else {
				lwsl_err("%s: '%s': bad member width %d\n",
					 __func__, map->colname, (int)map->aux);

				return LSJS_RESULT_ERROR;
			}
			q = dbuf;

			if (map->type == LSMT_BOOLEAN) {
				budget = (unsigned int)lws_snprintf(dbuf, sizeof(dbuf),
						"%s", uli ? "true" : "false");
			} else
				budget = (unsigned int)lws_snprintf(dbuf, sizeof(dbuf),
						      "%llu", uli);
			break;

		case LSMT_SIGNED:
			/* see the note on member widths above */
			if (map->aux == sizeof(signed char))
				li = (long long)*(signed char *)q;
			else if (map->aux == sizeof(short))
				li = (long long)*(short *)q;
			else if (map->aux == sizeof(int))
				li = (long long)*(int *)q;
			else if (map->aux == sizeof(long))
				li = (long long)*(long *)q;
			else if (map->aux == sizeof(long long))
				li = *(long long *)q;
			else {
				lwsl_err("%s: '%s': bad member width %d\n",
					 __func__, map->colname, (int)map->aux);

				return LSJS_RESULT_ERROR;
			}
			q = dbuf;
			budget = (unsigned int)lws_snprintf(dbuf, sizeof(dbuf), "%lld", li);
			break;

		case LSMT_STRING_CHAR_ARRAY:
		case LSMT_STRING_PTR:
			if (!js->offset) {
				ser_emit('\"');
			}
			break;

		case LSMT_LIST:
			ser_emit('[');
			if (js->sp + 1 == LEJP_MAX_PARSING_STACK_DEPTH)
				return LSJS_RESULT_ERROR;

			/* add a stack level to handle parsing array members */

			o = (struct lws_dll2_owner *)q;
			p = j->dllpos = lws_dll2_get_head(o);

			if (!j->dllpos) {
				ser_emit(']');
				do_up = 1;
				goto check_up;
			}

			n = j->idt;
			j = &js->st[++js->sp];
			j->idt = (char)(n + 2);
			j->map = map->child_map;
			j->map_entries = map->child_map_size;
			j->size = map->aux;
			j->subsequent = 0;
			j->map_entry = 0;
			if (lws_struct_pretty(js, &buf, &len))
				return LSJS_RESULT_ERROR;
			ser_emit('{');
			if (lws_struct_pretty(js, &buf, &len))
				return LSJS_RESULT_ERROR;
			if (p)
				j->obj = ((char *)p) - j->map->ofs_clist;
			else
				j->obj = NULL;
			continue;

		case LSMT_CHILD_PTR:

			if (js->sp + 1 == LEJP_MAX_PARSING_STACK_DEPTH)
				return LSJS_RESULT_ERROR;

			/* add a stack level to handle parsing child members */

			n = j->idt;
			j = &js->st[++js->sp];
			j->idt = (char)(n + 2);
			j->map = map->child_map;
			j->map_entries = map->child_map_size;
			j->size = map->aux;
			j->subsequent = 0;
			j->map_entry = 0;
			ser_emit('{');
			if (lws_struct_pretty(js, &buf, &len))
				return LSJS_RESULT_ERROR;
			j->obj = q;

			continue;

		case LSMT_SCHEMA:
			q = dbuf;
			ser_emit('{');
			j = &js->st[++js->sp];
			if (lws_struct_pretty(js, &buf, &len))
				return LSJS_RESULT_ERROR;
			if (!(js->flags & LSSERJ_FLAG_OMIT_SCHEMA)) {
				budget = (unsigned int)lws_snprintf(dbuf, 15, "\"schema\":");
				if (js->flags & LSSERJ_FLAG_PRETTY)
					dbuf[budget++] = ' ';

				budget += (unsigned int)lws_snprintf(dbuf + budget,
						       sizeof(dbuf) - budget,
						       "\"%s\"", map->colname);
			}


			if (js->sp != 1)
				return LSJS_RESULT_ERROR;
			j->map = map->child_map;
			j->map_entries = map->child_map_size;
			j->size = map->aux;
			j->subsequent = 0;
			j->map_entry = 0;
			j->obj = js->st[js->sp - 1].obj;
			j->dllpos = NULL;
			if (!(js->flags & LSSERJ_FLAG_OMIT_SCHEMA))
				/* we're actually at the same level */
				j->subsequent = 1;
			j->idt = 1;
			break;
		default:
			break;
		}

		switch (map->type) {
		case LSMT_STRING_CHAR_ARRAY:
		case LSMT_STRING_PTR:
			/*
			 * This is a bit tricky... we have to escape the string
			 * which may 6x its length depending on what the
			 * contents are.
			 *
			 * We offset the unescaped string starting point first
			 */

			q += js->offset;
			budget = strlen(q); /* how much unescaped is left */

			/*
			 * This is going to escape as much as it can fit, and
			 * let us know the amount of input that was consumed
			 * in "used".
			 *
			 * A positive *in_used on entry is an input cap, so it
			 * must be cleared or it would limit this string to
			 * what was consumed of the last one
			 */

			used = 0;
			/*
			 * Hand purify one byte less than we have, so that
			 * whatever it does there is always room left for the
			 * closing quote below plus the trailing NUL; it can
			 * otherwise consume all but one byte and leave the
			 * quote to be written past the end.
			 */
			if (len < 3)
				return LSJS_RESULT_ERROR;
			lws_json_purify((char *)buf, q, (int)len - 1, &used);
			m = strlen((const char *)buf);
			buf += m;
			len -= m;
			js->remaining = budget - (unsigned int)used;
			/* js->offset is from the start of the member string */
			js->offset += (unsigned int)used;
			if (!js->remaining)
				js->offset = 0;

			break;
		default:
			q += js->offset;
			budget -= js->remaining;

			/* keep one byte spare for the NUL at *buf below */

			if (len < 2)
				return LSJS_RESULT_ERROR;

			if (budget > len - 1) {
				js->remaining = budget - (len - 1);
				js->offset = len - 1;
				budget = len - 1;
			} else {
				js->remaining = 0;
				js->offset = 0;
			}

			memcpy(buf, q, budget);
			buf += budget;
			*buf = '\0';
			len -= budget;
			break;
		}



		switch (map->type) {
		case LSMT_STRING_CHAR_ARRAY:
		case LSMT_STRING_PTR:
			if (!js->remaining) {
				ser_emit('\"');
			}
			break;
		case LSMT_SCHEMA:
			continue;
		default:
			break;
		}

		if (js->remaining)
			continue;

		do_up = 1;

check_up:
		if (do_up) {
			while (1) {
				if (++j->map_entry < j->map_entries)
					break;

				if (!js->sp)
					break;
				js->sp--;
				if (!js->sp) {
					if (lws_struct_pretty(js, &buf, &len))
						return LSJS_RESULT_ERROR;
					ser_emit('}');
					if (lws_struct_pretty(js, &buf, &len))
						return LSJS_RESULT_ERROR;

					*written = olen - len;
					*buf = '\0'; /* convenience, a NUL after the official end */

					return LSJS_RESULT_FINISH;
				}
				js->offset = 0;
				j = &js->st[js->sp];
				map = &j->map[j->map_entry];

				if (map->type == LSMT_CHILD_PTR) {
					if (lws_struct_pretty(js, &buf, &len))
						return LSJS_RESULT_ERROR;
					ser_emit('}');

					/* we have done the singular child pointer */

					js->offset = 0;
					continue;
				}

				if (map->type != LSMT_LIST)
					break;
				/*
				 * we are coming back up to an array map, it means we should
				 * advance to the next array member if there is one
				 */

				if (lws_struct_pretty(js, &buf, &len))
					return LSJS_RESULT_ERROR;
				ser_emit('}');

				j->dllpos = lws_dll2_get_next(j->dllpos);
				p = j->dllpos;
				if (j->dllpos) {
					/*
					 * there was another item in the array to do... let's
					 * move on to that and do it
					 */
					ser_emit(',');
					if (lws_struct_pretty(js, &buf, &len))
						return LSJS_RESULT_ERROR;
					js->offset = 0;
					j = &js->st[++js->sp];
					j->map_entry = 0;
					map = &j->map[j->map_entry];

					ser_emit('{');
					if (lws_struct_pretty(js, &buf, &len))
						return LSJS_RESULT_ERROR;

					j->subsequent = 0;
					j->obj = ((char *)p) - j->map->ofs_clist;
					break;
				}

				/* there are no further items in the array */

				js->offset = 0;
				if (lws_struct_pretty(js, &buf, &len))
					return LSJS_RESULT_ERROR;
				ser_emit(']');
			}
		}
	}

	*written = olen - len;
	*buf = '\0'; /* convenience, a NUL after the official end */

	return LSJS_RESULT_CONTINUE;
}

#undef ser_emit
