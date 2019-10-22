/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

signed char
lws_struct_schema_only_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	lws_struct_args_t *a = (lws_struct_args_t *)ctx->user;
	const lws_struct_map_t *map = a->map_st[ctx->pst_sp];
	size_t n = a->map_entries_st[ctx->pst_sp];
	lejp_callback cb = map->lejp_cb;

	if (reason != LEJPCB_VAL_STR_END || ctx->path_match != 1)
		return 0;

	while (n--) {
		if (strcmp(ctx->buf, map->colname)) {
			map++;
			continue;
		}

		a->dest = lwsac_use_zero(&a->ac, map->aux, a->ac_block_size);
		if (!a->dest) {
			lwsl_err("%s: OOT\n", __func__);

			return 1;
		}
		a->dest_len = map->aux;

		if (!cb)
			cb = lws_struct_default_lejp_cb;

		lejp_parser_push(ctx, a->dest, &map->child_map[0].colname,
				 (uint8_t)map->child_map_size, cb);
		a->map_st[ctx->pst_sp] = map->child_map;
		a->map_entries_st[ctx->pst_sp] = map->child_map_size;

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

	lejp_parser_push(ctx, ch, (const char * const*)map->child_map,
			 (uint8_t)map->child_map_size, cb);

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
	char *u;
	size_t n;

	if (reason == LEJPCB_ARRAY_END) {
		lejp_parser_pop(ctx);

		return 0;
	}

	if (reason == LEJPCB_ARRAY_START) {
		map = &args->map_st[ctx->pst_sp][ctx->path_match - 1];
		n = args->map_entries_st[ctx->pst_sp];

		if (map->type == LSMT_LIST)
			lws_struct_lejp_push(ctx, args, map, NULL);

		return 0;
	}

	if (ctx->pst_sp)
		pmap = &args->map_st[ctx->pst_sp - 1]
	                 [ctx->pst[ctx->pst_sp - 1].path_match - 1];
	map = &args->map_st[ctx->pst_sp][ctx->path_match - 1];
	n = args->map_entries_st[ctx->pst_sp];

	if (reason == LEJPCB_OBJECT_START) {

		if (map->type != LSMT_CHILD_PTR) {
			ctx->pst[ctx->pst_sp].user = NULL;

			return 0;
		}
		pmap = map;

		lws_struct_lejp_push(ctx, args, map, NULL);
		map = &args->map_st[ctx->pst_sp][ctx->path_match - 1];
		n = args->map_entries_st[ctx->pst_sp];
	}

	if (reason == LEJPCB_OBJECT_END && pmap && pmap->type == LSMT_CHILD_PTR)
		lejp_parser_pop(ctx);

	if (map->type == LSMT_SCHEMA) {

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

			lws_struct_lejp_push(ctx, args, map, ch);

			return 0;
		}
		lwsl_notice("%s: unknown schema\n", __func__);

		goto cleanup;
	}

	if (!ctx->pst[ctx->pst_sp].user) {
		struct lws_dll2_owner *owner;
		struct lws_dll2 *list;

		/* create list item object if none already */

		if (!ctx->path_match || !pmap)
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
		lwsl_notice("%s: created child object size %d\n", __func__,
				(int)pmap->aux);

		if (pmap->type == LSMT_LIST) {
			list = (struct lws_dll2 *)((char *)ctx->pst[ctx->pst_sp].user +
				map->ofs_clist);

			lws_dll2_add_tail(list, owner);
		}
	}

	if (!ctx->path_match)
		return 0;

	if (reason == LEJPCB_VAL_STR_CHUNK) {
		lejp_collation_t *coll;

		/* don't cache stuff we are going to ignore */

		if (map->type == LSMT_STRING_CHAR_ARRAY &&
		    args->chunks_length >= map->aux)
			return 0;

		coll = lwsac_use_zero(&args->ac_chunks, sizeof(*coll),
				      sizeof(*coll));
		if (!coll) {
			lwsl_err("%s: OOT\n", __func__);

			return 1;
		}
		coll->chunks.prev = NULL;
		coll->chunks.next = NULL;
		coll->chunks.owner = NULL;

		coll->len = ctx->npos;
		lws_dll2_add_tail(&coll->chunks, &args->chunks_owner);

		memcpy(coll->buf, ctx->buf, ctx->npos);

		args->chunks_length += ctx->npos;

		return 0;
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
			if (map->aux == sizeof(signed char)) {
				signed char *pc;
				pc = (signed char *)(u + map->ofs);
				*pc = atoi(ctx->buf);
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
			} else {
				long long *pll;
				pll = (long long *)(u + map->ofs);
				*pll = atoll(ctx->buf);
			}
			break;

		case LSMT_UNSIGNED:
			if (map->aux == sizeof(unsigned char)) {
				unsigned char *pc;
				pc = (unsigned char *)(u + map->ofs);
				*pc = atoi(ctx->buf);
				break;
			}
			if (map->aux == sizeof(unsigned int)) {
				unsigned int *pi;
				pi = (unsigned int *)(u + map->ofs);
				*pi = atoi(ctx->buf);
				break;
			}
			if (map->aux == sizeof(unsigned long)) {
				unsigned long *pl;
				pl = (unsigned long *)(u + map->ofs);
				*pl = atol(ctx->buf);
			} else {
				unsigned long long *pll;
				pll = (unsigned long long *)(u + map->ofs);
				*pll = atoll(ctx->buf);
			}
			break;

		case LSMT_BOOLEAN:
			li = reason == LEJPCB_VAL_TRUE;
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
			goto chunk_copy;

		case LSMT_STRING_PTR:
			pp = (char **)(u + map->ofs);
			lim = args->chunks_length + ctx->npos;
			s = lwsac_use(&args->ac, lim + 1, args->ac_block_size);
			if (!s)
				goto cleanup;
			*pp = s;

chunk_copy:
			s[lim] = '\0';
			/* copy up to lim from the string chunk ac first */
			lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
						args->chunks_owner.head) {
				lejp_collation_t *coll = (lejp_collation_t *)p;

				if (lim) {
					b = coll->len;
					if (b > lim)
						b = lim;
					memcpy(s, coll->buf, b);
					s += b;
					lim -= b;
				}
			} lws_end_foreach_dll_safe(p, p1);

			lwsac_free(&args->ac_chunks);
			args->chunks_owner.count = 0;
			args->chunks_owner.head = NULL;
			args->chunks_owner.tail = NULL;

			if (lim) {
				b = ctx->npos;
				if (b > lim)
					b = lim;
				memcpy(s, ctx->buf, b);
			}
			break;
		default:
			break;
		}
	}

	if (args->cb)
		args->cb(args->dest, args->cb_arg);

	return 0;

cleanup:
	lwsl_notice("%s: cleanup\n", __func__);
	lwsac_free(&args->ac_chunks);
	args->chunks_owner.count = 0;
	args->chunks_owner.head = NULL;
	args->chunks_owner.tail = NULL;

	return 1;
}

static const char * schema[] = { "schema" };

int
lws_struct_json_init_parse(struct lejp_ctx *ctx, lejp_callback cb, void *user)
{
	if (!cb)
		cb = lws_struct_schema_only_lejp_cb;
	lejp_construct(ctx, cb, user, schema, 1);

	ctx->path_stride = sizeof(lws_struct_map_t);

	return 0;
}

lws_struct_serialize_t *
lws_struct_json_serialize_create(const lws_struct_map_t *map,
				 size_t map_entries, int flags,
				 void *ptoplevel)
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

static void
lws_struct_pretty(lws_struct_serialize_t *js, uint8_t **pbuf, size_t *plen)
{
	if (js->flags & LSSERJ_FLAG_PRETTY) {
		int n;

		*(*pbuf)++ = '\n';
		(*plen)--;
		for (n = 0; n < js->st[js->sp].idt; n++) {
			*(*pbuf)++ = ' ';
			(*plen)--;
		}
	}
}

lws_struct_json_serialize_result_t
lws_struct_json_serialize(lws_struct_serialize_t *js, uint8_t *buf,
			  size_t len, size_t *written)
{
	lws_struct_serialize_st_t *j;
	const lws_struct_map_t *map;
	size_t budget = 0, olen = len;
	struct lws_dll2_owner *o;
	unsigned long long uli;
	const char *q;
	const void *p;
	char dbuf[72];
	long long li;
	int n;

	*written = 0;
	*buf = '\0';

	while (len > sizeof(dbuf) + 20) {
		j = &js->st[js->sp];
		map = &j->map[j->map_entry];
		q = j->obj + map->ofs;

		/* early check if the entry should be elided */

		switch (map->type) {
		case LSMT_STRING_PTR:
		case LSMT_CHILD_PTR:
			q = (char *)*(char **)q;
			if (!q)
				goto up;
			break;

		case LSMT_LIST:
			o = (struct lws_dll2_owner *)q;
			p = j->dllpos = lws_dll2_get_head(o);
			if (!p)
				goto up;
			break;

		default:
			break;
		}

		if (j->subsequent) {
			*buf++ = ',';
			len--;
			lws_struct_pretty(js, &buf, &len);
		}
		j->subsequent = 1;

		if (map->type != LSMT_SCHEMA && !js->offset) {
			n = lws_snprintf((char *)buf, len, "\"%s\":",
					    map->colname);
			buf += n;
			len -= n;
			if (js->flags & LSSERJ_FLAG_PRETTY) {
				*buf++ = ' ';
				len--;
			}
		}

		switch (map->type) {
		case LSMT_BOOLEAN:
		case LSMT_UNSIGNED:
			if (map->aux == sizeof(char)) {
				uli = *(unsigned char *)q;
			} else {
				if (map->aux == sizeof(int)) {
					uli = *(unsigned int *)q;
				} else {
					if (map->aux == sizeof(long))
						uli = *(unsigned long *)q;
					else
						uli = *(unsigned long long *)q;
				}
			}
			q = dbuf;

			if (map->type == LSMT_BOOLEAN) {
				budget = lws_snprintf(dbuf, sizeof(dbuf),
						"%s", uli ? "true" : "false");
			} else
				budget = lws_snprintf(dbuf, sizeof(dbuf),
						      "%llu", uli);
			break;

		case LSMT_SIGNED:
			if (map->aux == sizeof(signed char)) {
				li = (long long)*(signed char *)q;
			} else {
				if (map->aux == sizeof(int)) {
					li = (long long)*(int *)q;
				} else {
					if (map->aux == sizeof(long))
						li = (long long)*(long *)q;
					else
						li = *(long long *)q;
				}
			}
			q = dbuf;
			budget = lws_snprintf(dbuf, sizeof(dbuf), "%lld", li);
			break;

		case LSMT_STRING_CHAR_ARRAY:
			budget = strlen(q);
			if (!js->offset) {
				*buf++ = '\"';
				len--;
			}
			break;

		case LSMT_STRING_PTR:
			budget = strlen(q);
			if (!js->offset) {
				*buf++ = '\"';
				len--;
			}
			break;
		case LSMT_LIST:
			*buf++ = '[';
			len--;
			if (js->sp + 1 == LEJP_MAX_PARSING_STACK_DEPTH)
				return LSJS_RESULT_ERROR;

			/* add a stack level to handle parsing array members */

			o = (struct lws_dll2_owner *)q;
			p = j->dllpos = lws_dll2_get_head(o);

			if (!j->dllpos) {
				*buf++ = ']';
				len--;
				goto up;
			}

			n = j->idt;
			j = &js->st[++js->sp];
			j->idt = n + 2;
			j->map = map->child_map;
			j->map_entries = map->child_map_size;
			j->size = map->aux;
			j->subsequent = 0;
			j->map_entry = 0;
			lws_struct_pretty(js, &buf, &len);
			*buf++ = '{';
			len--;
			lws_struct_pretty(js, &buf, &len);
			if (p)
				j->obj = ((char *)p) - j->map->ofs_clist;
			else
				j->obj = NULL;
			continue;

		case LSMT_CHILD_PTR:

			if (js->sp + 1 == LEJP_MAX_PARSING_STACK_DEPTH)
				return LSJS_RESULT_ERROR;

			/* add a stack level tto handle parsing child members */

			n = j->idt;
			j = &js->st[++js->sp];
			j->idt = n + 2;
			j->map = map->child_map;
			j->map_entries = map->child_map_size;
			j->size = map->aux;
			j->subsequent = 0;
			j->map_entry = 0;
			*buf++ = '{';
			len--;
			lws_struct_pretty(js, &buf, &len);
			j->obj = q;
			continue;

		case LSMT_SCHEMA:
			q = dbuf;
			*buf++ = '{';
			len--;
			j = &js->st[++js->sp];
			lws_struct_pretty(js, &buf, &len);
			budget = lws_snprintf(dbuf, 15, "\"schema\":");
			if (js->flags & LSSERJ_FLAG_PRETTY)
				dbuf[budget++] = ' ';

			budget += lws_snprintf(dbuf + budget,
					       sizeof(dbuf) - budget,
					      "\"%s\"", map->colname);


			if (js->sp != 1)
				return LSJS_RESULT_ERROR;
			j->map = map->child_map;
			j->map_entries = map->child_map_size;
			j->size = map->aux;
			j->subsequent = 0;
			j->map_entry = 0;
			j->obj = js->st[js->sp - 1].obj;
			j->dllpos = NULL;
			/* we're actually at the same level */
			j->subsequent = 1;
			j->idt = 1;
			break;
		}

		q += js->offset;
		budget -= js->remaining;

		if (budget > len) {
			js->remaining = budget - len;
			js->offset = len;
			budget = len;
		} else {
			js->remaining = 0;
			js->offset = 0;
		}

		memcpy(buf, q, budget);
		buf += budget;
		*buf = '\0';
		len -= budget;

		switch (map->type) {
		case LSMT_STRING_CHAR_ARRAY:
		case LSMT_STRING_PTR:
			*buf++ = '\"';
			len--;
			break;
		case LSMT_SCHEMA:
			continue;
		default:
			break;
		}

		if (js->remaining)
			continue;
up:
		if (++j->map_entry < j->map_entries)
			continue;

		if (!js->sp)
			continue;
		js->sp--;
		if (!js->sp) {
			lws_struct_pretty(js, &buf, &len);
			*buf++ = '}';
			len--;
			lws_struct_pretty(js, &buf, &len);
			break;
		}
		js->offset = 0;
		j = &js->st[js->sp];
		map = &j->map[j->map_entry];

		if (map->type == LSMT_CHILD_PTR) {
			lws_struct_pretty(js, &buf, &len);
			*buf++ = '}';
			len--;

			/* we have done the singular child pointer */

			js->offset = 0;
			goto up;
		}

		if (map->type != LSMT_LIST)
			continue;
		/*
		 * we are coming back up to an array map, it means we should
		 * advance to the next array member if there is one
		 */

		lws_struct_pretty(js, &buf, &len);
		*buf++ = '}';
		len--;

		p = j->dllpos = j->dllpos->next;
		if (j->dllpos) {
			/*
			 * there was another item in the array to do... let's
			 * move on to that nd do it
			 */
			*buf++ = ',';
			len--;
			lws_struct_pretty(js, &buf, &len);
			js->offset = 0;
			j = &js->st[++js->sp];
			j->map_entry = 0;
			map = &j->map[j->map_entry];

			*buf++ = '{';
			len--;
			lws_struct_pretty(js, &buf, &len);

			j->subsequent = 0;
			j->obj = ((char *)p) - j->map->ofs_clist;
			continue;
		}

		/* there are no further items in the array */

		js->offset = 0;
		lws_struct_pretty(js, &buf, &len);
		*buf++ = ']';
		len--;
		goto up;
	}

	*written = olen - len;
	*buf = '\0'; /* convenience, a NUL after the official end */

	return LSJS_RESULT_FINISH;
}
