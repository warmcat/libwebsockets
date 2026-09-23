/*
 * lhp-ua-gen.c
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Licensed under MIT
 *
 * Turns the built-in default (user-agent) stylesheet in lhp.c into const
 * tables, so it lives in flash instead of being lexed into the cascade
 * arenas on every page.  Its output is checked in as lhp-ua-css.h; rerun it
 * when default_css changes.
 *
 * Usage: build lws with -DLWS_WITH_LHP=1, then
 *
 *   gcc -I include -I <builddir> lib/misc/lhp-ua-gen.c \
 *	 -L <builddir>/lib -lwebsockets -o lhp-ua-gen && \
 *   LD_LIBRARY_PATH=<builddir>/lib ./lhp-ua-gen > lib/misc/lhp-ua-css.h
 *
 * It parses an empty document with an unmodified lws, which is what causes
 * the default stylesheet to be parsed, and emits what the parser built.  So
 * it has to be run against a lws that still parses default_css, ie, before
 * LWS_WITH_LHP_UA_FLASH is turned on, or with it off.
 */

#include <libwebsockets.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXOBJ 1024

static const void *stz_p[MAXOBJ], *nm_p[MAXOBJ], *def_p[MAXOBJ], *atr_p[MAXOBJ];
static unsigned int stz_c, nm_c, def_c, atr_c;

/* name of the emitted array an object of each kind lives in, by text length */
static unsigned int nm_len[MAXOBJ], atr_len[MAXOBJ];
/* index of the object within that array */
static unsigned int nm_idx[MAXOBJ], atr_idx[MAXOBJ];

static int
idx_of(const void *const *tbl, unsigned int count, const void *p)
{
	unsigned int n;

	for (n = 0; n < count; n++)
		if (tbl[n] == p)
			return (int)n;

	return -1;
}

/*
 * The emitted lvalue expression naming an object (without a leading &), so
 * the emitter can take the address of it or of one of its members.  Objects
 * that carry trailing text live in a per-length array and are reached through
 * its first member.
 */

static const char *
nm_expr(const void *p)
{
	static char buf[64];
	int n = idx_of(nm_p, nm_c, p);

	if (n < 0)
		return "*(lcsp_names_t *)NULL";

	lws_snprintf(buf, sizeof(buf), "lhp_ua_nm%u[%u].n", nm_len[n],
		     nm_idx[n]);

	return buf;
}

static const char *
atr_expr(const void *p)
{
	static char buf[64];
	int n = idx_of(atr_p, atr_c, p);

	if (n < 0)
		return "*(lcsp_atr_t *)NULL";

	lws_snprintf(buf, sizeof(buf), "lhp_ua_atr%u[%u].a", atr_len[n],
		     atr_idx[n]);

	return buf;
}

static const char *
def_expr(const void *p)
{
	static char buf[64];
	int n = idx_of(def_p, def_c, p);

	if (n < 0)
		return "*(lcsp_defs_t *)NULL";

	lws_snprintf(buf, sizeof(buf), "lhp_ua_def[%d]", n);

	return buf;
}

static const char *
stz_expr(const void *p)
{
	static char buf[64];
	int n = idx_of(stz_p, stz_c, p);

	if (n < 0)
		return "*(lcsp_stanza_t *)NULL";

	lws_snprintf(buf, sizeof(buf), "lhp_ua_stz[%d]", n);

	return buf;
}

/*
 * A dll2 link and a dll2 owner, emitted as what the parser actually built
 */

static void
emit_dll2(const lws_dll2_t *d, const char *(*expr)(const void *),
	  const char *owner)
{
	printf("{ ");
	if (d->prev)
		printf(".prev = (lws_dll2_t *)&%s.list, ", expr(d->prev));
	if (d->next)
		printf(".next = (lws_dll2_t *)&%s.list, ", expr(d->next));
	if (owner)
		printf(".owner = (lws_dll2_owner_t *)&%s", owner);
	printf(" }");
}

static void
emit_owner(const lws_dll2_owner_t *o, const char *(*expr)(const void *))
{
	printf("{ ");
	if (o->head)
		printf(".head = (lws_dll2_t *)&%s.list, ", expr(o->head));
	if (o->tail)
		printf(".tail = (lws_dll2_t *)&%s.list, ", expr(o->tail));
	printf(".count = %u }", (unsigned int)o->count);
}

static void
emit_c_string(const char *p, size_t len)
{
	printf("\"");
	while (len--) {
		if (*p == '"' || *p == '\\')
			printf("\\%c", *p);
		else
			if (*p >= 32 && *p < 127)
				printf("%c", *p);
			else
				printf("\\%03o", (unsigned char)*p);
		p++;
	}
	printf("\"");
}

static lws_stateful_ret_t
gen_cb(lhp_ctx_t *ctx, char reason)
{
	(void)ctx;
	(void)reason;

	return LWS_SRET_OK;
}

int
main(void)
{
	lws_surface_info_t ic;
	lws_displaylist_t dl;
	lws_dl_rend_t drt;
	const uint8_t *data;
	unsigned int n, m, mx;
	lhp_ctx_t ctx;
	size_t size;

	memset(&ic, 0, sizeof(ic));
	memset(&dl, 0, sizeof(dl));
	memset(&drt, 0, sizeof(drt));
	ic.wh_px[0].whole = 600;
	ic.wh_px[1].whole = 448;
	drt.dl = &dl;
	drt.w = 600;
	drt.h = 448;

	if (lws_lhp_construct(&ctx, gen_cb, &drt, &ic)) {
		fprintf(stderr, "lws_lhp_construct failed\n");

		return 1;
	}

	ctx.flags = LHP_FLAG_DOCUMENT_END;
	ctx.base_url = strdup("");

	/*
	 * Parsing anything at all is what makes lhp parse its default
	 * stylesheet, and an empty document adds nothing of its own to the
	 * cascade.  The <html> element also drives the first cascade pass,
	 * which is what builds the selector index we emit below.
	 */

	data = (const uint8_t *)"<html></html>";
	size = 13;

	if (lws_lhp_parse(&ctx, &data, &size) & LWS_SRET_FATAL) {
		fprintf(stderr, "parse failed\n");

		return 1;
	}

	/*
	 * Collect the objects, in the order the emitted arrays will hold them
	 */

	lws_start_foreach_dll(struct lws_dll2 *, ds,
			      lws_dll2_get_head(&ctx.css)) {
		lcsp_stanza_t *stz = lws_container_of(ds, lcsp_stanza_t, list);

		stz_p[stz_c++] = stz;

		lws_start_foreach_dll(struct lws_dll2 *, dn,
				      lws_dll2_get_head(&stz->names)) {
			nm_p[nm_c++] = lws_container_of(dn, lcsp_names_t, list);
		} lws_end_foreach_dll(dn);

		lws_start_foreach_dll(struct lws_dll2 *, dd,
				      lws_dll2_get_head(&stz->defs)) {
			lcsp_defs_t *def = lws_container_of(dd, lcsp_defs_t,
							    list);

			def_p[def_c++] = def;

			lws_start_foreach_dll(struct lws_dll2 *, da,
					      lws_dll2_get_head(&def->atrs)) {
				atr_p[atr_c++] = lws_container_of(da,
							lcsp_atr_t, list);
			} lws_end_foreach_dll(da);
		} lws_end_foreach_dll(dd);
	} lws_end_foreach_dll(ds);

	/*
	 * Group the text-carrying objects by the exact size of their text, so
	 * each array element is the size it needs and no more
	 */

	for (n = 0; n < nm_c; n++)
		nm_len[n] = (unsigned int)
			    ((const lcsp_names_t *)nm_p[n])->name_len + 1;
	for (n = 0; n < atr_c; n++)
		atr_len[n] = (unsigned int)
			     ((const lcsp_atr_t *)atr_p[n])->value_len + 1;

	printf("/*\n * Generated by lhp-ua-gen from the default stylesheet in\n"
	       " * lhp.c: the user-agent cascade as const tables, so it costs\n"
	       " * flash instead of ~19KB of heap on every page parsed.\n *\n"
	       " * DO NOT EDIT... see lhp-ua-gen.c to regenerate.\n */\n\n");

	printf("/* %u stanzas, %u selectors, %u declarations, %u values */\n\n",
	       stz_c, nm_c, def_c, atr_c);

	/* forward declarations: the arrays reference each other */

	printf("static const lcsp_stanza_t lhp_ua_stz[%u];\n", stz_c);
	printf("static const lcsp_defs_t lhp_ua_def[%u];\n\n", def_c);

	/* the selectors, by text length */

	mx = 0;
	for (n = 0; n < nm_c; n++)
		if (nm_len[n] > mx)
			mx = nm_len[n];

	for (m = 1; m <= mx; m++) {
		unsigned int cnt = 0;

		for (n = 0; n < nm_c; n++)
			if (nm_len[n] == m)
				nm_idx[n] = cnt++;

		if (!cnt)
			continue;

		printf("struct lhp_ua_nm_%u { lcsp_names_t n; char t[%u]; };\n"
		       "static const struct lhp_ua_nm_%u lhp_ua_nm%u[%u];\n",
		       m, m, m, m, cnt);
	}
	printf("\n");

	mx = 0;
	for (n = 0; n < atr_c; n++)
		if (atr_len[n] > mx)
			mx = atr_len[n];

	for (m = 1; m <= mx; m++) {
		unsigned int cnt = 0;

		for (n = 0; n < atr_c; n++)
			if (atr_len[n] == m)
				atr_idx[n] = cnt++;

		if (!cnt)
			continue;

		printf("struct lhp_ua_atr_%u { lcsp_atr_t a; char t[%u]; };\n"
		       "static const struct lhp_ua_atr_%u lhp_ua_atr%u[%u];\n",
		       m, m, m, m, cnt);
	}
	printf("\n");

	/* ... now the definitions */

	for (m = 1; m <= 256; m++) {
		unsigned int cnt = 0, first = 1;

		for (n = 0; n < atr_c; n++)
			if (atr_len[n] == m)
				cnt++;
		if (!cnt)
			continue;

		printf("static const struct lhp_ua_atr_%u lhp_ua_atr%u[%u] = {\n",
		       m, m, cnt);

		for (n = 0; n < atr_c; n++) {
			const lcsp_atr_t *a = atr_p[n];
			const int32_t *u = (const int32_t *)&a->u;

			if (atr_len[n] != m)
				continue;

			if (!first)
				printf(",\n");
			first = 0;

			printf("\t{ { .list = ");
			emit_dll2(&a->list, atr_expr, NULL);
			printf(",\n\t    .u.i = { (int32_t)0x%08xu, (int32_t)0x%08xu },"
			       "\n\t    .propval = %u, .value_len = %u, "
			       ".unit = %u, .op = %u }, ",
			       (unsigned int)u[0], (unsigned int)u[1],
			       (unsigned int)a->propval,
			       (unsigned int)a->value_len,
			       (unsigned int)a->unit, (unsigned int)a->op);
			emit_c_string((const char *)&a[1], m - 1);
			printf(" }");
		}
		printf("\n};\n\n");
	}

	for (m = 1; m <= 256; m++) {
		unsigned int cnt = 0, first = 1;

		for (n = 0; n < nm_c; n++)
			if (nm_len[n] == m)
				cnt++;
		if (!cnt)
			continue;

		printf("static const struct lhp_ua_nm_%u lhp_ua_nm%u[%u] = {\n",
		       m, m, cnt);

		for (n = 0; n < nm_c; n++) {
			const lcsp_names_t *nm = nm_p[n];
			char ownbuf[64];

			if (nm_len[n] != m)
				continue;

			if (!first)
				printf(",\n");
			first = 0;

			lws_snprintf(ownbuf, sizeof(ownbuf), "%s.names",
				     stz_expr((const char *)nm->list.owner -
					      offsetof(lcsp_stanza_t, names)));

			printf("\t{ { .list = ");
			emit_dll2(&nm->list, nm_expr, ownbuf);
			printf(",\n\t    .specificity = 0x%xu, .name_len = %u, "
			       ".key_ofs = %u,\n\t    .key_len = %u, "
			       ".key_kind = %u }, ",
			       (unsigned int)nm->specificity,
			       (unsigned int)nm->name_len,
			       (unsigned int)nm->key_ofs,
			       (unsigned int)nm->key_len,
			       (unsigned int)nm->key_kind);
			emit_c_string((const char *)&nm[1], m - 1);
			printf(" }");
		}
		printf("\n};\n\n");
	}

	printf("static const lcsp_defs_t lhp_ua_def[%u] = {\n", def_c);
	for (n = 0; n < def_c; n++) {
		const lcsp_defs_t *def = def_p[n];
		char ownbuf[64];

		if (n)
			printf(",\n");

		lws_snprintf(ownbuf, sizeof(ownbuf), "%s.defs",
			     stz_expr((const char *)def->list.owner -
				      offsetof(lcsp_stanza_t, defs)));

		printf("\t{ .list = ");
		emit_dll2(&def->list, def_expr, ownbuf);
		printf(",\n\t  .atrs = ");
		emit_owner(&def->atrs, atr_expr);
		printf(",\n\t  .prop = %u, .important = %u }",
		       (unsigned int)def->prop, (unsigned int)def->important);

		if (def->var)
			fprintf(stderr, "warning: def %u has a var, which the "
					"generator does not emit\n", n);
	}
	printf("\n};\n\n");

	printf("static const lcsp_stanza_t lhp_ua_stz[%u] = {\n", stz_c);
	for (n = 0; n < stz_c; n++) {
		const lcsp_stanza_t *stz = stz_p[n];

		if (n)
			printf(",\n");

		/*
		 * .list is left empty: the ua stanzas are not on ctx->css,
		 * nothing walks them as a list, and an owner pointer would
		 * have to name a per-parse object
		 */

		printf("\t{ .names = ");
		emit_owner(&stz->names, nm_expr);
		printf(",\n\t  .defs = ");
		emit_owner(&stz->defs, def_expr);
		printf(",\n\t  .seq = %u }", (unsigned int)stz->seq);
	}
	printf("\n};\n\n");

	/*
	 * The selector index the cascade consults, prebuilt: every selector
	 * of every stanza, bucketed by its key
	 */

	{
		const lhp_selidx_t *e;
		unsigned int idx = 0, cnt = 0;
		const void *idx_p[MAXOBJ];

		for (e = ctx.selidx_nokey; e; e = e->next)
			idx_p[cnt++] = e;
		for (m = 0; m < LHP_SELIDX_BUCKETS; m++)
			for (e = ctx.selidx[m]; e; e = e->next)
				idx_p[cnt++] = e;

		printf("static const lhp_selidx_t lhp_ua_idx[%u] = {\n", cnt);
		for (idx = 0; idx < cnt; idx++) {
			const lhp_selidx_t *q = idx_p[idx];
			int nx = idx_of(idx_p, cnt, q->next);

			if (idx)
				printf(",\n");
			printf("\t{ ");
			if (nx >= 0)
				printf(".next = (lhp_selidx_t *)"
				       "&lhp_ua_idx[%d], ", nx);
			printf(".nm = (lcsp_names_t *)&%s, ", nm_expr(q->nm));
			printf(".stz = (lcsp_stanza_t *)&%s }", stz_expr(q->stz));
		}
		printf("\n};\n\n");

		printf("static const lhp_selidx_t * const lhp_ua_nokey =");
		printf(" %s;\n\n", ctx.selidx_nokey ?
			(idx_of(idx_p, cnt, ctx.selidx_nokey) >= 0 ?
			 "&lhp_ua_idx[0]" : "NULL") : "NULL");

		printf("static const lhp_selidx_t * const "
		       "lhp_ua_buckets[LHP_SELIDX_BUCKETS] = {\n");
		for (m = 0; m < LHP_SELIDX_BUCKETS; m++) {
			int b = ctx.selidx[m] ?
				idx_of(idx_p, cnt, ctx.selidx[m]) : -1;

			if (m)
				printf(",\n");
			if (b >= 0)
				printf("\t[%u] = &lhp_ua_idx[%d]", m, b);
			else
				printf("\t[%u] = NULL", m);
		}
		printf("\n};\n\n");
	}

	/* the document's own stanzas carry on from here */

	printf("#define LHP_UA_STZ_SEQ %u\n", (unsigned int)ctx.stz_seq);

	lws_lhp_destruct(&ctx);

	return 0;
}
