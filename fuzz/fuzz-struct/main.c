/*
 * lws fuzz target: lws_struct, JSON to C structs and back
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The input is JSON for one of two schemas, picked by its "schema" member,
 * parsed by lws_struct into structs of every kind of member it has:
 * signed and unsigned integers, narrower than the JSON may say, booleans,
 * char arrays shorter than the JSON's strings, string pointers, a child
 * object and lists of objects with lists in them.  It goes to the parser in
 * two chunks, so the partial-input states are reached too.
 *
 * What lws_struct takes, it must be able to give back: the structs it made
 * are serialized, that JSON parsed again, and those structs serialized
 * again.  If its own JSON doesn't parse, or comes back different, it aborts
 * with "LWS FUZZ ORACLE: <what>" for libFuzzer to report.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct fzs_leaf {
	lws_dll2_t		list;
	const char		*v;
	int64_t			n;
} fzs_leaf_t;

typedef struct fzs_item {
	lws_dll2_t		list;
	lws_dll2_owner_t	leaves;		/* fzs_leaf_t */
	const char		*name;
	unsigned int		u;
	char			flag;
} fzs_item_t;

typedef struct fzs_child {
	char			tag[8];
	int			s;
} fzs_child_t;

typedef struct fzs_top {
	lws_dll2_owner_t	items;		/* fzs_item_t */
	fzs_child_t		*child;
	char			name[16];
	const char		*desc;
	int64_t			big;
	uint8_t			small;
	char			on;
} fzs_top_t;

typedef struct fzs_other {
	char			word[4];
	int			k;
} fzs_other_t;

static const lws_struct_map_t lsm_leaf[] = {
	LSM_STRING_PTR	(fzs_leaf_t, v,				"v"),
	LSM_SIGNED	(fzs_leaf_t, n,				"n"),
};

static const lws_struct_map_t lsm_item[] = {
	LSM_STRING_PTR	(fzs_item_t, name,			"name"),
	LSM_UNSIGNED	(fzs_item_t, u,				"u"),
	LSM_BOOLEAN	(fzs_item_t, flag,			"flag"),
	LSM_LIST	(fzs_item_t, leaves, fzs_leaf_t, list,
			 NULL, lsm_leaf,			"leaves"),
};

static const lws_struct_map_t lsm_child[] = {
	LSM_CARRAY	(fzs_child_t, tag,			"tag"),
	LSM_SIGNED	(fzs_child_t, s,			"s"),
};

static const lws_struct_map_t lsm_top[] = {
	LSM_CARRAY	(fzs_top_t, name,			"name"),
	LSM_STRING_PTR	(fzs_top_t, desc,			"desc"),
	LSM_SIGNED	(fzs_top_t, big,			"big"),
	LSM_UNSIGNED	(fzs_top_t, small,			"small"),
	LSM_BOOLEAN	(fzs_top_t, on,				"on"),
	LSM_CHILD_PTR	(fzs_top_t, child, fzs_child_t,
			 NULL, lsm_child,			"child"),
	LSM_LIST	(fzs_top_t, items, fzs_item_t, list,
			 NULL, lsm_item,			"items"),
};

static const lws_struct_map_t lsm_other[] = {
	LSM_CARRAY	(fzs_other_t, word,			"word"),
	LSM_SIGNED	(fzs_other_t, k,			"k"),
};

static const lws_struct_map_t lsm_schemas[] = {
	LSM_SCHEMA	(fzs_top_t, NULL, lsm_top,		"fz"),
	LSM_SCHEMA	(fzs_other_t, NULL, lsm_other,		"fz-other"),
};

/* what one parse made */
struct fzs_parsed {
	lws_struct_args_t	a;
	int			ok;
};

static char out1[65536], out2[65536];
static int verbose;

static void
fzs_broken_promise(const char *what, const char *a, const char *b)
{
	fprintf(stderr, "LWS FUZZ ORACLE: %s\n  first:  '%.512s'\n"
			"  second: '%.512s'\n", what, a, b ? b : "");
	abort();
}

/*
 * Parse len bytes of JSON at in, in two chunks split at split.  ok is set if
 * it made something.
 */
static void
fzs_parse(struct fzs_parsed *p, const uint8_t *in, size_t len, size_t split)
{
	struct lejp_ctx ctx;
	int m = LEJP_CONTINUE;

	memset(p, 0, sizeof(*p));
	p->a.map_st[0]		= lsm_schemas;
	p->a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_schemas);
	p->a.ac_block_size	= 512;

	lws_struct_json_init_parse(&ctx, NULL, &p->a);

	if (split && split < len)
		m = lejp_parse(&ctx, in, (int)split);
	else
		split = 0;
	/* the rest, unless the first chunk was already the end, or bad */
	if (m == LEJP_CONTINUE)
		m = lejp_parse(&ctx, in + split, (int)(len - split));

	lejp_destruct(&ctx);

	p->ok = m >= 0 && p->a.dest && p->a.top_schema_index >= 0 &&
		p->a.top_schema_index < (int)LWS_ARRAY_SIZE(lsm_schemas);
}

static void
fzs_free(struct fzs_parsed *p)
{
	lwsac_free(&p->a.ac);
	lwsac_free(&p->a.ac_chunks);
}

/*
 * The JSON for what a parse made, NUL-terminated in out.  Returns its length,
 * 0 if it doesn't fit, which is no finding, or -1 if lws_struct couldn't
 * serialize what it parsed itself.
 */
static int
fzs_render(const struct fzs_parsed *p, char *out, size_t len)
{
	lws_struct_serialize_t *js;
	lws_struct_json_serialize_result_t r;
	size_t used = 0, w;

	js = lws_struct_json_serialize_create(
				&lsm_schemas[p->a.top_schema_index], 1, 0,
				p->a.dest);
	if (!js)
		return -1;

	do {
		if (used >= len - 1) {
			lws_struct_json_serialize_destroy(&js);
			return 0;
		}
		w = 0;
		r = lws_struct_json_serialize(js, (uint8_t *)out + used,
					      len - 1 - used, &w);
		used += w;
	} while (r == LSJS_RESULT_CONTINUE);

	lws_struct_json_serialize_destroy(&js);
	out[used] = '\0';

	return r == LSJS_RESULT_FINISH ? (int)used : -1;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	/* LWS_FUZZ_VERBOSE=1 also shows the JSON each input came back as */
	verbose = !!getenv("LWS_FUZZ_VERBOSE");
	if (!verbose)
		lws_set_log_level(0, NULL);

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fzs_parsed p1, p2;
	int n1, n2;

	fzs_parse(&p1, data, size, size / 2);
	if (!p1.ok)
		goto bail1;

	n1 = fzs_render(&p1, out1, sizeof(out1));
	if (!n1)
		goto bail1;
	if (n1 < 0)
		fzs_broken_promise("what lws_struct parsed didn't serialize",
				   (const char *)data, NULL);

	if (verbose)
		fprintf(stderr, "serialized: %s\n", out1);

	/* its own JSON, in one go this time */
	fzs_parse(&p2, (const uint8_t *)out1, (size_t)n1, 0);
	if (!p2.ok)
		fzs_broken_promise("lws_struct's own JSON didn't parse back",
				   out1, NULL);
	if (p2.a.top_schema_index != p1.a.top_schema_index)
		fzs_broken_promise("lws_struct's own JSON came back as another "
				   "schema", out1, NULL);

	n2 = fzs_render(&p2, out2, sizeof(out2));
	if (n2 < 0)
		fzs_broken_promise("lws_struct's own JSON, parsed back, didn't "
				   "serialize", out1, NULL);
	if (n2 != n1 || memcmp(out1, out2, (size_t)n1))
		fzs_broken_promise("lws_struct's own JSON came back different",
				   out1, out2);

	fzs_free(&p2);
bail1:
	fzs_free(&p1);

	return 0;
}
