/*
 * lws-api-test-lws_struct-sqlite
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_struct apis are used to serialize and deserialize your C structs and
 * linked-lists in a standardized way that's very modest on memory but
 * convenient and easy to maintain.
 *
 * The API test shows how to serialize and deserialize a struct with a linked-
 * list of child structs in JSON using lws_struct APIs.
 */

#include <libwebsockets.h>


enum {
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

typedef struct teststruct {
	lws_dll2_t		list; /* not directly serialized */

	char 			str1[32];
	const char		*str2;
	uint8_t			u8;
	uint16_t		u16;
	uint32_t		u32;
	uint64_t		u64;
	int32_t			s32;
} teststruct_t;

/*
 * These are the members that we will serialize and deserialize, not every
 * member in the struct (eg, the dll2 list member)
 */

static const lws_struct_map_t lsm_teststruct[] = {
	LSM_CARRAY	(teststruct_t, str1,		"str1"),
	LSM_STRING_PTR  (teststruct_t, str2,		"str2"),
	LSM_UNSIGNED	(teststruct_t, u8,		"u8"),
	LSM_UNSIGNED	(teststruct_t, u16,		"u16"),
	LSM_UNSIGNED	(teststruct_t, u32,		"u32"),
	LSM_UNSIGNED	(teststruct_t, u64,		"u64"),
	LSM_SIGNED	(teststruct_t, s32,		"s32"),
};

static const lws_struct_map_t lsm_schema_apitest[] = {
	LSM_SCHEMA_DLL2	(teststruct_t, list, NULL, lsm_teststruct, "apitest")
};

/*
 * A row written by lws_struct_sq3_upsert() / _update(), selected by its
 * unique name column.  The first member is the primary key.
 */

typedef struct rowtest {
	lws_dll2_t		list; /* not directly serialized */

	uint32_t		idx;
	const char		*name;
	const char		*note;
	int8_t			s8;
	int16_t			s16;
	uint64_t		u64;
	int64_t			s64;
} rowtest_t;

static const lws_struct_map_t lsm_rowtest[] = {
	LSM_UNSIGNED	(rowtest_t, idx,		"idx"),
	LSM_STRING_PTR	(rowtest_t, name,		"name"),
	LSM_STRING_PTR	(rowtest_t, note,		"note"),
	LSM_SIGNED	(rowtest_t, s8,			"s8"),
	LSM_SIGNED	(rowtest_t, s16,		"s16"),
	LSM_UNSIGNED	(rowtest_t, u64,		"u64"),
	LSM_SIGNED	(rowtest_t, s64,		"s64"),
};

static const lws_struct_map_t lsm_schema_rowtest[] = {
	LSM_SCHEMA_DLL2	(rowtest_t, list, NULL, lsm_rowtest, "rowtest")
};

static const char *test_string =
	"No one would have believed in the last years of the nineteenth "
	"century that this world was being watched keenly and closely by "
	"intelligences greater than man's and yet as mortal as his own; that as "
	"men busied themselves about their various concerns they were "
	"scrutinised and studied, perhaps almost as narrowly as a man with a "
	"microscope might scrutinise the transient creatures that swarm and "
	"multiply in a drop of water.  With infinite complacency men went to "
	"and fro over this globe about their little affairs, serene in their "
	"assurance of their empire over matter. It is possible that the "
	"infusoria under the microscope do the same.  No one gave a thought to "
	"the older worlds of space as sources of human danger, or thought of "
	"them only to dismiss the idea of life upon them as impossible or "
	"improbable.  It is curious to recall some of the mental habits of "
	"those departed days.  At most terrestrial men fancied there might be "
	"other men upon Mars, perhaps inferior to themselves and ready to "
	"welcome a missionary enterprise. Yet across the gulf of space, minds "
	"that are to our minds as ours are to those of the beasts that perish, "
	"intellects vast and cool and unsympathetic, regarded this earth with "
	"envious eyes, and slowly and surely drew their plans against us.  And "
	"early in the twentieth century came the great disillusionment. ";

/*
 * Read back the only row named "alpha" and compare it with what we wrote
 */

static int
rowtest_check(sqlite3 *db, const rowtest_t *w, const char *what)
{
	lws_dll2_owner_t resown;
	struct lwsac *ac = NULL;
	const rowtest_t *r;
	int ret = 1;

	if (lws_struct_sq3_deserialize(db, " and name='alpha'", NULL,
				       lsm_schema_rowtest, &resown, &ac, 0, 10)) {
		lwsl_err("%s: %s: deserialize failed\n", __func__, what);
		goto bail;
	}

	if (resown.count != 1) {
		lwsl_err("%s: %s: %d rows\n", __func__, what, resown.count);
		goto bail;
	}

	r = lws_container_of(lws_dll2_get_head(&resown), rowtest_t, list);

	if (!r->name || strcmp(r->name, w->name)) {
		lwsl_err("%s: %s: bad name\n", __func__, what);
		goto bail;
	}

	/* a NULL string member is stored as SQL NULL and comes back NULL */

	if (!w->note != !r->note || (w->note && strcmp(r->note, w->note))) {
		lwsl_err("%s: %s: note %s, len %d\n", __func__, what,
			 r->note ? "differs" : "NULL",
			 r->note ? (int)strlen(r->note) : 0);
		goto bail;
	}

	if (r->s8 != w->s8 || r->s16 != w->s16 || r->u64 != w->u64 ||
	    r->s64 != w->s64) {
		lwsl_err("%s: %s: %d %d 0x%llx %lld\n", __func__, what,
			 r->s8, r->s16, (unsigned long long)r->u64,
			 (long long)r->s64);
		goto bail;
	}

	ret = 0;

bail:
	lwsac_free(&ac);

	return ret;
}

/*
 * lws_struct_sq3_upsert() and _update() bind the member values: a NULL string
 * member is SQL NULL, a long string is stored whole, quotes in it are just
 * data, and integers keep their sign and all 64 bits.
 */

static int
rowtest(sqlite3 *db)
{
	char long_note[2500];
	rowtest_t w;
	size_t n;

	if (lws_struct_sq3_create_table(db, lsm_schema_rowtest)) {
		lwsl_err("%s: create table failed\n", __func__);
		return 1;
	}

	/* longer than any fixed-size escaping buffer, with quotes to escape */

	for (n = 0; n < sizeof(long_note) - 1; n++)
		long_note[n] = (n % 7) ? (char)('a' + (n % 26)) : '\'';
	long_note[sizeof(long_note) - 1] = '\0';

	memset(&w, 0, sizeof(w));
	w.name	= "alpha";
	w.note	= NULL;
	w.s8	= -5;
	w.s16	= -300;
	w.u64	= 0xfedcba9876543210ull;
	w.s64	= -0x123456789abll;

	/* 1: upsert inserts a row with a NULL string member */

	if (lws_struct_sq3_upsert(db, "rowtest", lsm_rowtest,
				  LWS_ARRAY_SIZE(lsm_rowtest), &w, "name")) {
		lwsl_err("%s: upsert insert failed\n", __func__);
		return 1;
	}
	if (rowtest_check(db, &w, "upsert insert"))
		return 1;

	/* 2: update the row with a long string, selected by its name */

	w.note	= long_note;
	w.s8	= 100;
	if (lws_struct_sq3_update(db, "rowtest", lsm_rowtest,
				  LWS_ARRAY_SIZE(lsm_rowtest), &w, "name")) {
		lwsl_err("%s: update failed\n", __func__);
		return 1;
	}
	if (rowtest_check(db, &w, "update"))
		return 1;

	/* 3: upsert of the same name updates it, back to a NULL member */

	w.note	= NULL;
	w.s16	= 32767;
	if (lws_struct_sq3_upsert(db, "rowtest", lsm_rowtest,
				  LWS_ARRAY_SIZE(lsm_rowtest), &w, "name")) {
		lwsl_err("%s: upsert update failed\n", __func__);
		return 1;
	}
	if (rowtest_check(db, &w, "upsert update"))
		return 1;

	/* 4: update of a row that isn't there changes nothing, and says so */

	w.name	= "nosuch";
	if (lws_struct_sq3_update(db, "rowtest", lsm_rowtest,
				  LWS_ARRAY_SIZE(lsm_rowtest), &w, "name") != 1) {
		lwsl_err("%s: update of missing row didn't report it\n",
			 __func__);
		return 1;
	}
	w.name	= "alpha";

	return rowtest_check(db, &w, "update missing");
}

int main(int argc, const char **argv)
{
	int e = 0, n;
	struct lws_context_creation_info info;
	struct lws_context *context;
	struct lwsac *ac = NULL;
	lws_dll2_owner_t resown;
	teststruct_t ts, *pts;
	sqlite3 *db;
	(void)switches;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}



	lwsl_user("LWS API selftest: lws_struct SQLite\n");

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}


	unlink("_lws_apitest.sq3");

	if (lws_struct_sq3_open(context, "_lws_apitest.sq3", 1, &db)) {
		lwsl_err("%s: failed to open table\n", __func__);
		goto bail;
	}

	/* 1. populate the struct */

	memset(&ts, 0, sizeof(ts));

	lws_strncpy(ts.str1, "hello", sizeof(ts.str1));
	ts.str2 = test_string;
	ts.u8 = 1;
	ts.u16 = 512,
	ts.u32 = 0x55aa1234; /* 1437209140, */
	ts.u64 = 0x34abcdef01ull;
	ts.s32 = -1;

	/* add our struct to the dll2 owner list */

	lws_dll2_owner_clear(&resown);
	lws_dll2_add_head(&ts.list, &resown);

	/* gratuitously create the table */

	if (lws_struct_sq3_create_table(db, lsm_schema_apitest)) {
		lwsl_err("%s: Create table failed\n", __func__);
		e++;
		goto done;
	}

	/* serialize the items on the dll2 owner */

	if (lws_struct_sq3_serialize(db, lsm_schema_apitest, &resown, 0)) {
		lwsl_err("%s: Serialize failed\n", __func__);
		e++;
		goto done;
	}

	/* resown should be cleared by deserialize, ac is already NULL */

	lws_dll2_owner_clear(&resown); /* make sure old resown data is gone */

	if (lws_struct_sq3_deserialize(db, NULL, NULL, lsm_schema_apitest,
				       &resown, &ac, 0, 1)) {
		lwsl_err("%s: Deserialize failed\n", __func__);
		e++;
		goto done;
	}

	/* we should have 1 entry in resown now (created into the ac) */

	if (resown.count != 1) {
		lwsl_err("%s: Expected 1 result got %d\n", __func__,
				resown.count);
		e++;
		goto done;
	}

	/*
	 * Convert the pointer to the embedded lws_dll2 into a pointer
	 * to the actual struct with the correct type
	 */

	pts = lws_container_of(lws_dll2_get_head(&resown),
			       teststruct_t, list);

	if (strcmp(pts->str1, "hello") ||
	    strcmp(pts->str2, test_string) ||
	    pts->u8 != 1 ||
	    pts->u16 != 512 ||
	    pts->u32 != 0x55aa1234 ||
	    pts->u64 != 0x34abcdef01ull ||
	    pts->s32 != -1) {
		lwsl_err("%s: unexpected deser values: %s\n", __func__, pts->str1);
		lwsl_err("%s: %s\n", __func__, pts->str2);
		lwsl_err("%s: %u %u %u 0x%llx %d\n", __func__, pts->u8, pts->u16,
			 pts->u32, (unsigned long long)pts->u64, pts->s32);

		e++;
		goto done;
	}

	/*
	 * 2. A filter can be long, eg, when it matches long names, and the
	 * statement grows to fit it, rather than being refused, or truncated
	 * and losing the restriction.  Test it both selects the row it
	 * matches, and not one it doesn't.
	 */

	for (n = 0; n < 2; n++) {
		char pad[1024], filter[1200];

		memset(pad, 'x', sizeof(pad) - 1);
		pad[sizeof(pad) - 1] = '\0';
		lws_snprintf(filter, sizeof(filter),
			     " and str1='%s' and str2 != '%s'",
			     n ? "nomatch" : "hello", pad);

		lwsac_free(&ac);
		if (lws_struct_sq3_deserialize(db, filter, NULL,
					       lsm_schema_apitest, &resown,
					       &ac, 0, 1)) {
			lwsl_err("%s: long filter deserialize failed\n",
				 __func__);
			e++;
			goto done;
		}

		if (resown.count != (n ? 0u : 1u)) {
			lwsl_err("%s: long filter %d: %d results\n", __func__,
				 n, resown.count);
			e++;
			goto done;
		}
	}

	/* 3. single-row update / upsert */

	if (rowtest(db)) {
		e++;
		goto done;
	}

done:
	lwsac_free(&ac);
	lws_struct_sq3_close(&db);


	if (e)
		goto bail;

	lws_context_destroy(context);

	lwsl_user("Completed: PASS\n");

	return 0;

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: FAIL\n");

	return 1;
}
