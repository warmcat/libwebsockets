/*
 * lws-api-test-lws_struct-json
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
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

/*
 * in this example, the JSON is for one "builder" object, which may specify
 * a child list "targets" of zero or more "target" objects.
 */

static const char * const json_tests[] = {
	"{" /* test 1 */
		"\"schema\":\"com-warmcat-sai-builder\","

		"\"hostname\":\"learn\","
		"\"nspawn_timeout\":1800,"
		"\"targets\":["
			"{"
				"\"name\":\"target1\","
				"\"someflag\":true"
			"},"
			"{"
				"\"name\":\"target2\","
				"\"someflag\":false"
			"}"
		"]"
	"}",
	"{" /* test 2 */
		"\"schema\":\"com-warmcat-sai-builder\","

		"\"hostname\":\"learn\","
		"\"targets\":["
			"{"
				"\"name\":\"target1\""
			"},"
			"{"
				"\"name\":\"target2\""
			"},"
			"{"
				"\"name\":\"target3\""
			"}"
		"]"
	"}", "{" /* test 3 */
		"\"schema\":\"com-warmcat-sai-builder\","

		"\"hostname\":\"learn\","
		"\"nspawn_timeout\":1800,"
		"\"targets\":["
			"{"
				"\"name\":\"target1\","
				"\"unrecognized\":\"xyz\","
				"\"child\": {"
					"\"somename\": \"abc\","
					"\"junk\": { \"x\": \"y\" }"
				"}"
			"},"
			"{"
				"\"name\":\"target2\""
			"}"
		"]"
	"}",
	"{" /* test 4 */
		"\"schema\":\"com-warmcat-sai-builder\","

		"\"hostname\":\"learn\","
		"\"nspawn_timeout\":1800"
	"}",
	"{" /* test 5 */
		"\"schema\":\"com-warmcat-sai-builder\""
	"}",
	"{" /* test 6 ... check huge strings into smaller fixed char array */
		"\"schema\":\"com-warmcat-sai-builder\","
		"\"hostname\":\""
		"PYvtan6kqppjnS0KpYTCaiOLsJkc7XecAr1kcE0aCIciewYB+JcLG82mO1Vb1mJtjDwUjBxy2I6A"
		"zefzoWUWmqZbsv4MXR55j9bKlyz1liiSX63iO0x6JAwACMtE2MkgcLwR86TSWAD9D1QKIWqg5RJ/"
		"CRuVsW0DKAUMD52ql4JmPFuJpJgTq28z6PhYNzN3yI3bmQt6bzhA+A/xAsFzSBnb3MHYWzGMprr5"
		"3FAP1ISo5Ec9i+2ehV40sG6Q470sH3PGQZ0YRPO7Sh/SyrSQ/scONmxRc3AcXl7X/CSs417ii+CV"
		"8sq3ZgcxKNB7tNfN7idNx3upZ00G2BZy9jSy03cLKKLNaNUt0TQsxXbH55uDHzSEeZWvxJgT6zB1"
		"NoMhdC02w+oXim94M6z6COCnqT3rgkGk8PHMry9Bkh4yVpRmzIRfMmln/lEhdZgxky2+g5hhlSIG"
		"JYDCrdynD9kCfvfy6KGOpNIi1X+mhbbWn4lnL9ZKihL/RrfOV+oV4R26IDq+KqUiJBENeo8/GXkG"
		"LUH/87iPyzXKEMavr6fkrK0vTGto8yEYxmOyaVz8phG5rwf4jJgmYNoMbGo8gWvhqO7UAGy2g7MW"
		"v+B/t1eZZ+1euLsNrWAsFJiFbQKgdFfQT3RjB14iU8knlQ8usoy+pXssY2ddGJGVcGC21oZvstK9"
		"eu1eRZftda/wP+N5unT1Hw7kCoVzqxHieiYt47EGIOaaQ7XjZDK6qPN6O/grHnvJZm2vBkxuXgsY"
		"VkRQ7AuTWIecphqFsq7Wbc1YNbMW47SVU5zMD0WaCqbaaI0t4uIzRvPlD8cpiiTzFTrEHlIBTf8/"
		"uZjjEGGLhJR1jPqA9D1Ej3ChV+ye6F9JTUMlozRMsGuF8U4btDzH5xdnmvRS4Ar6LKEtAXGkj2yu"
		"yJln+v4RIWj2xOGPJovOqiXwi0FyM61f8U8gj0OiNA2/QlvrqQVDF7sMXgjvaE7iQt5vMETteZlx"
		"+z3f+jTFM/aon511W4+ZkRD+6AHwucvM9BEC\""
	"}",
	"{" /* test 7 ... check huge strings into char * */
		"\"schema\":\"com-warmcat-sai-builder\","
		"\"targets\":["
			"{"
				"\"name\":\""
		"PYvtan6kqppjnS0KpYTCaiOLsJkc7XecAr1kcE0aCIciewYB+JcLG82mO1Vb1mJtjDwUjBxy2I6A"
		"zefzoWUWmqZbsv4MXR55j9bKlyz1liiSX63iO0x6JAwACMtE2MkgcLwR86TSWAD9D1QKIWqg5RJ/"
		"CRuVsW0DKAUMD52ql4JmPFuJpJgTq28z6PhYNzN3yI3bmQt6bzhA+A/xAsFzSBnb3MHYWzGMprr5"
		"3FAP1ISo5Ec9i+2ehV40sG6Q470sH3PGQZ0YRPO7Sh/SyrSQ/scONmxRc3AcXl7X/CSs417ii+CV"
		"8sq3ZgcxKNB7tNfN7idNx3upZ00G2BZy9jSy03cLKKLNaNUt0TQsxXbH55uDHzSEeZWvxJgT6zB1"
		"NoMhdC02w+oXim94M6z6COCnqT3rgkGk8PHMry9Bkh4yVpRmzIRfMmln/lEhdZgxky2+g5hhlSIG"
		"JYDCrdynD9kCfvfy6KGOpNIi1X+mhbbWn4lnL9ZKihL/RrfOV+oV4R26IDq+KqUiJBENeo8/GXkG"
		"LUH/87iPyzXKEMavr6fkrK0vTGto8yEYxmOyaVz8phG5rwf4jJgmYNoMbGo8gWvhqO7UAGy2g7MW"
		"v+B/t1eZZ+1euLsNrWAsFJiFbQKgdFfQT3RjB14iU8knlQ8usoy+pXssY2ddGJGVcGC21oZvstK9"
		"eu1eRZftda/wP+N5unT1Hw7kCoVzqxHieiYt47EGIOaaQ7XjZDK6qPN6O/grHnvJZm2vBkxuXgsY"
		"VkRQ7AuTWIecphqFsq7Wbc1YNbMW47SVU5zMD0WaCqbaaI0t4uIzRvPlD8cpiiTzFTrEHlIBTf8/"
		"uZjjEGGLhJR1jPqA9D1Ej3ChV+ye6F9JTUMlozRMsGuF8U4btDzH5xdnmvRS4Ar6LKEtAXGkj2yu"
		"yJln+v4RIWj2xOGPJovOqiXwi0FyM61f8U8gj0OiNA2/QlvrqQVDF7sMXgjvaE7iQt5vMETteZlx"
		"+z3f+jTFM/aon511W4+ZkRD+6AHwucvM9BEC\"}]}"
	"}",
};

/*
 * These are the expected outputs for each test, without pretty formatting.
 *
 * There are some differences to do with missing elements being rendered with
 * default values.
 */

static const char * const json_expected[] = {
	"{\"schema\":\"com-warmcat-sai-builder\",\"hostname\":\"learn\","
	  "\"nspawn_timeout\":1800,\"targets\":[{\"name\":\"target1\",\"someflag\":true},"
	  "{\"name\":\"target2\",\"someflag\":false}]}",

	"{\"schema\":\"com-warmcat-sai-builder\",\"hostname\":\"learn\","
	 "\"nspawn_timeout\":0,\"targets\":[{\"name\":\"target1\",\"someflag\":false},"
	  "{\"name\":\"target2\",\"someflag\":false},{\"name\":\"target3\",\"someflag\":false}]}",

	"{\"schema\":\"com-warmcat-sai-builder\",\"hostname\":\"learn\","
	"\"nspawn_timeout\":1800,\"targets\":[{\"name\":\"target1\",\"someflag\":false,"
	  "\"child\":{\"somename\":\"abc\"}},{\"name\":\"target2\",\"someflag\":false}]}",

	"{\"schema\":\"com-warmcat-sai-builder\","
	  "\"hostname\":\"learn\",\"nspawn_timeout\":1800}",

	"{\"schema\":\"com-warmcat-sai-builder\",\"hostname\":\"\","
	"\"nspawn_timeout\":0}",

	"{\"schema\":\"com-warmcat-sai-builder\",\"hostname\":"
		"\"PYvtan6kqppjnS0KpYTCaiOLsJkc7Xe\","
	"\"nspawn_timeout\":0}",

	"{\"schema\":\"com-warmcat-sai-builder\",\"hostname\":\"\","
	  "\"nspawn_timeout\":0,\"targets\":[{\"name\":\"PYvtan6kqppjnS0KpYTC"
		"aiOLsJkc7XecAr1kcE0aCIciewYB+JcLG82mO1Vb1mJtjDwUjBxy2I6Azefz"
		"oWUWmqZbsv4MXR55j9bKlyz1liiSX63iO0x6JAwACMtE2MkgcLwR86TSWAD9"
		"D1QKIWqg5RJ/CRuVsW0DKAUMD52ql4JmPFuJpJgTq28z6PhYNzN3yI3bmQt6"
		"bzhA+A/xAsFzSBnb3MHYWzGMprr53FAP1ISo5Ec9i+2ehV40sG6Q470sH3PG"
		"QZ0YRPO7Sh/SyrSQ/scONmxRc3AcXl7X/CSs417ii+CV8sq3ZgcxKNB7tNfN"
		"7idNx3upZ00G2BZy9jSy03cLKKLNaNUt0TQsxXbH55uDHzSEeZWvxJgT6zB1"
		"NoMhdC02w+oXim94M6z6COCnqT3rgkGk8PHMry9Bkh4yVpRmzIRfMmln/lEh"
		"dZgxky2+g5hhlSIGJYDCrdynD9kCfvfy6KGOpNIi1X+mhbbWn4lnL9ZKihL/"
		"RrfOV+oV4R26IDq+KqUiJBENeo8/GXkGLUH/87iPyzXKEMavr6fkrK0vTGto"
		"8yEYxmOyaVz8phG5rwf4jJgmYNoMbGo8gWvhqO7UAGy2g7MWv+B/t1eZZ+1e"
		"uLsNrWAsFJiFbQKgdFfQT3RjB14iU8knlQ8usoy+pXssY2ddGJGVcGC21oZv"
		"stK9eu1eRZftda/wP+N5unT1Hw7kCoVzqxHieiYt47EGIOaaQ7XjZDK6qPN6"
		"O/grHnvJZm2vBkxuXgsYVkRQ7AuTWIecphqFsq7Wbc1YNbMW47SVU5zMD0Wa"
		"CqbaaI0t4uIzRvPlD8cpiiTzFTrEHlIBTf8/uZjjEGGLhJR1jPqA9D1Ej3Ch"
		"V+ye6F9JTUMlozRMsGuF8U4btDzH5xdnmvRS4Ar6LKEtAXGkj2yuyJln+v4R"
		"IWj2xOGPJovOqiXwi0FyM61f8U8gj0OiNA2/QlvrqQVDF7sMXgjvaE7iQt5v"
		"METteZlx+z3f+jTFM/aon511W4+ZkRD+6AHwucvM9BEC\""
			",\"someflag\":false}]}"
};

/*
 * These annotate the members in the struct that will be serialized and
 * deserialized with type and size information, as well as the name to use
 * in the serialization format.
 *
 * Struct members that aren't annotated like this won't be serialized and
 * when the struct is created during deserialiation, the will be set to 0
 * or NULL.
 */

/* child object */

typedef struct sai_child {
	const char *	somename;
} sai_child_t;

lws_struct_map_t lsm_child[] = { /* describes serializable members */
	LSM_STRING_PTR	(sai_child_t, somename,			"somename"),
};

/* target object */

typedef struct sai_target {
	struct lws_dll2 target_list;
	sai_child_t *		child;

	const char *		name;
	char			someflag;
} sai_target_t;

static const lws_struct_map_t lsm_target[] = {
	LSM_STRING_PTR	(sai_target_t, name,			"name"),
	LSM_BOOLEAN	(sai_target_t, someflag,		"someflag"),
	LSM_CHILD_PTR	(sai_target_t, child, sai_child_t,
			 NULL, lsm_child,			"child"),
};

/* builder object */

typedef struct sai_builder {
	struct lws_dll2_owner	targets;

	char 			hostname[32];
	unsigned int 		nspawn_timeout;
} sai_builder_t;

static const lws_struct_map_t lsm_builder[] = {
	LSM_CARRAY	(sai_builder_t, hostname,		"hostname"),
	LSM_UNSIGNED	(sai_builder_t, nspawn_timeout,		"nspawn_timeout"),
	LSM_LIST	(sai_builder_t, targets,
			 sai_target_t, target_list,
			 NULL, lsm_target,			"targets"),
};

/* Schema table
 *
 * Before we can understand the serialization top level format, we must read
 * the schema, use the table below to create the right toplevel object for the
 * schema name, and select the correct map tables to interpret the rest of the
 * serialization.
 *
 * Therefore the schema tables below are the starting point for the
 * JSON deserialization.
 */

static const lws_struct_map_t lsm_schema_map[] = {
	LSM_SCHEMA	(sai_builder_t, NULL,
			 lsm_builder,		"com-warmcat-sai-builder"),
};

static int
show_target(struct lws_dll2 *d, void *user)
{
	sai_target_t *t = lws_container_of(d, sai_target_t, target_list);

	lwsl_notice("    target.name '%s' (target %p)\n", t->name, t);

	if (t->child)
		lwsl_notice("      child %p, target.child.somename '%s'\n",
			  t->child, t->child->somename);

	return 0;
}


int main(int argc, const char **argv)
{
	int n, m, e = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
#if 1
	lws_struct_serialize_t *ser;
	uint8_t buf[4096];
	size_t written;
#endif
	struct lejp_ctx ctx;
	lws_struct_args_t a;
	sai_builder_t *b;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: lws_struct JSON\n");

	for (m = 0; m < (int)LWS_ARRAY_SIZE(json_tests); m++) {

		/* 1. deserialize the canned JSON into structs */

		lwsl_notice("%s: ++++++++++++++++ test %d\n", __func__, m + 1);

		memset(&a, 0, sizeof(a));
		a.map_st[0] = lsm_schema_map;
		a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_schema_map);
		a.ac_block_size = 512;

		lws_struct_json_init_parse(&ctx, NULL, &a);
		n = (int)(signed char)lejp_parse(&ctx, (uint8_t *)json_tests[m],
						 strlen(json_tests[m]));
		if (n < 0) {
			lwsl_err("%s: notification JSON decode failed '%s'\n",
					__func__, lejp_error_to_string(n));
			e++;
			goto done;
		}
		lwsac_info(a.ac);

		b = a.dest;
		if (!b) {
			lwsl_err("%s: didn't produce any output\n", __func__);
			e++;
			goto done;
		}

		lwsl_notice("builder.hostname = '%s', timeout = %d, targets (%d)\n",
			    b->hostname, b->nspawn_timeout,
			    b->targets.count);

		lws_dll2_foreach_safe(&b->targets, NULL, show_target);

		/* 2. serialize the structs into JSON and confirm */

		lwsl_notice("%s:    .... strarting serialization of test %d\n",
				__func__, m + 1);
		ser = lws_struct_json_serialize_create(lsm_schema_map,
						LWS_ARRAY_SIZE(lsm_schema_map),
						       0//LSSERJ_FLAG_PRETTY
						       , b);
		if (!ser) {
			lwsl_err("%s: unable to init serialization\n", __func__);
			goto bail;
		}

		do {
			n = lws_struct_json_serialize(ser, buf, sizeof(buf),
						      &written);
			lwsl_notice("ser says %d\n", n);
			switch (n) {
			case LSJS_RESULT_CONTINUE:
			case LSJS_RESULT_FINISH:
				puts((const char *)buf);
				break;
			case LSJS_RESULT_ERROR:
				goto bail;
			}
		} while(n == LSJS_RESULT_CONTINUE);

		if (strcmp(json_expected[m], (char *)buf)) {
			lwsl_err("%s: test %d: expected %s\n", __func__, m + 1,
					json_expected[m]);
			e++;
		}

		lws_struct_json_serialize_destroy(&ser);

done:
		lwsac_free(&a.ac);
	}

	if (e)
		goto bail;

	lwsl_user("Completed: PASS\n");

	return 0;

bail:
	lwsl_user("Completed: FAIL\n");

	return 1;
}
