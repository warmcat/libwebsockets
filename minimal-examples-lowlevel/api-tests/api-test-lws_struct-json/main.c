/*
 * lws-api-test-lws_struct-json
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

typedef struct {
	lws_dll2_t		list;

	struct gpiod_line	*line;

	const char		*name;
	const char		*wire;

	int			chip_idx;
	int			offset;
	int			safe;
} sai_jig_gpio_t;

typedef struct {
	lws_dll2_t		list;
	sai_jig_gpio_t		*gpio; /* null = wait ms */
	const char		*gpio_name;
	int			value;
} sai_jig_seq_item_t;

typedef struct {
	lws_dll2_t		list;
	lws_dll2_owner_t	seq_owner;
	const char		*name;
} sai_jig_sequence_t;

typedef struct {
	lws_dll2_t		list;
	lws_dll2_owner_t	gpio_owner;
	lws_dll2_owner_t	seq_owner;

	lws_sorted_usec_list_t	sul;		/* next step in ongoing seq */
	sai_jig_seq_item_t	*current;	/* next seq step */

	const char		*name;

	struct lws		*wsi;
} sai_jig_target_t;

typedef struct {
	lws_dll2_owner_t	target_owner;
	struct gpiod_chip	*chip[16];
	struct lwsac		*ac_conf;
	int			port;
	const char		*iface;
	struct lws_context	*ctx;
} sai_jig_t;

/*
 * We read the JSON config using lws_struct... instrument the related structures
 */

static const lws_struct_map_t lsm_sai_jig_gpio[] = {
	LSM_UNSIGNED	(sai_jig_gpio_t, chip_idx,		"chip_idx"),
	LSM_UNSIGNED	(sai_jig_gpio_t, offset,		"offset"),
	LSM_UNSIGNED	(sai_jig_gpio_t, safe,			"safe"),
	LSM_STRING_PTR	(sai_jig_gpio_t, name,			"name"),
	LSM_STRING_PTR	(sai_jig_gpio_t, wire,			"wire"),
};

static const lws_struct_map_t lsm_sai_jig_seq_item[] = {
	LSM_STRING_PTR	(sai_jig_seq_item_t, gpio_name,		"gpio_name"),
	LSM_UNSIGNED	(sai_jig_seq_item_t, value,		"value"),
};

static const lws_struct_map_t lsm_sai_jig_sequence[] = {
	LSM_STRING_PTR	(sai_jig_sequence_t, name,		"name"),
	LSM_LIST	(sai_jig_sequence_t, seq_owner,
			 sai_jig_seq_item_t, list,
			 NULL, lsm_sai_jig_seq_item,		"seq"),
};

static const lws_struct_map_t lsm_sai_jig_target[] = {
	LSM_STRING_PTR	(sai_jig_target_t, name,		"name"),
	LSM_LIST	(sai_jig_target_t, gpio_owner, sai_jig_gpio_t, list,
			 NULL, lsm_sai_jig_gpio,		"gpios"),
	LSM_LIST	(sai_jig_target_t, seq_owner, sai_jig_sequence_t, list,
			 NULL, lsm_sai_jig_sequence,		"sequences"),
};

static const lws_struct_map_t lsm_sai_jig[] = {
	LSM_STRING_PTR	(sai_jig_t, iface,			"iface"),
	LSM_UNSIGNED	(sai_jig_t, port,			"port"),
	LSM_LIST	(sai_jig_t, target_owner, sai_jig_target_t, list,
			 NULL, lsm_sai_jig_target,		"targets"),
};

static const lws_struct_map_t lsm_jig_schema[] = {
        LSM_SCHEMA      (sai_jig_t, NULL, lsm_sai_jig,		"sai-jig"),
};

static const char * const jig_conf =
"{"
	"\"schema\":	\"sai-jig\","
	"\"port\":		44000,"
	"\"targets\":	["
		"{"
			"\"name\": \"linkit-7697-1\","
                	"\"gpios\": ["
                	        "{"
					"\"chip_index\":	0,"
					"\"name\":		\"nReset\","
                                	"\"offset\":	17,"
                                	"\"wire\":		\"RST\","
					"\"safe\":		0"
	                        "}, {"
					"\"name\":		\"usr\","
	                                "\"chip_index\":	0,"
                                	"\"offset\":	22,"
                                	"\"wire\":		\"P6\","
					"\"safe\":		0"
				"}"
                        "], \"sequences\": ["
                        	"{"
					"\"name\":		\"reset\","
					"\"seq\": ["
		                                "{ \"gpio_name\": \"nReset\", 	\"value\": 0 },"
		                                "{ \"gpio_name\": \"usr\",		\"value\": 0 },"
	        	                        "{				\"value\": 300 },"
		                                "{ \"gpio_name\": \"nReset\",	\"value\": 1 }"
					"]"
                        	"}, {"
					"\"name\":		\"flash\","
					"\"seq\": ["
		                                "{ \"gpio_name\": \"nReset\",	\"value\": 0 },"
		                                "{ \"gpio_name\": \"usr\",		\"value\": 1 },"
	        	                        "{				\"value\": 300 },"
		                                "{ \"gpio_name\": \"nReset\",	\"value\": 1 },"
	        	                        "{				\"value\": 100 },"
		                                "{ \"gpio_name\": \"usr\",		\"value\": 0 }"
					"]"
                        	"}"
                	"]"
		"}"
	"]"
"}";



extern int test2(void);

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
	"{" /* test 8 the "other" schema */
		"\"schema\":\"com-warmcat-sai-other\","
		"\"name\":\"somename\""
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
			",\"someflag\":false}]}",
	"{\"schema\":\"com-warmcat-sai-other\",\"name\":\"somename\"}"
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

/* the first kind of struct / schema we can receive */

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

/*
 * the second kind of struct / schema we can receive
 */

typedef struct sai_other {
	char 			name[32];
} sai_other_t;

static const lws_struct_map_t lsm_other[] = {
	LSM_CARRAY	(sai_other_t, name,		"name"),
};

/*
 * meta composed pointers test
 *
 * We serialize a struct that consists of members that point to other objects,
 * we expect this kind of thing
 *
 * {
 *   "schema": "meta",
 *   "t": { ... },
 *   "e": { ...}
 * }
 */

typedef struct meta {
	sai_target_t	*t;
	sai_builder_t	*b;
} meta_t;

static const lws_struct_map_t lsm_meta[] = {
	LSM_CHILD_PTR	(meta_t, t, sai_target_t, NULL, lsm_target, "t"),
	LSM_CHILD_PTR	(meta_t, b, sai_child_t, NULL, lsm_builder, "e"),
};

static const lws_struct_map_t lsm_schema_meta[] = {
	LSM_SCHEMA	(meta_t, NULL, lsm_meta, "meta.schema"),
};

/*
 * Schema table
 *
 * Before we can understand the serialization top level format, we must read
 * the schema, use the table below to create the right toplevel object for the
 * schema name, and select the correct map tables to interpret the rest of the
 * serialization.
 *
 * In this example there are two completely separate structs / schemas possible
 * to receive, and we disambiguate and create the correct one using the schema
 * JSON node.
 *
 * Therefore the schema table below is the starting point for the JSON
 * deserialization.
 */

static const lws_struct_map_t lsm_schema_map[] = {
	LSM_SCHEMA	(sai_builder_t, NULL,
			 lsm_builder,		"com-warmcat-sai-builder"),
	LSM_SCHEMA	(sai_other_t, NULL,
			 lsm_other,		"com-warmcat-sai-other"),
};

typedef struct sai_cancel {
	char task_uuid[65];
} sai_cancel_t;

const lws_struct_map_t lsm_task_cancel[] = {
	LSM_CARRAY	(sai_cancel_t, task_uuid,	 "uuid"),
};

static const lws_struct_map_t t2_map[] = {
	LSM_SCHEMA	(sai_cancel_t, NULL, lsm_task_cancel,
					      "com.warmcat.sai.taskinfo"),
	LSM_SCHEMA	(sai_cancel_t, NULL, lsm_task_cancel,
					      "com.warmcat.sai.eventinfo"),
	LSM_SCHEMA	(sai_cancel_t, NULL, lsm_task_cancel,
			/* shares struct */   "com.warmcat.sai.taskreset"),
	LSM_SCHEMA	(sai_cancel_t, NULL, lsm_task_cancel,
			/* shares struct */   "com.warmcat.sai.eventreset"),
	LSM_SCHEMA	(sai_cancel_t, NULL, lsm_task_cancel,
			/* shares struct */   "com.warmcat.sai.eventdelete"),
	LSM_SCHEMA	(sai_cancel_t,		 NULL, lsm_task_cancel,
					      "com.warmcat.sai.taskcan"),
};

static const char *t2 =
	"{\"schema\":\"com.warmcat.sai.taskcan\","
	 "\"uuid\": \"071ab46ab4296e5de674c628fec17c55088254679f7714ad991f8c4873dca\"}\x01\x02\xff\xff\xff\xff";

typedef struct xlws_wifi_creds {
	lws_dll2_t	list;
	char 		ssid[33];
	char		passphrase[64];
	int		alg;
	char		bssid[6];
} xlws_wifi_creds_t;

typedef struct xlws_netdevs {
	lws_dll2_owner_t	owner_creds;
} xlws_netdevs_t;

static const lws_struct_map_t lsm_wifi_creds[] = {
	LSM_CARRAY	(xlws_wifi_creds_t, ssid,		"ssid"),
	LSM_CARRAY	(xlws_wifi_creds_t, passphrase,		"passphrase"),
	LSM_UNSIGNED	(xlws_wifi_creds_t, alg,			"alg"),
	LSM_STRING_PTR	(xlws_wifi_creds_t, bssid,		"bssid"),
};

static const lws_struct_map_t lsm_netdev_credentials[] = {
	LSM_LIST	(xlws_netdevs_t, owner_creds, xlws_wifi_creds_t, list,
			 NULL, lsm_wifi_creds,			"credentials"),
};

static const lws_struct_map_t lsm_netdev_schema[] = {
	LSM_SCHEMA	(xlws_netdevs_t, NULL, lsm_netdev_credentials,
					      "com.warmcat.sai.taskinfo"),
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
	sai_builder_t *b, mb;
	sai_target_t mt;
	sai_other_t *o;
	const char *p;
	meta_t meta;

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
		n = lejp_parse(&ctx, (uint8_t *)json_tests[m],
						 (int)strlen(json_tests[m]));
		if (n < 0) {
			lwsl_err("%s: notification JSON decode failed '%s'\n",
					__func__, lejp_error_to_string(n));
			e++;
			goto done;
		}
		lwsac_info(a.ac);

		if (m + 1 != 8) {
			b = a.dest;
			if (!b) {
				lwsl_err("%s: didn't produce any output\n", __func__);
				e++;
				goto done;
			}

			if (a.top_schema_index) {
				lwsl_err("%s: wrong top_schema_index\n", __func__);
				e++;
				goto done;
			}

			lwsl_notice("builder.hostname = '%s', timeout = %d, targets (%d)\n",
				    b->hostname, b->nspawn_timeout,
				    b->targets.count);

			lws_dll2_foreach_safe(&b->targets, NULL, show_target);
		} else {
			o = a.dest;
			if (!o) {
				lwsl_err("%s: didn't produce any output\n", __func__);
				e++;
				goto done;
			}

			if (a.top_schema_index != 1) {
				lwsl_err("%s: wrong top_schema_index\n", __func__);
				e++;
				goto done;
			}

			lwsl_notice("other.name = '%s'\n", o->name);
		}

		/* 2. serialize the structs into JSON and confirm */

		lwsl_notice("%s:    .... starting serialization of test %d\n",
				__func__, m + 1);

		if (m + 1 != 8) {
			ser = lws_struct_json_serialize_create(lsm_schema_map,
						LWS_ARRAY_SIZE(lsm_schema_map),
						       0//LSSERJ_FLAG_PRETTY
						       , b);
		} else {
			ser = lws_struct_json_serialize_create(&lsm_schema_map[1],
						1,
						       0//LSSERJ_FLAG_PRETTY
						       , o);
		}
		if (!ser) {
			lwsl_err("%s: unable to init serialization\n", __func__);
			goto bail;
		}

		do {
			n = (int)lws_struct_json_serialize(ser, buf, sizeof(buf),
						      &written);
			switch (n) {
			case LSJS_RESULT_FINISH:
				puts((const char *)buf);
				break;
			case LSJS_RESULT_CONTINUE:
				lwsl_warn("%s: unexpected continue\n", __func__);
				goto bail;
			case LSJS_RESULT_ERROR:
				lwsl_warn("%s: error\n", __func__);
				goto bail;
			}
		} while (n == LSJS_RESULT_CONTINUE);

		if (strcmp(json_expected[m], (char *)buf)) {
			lwsl_err("%s: test %d: expected %s\n", __func__, m + 1,
					json_expected[m]);
			e++;
			goto done;
		}

		lws_struct_json_serialize_destroy(&ser);

done:
		lwsac_free(&a.ac);
	}

	if (e) {
		lwsl_warn("%s: error: %d\n", __func__, e);
		goto bail;
	}

	/* ad-hoc tests */

	memset(&meta, 0, sizeof(meta));
	memset(&mb, 0, sizeof(mb));
	memset(&mt, 0, sizeof(mt));

	meta.t = &mt;
	meta.b = &mb;

	meta.t->name = "mytargetname";
	lws_strncpy(meta.b->hostname, "myhostname", sizeof(meta.b->hostname));
	ser = lws_struct_json_serialize_create(lsm_schema_meta, 1, 0,
					       &meta);
	if (!ser) {
		lwsl_err("%s: failed to create json\n", __func__);


	}
	do {
		n = (int)lws_struct_json_serialize(ser, buf, sizeof(buf), &written);
		switch (n) {
		case LSJS_RESULT_CONTINUE:
		case LSJS_RESULT_FINISH:
			puts((const char *)buf);
			if (strcmp((const char *)buf,
				"{\"schema\":\"meta.schema\","
				"\"t\":{\"name\":\"mytargetname\","
					"\"someflag\":false},"
				"\"e\":{\"hostname\":\"myhostname\","
					"\"nspawn_timeout\":0}}")) {
				lwsl_err("%s: meta test fail\n", __func__);
				goto bail;
			}
			break;
		case LSJS_RESULT_ERROR:
			goto bail;
		}
	} while(n == LSJS_RESULT_CONTINUE);

	lws_struct_json_serialize_destroy(&ser);

	lwsl_notice("Test set 2\n");

	memset(&a, 0, sizeof(a));
	a.map_st[0] = t2_map;
	a.map_entries_st[0] = LWS_ARRAY_SIZE(t2_map);
	a.ac_block_size = 128;

	lws_struct_json_init_parse(&ctx, NULL, &a);
	m = lejp_parse(&ctx, (uint8_t *)t2, (int)strlen(t2));
	if (m < 0 || !a.dest) {
		lwsl_notice("%s: notification JSON decode failed '%s'\n",
				__func__, lejp_error_to_string(m));
		goto bail;
	}

	lwsl_notice("Test set 2: %d: %s\n", m,
			((sai_cancel_t *)a.dest)->task_uuid);

	lwsac_free(&a.ac);

	if (test2())
		goto bail;

	{
		lws_struct_serialize_t *js;
		xlws_wifi_creds_t creds;
		xlws_netdevs_t netdevs;
		unsigned char *buf;
		size_t w;
		int n;

		memset(&creds, 0, sizeof(creds));
		memset(&netdevs, 0, sizeof(netdevs));

		lws_strncpy(creds.ssid, "xxx", sizeof(creds.ssid));
		lws_strncpy(creds.passphrase, "yyy", sizeof(creds.passphrase));
		lws_dll2_add_tail(&creds.list, &netdevs.owner_creds);

		buf = malloc(2048); /* length should be computed */

		js = lws_struct_json_serialize_create(lsm_netdev_schema,
			LWS_ARRAY_SIZE(lsm_netdev_schema), 0, &netdevs);
		if (!js)
			goto bail;

		n = (int)lws_struct_json_serialize(js, buf, 2048, &w);
		lws_struct_json_serialize_destroy(&js);
		if (n != LSJS_RESULT_FINISH)
			goto bail;
		if (strcmp("{\"schema\":\"com.warmcat.sai.taskinfo\",\"credentials\":[{\"ssid\":\"xxx\",\"passphrase\":\"yyy\",\"alg\":0}]}", (const char *)buf)) {
			puts((const char *)buf);
			goto bail;
		}
		free(buf);
	}

	{
		struct x { lws_dll2_t list; const char *sz; };
		struct x x1, x2, *xp;
		lws_dll2_owner_t o;

		lws_dll2_owner_clear(&o);
		memset(&x1, 0, sizeof(x1));
		memset(&x2, 0, sizeof(x2));

		x1.sz = "nope";
		x2.sz = "yes";

		lws_dll2_add_tail(&x1.list, &o);
		lws_dll2_add_tail(&x2.list, &o);

		xp = lws_dll2_search_sz_pl(&o, "yes", 3, struct x, list, sz);
		if (xp != &x2) {
			lwsl_err("%s: 1 xp %p\n", __func__, xp);
			goto bail;
		}
		xp = lws_dll2_search_sz_pl(&o, "nope", 4, struct x, list, sz);
		if (xp != &x1) {
			lwsl_err("%s: 2 xp %p\n", __func__, xp);
			goto bail;
		}
		xp = lws_dll2_search_sz_pl(&o, "wrong", 4, struct x, list, sz);
		if (xp) {
			lwsl_err("%s: 3 xp %p\n", __func__, xp);
			goto bail;
		}
	}

	{
		lws_struct_args_t a;
		struct lejp_ctx ctx;
		int m;

		memset(&a, 0, sizeof(a));
		a.map_st[0] = lsm_jig_schema;
		a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_jig_schema);
		a.ac_block_size = 512;

		lws_struct_json_init_parse(&ctx, NULL, &a);

		m = lejp_parse(&ctx, (uint8_t *)jig_conf, (int)strlen(jig_conf));

		if (m < 0 || !a.dest) {
			lwsl_err("%s: line %d: JSON decode failed '%s'\n",
				    __func__, ctx.line, lejp_error_to_string(m));
			goto bail;
		}
	}

	{
		const char *inp = "{\"schema\":\"com.warmcat.sai.internal.taskinfo_auth\","
				  "\"ti\":{\"task_hash\":\"B8C26049D88F1AA4B6089E164F465A103A95D931D48A2EE8CC98CF9F70E03E31\","
				  		"\"logs\":1,\"js_api_version\":3,\"last_log_ts\":0},"
				  "\"auth_user\":\"andy@warmcat.com\",\"authorized\":1,\"auth_secs\":126478}";
		typedef struct sai_browse_rx_taskinfo {
			char            		task_hash[65];
			uint64_t        		last_log_ts;
			unsigned int    		log_start;
			unsigned int    		js_api_version;
			uint8_t         		logs;
		} sai_browse_rx_taskinfo_t;
		/*
		 * Internal message from sai-web -> sai-server, carrying browser auth
		 * context along with the original request from the browser.
		 */
		typedef struct sai_web_to_server_taskinfo {
			sai_browse_rx_taskinfo_t        *ti;
			char                            auth_user[33];
			int                             authorized;
			int                             auth_secs;
		} sai_web_to_server_taskinfo_t;
		const lws_struct_map_t lsm_browse_rx_taskinfo[] = {
			LSM_CARRAY         (sai_browse_rx_taskinfo_t, task_hash,           "task_hash"),
			LSM_UNSIGNED       (sai_browse_rx_taskinfo_t, logs,                "logs"),
			LSM_UNSIGNED       (sai_browse_rx_taskinfo_t, js_api_version,      "js_api_version"),
			LSM_UNSIGNED       (sai_browse_rx_taskinfo_t, last_log_ts,         "last_log_ts"),
		};
		const lws_struct_map_t lsm_web_to_server_taskinfo[] = {
			LSM_JO_CHILD_PTR   (sai_web_to_server_taskinfo_t, ti, sai_browse_rx_taskinfo_t,
						NULL, lsm_browse_rx_taskinfo,		   "ti"),
			LSM_CARRAY         (sai_web_to_server_taskinfo_t, auth_user,	   "auth_user"),
			LSM_SIGNED         (sai_web_to_server_taskinfo_t, authorized,	   "authorized"),
			LSM_SIGNED         (sai_web_to_server_taskinfo_t, auth_secs,	   "auth_secs"),
		};
		const lws_struct_map_t lsm_schema_json_map[] = {
			LSM_SCHEMA      (sai_web_to_server_taskinfo_t, NULL,
					lsm_web_to_server_taskinfo,
					"com.warmcat.sai.internal.taskinfo_auth"),
		};
		sai_web_to_server_taskinfo_t *wst;
		lws_struct_args_t a;
		struct lejp_ctx ctx;
		int n;

		lwsl_user("%s: taskinfo test\n", __func__);

		memset(&a, 0, sizeof(a));
		a.map_st[0]		= lsm_schema_json_map;
		a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_schema_json_map);
		a.map_entries_st[1]	= LWS_ARRAY_SIZE(lsm_schema_json_map);
		a.ac_block_size		= 128;

		lws_struct_json_init_parse(&ctx, NULL, &a);
		n = lejp_parse(&ctx, (uint8_t *)inp, (int)strlen(inp));
		if (n < 0 || !a.dest) {
			lwsl_notice("%s: notification JSON decode failed '%s'\n",
					__func__, lejp_error_to_string(n));
			goto bail;
		}

		wst = (sai_web_to_server_taskinfo_t *)a.dest;
		if (!wst->ti) {
			lwsl_warn("%s: ti (%p) not set\n", __func__, (void *)&wst->ti);
			goto bail;
		}
		if (!wst->ti->task_hash[0]) {
			lwsl_warn("%s: no task hash\n", __func__);
			goto bail;
		}
		if (!wst->authorized) {
			lwsl_warn("%s: authorized not set\n", __func__);
			goto bail;
		}

	}

	{
		typedef struct sai_active_task_info {
			lws_dll2_t              list;
			char                    task_uuid[65];
			char                    task_name[96];
			int                     build_step;
			int                     total_steps;
			unsigned int            est_peak_mem_kib;
			unsigned int            est_cpu_load_pct;
			unsigned int            est_disk_kib;
			uint64_t                started;
		} sai_active_task_info_t;

		typedef struct sai_load_report {
			lws_dll2_t              list; /* For queuing on sai_plat_server */
			char                    builder_name[64];
			int                     core_count;
			unsigned int            initial_free_ram_kib;
			unsigned int            reserved_ram_kib;
			unsigned int            initial_free_disk_kib;
			unsigned int            reserved_disk_kib;
			unsigned int            active_steps;
			unsigned int            cpu_percent;
			lws_dll2_owner_t        active_tasks;
		} sai_load_report_t;

		static const lws_struct_map_t lsm_active_task_info[] = {
			LSM_CARRAY      (sai_active_task_info_t, task_uuid, "task_uuid"),
			LSM_CARRAY      (sai_active_task_info_t, task_name, "task_name"),
			LSM_SIGNED      (sai_active_task_info_t, build_step, "build_step"),
			LSM_SIGNED      (sai_active_task_info_t, total_steps, "total_steps"),
			LSM_UNSIGNED    (sai_active_task_info_t, est_peak_mem_kib, "est_peak_mem_kib"),
			LSM_UNSIGNED    (sai_active_task_info_t, est_cpu_load_pct, "est_cpu_load_pct"),
			LSM_UNSIGNED    (sai_active_task_info_t, est_disk_kib, "est_disk_kib"),
			LSM_UNSIGNED    (sai_active_task_info_t, started, "started"),
		};

		static const lws_struct_map_t lsm_load_report_members[] = {
			LSM_CARRAY      (sai_load_report_t, builder_name, "builder_name"),
			LSM_SIGNED      (sai_load_report_t, core_count, "core_count"),
			LSM_UNSIGNED    (sai_load_report_t, initial_free_ram_kib, "initial_free_ram_kib"),
			LSM_UNSIGNED    (sai_load_report_t, reserved_ram_kib, "reserved_ram_kib"),
			LSM_UNSIGNED    (sai_load_report_t, initial_free_disk_kib, "initial_free_disk_kib"),
			LSM_UNSIGNED    (sai_load_report_t, reserved_disk_kib, "reserved_disk_kib"),
			LSM_UNSIGNED    (sai_load_report_t, active_steps, "active_steps"),
			LSM_UNSIGNED    (sai_load_report_t, cpu_percent, "cpu_percent"),
			LSM_LIST        (sai_load_report_t, active_tasks, sai_active_task_info_t, list,
					 NULL, lsm_active_task_info, "active_tasks"),
		};

		static const lws_struct_map_t lsm_schema_json_loadreport[] = {
		        LSM_SCHEMA      (sai_load_report_t, NULL, lsm_load_report_members, "com.warmcat.sai.loadreport"),
		};
		sai_active_task_info_t ati[5];
		sai_load_report_t lr;
		lws_struct_serialize_t *js;
		unsigned int ssf = LWSSS_FLAG_SOM;
		uint8_t buf[1024];
		size_t w = 0;
		int step = 0;

		memset(&ati, 0, sizeof(ati));
                memset(&lr, 0, sizeof(lr));

                lws_strncpy(lr.builder_name, "hello", sizeof(lr.builder_name));
                lr.core_count                   = 1;
                lr.initial_free_ram_kib         = 1234;
                lr.initial_free_disk_kib        = 4567;
                lr.reserved_ram_kib             = 0;
                lr.reserved_disk_kib            = 0;
                lr.cpu_percent                  = 33u;
                lr.active_steps                 = 0;
                lws_dll2_owner_clear(&lr.active_tasks);

		strcpy(ati[0].task_uuid, "0123456789012345678901234567890101234567890123456789012345678901");
		strcpy(ati[1].task_uuid, "0123456789012345678901234567890101234567890123456789012345678901");
		strcpy(ati[2].task_uuid, "0123456789012345678901234567890101234567890123456789012345678901");
		strcpy(ati[3].task_uuid, "0123456789012345678901234567890101234567890123456789012345678901");

		strcpy(ati[0].task_name, "task1");
		strcpy(ati[1].task_name, "task2");
		strcpy(ati[2].task_name, "task3");
		strcpy(ati[2].task_name, "task4");

		lws_dll2_add_tail(&ati[0].list, &lr.active_tasks);
		lws_dll2_add_tail(&ati[1].list, &lr.active_tasks);
		lws_dll2_add_tail(&ati[2].list, &lr.active_tasks);
		lws_dll2_add_tail(&ati[3].list, &lr.active_tasks);

		js = lws_struct_json_serialize_create(lsm_schema_json_loadreport, LWS_ARRAY_SIZE(lsm_schema_json_loadreport), 0, &lr);
		if (!js) {
			lwsl_warn("%s: failed to serialize\n", __func__);
			return -1;
		}

		/*
		 * This should come out in two pieces, one is CONTINUE and the
		 * other is FINISH
		 */

		do {
			switch (lws_struct_json_serialize(js, buf, sizeof(buf), &w)) {
				case LSJS_RESULT_CONTINUE:
					if (step != 0) {
						lwsl_err("%s: continue at wrong step\n", __func__);
						goto bail;
					}
					step++;
					lwsl_notice("%s: LSJS_RESULT_CONTINUE\n", __func__);
					break;
				case LSJS_RESULT_FINISH:
					if (step != 1) {
						lwsl_err("%s: finished too early\n", __func__);
						goto bail;
					}
					step++;
					lwsl_notice("%s: LSJS_RESULT_FINISH\n", __func__);
					ssf |= LWSSS_FLAG_EOM;
					break;
				case LSJS_RESULT_ERROR:
					lwsl_warn("%s: serialization failed\n", __func__);
					goto bail;
			}

			lwsl_notice("%s: QUEUEing %d bytes, ss_flags %d\n", __func__, (int)w, ssf);
			lwsl_hexdump_notice(buf, w);

			ssf &= ~((unsigned int)LWSSS_FLAG_SOM);
		} while (!(ssf & LWSSS_FLAG_EOM));

		lws_struct_json_serialize_destroy(&js);

		if (step != 2) {
			lwsl_err("%s: test should have two steps\n", __func__);
			goto bail;
		}
	}

	lwsl_user("Completed: PASS\n");

	return 0;

bail:

	lwsl_user("Completed: FAIL\n");

	return 1;
}
