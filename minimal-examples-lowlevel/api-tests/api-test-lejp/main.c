/*
 * lws-api-test-lejp
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * sanity tests for lejp
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
	"{" /* test 8 the "other" schema */
		"\"schema\":\"com-warmcat-sai-logs\","
		"\"task_uuid\":\"97fc90052506af8b3eb43b87aaa6fb76feab32bc128ede479a8a6b961e801f06\","
		"\"timestamp\": 170366786103,\"channel\":3, \"len\":20, "
		"\"log\": \"PnNhaWI+IE5TU1RBVEVfSU5JVAo=\"}\x0a"
		"ntu-xenial-amd64\"},{\"name\":\"linux-ubuntu-bionic-amd64\"},{\"name\":\"linux-fedora-32-x86_64\"}]}\",",

	"{" /* test 9, empty object */
		"\"a\":123,\"b\":{}"
	"}",

	"{" /* SHOULD_FAIL: test 10, missing open */
		"\"a\":123,\"b\":}"
	"}",

	"{" /* test 11: array of arrays */
		"\"array1\": [[\"a\", \"b\", \"b1\"], [\"c\", \"d\", \"d1\"]],"
		"\"array2\": [[\"e\", \"f\", \"f1\"], [\"g\", \"h\", \"h1\"]]"
	"}",

	"{" /* test 12: test 11 but done with LEJP_FLAG_FEAT_OBJECT_INDEXES  */
		"\"array1\": [[\"a\", \"b\", \"b1\"], [\"c\", \"d\", \"d1\"]],"
		"\"array2\": [[\"e\", \"f\", \"f1\"], [\"g\", \"h\", \"h1\"]]"
	"}",

	"{" /* test 13: float vs int */
		"\"a\": 1, \"b\": 1.0, \"c\": 1e-3, \"d\": 1e3"
	"}",
	"{}" /* test 14: empty body */
};

static struct lejp_results {
	int		reason;
	int		ipos;
	int		path_match;
	uint16_t		indexes[12];
	const char	*path;
	const char	*buf;
} r1[] = {
	{ 0, 0, 0, { 0 }, "", "" },
	{ 2, 0, 0, { 0 }, "", "" },
	{ 16, 0, 0, { 0 }, "", "" },
	{ 5, 0, 0, { 0 }, "schema", "" },
	{ 11, 0, 0, { 0 }, "schema", "" },
	{ 77, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
	{ 5, 0, 0, { 0 }, "hostname", "com-warmcat-sai-builder" },
	{ 11, 0, 0, { 0 }, "hostname", "" },
	{ 77, 0, 0, { 0 }, "hostname", "learn" },
	{ 5, 0, 0, { 0 }, "nspawn_timeout", "learn" },
	{ 73, 0, 0, { 0 }, "nspawn_timeout", "1800" },
	{ 5, 0, 0, { 0 }, "targets", "1800" },
	{ 14, 0, 0, { 0 }, "targets[]", "1800" },
	{ 16, 1, 0, { 0,  }, "targets[]", "1800" },
	{ 5, 1, 0, { 0,  }, "targets[].name", "1800" },
	{ 11, 1, 0, { 0,  }, "targets[].name", "" },
	{ 77, 1, 0, { 0,  }, "targets[].name", "target1" },
	{ 5, 1, 0, { 0,  }, "targets[].someflag", "target1" },
	{ 70, 1, 0, { 0,  }, "targets[].someflag", "1" },
	{ 17, 1, 0, { 0,  }, "targets[]", "1" },
	{ 16, 1, 0, { 1,  }, "targets[]", "1" },
	{ 5, 1, 0, { 1,  }, "targets[].name", "1" },
	{ 11, 1, 0, { 1,  }, "targets[].name", "" },
	{ 77, 1, 0, { 1,  }, "targets[].name", "target2" },
	{ 5, 1, 0, { 1,  }, "targets[].someflag", "target2" },
	{ 71, 1, 0, { 1,  }, "targets[].someflag", "0" },
	{ 17, 1, 0, { 1,  }, "targets[]", "0" },
	{ 15, 1, 0, { 1,  }, "targets[]", "0" },
	{ 17, 1, 0, { 1,  }, "targets[]", "0" },
	{ 3, 1, 0, { 1,  }, "targets[]", "0" },
}, r2[] = {
	{ 0, 0, 0, { 0 }, "", "0" },
	{ 2, 0, 0, { 0 }, "", "0" },
	{ 16, 0, 0, { 0 }, "", "0" },
	{ 5, 0, 0, { 0 }, "schema", "0" },
	{ 11, 0, 0, { 0 }, "schema", "" },
	{ 77, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
	{ 5, 0, 0, { 0 }, "hostname", "com-warmcat-sai-builder" },
	{ 11, 0, 0, { 0 }, "hostname", "" },
	{ 77, 0, 0, { 0 }, "hostname", "learn" },
	{ 5, 0, 0, { 0 }, "targets", "learn" },
	{ 14, 0, 0, { 0 }, "targets[]", "learn" },
	{ 16, 1, 0, { 0,  }, "targets[]", "learn" },
	{ 5, 1, 0, { 0,  }, "targets[].name", "learn" },
	{ 11, 1, 0, { 0,  }, "targets[].name", "" },
	{ 77, 1, 0, { 0,  }, "targets[].name", "target1" },
	{ 17, 1, 0, { 0,  }, "targets[]", "target1" },
	{ 16, 1, 0, { 1,  }, "targets[]", "target1" },
	{ 5, 1, 0, { 1,  }, "targets[].name", "target1" },
	{ 11, 1, 0, { 1,  }, "targets[].name", "" },
	{ 77, 1, 0, { 1,  }, "targets[].name", "target2" },
	{ 17, 1, 0, { 1,  }, "targets[]", "target2" },
	{ 16, 1, 0, { 2,  }, "targets[]", "target2" },
	{ 5, 1, 0, { 2,  }, "targets[].name", "target2" },
	{ 11, 1, 0, { 2,  }, "targets[].name", "" },
	{ 77, 1, 0, { 2,  }, "targets[].name", "target3" },
	{ 17, 1, 0, { 2,  }, "targets[]", "target3" },
	{ 15, 1, 0, { 2,  }, "targets[]", "target3" },
	{ 17, 1, 0, { 2,  }, "targets[]", "target3" },
	{ 3, 1, 0, { 2,  }, "targets[]", "target3" },
}, r3[] = {
	{ 0, 0, 0, { 0 }, "", "target3" },
	{ 2, 0, 0, { 0 }, "", "target3" },
	{ 16, 0, 0, { 0 }, "", "target3" },
	{ 5, 0, 0, { 0 }, "schema", "target3" },
	{ 11, 0, 0, { 0 }, "schema", "" },
	{ 77, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
	{ 5, 0, 0, { 0 }, "hostname", "com-warmcat-sai-builder" },
	{ 11, 0, 0, { 0 }, "hostname", "" },
	{ 77, 0, 0, { 0 }, "hostname", "learn" },
	{ 5, 0, 0, { 0 }, "nspawn_timeout", "learn" },
	{ 73, 0, 0, { 0 }, "nspawn_timeout", "1800" },
	{ 5, 0, 0, { 0 }, "targets", "1800" },
	{ 14, 0, 0, { 0 }, "targets[]", "1800" },
	{ 16, 1, 0, { 0,  }, "targets[]", "1800" },
	{ 5, 1, 0, { 0,  }, "targets[].name", "1800" },
	{ 11, 1, 0, { 0,  }, "targets[].name", "" },
	{ 77, 1, 0, { 0,  }, "targets[].name", "target1" },
	{ 5, 1, 0, { 0,  }, "targets[].unrecognized", "target1" },
	{ 11, 1, 0, { 0,  }, "targets[].unrecognized", "" },
	{ 77, 1, 0, { 0,  }, "targets[].unrecognized", "xyz" },
	{ 5, 1, 0, { 0,  }, "targets[].child", "xyz" },
	{ 16, 1, 0, { 0,  }, "targets[].child", "xyz" },
	{ 5, 1, 0, { 0,  }, "targets[].child.somename", "xyz" },
	{ 11, 1, 0, { 0,  }, "targets[].child.somename", "" },
	{ 77, 1, 0, { 0,  }, "targets[].child.somename", "abc" },
	{ 5, 1, 0, { 0,  }, "targets[].child.junk", "abc" },
	{ 16, 1, 0, { 0,  }, "targets[].child.junk", "abc" },
	{ 5, 1, 0, { 0,  }, "targets[].child.junk.x", "abc" },
	{ 11, 1, 0, { 0,  }, "targets[].child.junk.x", "" },
	{ 77, 1, 0, { 0,  }, "targets[].child.junk.x", "y" },
	{ 17, 1, 0, { 0,  }, "targets[].child.junk", "y" },
	{ 17, 1, 0, { 0,  }, "targets[].child", "y" },
	{ 17, 1, 0, { 0,  }, "targets[]", "y" },
	{ 16, 1, 0, { 1,  }, "targets[]", "y" },
	{ 5, 1, 0, { 1,  }, "targets[].name", "y" },
	{ 11, 1, 0, { 1,  }, "targets[].name", "" },
	{ 77, 1, 0, { 1,  }, "targets[].name", "target2" },
	{ 17, 1, 0, { 1,  }, "targets[]", "target2" },
	{ 15, 1, 0, { 1,  }, "targets[]", "target2" },
	{ 17, 1, 0, { 1,  }, "targets[]", "target2" },
	{ 3, 1, 0, { 1,  }, "targets[]", "target2" },
}, r4[] = {
	{ 0, 0, 0, { 0 }, "", "target2" },
	{ 2, 0, 0, { 0 }, "", "target2" },
	{ 16, 0, 0, { 0 }, "", "target2" },
	{ 5, 0, 0, { 0 }, "schema", "target2" },
	{ 11, 0, 0, { 0 }, "schema", "" },
	{ 77, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
	{ 5, 0, 0, { 0 }, "hostname", "com-warmcat-sai-builder" },
	{ 11, 0, 0, { 0 }, "hostname", "" },
	{ 77, 0, 0, { 0 }, "hostname", "learn" },
	{ 5, 0, 0, { 0 }, "nspawn_timeout", "learn" },
	{ 73, 0, 0, { 0 }, "nspawn_timeout", "1800" },
	{ 17, 0, 0, { 0 }, "nspawn_timeout", "1800" },
	{ 3, 0, 0, { 0 }, "nspawn_timeout", "1800" },
}, r5[] = {
	{ 0, 0, 0, { 0 }, "", "1800" },
	{ 2, 0, 0, { 0 }, "", "1800" },
	{ 16, 0, 0, { 0 }, "", "1800" },
	{ 5, 0, 0, { 0 }, "schema", "1800" },
	{ 11, 0, 0, { 0 }, "schema", "" },
	{ 77, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
	{ 17, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
	{ 3, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
}, r6[] = {
	{ 0, 0, 0, { 0 }, "", "com-warmcat-sai-builder" },
	{ 2, 0, 0, { 0 }, "", "com-warmcat-sai-builder" },
	{ 16, 0, 0, { 0 }, "", "com-warmcat-sai-builder" },
	{ 5, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
	{ 11, 0, 0, { 0 }, "schema", "" },
	{ 77, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
	{ 5, 0, 0, { 0 }, "hostname", "com-warmcat-sai-builder" },
	{ 11, 0, 0, { 0 }, "hostname", "" },
	{ 76, 0, 0, { 0 }, "hostname", "PYvtan6kqppjnS0KpYTCaiOLsJkc7XecAr1kcE0aCIciewYB+JcLG82mO1Vb1mJtjDwUjBxy2I6AzefzoWUWmqZbsv4MXR55j9bKlyz1liiSX63iO0x6JAwACMtE2MkgcLwR86TSWAD9D1QKIWqg5RJ/CRuVsW0DKAUMD52ql4JmPFuJpJgTq28z6PhYNzN3yI3bmQt6bzhA+A/xAsFzSBnb3MHYWzGMprr53FAP1ISo5Ec9i+2ehV40sG6Q47" },
	{ 76, 0, 0, { 0 }, "hostname", "0sH3PGQZ0YRPO7Sh/SyrSQ/scONmxRc3AcXl7X/CSs417ii+CV8sq3ZgcxKNB7tNfN7idNx3upZ00G2BZy9jSy03cLKKLNaNUt0TQsxXbH55uDHzSEeZWvxJgT6zB1NoMhdC02w+oXim94M6z6COCnqT3rgkGk8PHMry9Bkh4yVpRmzIRfMmln/lEhdZgxky2+g5hhlSIGJYDCrdynD9kCfvfy6KGOpNIi1X+mhbbWn4lnL9ZKihL/RrfOV+oV" },
	{ 76, 0, 0, { 0 }, "hostname", "4R26IDq+KqUiJBENeo8/GXkGLUH/87iPyzXKEMavr6fkrK0vTGto8yEYxmOyaVz8phG5rwf4jJgmYNoMbGo8gWvhqO7UAGy2g7MWv+B/t1eZZ+1euLsNrWAsFJiFbQKgdFfQT3RjB14iU8knlQ8usoy+pXssY2ddGJGVcGC21oZvstK9eu1eRZftda/wP+N5unT1Hw7kCoVzqxHieiYt47EGIOaaQ7XjZDK6qPN6O/grHnvJZm2vBkxuXgsYVk" },
	{ 76, 0, 0, { 0 }, "hostname", "RQ7AuTWIecphqFsq7Wbc1YNbMW47SVU5zMD0WaCqbaaI0t4uIzRvPlD8cpiiTzFTrEHlIBTf8/uZjjEGGLhJR1jPqA9D1Ej3ChV+ye6F9JTUMlozRMsGuF8U4btDzH5xdnmvRS4Ar6LKEtAXGkj2yuyJln+v4RIWj2xOGPJovOqiXwi0FyM61f8U8gj0OiNA2/QlvrqQVDF7sMXgjvaE7iQt5vMETteZlx+z3f+jTFM/aon511W4+ZkRD+6AHw" },
	{ 77, 0, 0, { 0 }, "hostname", "ucvM9BEC" },
	{ 17, 0, 0, { 0 }, "hostname", "ucvM9BEC" },
	{ 3, 0, 0, { 0 }, "hostname", "ucvM9BEC" },
}, r7[] = {
	{ 0, 0, 0, { 0 }, "", "ucvM9BEC" },
	{ 2, 0, 0, { 0 }, "", "ucvM9BEC" },
	{ 16, 0, 0, { 0 }, "", "ucvM9BEC" },
	{ 5, 0, 0, { 0 }, "schema", "ucvM9BEC" },
	{ 11, 0, 0, { 0 }, "schema", "" },
	{ 77, 0, 0, { 0 }, "schema", "com-warmcat-sai-builder" },
	{ 5, 0, 0, { 0 }, "targets", "com-warmcat-sai-builder" },
	{ 14, 0, 0, { 0 }, "targets[]", "com-warmcat-sai-builder" },
	{ 16, 1, 0, { 0,  }, "targets[]", "com-warmcat-sai-builder" },
	{ 5, 1, 0, { 0,  }, "targets[].name", "com-warmcat-sai-builder" },
	{ 11, 1, 0, { 0,  }, "targets[].name", "" },
	{ 76, 1, 0, { 0,  }, "targets[].name", "PYvtan6kqppjnS0KpYTCaiOLsJkc7XecAr1kcE0aCIciewYB+JcLG82mO1Vb1mJtjDwUjBxy2I6AzefzoWUWmqZbsv4MXR55j9bKlyz1liiSX63iO0x6JAwACMtE2MkgcLwR86TSWAD9D1QKIWqg5RJ/CRuVsW0DKAUMD52ql4JmPFuJpJgTq28z6PhYNzN3yI3bmQt6bzhA+A/xAsFzSBnb3MHYWzGMprr53FAP1ISo5Ec9i+2ehV40sG6Q47" },
	{ 76, 1, 0, { 0,  }, "targets[].name", "0sH3PGQZ0YRPO7Sh/SyrSQ/scONmxRc3AcXl7X/CSs417ii+CV8sq3ZgcxKNB7tNfN7idNx3upZ00G2BZy9jSy03cLKKLNaNUt0TQsxXbH55uDHzSEeZWvxJgT6zB1NoMhdC02w+oXim94M6z6COCnqT3rgkGk8PHMry9Bkh4yVpRmzIRfMmln/lEhdZgxky2+g5hhlSIGJYDCrdynD9kCfvfy6KGOpNIi1X+mhbbWn4lnL9ZKihL/RrfOV+oV" },
	{ 76, 1, 0, { 0,  }, "targets[].name", "4R26IDq+KqUiJBENeo8/GXkGLUH/87iPyzXKEMavr6fkrK0vTGto8yEYxmOyaVz8phG5rwf4jJgmYNoMbGo8gWvhqO7UAGy2g7MWv+B/t1eZZ+1euLsNrWAsFJiFbQKgdFfQT3RjB14iU8knlQ8usoy+pXssY2ddGJGVcGC21oZvstK9eu1eRZftda/wP+N5unT1Hw7kCoVzqxHieiYt47EGIOaaQ7XjZDK6qPN6O/grHnvJZm2vBkxuXgsYVk" },
	{ 76, 1, 0, { 0,  }, "targets[].name", "RQ7AuTWIecphqFsq7Wbc1YNbMW47SVU5zMD0WaCqbaaI0t4uIzRvPlD8cpiiTzFTrEHlIBTf8/uZjjEGGLhJR1jPqA9D1Ej3ChV+ye6F9JTUMlozRMsGuF8U4btDzH5xdnmvRS4Ar6LKEtAXGkj2yuyJln+v4RIWj2xOGPJovOqiXwi0FyM61f8U8gj0OiNA2/QlvrqQVDF7sMXgjvaE7iQt5vMETteZlx+z3f+jTFM/aon511W4+ZkRD+6AHw" },
	{ 77, 1, 0, { 0,  }, "targets[].name", "ucvM9BEC" },
	{ 17, 1, 0, { 0,  }, "targets[]", "ucvM9BEC" },
	{ 15, 1, 0, { 0,  }, "targets[]", "ucvM9BEC" },
	{ 17, 1, 0, { 0,  }, "targets[]", "ucvM9BEC" },
	{ 3, 1, 0, { 0,  }, "targets[]", "ucvM9BEC" },
}, r8[] = {
	{ 0, 0, 0, { 0 }, "", "ucvM9BEC" },
	{ 2, 0, 0, { 0 }, "", "ucvM9BEC" },
	{ 16, 0, 0, { 0 }, "", "ucvM9BEC" },
	{ 5, 0, 0, { 0 }, "schema", "ucvM9BEC" },
	{ 11, 0, 0, { 0 }, "schema", "" },
	{ 77, 0, 0, { 0 }, "schema", "com-warmcat-sai-logs" },
	{ 5, 0, 0, { 0 }, "task_uuid", "com-warmcat-sai-logs" },
	{ 11, 0, 0, { 0 }, "task_uuid", "" },
	{ 77, 0, 0, { 0 }, "task_uuid", "97fc90052506af8b3eb43b87aaa6fb76feab32bc128ede479a8a6b961e801f06" },
	{ 5, 0, 0, { 0 }, "timestamp", "97fc90052506af8b3eb43b87aaa6fb76feab32bc128ede479a8a6b961e801f06" },
	{ 73, 0, 0, { 0 }, "timestamp", "170366786103" },
	{ 5, 0, 0, { 0 }, "channel", "170366786103" },
	{ 73, 0, 0, { 0 }, "channel", "3" },
	{ 5, 0, 0, { 0 }, "len", "3" },
	{ 73, 0, 0, { 0 }, "len", "20" },
	{ 5, 0, 0, { 0 }, "log", "20" },
	{ 11, 0, 0, { 0 }, "log", "" },
	{ 77, 0, 0, { 0 }, "log", "PnNhaWI+IE5TU1RBVEVfSU5JVAo=" },
	{ 17, 0, 0, { 0 }, "log", "PnNhaWI+IE5TU1RBVEVfSU5JVAo=" },
	{ 3, 0, 0, { 0 }, "log", "PnNhaWI+IE5TU1RBVEVfSU5JVAo=" },
}, r9[] = {
	{ 0, 0, 0, { 0 }, "", "PnNhaWI+IE5TU1RBVEVfSU5JVAo=" },
	{ 2, 0, 0, { 0 }, "", "PnNhaWI+IE5TU1RBVEVfSU5JVAo=" },
	{ 16, 0, 0, { 0 }, "", "PnNhaWI+IE5TU1RBVEVfSU5JVAo=" },
	{ 5, 0, 0, { 0 }, "a", "PnNhaWI+IE5TU1RBVEVfSU5JVAo=" },
	{ 73, 0, 0, { 0 }, "a", "123" },
	{ 5, 0, 0, { 0 }, "b", "123" },
	{ 16, 0, 0, { 0 }, "b", "123" },
	{ 17, 0, 0, { 0 }, "b", "123" },
	{ 17, 0, 0, { 0 }, "b", "123" },
	{ 3, 0, 0, { 0 }, "b", "123" },
}, r10[] = {
	{ 0, 0, 0, { 0 }, "", "123" },
	{ 2, 0, 0, { 0 }, "", "123" },
	{ 16, 0, 0, { 0 }, "", "123" },
	{ 5, 0, 0, { 0 }, "a", "123" },
	{ 73, 0, 0, { 0 }, "a", "123" },
	{ 5, 0, 0, { 0 }, "b", "123" },
	{ 4, 0, 0, { 0 }, "b", "123" },
}, r11[] = {
	{ 0, 0, 0, { 0 }, "", "123" },
	{ 2, 0, 0, { 0 }, "", "123" },
	{ 16, 0, 0, { 0 }, "", "123" },
	{ 5, 0, 0, { 0 }, "array1", "123" },
	{ 14, 0, 2, { 0 }, "array1[]", "123" },
	{ 14, 1, 1, { 0,  }, "array1[][]", "123" },
	{ 11, 2, 1, { 0, 0,  }, "array1[][]", "" },
	{ 77, 2, 1, { 0, 0,  }, "array1[][]", "a" },
	{ 11, 2, 1, { 0, 1,  }, "array1[][]", "" },
	{ 77, 2, 1, { 0, 1,  }, "array1[][]", "b" },
	{ 11, 2, 1, { 0, 2,  }, "array1[][]", "" },
	{ 77, 2, 1, { 0, 2,  }, "array1[][]", "b1" },
	{ 15, 1, 2, { 0,  }, "array1[]", "b1" },
	{ 14, 1, 1, { 1,  }, "array1[][]", "b1" },
	{ 11, 2, 1, { 1, 0,  }, "array1[][]", "" },
	{ 77, 2, 1, { 1, 0,  }, "array1[][]", "c" },
	{ 11, 2, 1, { 1, 1,  }, "array1[][]", "" },
	{ 77, 2, 1, { 1, 1,  }, "array1[][]", "d" },
	{ 11, 2, 1, { 1, 2,  }, "array1[][]", "" },
	{ 77, 2, 1, { 1, 2,  }, "array1[][]", "d1" },
	{ 15, 1, 2, { 1,  }, "array1[]", "d1" },
	{ 15, 1, 2, { 1,  }, "array1[]", "d1" },
	{ 5, 1, 0, { 1,  }, "array2", "d1" },
	{ 14, 1, 2, { 1,  }, "array2[]", "d1" },
	{ 14, 2, 1, { 1, 0,  }, "array2[][]", "d1" },
	{ 11, 3, 1, { 1, 0, 0,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 0, 0,  }, "array2[][]", "e" },
	{ 11, 3, 1, { 1, 0, 1,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 0, 1,  }, "array2[][]", "f" },
	{ 11, 3, 1, { 1, 0, 2,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 0, 2,  }, "array2[][]", "f1" },
	{ 15, 2, 2, { 1, 0,  }, "array2[]", "f1" },
	{ 14, 2, 1, { 1, 1,  }, "array2[][]", "f1" },
	{ 11, 3, 1, { 1, 1, 0,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 1, 0,  }, "array2[][]", "g" },
	{ 11, 3, 1, { 1, 1, 1,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 1, 1,  }, "array2[][]", "h" },
	{ 11, 3, 1, { 1, 1, 2,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 1, 2,  }, "array2[][]", "h1" },
	{ 15, 2, 2, { 1, 1,  }, "array2[]", "h1" },
	{ 15, 2, 2, { 1, 1,  }, "array2[]", "h1" },
	{ 17, 2, 0, { 1, 1,  }, "array2[]", "h1" },
	{ 3, 2, 0, { 1, 1,  }, "array2[]", "h1" },
}, r12[] = { /* test 11 but done with LEJP_FLAG_FEAT_OBJECT_INDEXES */
	{ 0, 0, 0, { 0 }, "", "h1" },
	{ 2, 0, 0, { 0 }, "", "h1" },
	{ 16, 1, 0, { 0, }, "", "h1" },
	{ 5, 1, 0, { 0, }, "array1", "h1" },
	{ 14, 1, 2, { 0, }, "array1[]", "h1" },
	{ 14, 2, 1, { 0, 0, }, "array1[][]", "h1" },
	{ 11, 3, 1, { 0, 0, 0,  }, "array1[][]", "" },
	{ 77, 3, 1, { 0, 0, 0,  }, "array1[][]", "a" },
	{ 11, 3, 1, { 0, 0, 1,  }, "array1[][]", "" },
	{ 77, 3, 1, { 0, 0, 1,  }, "array1[][]", "b" },
	{ 11, 3, 1, { 0, 0, 2,  }, "array1[][]", "" },
	{ 77, 3, 1, { 0, 0, 2,  }, "array1[][]", "b1" },
	{ 15, 2, 2, { 0, 0,  }, "array1[]", "b1" },
	{ 14, 2, 1, { 0, 1,  }, "array1[][]", "b1" },
	{ 11, 3, 1, { 0, 1, 0,  }, "array1[][]", "" },
	{ 77, 3, 1, { 0, 1, 0,  }, "array1[][]", "c" },
	{ 11, 3, 1, { 0, 1, 1,  }, "array1[][]", "" },
	{ 77, 3, 1, { 0, 1, 1,  }, "array1[][]", "d" },
	{ 11, 3, 1, { 0, 1, 2,  }, "array1[][]", "" },
	{ 77, 3, 1, { 0, 1, 2,  }, "array1[][]", "d1" },
	{ 15, 2, 2, { 0, 1,  }, "array1[]", "d1" },
	{ 15, 1, 2, { 0, 1,  }, "array1[]", "d1" },
	{ 5, 1, 0, { 1,  }, "array2", "d1" },
	{ 14, 1, 2, { 1,  }, "array2[]", "d1" },
	{ 14, 2, 1, { 1, 0,  }, "array2[][]", "d1" },
	{ 11, 3, 1, { 1, 0, 0,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 0, 0,  }, "array2[][]", "e" },
	{ 11, 3, 1, { 1, 0, 1,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 0, 1,  }, "array2[][]", "f" },
	{ 11, 3, 1, { 1, 0, 2,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 0, 2,  }, "array2[][]", "f1" },
	{ 15, 2, 2, { 1, 0,  }, "array2[]", "f1" },
	{ 14, 2, 1, { 1, 1,  }, "array2[][]", "f1" },
	{ 11, 3, 1, { 1, 1, 0,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 1, 0,  }, "array2[][]", "g" },
	{ 11, 3, 1, { 1, 1, 1,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 1, 1,  }, "array2[][]", "h" },
	{ 11, 3, 1, { 1, 1, 2,  }, "array2[][]", "" },
	{ 77, 3, 1, { 1, 1, 2,  }, "array2[][]", "h1" },
	{ 15, 2, 2, { 1, 1,  }, "array2[]", "h1" },
	{ 15, 1, 2, { 1,  }, "array2[]", "h1" },
	{ 17, 1, 0, { 1, }, "array2[]", "h1" },
	{ 3, 1, 0, { 1,  }, "array2[]", "h1" },
}, r13[] = {
	{ 0, 0, 0, {  }, "", "h1" },
	{ 2, 0, 0, {  }, "", "h1" },
	{ 16, 0, 0, { 0,  }, "", "h1" },
	{ 5, 0, 0, { 0,  }, "a", "h1" },
	{ 73, 0, 0, { 0,  }, "a", "1" },
	{ 5, 0, 0, { 1,  }, "b", "1" },
	{ 74, 0, 0, { 1,  }, "b", "1.0" },
	{ 5, 0, 0, { 2,  }, "c", "1.0" },
	{ 74, 0, 0, { 2,  }, "c", "1e-3" },
	{ 5, 0, 0, { 3,  }, "d", "1e-3" },
	{ 74, 0, 0, { 3,  }, "d", "1e3" },
	{ 17, 0, 0, { 3,  }, "d", "1e3" },
	{ 3, 0, 0, { 3,  }, "d", "1e3" },
}, r14[] = {
	{ 0, 0, 0, {  }, "", "1e3" },
	{ 2, 0, 0, {  }, "", "1e3" },
	{ 16, 0, 0, {  }, "", "1e3" },
	{ 17, 0, 0, {  }, "", "1e3" },
	{ 3, 0, 0, {  }, "", "1e3" },
};

static const char * const tok[] = {
	"something",
}, * const tok_test11[] = { /* matches for test 11, 12 */
	"*[][]",
	"*[]",
};

struct lejp_results_pkg {
	const struct lejp_results *r;
	size_t			  len;
	const char		  * const *tokens;
	size_t			  tokens_len;
	uint16_t		  ctx_flags;
} rpkg[] = {
	{ r1, LWS_ARRAY_SIZE(r1), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r2, LWS_ARRAY_SIZE(r2), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r3, LWS_ARRAY_SIZE(r3), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r4, LWS_ARRAY_SIZE(r4), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r5, LWS_ARRAY_SIZE(r5), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r6, LWS_ARRAY_SIZE(r6), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r7, LWS_ARRAY_SIZE(r7), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r8, LWS_ARRAY_SIZE(r8), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r9, LWS_ARRAY_SIZE(r9), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r10, LWS_ARRAY_SIZE(r10), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r11, LWS_ARRAY_SIZE(r11), tok_test11, LWS_ARRAY_SIZE(tok_test11),
			LEJP_FLAG_FEAT_LEADING_WC},
	{ r12, LWS_ARRAY_SIZE(r12), tok_test11, LWS_ARRAY_SIZE(tok_test11),
			LEJP_FLAG_FEAT_LEADING_WC |
			LEJP_FLAG_FEAT_OBJECT_INDEXES },
	{ r13, LWS_ARRAY_SIZE(r13), tok, LWS_ARRAY_SIZE(tok), 0 },
	{ r14, LWS_ARRAY_SIZE(r14), tok, LWS_ARRAY_SIZE(tok), 0 },
};


static unsigned int m, step;



static signed char
test_cb(struct lejp_ctx *ctx, char reason)
{
	char i[128];
	int n, t = 0;

	i[0] = 0;
	for (n = 0; n < ctx->ipos; n++)
		t += lws_snprintf(i + t, sizeof(i) - (size_t)t - 1ul, "%d, ", ctx->i[n]);

	lwsl_notice("{ %d, %d, %d, { %s }, \"%s\", \"%s\" },\n", reason, ctx->ipos, ctx->path_match, i, ctx->path, ctx->buf);

	if (m < LWS_ARRAY_SIZE(rpkg)) {
		if (step < rpkg[m].len) {
			// lwsl_notice("test %d, step %d\n", m, step);
			if (reason != rpkg[m].r[step].reason) {
				lwsl_err("%s: reason mismatch %d vs %d\n", __func__, reason, rpkg[m].r[step].reason);
				return -1;
			}
			if (ctx->ipos != rpkg[m].r[step].ipos) {
				lwsl_err("%s: ipos mismatch %d vs %d\n", __func__, ctx->ipos, rpkg[m].r[step].ipos);
				return -1;
			}
			if (ctx->ipos && memcmp(ctx->i, rpkg[m].r[step].indexes, ctx->ipos)) {
				lwsl_err("%s: indexes mismatch\n", __func__);
				lwsl_hexdump_err(ctx->i, ctx->ipos);
				lwsl_hexdump_err(rpkg[m].r[step].indexes, ctx->ipos);
				return -1;
			}
			if (ctx->path_match != rpkg[m].r[step].path_match) {
				lwsl_err("%s: path_match mismatch %d vs %d\n", __func__, ctx->path_match, rpkg[m].r[step].path_match);
				return -1;
			}
			if (strcmp(ctx->path, rpkg[m].r[step].path)) {
				lwsl_err("%s: path mismatch '%s' vs '%s'\n", __func__, ctx->path, rpkg[m].r[step].path);
				return -1;
			}
			if (strcmp(ctx->buf, rpkg[m].r[step].buf)) {
				lwsl_err("%s: buf mismatch '%s' vs '%s'\n", __func__, ctx->buf, rpkg[m].r[step].buf);
				return -1;
			}
		} else {
			lwsl_err("%s: extra steps\n", __func__);
			return -1;
		}

		step++;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	int n, e = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lejp_ctx ctx;
	const char *p;

	memset(&ctx, 0, sizeof(ctx));

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: lws_struct JSON\n");

	for (m = 0; m < (int)LWS_ARRAY_SIZE(json_tests); m++) {

		lwsl_user("%s: ++++++++++++++++ test %d\n", __func__, m + 1);
		step = 0;

		lejp_construct(&ctx, test_cb, NULL, rpkg[m].tokens, (uint8_t)rpkg[m].tokens_len);
		ctx.flags = rpkg[m].ctx_flags;

		lwsl_hexdump_info(json_tests[m], strlen(json_tests[m]));

		if (m == 7)
			n = lejp_parse(&ctx, (uint8_t *)json_tests[m],
							 0xc8);
		else
			n = lejp_parse(&ctx, (uint8_t *)json_tests[m],
						 (int)strlen(json_tests[m]));

		lwsl_info("n = %d\n", n);
		if (n < 0 && m != 9) {
			lwsl_err("%s: test %d: JSON decode failed '%s'\n",
					__func__, m + 1, lejp_error_to_string(n));
			e++;
		}
		if (n >= 0 && m == 9) {
			lwsl_err("%s: test %d: JSON decode should have failed '%s'\n",
					__func__, m + 1, lejp_error_to_string(n));
			e++;
		}
	}

	{
		const char *cs;
		size_t cslen;
		cs = lws_json_simple_find("{\"blah\":123,\"ext\":{\"authorized\":1}}", 35,
					    "\"ext\":", &cslen);
		if (!cs) {
			lwsl_err("%s: simple_find failed\n", __func__);
			e++;
		} else {
			if (lws_json_simple_strcmp(cs, cslen,
					"\"authorized\":", "1"))
				e++;
		}
		cs = lws_json_simple_find("{\"blah\":123,\"auth_user\":\"andy@warmcat.com\",\"thing\":\"yeah\"}", 57,
					    "\"auth_user\":", &cslen);
		if (cslen != 16) {
			lwsl_err("%s: wrong string len %d isolated\n", __func__, (int)cslen);
			e++;
		}
	}

	if (e)
		goto bail;

	lwsl_user("Completed: PASS\n");

	return 0;

bail:
	lwsl_user("Completed: FAIL\n");

	return 1;
}
