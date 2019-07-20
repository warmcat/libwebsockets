/*
 * lws-api-test-lws_tokenize
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the most minimal http server you can make with lws.
 *
 * To keep it simple, it serves stuff from the subdirectory 
 * "./mount-origin" of the directory it was started in.
 * You can change that by changing mount.origin below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

struct expected {
	lws_tokenize_elem e;
	const char *value;
	int len;
};

struct tests {
	const char *string;
	struct expected *exp;
	int count;
	int flags;
};

struct expected expected1[] = {
			{ LWS_TOKZE_TOKEN,		"protocol-1", 10 },
		{ LWS_TOKZE_DELIMITER, ",", 1},
			{ LWS_TOKZE_TOKEN,		"protocol_2", 10 },
		{ LWS_TOKZE_DELIMITER, ",", 1},
			{ LWS_TOKZE_TOKEN,		"protocol3", 9 },
		{ LWS_TOKZE_ENDED, NULL, 0 },
	},
	expected2[] = {
		{ LWS_TOKZE_TOKEN_NAME_COLON,		"Accept-Language", 15 },
			{ LWS_TOKZE_TOKEN,		"fr-CH", 5 },
		{ LWS_TOKZE_DELIMITER,			",", 1 },
			{ LWS_TOKZE_TOKEN,		"fr", 2 },
			{ LWS_TOKZE_DELIMITER,		";", 1},
			{ LWS_TOKZE_TOKEN_NAME_EQUALS,	"q", 1 },
			{ LWS_TOKZE_FLOAT,		"0.9", 3 },
		{ LWS_TOKZE_DELIMITER,			",", 1 },
			{ LWS_TOKZE_TOKEN,		"en", 2 },
			{ LWS_TOKZE_DELIMITER,		";", 1},
			{ LWS_TOKZE_TOKEN_NAME_EQUALS,	"q", 1 },
			{ LWS_TOKZE_FLOAT,		"0.8", 3 },
		{ LWS_TOKZE_DELIMITER,			",", 1 },
			{ LWS_TOKZE_TOKEN,		"de", 2 },
			{ LWS_TOKZE_DELIMITER,		";", 1},
			{ LWS_TOKZE_TOKEN_NAME_EQUALS,	"q", 1 },
			{ LWS_TOKZE_FLOAT,		"0.7", 3 },
		{ LWS_TOKZE_DELIMITER, ",", 1 },
			{ LWS_TOKZE_DELIMITER,		"*", 1 },
			{ LWS_TOKZE_DELIMITER,		";", 1 },
			{ LWS_TOKZE_TOKEN_NAME_EQUALS,	"q", 1 },
			{ LWS_TOKZE_FLOAT,		"0.5", 3 },
		{ LWS_TOKZE_ENDED, NULL, 0 },
	},
	expected3[] = {
			{ LWS_TOKZE_TOKEN_NAME_EQUALS,	"quoted", 6 },
			{ LWS_TOKZE_QUOTED_STRING,	"things:", 7 },
		{ LWS_TOKZE_DELIMITER,			",", 1 },
			{ LWS_TOKZE_INTEGER,		"1234", 4 },
		{ LWS_TOKZE_ENDED, NULL, 0 },
	},
	expected4[] = {
		{ LWS_TOKZE_ERR_COMMA_LIST,		",", 1 },
	},
	expected5[] = {
			{ LWS_TOKZE_TOKEN,		"brokenlist2", 11 },
		{ LWS_TOKZE_DELIMITER, ",", 1 },
		{ LWS_TOKZE_ERR_COMMA_LIST,		",", 1 },
	},
	expected6[] = {
			{ LWS_TOKZE_TOKEN,		"brokenlist3", 11 },
		{ LWS_TOKZE_DELIMITER, ",", 1 },
		{ LWS_TOKZE_ERR_COMMA_LIST,		",", 1 },

	},
	expected7[] = {
			{ LWS_TOKZE_TOKEN, "fr", 2 },
			{ LWS_TOKZE_DELIMITER, "-", 1 },
			{ LWS_TOKZE_TOKEN, "CH", 2 },
			{ LWS_TOKZE_DELIMITER, ",", 1 },
			{ LWS_TOKZE_TOKEN, "fr", 2 },
			{ LWS_TOKZE_DELIMITER, ";", 1 },
			{ LWS_TOKZE_TOKEN_NAME_EQUALS, "q", 1 },
			{ LWS_TOKZE_FLOAT, "0.9", 3 },
			{ LWS_TOKZE_DELIMITER, ",", 1 },
			{ LWS_TOKZE_TOKEN, "en", 2 },
			{ LWS_TOKZE_DELIMITER, ";", 1 },
			{ LWS_TOKZE_TOKEN_NAME_EQUALS, "q", 1 },
			{ LWS_TOKZE_FLOAT, "0.8", 3 },
			{ LWS_TOKZE_DELIMITER, ",", 1 },
			{ LWS_TOKZE_TOKEN, "de", 2 },
			{ LWS_TOKZE_DELIMITER, ";", 1 },
			{ LWS_TOKZE_TOKEN_NAME_EQUALS, "q", 1 },
			{ LWS_TOKZE_FLOAT, "0.7", 3 },
			{ LWS_TOKZE_DELIMITER, ",", 1 },
			{ LWS_TOKZE_TOKEN, "*", 1 },
			{ LWS_TOKZE_DELIMITER, ";", 1 },
			{ LWS_TOKZE_TOKEN_NAME_EQUALS, "q", 1 },
			{ LWS_TOKZE_FLOAT, "0.5", 3 },
			{ LWS_TOKZE_ENDED, "", 0 },
	},
	expected8[] = {
		{ LWS_TOKZE_TOKEN, "Οὐχὶ", 10 },
		{ LWS_TOKZE_TOKEN, "ταὐτὰ", 12 },
		{ LWS_TOKZE_TOKEN, "παρίσταταί", 22 },
		{ LWS_TOKZE_TOKEN, "μοι", 6 },
		{ LWS_TOKZE_TOKEN, "γιγνώσκειν", 21 },
		{ LWS_TOKZE_DELIMITER, ",", 1 },
		{ LWS_TOKZE_TOKEN, "ὦ", 3 },
		{ LWS_TOKZE_TOKEN, "ἄνδρες", 13 },
		{ LWS_TOKZE_TOKEN, "᾿Αθηναῖοι", 20 },
		{ LWS_TOKZE_DELIMITER, ",", 1 },
		{ LWS_TOKZE_TOKEN, "greek", 5 },
		{ LWS_TOKZE_ENDED, "", 0 },
	},
	expected9[] = {
		/*
		 *  because the tokenizer scans ahead for = aggregation,
		 * it finds the broken utf8 before reporting the token
		 */
		{ LWS_TOKZE_ERR_BROKEN_UTF8, "", 0 },
	},
	expected10[] = {
		{ LWS_TOKZE_TOKEN, "badutf8-2", 9 },
		{ LWS_TOKZE_TOKEN, "퟿", 3 },
		{ LWS_TOKZE_DELIMITER, ",", 1 },
		{ LWS_TOKZE_ERR_BROKEN_UTF8, "", 0 },
	},
	expected11[] = {
		{ LWS_TOKZE_TOKEN, "1.myserver", 10 },
		{ LWS_TOKZE_DELIMITER, ".", 1 },
		{ LWS_TOKZE_TOKEN, "com", 3 },
		{ LWS_TOKZE_ENDED, "", 0 },
	},
	expected12[] = {
		{ LWS_TOKZE_TOKEN, "1.myserver.com", 14 },
		{ LWS_TOKZE_ENDED, "", 0 },
	},
	expected13[] = {
		{ LWS_TOKZE_TOKEN, "1.myserver.com", 14 },
		{ LWS_TOKZE_ENDED, "", 0 },
	},
	expected14[] = {
		{ LWS_TOKZE_INTEGER, "1", 1 },
		{ LWS_TOKZE_DELIMITER, ".", 1 },
		{ LWS_TOKZE_TOKEN, "myserver", 8 },
		{ LWS_TOKZE_DELIMITER, ".", 1 },
		{ LWS_TOKZE_TOKEN, "com", 3 },
		{ LWS_TOKZE_ENDED, "", 0 },
	},
	expected15[] = {
		{ LWS_TOKZE_TOKEN, "close", 5 },
		{ LWS_TOKZE_DELIMITER, ",", 1 },
		{ LWS_TOKZE_TOKEN, "Upgrade", 7 },
		{ LWS_TOKZE_ENDED, "", 0 },
	},
	expected16[] = {
		{ LWS_TOKZE_TOKEN_NAME_EQUALS, "a", 1 },
		{ LWS_TOKZE_TOKEN, "5", 1 },
		{ LWS_TOKZE_ENDED, "", 0 },
	}

;

struct tests tests[] = {
	{
		" protocol-1, protocol_2\t,\tprotocol3\n",
		expected1, LWS_ARRAY_SIZE(expected1),
		LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_AGG_COLON
	}, {
		"Accept-Language: fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
		expected2, LWS_ARRAY_SIZE(expected2),
		LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_AGG_COLON
	}, {
		"quoted = \"things:\", 1234",
		expected3, LWS_ARRAY_SIZE(expected3),
		LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_AGG_COLON
	}, {
		", brokenlist1",
		expected4, LWS_ARRAY_SIZE(expected4),
		LWS_TOKENIZE_F_COMMA_SEP_LIST
	}, {
		"brokenlist2,,",
		expected5, LWS_ARRAY_SIZE(expected5),
		LWS_TOKENIZE_F_COMMA_SEP_LIST
	}, {
		"brokenlist3,",
		expected6, LWS_ARRAY_SIZE(expected6),
		LWS_TOKENIZE_F_COMMA_SEP_LIST
	}, {
		"fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
		expected7, LWS_ARRAY_SIZE(expected7),
		LWS_TOKENIZE_F_RFC7230_DELIMS
	},
	{
		" Οὐχὶ ταὐτὰ παρίσταταί μοι γιγνώσκειν, ὦ ἄνδρες ᾿Αθηναῖοι, greek",
		expected8, LWS_ARRAY_SIZE(expected8),
		LWS_TOKENIZE_F_RFC7230_DELIMS
	},
	{
		"badutf8-1 \x80...",
		expected9, LWS_ARRAY_SIZE(expected9),
		LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_RFC7230_DELIMS
	},
	{
		"badutf8-2 \xed\x9f\xbf,\x80...",
		expected10, LWS_ARRAY_SIZE(expected10),
		LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_RFC7230_DELIMS
	},
	{
		"1.myserver.com",
		expected11, LWS_ARRAY_SIZE(expected11),
		0
	},
	{
		"1.myserver.com",
		expected12, LWS_ARRAY_SIZE(expected12),
		LWS_TOKENIZE_F_DOT_NONTERM
	},
	{
		"1.myserver.com",
		expected13, LWS_ARRAY_SIZE(expected13),
		LWS_TOKENIZE_F_DOT_NONTERM | LWS_TOKENIZE_F_NO_FLOATS
	},
	{
		"1.myserver.com",
		expected14, LWS_ARRAY_SIZE(expected14),
		LWS_TOKENIZE_F_NO_FLOATS
	},
	{
		"close,  Upgrade",
		expected15, LWS_ARRAY_SIZE(expected15),
		LWS_TOKENIZE_F_COMMA_SEP_LIST
	},
	{
		"a=5", expected16, LWS_ARRAY_SIZE(expected16),
		LWS_TOKENIZE_F_NO_INTEGERS
	},
};

/*
 * add LWS_TOKZE_ERRS to the element index (which may be negative by that
 * amount) to index this array
 */

static const char *element_names[] = {
	"LWS_TOKZE_ERR_BROKEN_UTF8",
	"LWS_TOKZE_ERR_UNTERM_STRING",
	"LWS_TOKZE_ERR_MALFORMED_FLOAT",
	"LWS_TOKZE_ERR_NUM_ON_LHS",
	"LWS_TOKZE_ERR_COMMA_LIST",
	"LWS_TOKZE_ENDED",
	"LWS_TOKZE_DELIMITER",
	"LWS_TOKZE_TOKEN",
	"LWS_TOKZE_INTEGER",
	"LWS_TOKZE_FLOAT",
	"LWS_TOKZE_TOKEN_NAME_EQUALS",
	"LWS_TOKZE_TOKEN_NAME_COLON",
	"LWS_TOKZE_QUOTED_STRING",
};

int main(int argc, const char **argv)
{
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	const char *p;
	int n, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;
	int fail = 0, ok = 0, flags = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: lws_tokenize\n");

	if ((p = lws_cmdline_option(argc, argv, "-f")))
		flags = atoi(p);

	p = lws_cmdline_option(argc, argv, "-s");

	for (n = 0; n < (int)LWS_ARRAY_SIZE(tests); n++) {
		int m = 0, in_fail = fail;
		struct expected *exp = tests[n].exp;

		ts.start = tests[n].string;
		ts.len = strlen(ts.start);
		ts.flags = tests[n].flags;

		do {
			e = lws_tokenize(&ts);

			lwsl_info("{ %s, \"%.*s\", %d }\n",
				  element_names[e + LWS_TOKZE_ERRS],
				  (int)ts.token_len, ts.token,
				  (int)ts.token_len);

			if (m == (int)tests[n].count) {
				lwsl_notice("fail: expected end earlier\n");
				fail++;
				break;
			}

			if (e != exp->e) {
				lwsl_notice("fail... tok %s vs expected %s\n",
					element_names[e + LWS_TOKZE_ERRS],
					element_names[exp->e + LWS_TOKZE_ERRS]);
				fail++;
				break;
			}

			if (e > 0 &&
			    (ts.token_len != exp->len ||
			     memcmp(exp->value, ts.token, exp->len))) {
				lwsl_notice("fail token mismatch %d %d %.*s\n",
						ts.token_len, exp->len, ts.token_len, ts.token);
				fail++;
				break;
			}

			m++;
			exp++;

		} while (e > 0);

		if (fail == in_fail)
			ok++;
	}

	if (p) {
		ts.start = p;
		ts.len = strlen(p);
		ts.flags = flags;

		printf("\t{\n\t\t\"%s\",\n"
		       "\t\texpected%d, LWS_ARRAY_SIZE(expected%d),\n\t\t",
		       p, (int)LWS_ARRAY_SIZE(tests) + 1,
		       (int)LWS_ARRAY_SIZE(tests) + 1);

		if (!flags)
			printf("0\n\t},\n");
		else {
			if (flags & LWS_TOKENIZE_F_MINUS_NONTERM)
				printf("LWS_TOKENIZE_F_MINUS_NONTERM");
			if (flags & LWS_TOKENIZE_F_AGG_COLON) {
				if (flags & 1)
					printf(" | ");
				printf("LWS_TOKENIZE_F_AGG_COLON");
			}
			if (flags & LWS_TOKENIZE_F_COMMA_SEP_LIST) {
				if (flags & 3)
					printf(" | ");
				printf("LWS_TOKENIZE_F_COMMA_SEP_LIST");
			}
			if (flags & LWS_TOKENIZE_F_RFC7230_DELIMS) {
				if (flags & 7)
					printf(" | ");
				printf("LWS_TOKENIZE_F_RFC7230_DELIMS");
			}
			if (flags & LWS_TOKENIZE_F_DOT_NONTERM) {
				if (flags & 15)
					printf(" | ");
				printf("LWS_TOKENIZE_F_DOT_NONTERM");
			}
			if (flags & LWS_TOKENIZE_F_NO_FLOATS) {
				if (flags & 31)
					printf(" | ");
				printf("LWS_TOKENIZE_F_NO_FLOATS");
			}
			printf("\n\t},\n");
		}

		printf("\texpected%d[] = {\n", (int)LWS_ARRAY_SIZE(tests) + 1);

		do {
			e = lws_tokenize(&ts);

			printf("\t\t{ %s, \"%.*s\", %d },\n",
				  element_names[e + LWS_TOKZE_ERRS],
				  (int)ts.token_len,
				  ts.token, (int)ts.token_len);

		} while (e > 0);

		printf("\t}\n");
	}


	lwsl_user("Completed: PASS: %d, FAIL: %d\n", ok, fail);

	return !(ok && !fail);
}
