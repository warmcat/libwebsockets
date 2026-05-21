/*
 * lws-api-test-jose
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
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

int
test_jwk(struct lws_context *context);
int
test_jws(struct lws_context *context);
int
test_jwe(struct lws_context *context);

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int result = 0;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}



	lwsl_user("LWS JOSE api tests\n");

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	result |= test_jwk(context);
	lwsl_notice("%d\n", result);
	result |= test_jws(context);
	lwsl_notice("%d\n", result);
	result |= test_jwe(context);
	lwsl_notice("%d\n", result);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	lws_context_destroy(context);

	return result;
}
