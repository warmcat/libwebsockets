/*
 * lws-crypto-jwk
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_ALG,
	LWS_SW_CURVE,
	LWS_SW_KEY_OPS,
	LWS_SW_KID,
	LWS_SW_PUBLIC,
	LWS_SW_USE,
	LWS_SW_B,
	LWS_SW_C,
	LWS_SW_D,
	LWS_SW_T,
	LWS_SW_V,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_ALG]	= { "--alg",           "Set the 'alg' JWS algorithm (e.g. RS256)" },
	[LWS_SW_CURVE]	= { "--curve",         "Set the EC curve (e.g. P-256)" },
	[LWS_SW_KEY_OPS]	= { "--key-ops",       "Set the 'key_ops' (e.g. sign, verify)" },
	[LWS_SW_KID]	= { "--kid",           "Set the 'kid' Key ID" },
	[LWS_SW_PUBLIC]	= { "--public",        "Output public key only to specified file" },
	[LWS_SW_USE]	= { "--use",           "Set the 'use' intended usage (e.g. sig)" },
	[LWS_SW_B]	= { "-b",              "Number of bits to generate (e.g. 2048, 4096)" },
	[LWS_SW_C]	= { "-c",              "Format output as C array for header files" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_T]	= { "-t",              "Key type to generate (RSA, EC, OCT)" },
	[LWS_SW_V]	= { "-v",              "Alias for --curve" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information (-h, --help)" },
};

#include <sys/types.h>
#include <fcntl.h>

/*
 * handles escapes and line wrapping suitable for use
 * defining a C char array ( -c option )
 */

static int
format_c(int fd, const char *key)
{
	const char *k = key;
	int seq = 0;

	while (*k) {
		if (*k == '{') {
			if (write(fd, "\"{\"\n\t\"", 6) < 6)
				return -1;
			k++;
			seq = 0;
			continue;
		}
		if (*k == '}') {
			if (write(fd, "\"\n\"}\"\n", 6) < 6)
				return -1;
			k++;
			seq = 0;
			continue;
		}
		if (*k == '\"') {
			if (write(fd, "\\\"", 2) < 2)
				return -1;
			seq += 2;
			k++;
			continue;
		}
		if (*k == ',') {
			if (write(fd, ",\"\n\t\"", 5) < 5)
				return -1;
			k++;
			seq = 0;
			continue;
		}
		if (write(fd, k, 1) < 1)
			return -1;
		seq++;
		if (seq >= 60) {
			if (write(fd, "\"\n\t \"", 5) < 5)
				return -1;
			seq = 1;
		}
		k++;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	int result = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	enum lws_gencrypto_kty kty = LWS_GENCRYPTO_KTY_RSA;
	struct lws_context_creation_info info;
	const char *curve = "P-256", *p;
	struct lws_context *context;
	struct lws_jwk jwk;
	int bits = 4096;
	char key[32768];
	int vl = sizeof(key);
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, "-h") || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}


	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS JWK example\n");

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_B].sw)))
		bits = atoi(p);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_CURVE].sw)))
		curve = p;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_T].sw))) {
		if (!strcmp(p, "RSA"))
			kty = LWS_GENCRYPTO_KTY_RSA;
		else
			if (!strcmp(p, "OCT"))
				kty = LWS_GENCRYPTO_KTY_OCT;
			else
				if (!strcmp(p, "EC"))
					kty = LWS_GENCRYPTO_KTY_EC;
				else {
					lwsl_err("Unknown key type (must be "
						 "OCT, RSA or EC)\n");

					return 1;
				}
	}

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_V].sw)))
		curve = p;

	if (lws_jwk_generate(context, &jwk, kty, bits, curve)) {
		lwsl_err("lws_jwk_generate failed\n");

		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_KID].sw)))
		lws_jwk_strdup_meta(&jwk, JWK_META_KID, p, (int)strlen(p));

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_USE].sw)))
		lws_jwk_strdup_meta(&jwk, JWK_META_USE, p, (int)strlen(p));

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_ALG].sw)))
		lws_jwk_strdup_meta(&jwk, JWK_META_ALG, p, (int)strlen(p));

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_KEY_OPS].sw)))
		lws_jwk_strdup_meta(&jwk, JWK_META_KEY_OPS, p, (int)strlen(p));

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PUBLIC].sw)) &&
	    kty != LWS_GENCRYPTO_KTY_OCT) {

		int fd;

		/* public version */

		if (lws_jwk_export(&jwk, LWSJWKF_EXPORT_NOCRLF, key, &vl) < 0) {
			lwsl_err("lws_jwk_export failed\n");

			return 1;
		}

		fd = open(p, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0600);
		if (fd < 0) {
			lwsl_err("Can't open public key file %s\n", p);
			return 1;
		}

		if (lws_cmdline_option(argc, argv, switches[LWS_SW_C].sw))
			format_c(fd, key);
		else {
			if (write(fd, key,
#if defined(WIN32)
					(unsigned int)
#endif
					strlen(key)) < 0) {
				lwsl_err("Write public failed\n");
				return 1;
			}
		}

		close(fd);
	}

	/* private version */

	if (lws_jwk_export(&jwk, LWSJWKF_EXPORT_NOCRLF | LWSJWKF_EXPORT_PRIVATE, key, &vl) < 0) {
		lwsl_err("lws_jwk_export failed\n");

		return 1;
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_C].sw)) {
		if (format_c(1, key) < 0)
			return 1;
	} else
		if (write(1, key,
#if defined(WIN32)
				(unsigned int)
#endif
				strlen(key)) < 0) {
			lwsl_err("Write stdout failed\n");
			return 1;
		}

	lws_jwk_destroy(&jwk);

	lws_context_destroy(context);

	return result;
}
