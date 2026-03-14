/*
 * lws-crypto-x509
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_ALG,
	LWS_SW_C,
	LWS_SW_D,
	LWS_SW_P,
	LWS_SW_T,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_ALG]	= { "--alg",           "Set custom 'alg' parameter in output JWK" },
	[LWS_SW_C]	= { "-c",              "Path to the X.509 certificate PEM file" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_P]	= { "-p",              "Path to the matching private key PEM file" },
	[LWS_SW_T]	= { "-t",              "Path to a trusted root CA certificate for verification" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information (-h, --help)" },
};

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

static int
read_pem(const char *filename, char *pembuf, int pembuf_len)
{
	int n, fd = open(filename, LWS_O_RDONLY);
	if (fd == -1)
		return -1;

	n = (int)read(fd, pembuf, (unsigned int)pembuf_len - 1);
	close(fd);

	pembuf[n++] = '\0';

	return n;
}

static int
read_pem_c509_cert(struct lws_x509_cert **x509, const char *filename,
		   char *pembuf, int pembuf_len)
{
	int n;

	n = read_pem(filename, pembuf, pembuf_len);
	if (n < 0)
		return -1;

	if (lws_x509_create(x509)) {
		lwsl_err("%s: failed to create x509\n", __func__);

		return -1;
	}

	if (lws_x509_parse_from_pem(*x509, pembuf, (unsigned int)n) < 0) {
		lwsl_err("%s: unable to parse PEM %s\n", __func__, filename);
		lws_x509_destroy(x509);

		return -1;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	int n, result = 1, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_x509_cert *x509 = NULL, *x509_trusted = NULL;
	struct lws_context_creation_info info;
	struct lws_context *context;
	struct lws_jwk jwk;
	char pembuf[6144];
	const char *p;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, "-h") || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}


	memset(&jwk, 0, sizeof(jwk));

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS X509 api example\n");

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


	p = lws_cmdline_option(argc, argv, switches[LWS_SW_C].sw);
	if (!p) {
		lwsl_err("%s: missing -c <cert pem file>\n", __func__);
		goto bail;
	}
	if (read_pem_c509_cert(&x509, p, pembuf, sizeof(pembuf))) {
		lwsl_err("%s: unable to read \"%s\": errno %d\n",
			 __func__, p, errno);
		goto bail;
	}

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_T].sw);
	if (p) {

		if (read_pem_c509_cert(&x509_trusted, p, pembuf,
				       sizeof(pembuf))) {
			lwsl_err("%s: unable to read \"%s\": errno %d\n",
				 __func__, p, errno);
			goto bail1;
		}

		lwsl_notice("%s: certs loaded OK\n", __func__);

		if (lws_x509_verify(x509, x509_trusted, NULL)) {
			lwsl_err("%s: verify failed\n", __func__);
			goto bail2;
		}

		lwsl_notice("%s: verified OK\n", __func__);
	}

	if (x509_trusted) {

		/* show the trusted cert public key as a JWK */

		if (lws_x509_public_to_jwk(&jwk, x509_trusted,
					   "P-256,P-384,P-521", 4096)) {
			lwsl_err("%s: unable to get trusted cert pubkey as JWK\n",
				 __func__);

			goto bail2;
		}

		if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_ALG].sw)))
			lws_jwk_strdup_meta(&jwk, JWK_META_ALG, p, (int)strlen(p));

		lwsl_info("JWK version of trusted cert:\n");
		lws_jwk_dump(&jwk);
		lws_jwk_destroy(&jwk);
	}

	/* get the cert public key as a JWK */

	if (lws_x509_public_to_jwk(&jwk, x509, "P-256,P-384,P-521", 4096)) {
		lwsl_err("%s: unable to get cert pubkey as JWK\n", __func__);

		goto bail3;
	}
	lwsl_info("JWK version of cert:\n");

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_ALG].sw)))
		lws_jwk_strdup_meta(&jwk, JWK_META_ALG, p, (int)strlen(p));

	lws_jwk_dump(&jwk);
	/* only print public if he doesn't provide private */
	if (!lws_cmdline_option(argc, argv, switches[LWS_SW_P].sw)) {
		lwsl_notice("Issuing Cert Public JWK on stdout\n");
		n = sizeof(pembuf);
		if (lws_jwk_export(&jwk, 0, pembuf, &n))
			puts(pembuf);
	}

	/* if we know where the cert private key is, add that to the cert JWK */

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_P].sw);
	if (p) {
		n = read_pem(p, pembuf, sizeof(pembuf));
		if (n < 0) {
			lwsl_err("%s: unable read privkey %s\n", __func__, p);

			goto bail3;
		}
		if (lws_x509_jwk_privkey_pem(context, &jwk, pembuf,
						(unsigned int)n, NULL)) {
			lwsl_err("%s: unable to parse privkey %s\n",
					__func__, p);

			goto bail3;
		}

		if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_ALG].sw)))
			lws_jwk_strdup_meta(&jwk, JWK_META_ALG, p, (int)strlen(p));

		lwsl_info("JWK version of cert + privkey:\n");
		lws_jwk_dump(&jwk);
		lwsl_notice("Issuing Cert + Private JWK on stdout\n");
		n = sizeof(pembuf);
		if (lws_jwk_export(&jwk, LWSJWKF_EXPORT_PRIVATE, pembuf, &n))
			puts(pembuf);
	}

	result = 0;

bail3:
	lws_jwk_destroy(&jwk);
bail2:
	lws_x509_destroy(&x509_trusted);
bail1:
	lws_x509_destroy(&x509);
bail:
	lws_context_destroy(context);

	if (result)
		lwsl_err("%s: failed\n", __func__);
	else
		lwsl_notice("%s: OK\n", __func__);

	return result;
}
