/*
 * lws-api-test-x509-info
 *
 * Written in 2010-2024 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests for lws_x509_info() API
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <string.h>

static void
print_hex(const char *label, const uint8_t *data, int len)
{
	char buf[256], *p = buf;
	size_t offset;
	int i;

	p += lws_snprintf(p, sizeof(buf), "%s (%d bytes): ", label, len);
	for (i = 0; i < len && i < 32 && p < buf + sizeof(buf) - 4; i++) {
		offset = (size_t)(p - buf);
		p += lws_snprintf(p, sizeof(buf) - offset, "%02x", data[i]);
	}
	if (len > 32) {
		offset = (size_t)(p - buf);
		p += lws_snprintf(p, sizeof(buf) - offset, "...");
	}
	lwsl_user("%s", buf);
}

static void
test_cert_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type, const char *name)
{
	char big[4096];
	union lws_tls_cert_info_results *buf = (union lws_tls_cert_info_results *)big;
	int ret;

	memset(big, 0, sizeof(big));
	ret = lws_x509_info(x509, type, buf, sizeof(big) - sizeof(*buf) + sizeof(buf->ns.name));
	lwsl_user("\n=== %s ===", name);
	lwsl_user("Return: %d", ret);
	if (ret == 0) {
		switch (type) {
		case LWS_TLS_CERT_INFO_VALIDITY_FROM:
		case LWS_TLS_CERT_INFO_VALIDITY_TO:
			lwsl_user("Time: %lld", (long long)buf->time);
			break;
		case LWS_TLS_CERT_INFO_USAGE:
			lwsl_user("Usage: 0x%08x", buf->usage);
			break;
		case LWS_TLS_CERT_INFO_COMMON_NAME:
		case LWS_TLS_CERT_INFO_ISSUER_NAME:
			lwsl_user("String: '%s' (len=%d)", buf->ns.name, buf->ns.len);
			break;
		case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
		case LWS_TLS_CERT_INFO_DER_RAW:
		case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID:
		case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL:
		case LWS_TLS_CERT_INFO_SUBJECT_KEY_ID:
			print_hex("Data", (uint8_t *)buf->ns.name, buf->ns.len);
			break;
		case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER:
			lwsl_user("Issuer: '%s' (len=%d)", buf->ns.name, buf->ns.len);
			break;
		default:
			break;
		}
	} else if (ret == 1) {
		lwsl_user("Not present");
	} else {
		lwsl_user("Error");
	}
}

#if defined(LWS_WITH_OPENHITLS)
static int
expect_cert_info_string(struct lws_x509_cert *x509,
			enum lws_tls_cert_info type, const char *name,
			const char *needle)
{
	char big[4096];
	union lws_tls_cert_info_results *buf =
		(union lws_tls_cert_info_results *)big;
	size_t len = sizeof(big) - sizeof(*buf) + sizeof(buf->ns.name);
	int ret;

	memset(big, 0, sizeof(big));
	ret = lws_x509_info(x509, type, buf, len);
	if (ret) {
		lwsl_err("%s: %s returned %d", __func__, name, ret);
		return 1;
	}

	if (!buf->ns.len || !strstr(buf->ns.name, needle)) {
		lwsl_err("%s: %s missing '%s' in '%s'", __func__, name,
			 needle, buf->ns.name);
		return 1;
	}

	return 0;
}

static int
expect_cert_info_small_buffer(struct lws_x509_cert *x509,
			      enum lws_tls_cert_info type, const char *name)
{
	char small[sizeof(union lws_tls_cert_info_results) + 2];
	union lws_tls_cert_info_results *buf =
		(union lws_tls_cert_info_results *)small;
	int ret;

	memset(small, 0, sizeof(small));
	ret = lws_x509_info(x509, type, buf, 2);
	if (ret != -1) {
		lwsl_err("%s: %s small buffer returned %d", __func__, name,
			 ret);
		return 1;
	}

	return 0;
}
#endif

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	struct lws_x509_cert *x509 = NULL;
	char cert_path[512];
	char pem[8192];
	const char *cert_dir = ".";
	const char *p;
	FILE *fp;
	size_t len;
	int ret, fail = 0;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	if ((p = lws_cmdline_option(argc, argv, "-d"))) {
		logs = atoi(p);
	}
	if ((p = lws_cmdline_option(argc, argv, "-c"))) {
		cert_dir = p;
	}
	lws_set_log_level(logs, NULL);
	lwsl_user("LWS X509 info api tests");
	lwsl_user("Certificate directory: %s", cert_dir);
	lws_snprintf(cert_path, sizeof(cert_path), "%s/x509-content.crt", cert_dir);
	lwsl_user("Certificate: %s", cert_path);
	fp = fopen(cert_path, "rb");
	if (!fp) {
		lwsl_err("Failed to open %s", cert_path);
		return 1;
	}
	len = fread(pem, 1, sizeof(pem) - 1, fp);
	fclose(fp);
	pem[len] = '\0';
	memset(&info, 0, sizeof info);
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed");
		return 1;
	}
	ret = lws_x509_create(&x509);
	if (ret) {
		lwsl_err("lws_x509_create failed with code %d", ret);
		lws_context_destroy(context);
		return 1;
	}
	ret = lws_x509_parse_from_pem(x509, pem, len + 1);
	if (ret) {
		lwsl_err("lws_x509_parse_from_pem failed with code %d", ret);
		lws_x509_destroy(&x509);
		lws_context_destroy(context);
		return 1;
	}
	lwsl_user("Certificate parsed successfully");
	test_cert_info(x509, LWS_TLS_CERT_INFO_VALIDITY_FROM, "VALIDITY_FROM");
	test_cert_info(x509, LWS_TLS_CERT_INFO_VALIDITY_TO, "VALIDITY_TO");
	test_cert_info(x509, LWS_TLS_CERT_INFO_COMMON_NAME, "COMMON_NAME");
	test_cert_info(x509, LWS_TLS_CERT_INFO_ISSUER_NAME, "ISSUER_NAME");
	test_cert_info(x509, LWS_TLS_CERT_INFO_USAGE, "USAGE");
	test_cert_info(x509, LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY, "OPAQUE_PUBLIC_KEY");
	test_cert_info(x509, LWS_TLS_CERT_INFO_DER_RAW, "DER_RAW");
	test_cert_info(x509, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID, "AUTHORITY_KEY_ID");
	test_cert_info(x509, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER, "AUTHORITY_KEY_ID_ISSUER");
	test_cert_info(x509, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL, "AUTHORITY_KEY_ID_SERIAL");
	test_cert_info(x509, LWS_TLS_CERT_INFO_SUBJECT_KEY_ID, "SUBJECT_KEY_ID");
#if defined(LWS_WITH_OPENHITLS)
	fail |= expect_cert_info_string(x509,
			LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER,
			"AUTHORITY_KEY_ID_ISSUER", "Test CA");
	fail |= expect_cert_info_small_buffer(x509,
			LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER,
			"AUTHORITY_KEY_ID_ISSUER");
#endif
	lws_x509_destroy(&x509);
	lwsl_user("\n---");
	lwsl_user("Completed: %s", fail ? "FAIL" : "PASS");
	lws_context_destroy(context);
	return fail;
}
