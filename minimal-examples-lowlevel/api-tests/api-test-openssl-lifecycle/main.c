#include <libwebsockets.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

int
main(void)
{
	struct lws_context_creation_info info;
	struct lws_context *context;

	lws_context_info_defaults(&info, NULL);
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws_create_context failed\n");
		return 1;
	}

	lws_context_destroy(context);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL)) {
		lwsl_err("OpenSSL was cleaned up when the lws context was destroyed\n");
		return 1;
	}
#endif

	lwsl_user("OpenSSL remains available after lws context destruction\n");

	return 0;
}
