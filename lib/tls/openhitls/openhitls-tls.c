/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * openHiTLS TLS context and global initialization
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

void
lws_tls_err_describe_clear(void)
{
	const char *file = NULL;
	uint32_t line = 0;
	int32_t err;

	do {
		err = BSL_ERR_PeekErrorFileLine(&file, &line);
		if (!err) {
			break;
		}

		BSL_ERR_GetErrorFileLine(&file, &line);
		lwsl_info("   openhitls error: 0x%x (%s:%u)\n",
			  (unsigned int)err, file ? file : "?",
			  (unsigned int)line);
	} while (err);
	lwsl_info("\n");
}

#if LWS_MAX_SMP != 1

static void
lws_openssl_lock_callback(int mode, int type, const char *file, int line)
{
	/* openHiTLS does not support this locking mechanism */
	(void)file;
	(void)line;
	(void)mode;
	(void)type;
}

static unsigned long
lws_openssl_thread_id(void)
{
	/* openHiTLS does not support this threading mechanism */
	return 0;
}
#endif

int
lws_context_init_ssl_library(struct lws_context *cx,
                             const struct lws_context_creation_info *info)
{
	int ret;

	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT)) {
		lwsl_cx_info(cx, " SSL disabled: no "
			"LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT");
		return 0;
	}


	ret = BSL_ERR_Init();
	if (ret != BSL_SUCCESS) {
		lwsl_cx_err(cx, "BSL_ERR_Init failed: 0x%x", ret);
		return 1;
	}

	ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
	if (ret != CRYPT_SUCCESS) {
		lwsl_cx_err(cx, "CRYPT_EAL_Init failed: 0x%x", ret);
		return 1;
	}

#if defined(LWS_WITH_NETWORK)
	/* openHiTLS does not require ex indexes like OpenSSL */
#endif

#if LWS_MAX_SMP != 1
		/*
		 * openHiTLS does not support this locking mechanism
		 */

		(void)lws_openssl_thread_id;
		(void)lws_openssl_lock_callback;
#endif

	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{
#if LWS_MAX_SMP != 1
	if (!lws_check_opt(context->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return;
#endif
	(void)context;
	/* openHiTLS does not require global cleanup */
}

int
lws_openhitls_apply_tls_version_by_ssl_options(HITLS_Config *config, long set,
					       long clear, const char *who)
{
	unsigned long long no_tls12 = !!((unsigned long long)set &
					 (unsigned long long)SSL_OP_NO_TLSv1_2) &&
				    !((unsigned long long)clear &
				      (unsigned long long)SSL_OP_NO_TLSv1_2);
	unsigned long long no_tls13 = !!((unsigned long long)set &
					 (unsigned long long)SSL_OP_NO_TLSv1_3) &&
				    !((unsigned long long)clear &
				      (unsigned long long)SSL_OP_NO_TLSv1_3);

	if (no_tls12 && no_tls13) {
		lwsl_err("%s: SSL_OP_NO_TLSv1_2 and SSL_OP_NO_TLSv1_3 cannot "
			 "both be active\n", who);
		return -1;
	}

	if (no_tls13) {
		if (HITLS_CFG_SetVersion(config, HITLS_VERSION_TLS12,
					 HITLS_VERSION_TLS12) != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_SetVersion(TLS1.2) failed\n",
				 who);
			return -1;
		}
	} else if (no_tls12) {
		if (HITLS_CFG_SetVersion(config, HITLS_VERSION_TLS13,
					 HITLS_VERSION_TLS13) != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_SetVersion(TLS1.3) failed\n",
				 who);
			return -1;
		}
	}

	return 0;
}
