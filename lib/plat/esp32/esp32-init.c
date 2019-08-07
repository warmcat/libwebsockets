/*
 * libwebsockets - lib/plat/lws-plat-esp32.c
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "core/private.h"

int
lws_plat_context_early_init(void)
{
	return 0;
}

void
lws_plat_context_early_destroy(struct lws_context *context)
{
#if defined(LWS_AMAZON_RTOS)
	mbedtls_ctr_drbg_free(&context->mcdc);
	mbedtls_entropy_free(&context->mec);
#endif
}

void
lws_plat_context_late_destroy(struct lws_context *context)
{
#ifdef LWS_WITH_PLUGINS
	if (context->plugin_list)
		lws_plat_plugins_destroy(context);
#endif

	if (context->lws_lookup)
		lws_free(context->lws_lookup);
}

#if defined(LWS_WITH_HTTP2)
/*
 * These are the default SETTINGS used on this platform.  The user
 * can selectively modify them for a vhost during vhost creation.
 */
const struct http2_settings lws_h2_defaults_esp32 = { {
	1,
	/* H2SET_HEADER_TABLE_SIZE */			 512,
	/* H2SET_ENABLE_PUSH */				   0,
	/* H2SET_MAX_CONCURRENT_STREAMS */		   8,
	/* H2SET_INITIAL_WINDOW_SIZE */		       65535,
	/* H2SET_MAX_FRAME_SIZE */		       16384,
	/* H2SET_MAX_HEADER_LIST_SIZE */	 	 512,
	/* H2SET_RESERVED7 */				   0,
	/* H2SET_ENABLE_CONNECT_PROTOCOL */		   1,
}};
#endif

int
lws_plat_init(struct lws_context *context,
	      const struct lws_context_creation_info *info)
{
#if defined(LWS_AMAZON_RTOS)
	int n;

	/* initialize platform random through mbedtls */
	mbedtls_entropy_init(&context->mec);
	mbedtls_ctr_drbg_init(&context->mcdc);

	n = mbedtls_ctr_drbg_seed(&context->mcdc, mbedtls_entropy_func,
				  &context->mec, NULL, 0);
	if (n) {
		lwsl_err("%s: mbedtls_ctr_drbg_seed() returned 0x%x\n",
			 __func__, n);

		return 1;
	}
#endif

	/* master context has the global fd lookup array */
	context->lws_lookup = lws_zalloc(sizeof(struct lws *) *
					 context->max_fds, "esp32 lws_lookup");
	if (context->lws_lookup == NULL) {
		lwsl_err("OOM on lws_lookup array for %d connections\n",
			 context->max_fds);
		return 1;
	}

	lwsl_notice(" mem: platform fd map: %5lu bytes\n",
		    (unsigned long)(sizeof(struct lws *) * context->max_fds));

#ifdef LWS_WITH_PLUGINS
	if (info->plugin_dirs)
		lws_plat_plugins_init(context, info->plugin_dirs);
#endif
#if defined(LWS_WITH_HTTP2)
	/* override settings */
	context->set = lws_h2_defaults_esp32;
#endif

	return 0;
}
