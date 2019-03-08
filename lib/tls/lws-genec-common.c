/*
 * libwebsockets - generic EC api hiding the backend - common parts
 *
 * Copyright (C) 2017 - 2019 Andy Green <andy@warmcat.com>
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
 *
 *  lws_genec provides an EC abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls crypto functions underneath.
 */
#include "core/private.h"

const struct lws_ec_curves *
lws_genec_curve(const struct lws_ec_curves *table, const char *name)
{
	const struct lws_ec_curves *c = lws_ec_curves;

	if (table)
		c = table;

	while (c->name) {
		if (!strcmp(name, c->name))
			return c;
		c++;
	}

	return NULL;
}

//extern const struct lws_ec_curves *lws_ec_curves;

int
lws_genec_confirm_curve_allowed_by_tls_id(const char *allowed, int id,
					  struct lws_jwk *jwk)
{
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	int n, len;

	lws_tokenize_init(&ts, allowed, LWS_TOKENIZE_F_COMMA_SEP_LIST |
				       LWS_TOKENIZE_F_MINUS_NONTERM);
	ts.len = strlen(allowed);
	do {
		e = lws_tokenize(&ts);
		switch (e) {
		case LWS_TOKZE_TOKEN:
			n = 0;
			while (lws_ec_curves[n].name) {
				if (id != lws_ec_curves[n].tls_lib_nid) {
					n++;
					continue;
				}
				lwsl_info("match curve %s\n",
					  lws_ec_curves[n].name);
				len = strlen(lws_ec_curves[n].name);
				jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].len = len;
				jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf =
						lws_malloc(len + 1, "cert crv");
				if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) {
					lwsl_err("%s: OOM\n", __func__);
					return 1;
				}
				memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf,
				       lws_ec_curves[n].name, len + 1);
				return 0;
			}
			break;

		case LWS_TOKZE_DELIMITER:
			break;

		default: /* includes ENDED */
			lwsl_err("%s: malformed or curve name in list\n",
				 __func__);

			return -1;
		}
	} while (e > 0);

	lwsl_err("%s: unsupported curve group nid %d\n", __func__, n);

	return -1;
}

LWS_VISIBLE void
lws_genec_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	int n;

	for (n = 0; n < LWS_GENCRYPTO_EC_KEYEL_COUNT; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
}

static const char *enames[] = { "crv", "x", "d", "y" };

LWS_VISIBLE int
lws_genec_dump(struct lws_gencrypto_keyelem *el)
{
	int n;

	(void)enames;

	lwsl_info("  genec %p: crv: '%s'\n", el,
		  !!el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf ?
		  (char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf: "no curve name");

	for (n = LWS_GENCRYPTO_EC_KEYEL_X; n < LWS_GENCRYPTO_EC_KEYEL_COUNT;
	     n++) {
		lwsl_info("  e: %s\n", enames[n]);
		lwsl_hexdump_info(el[n].buf, el[n].len);
	}

	lwsl_info("\n");

	return 0;
}
