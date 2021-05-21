/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
 */

#include "private-lib-core.h"

static int
lws_tls_kid_cmp(const lws_tls_kid_t *a, const lws_tls_kid_t *b)
{
	if (a->kid_len != b->kid_len)
		return 1;

	return memcmp(a->kid, b->kid, a->kid_len);
}

/*
 * We have the SKID and AKID for every peer cert captured, but they may be
 * in any order, and eg, falsely have sent the root CA, or an attacker may
 * send unresolveable self-referencing loops of KIDs.
 *
 * Let's sort them into the SKID -> AKID hierarchy, so the last entry is the
 * server cert and the first entry is the highest parent that the server sent.
 * Normally the top one will be an intermediate, and its AKID is the ID of the
 * root CA cert we would need to trust to validate the chain.
 *
 * It's not unknown the server is misconfigured to also send the root CA, if so
 * the top slot's AKID is empty and we should look for its SKID in the trust
 * blob.
 *
 * If we return 0, we succeeded and the AKID of ch[0] is the SKID we want to see
 * try to import from the trust blob.
 *
 * If we return nonzero, we can't identify what we want and should abandon the
 * connection.
 */

int
lws_tls_jit_trust_sort_kids(lws_tls_kid_chain_t *ch)
{
	int n, m, sanity = 10;
	char more = 1;

	/* something to work with? */

	if (!ch->count)
		return 1;

	/* do we need to sort? */

	if (ch->count > 1) {

		/* okie... */

		while (more) {

			if (!sanity--)
				/* let's not get fooled into spinning */
				return 1;

			more = 0;
			for (n = 0; n < ch->count - 1; n++) {

				if (!lws_tls_kid_cmp(&ch->skid[n],
						     &ch->akid[n + 1]))
					/* next belongs with this one */
					continue;

				/*
				 * next doesn't belong with this one, let's
				 * try to figure out where this one does belong
				 * then
				 */

				for (m = 0; m < ch->count; m++) {
					if (n == m)
						continue;
					if (!lws_tls_kid_cmp(&ch->skid[n],
							     &ch->akid[m])) {
						lws_tls_kid_t t;

						/*
						 * m references us, so we
						 * need to go one step above m,
						 * swap m and n
						 */

						more = 1;
						t = ch->akid[m];
						ch->akid[m] = ch->akid[n];
						ch->akid[n] = t;
						t = ch->skid[m];
						ch->skid[m] = ch->skid[n];
						ch->skid[n] = t;

						break;
					}
				}

				if (more)
					n = -1;
			}
		}

		/* then we should be sorted */
	}

	for (n = 0; n < ch->count; n++) {
		lwsl_notice("%s: AKID[%d]\n", __func__, n);
		lwsl_hexdump_notice(ch->akid[n].kid, ch->akid[n].kid_len);
		lwsl_notice("%s: SKID[%d]\n", __func__, n);
		lwsl_hexdump_notice(ch->skid[n].kid, ch->skid[n].kid_len);
	}

	return !ch->akid[0].kid_len;
}
