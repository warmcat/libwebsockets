/*
 * lws System Fault Injection
 *
 * Copyright (C) 2019 - 2021 Andy Green <andy@warmcat.com>
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

#include <assert.h>


static lws_fi_priv_t *
lws_fi_lookup(lws_fi_ctx_t *fic, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, fic->fi_owner.head) {
		lws_fi_priv_t *pv = lws_container_of(p, lws_fi_priv_t, list);

		if (!strcmp(pv->fi.name, name))
			return pv;

	} lws_end_foreach_dll(p);

	return NULL;
}

int
lws_fi(lws_fi_ctx_t *fic, const char *name)
{
	lws_fi_priv_t *pv = NULL;

	do {
		pv = lws_fi_lookup(fic, name);

		if (pv) {
			int n;

			switch (pv->fi.type) {
			case LWSFI_ALWAYS:
				goto inject;

			case LWSFI_DETERMINISTIC:
				pv->fi.times++;
				if (pv->fi.times >= pv->fi.pre)
					if (pv->fi.times < pv->fi.pre + pv->fi.count)
						goto inject;
				return 0;

			case LWSFI_PROBABILISTIC:
				pv->fi.times = (unsigned long)(pv->fi.times * 3) ^
						(unsigned long)lws_now_usecs();
				if ((uint16_t)pv->fi.times % 101 >= pv->fi.pre)
					goto inject;
				return 0;

			case LWSFI_PATTERN:
				n = (int)(pv->fi.times % pv->fi.pre);
				if (pv->fi.pattern[n >> 3] & (1 << (n & 7)))
					goto inject;

				return 0;

			default:
				return 0;
			}
		}

		fic = fic->parent;
	} while (fic);

	return 0;

inject:
	lwsl_warn("%s: Injecting fault %s->%s\n", __func__, fic->name,
						  pv->fi.name);

	return 1;
}

int
lws_fi_add(lws_fi_ctx_t *fic, const lws_fi_t *fi)
{
	lws_fi_priv_t *pv;
	size_t n = strlen(fi->name);

	pv = lws_malloc(sizeof(*pv) + n + 1, __func__);
	if (!pv)
		return 1;

	lws_dll2_clear(&pv->list);

	memcpy(&pv->fi, fi, sizeof(*fi));
	pv->fi.name = (const char *)&pv[1];
	memcpy(&pv[1], fi->name, n + 1);

	lws_dll2_add_tail(&pv->list, &fic->fi_owner);

	return 0;
}

void
lws_fi_remove(lws_fi_ctx_t *fic, const char *name)
{
	lws_fi_priv_t *pv = lws_fi_lookup(fic, name);

	if (!pv)
		return;

	lws_dll2_remove(&pv->list);
	lws_free(pv);
}

void
lws_fi_import(lws_fi_ctx_t *fic_dest, const lws_fi_ctx_t *fic_src)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1, fic_src->fi_owner.head) {
		lws_fi_priv_t *pv = lws_container_of(p, lws_fi_priv_t, list);

		lws_dll2_remove(&pv->list);
		lws_dll2_add_tail(&pv->list, &fic_dest->fi_owner);

	} lws_end_foreach_dll_safe(p, p1);
}

void
lws_fi_destroy(lws_fi_ctx_t *fic)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1, fic->fi_owner.head) {
		lws_fi_priv_t *pv = lws_container_of(p, lws_fi_priv_t, list);

		lws_dll2_remove(&pv->list);
		lws_free(pv);

	} lws_end_foreach_dll_safe(p, p1);
}
