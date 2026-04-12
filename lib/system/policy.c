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
 */

#include <private-lib-core.h>

#if defined(LWS_WITH_NETWORK)

static const char * const policy_paths[] = {
	"dns_base_dir",
	"seeds[]",
};

enum lejp_policy_paths {
	LEJP_PLCY_DNS_BASE_DIR,
	LEJP_PLCY_SEEDS,
};

struct policy_parse_ctx {
	lws_system_policy_t *p;
};

static signed char
policy_cb(struct lejp_ctx *ctx, char reason)
{
	struct policy_parse_ctx *pctx = (struct policy_parse_ctx *)ctx->user;
	lws_system_seed_t *s;

	if (reason == LEJPCB_VAL_STR_END) {
        int match = ctx->path_match - 1;
        if (match < 0) {
            if (!strcmp(ctx->path, "dns_base_dir")) match = LEJP_PLCY_DNS_BASE_DIR;
            else if (!strcmp(ctx->path, "seeds[]")) match = LEJP_PLCY_SEEDS;
        }

		switch (match) {
		case LEJP_PLCY_DNS_BASE_DIR:
			lws_strncpy(pctx->p->dns_base_dir, ctx->buf, sizeof(pctx->p->dns_base_dir));
			break;
		case LEJP_PLCY_SEEDS:
			s = lws_zalloc(sizeof(*s), "policy seed");
			if (!s)
				return -1;
			lws_strncpy(s->hostname, ctx->buf, sizeof(s->hostname));
			lws_dll2_add_tail(&s->list, &pctx->p->seeds);
			break;
		}
	}

	return 0;
}

static const char *default_policy =
	"{\n"
	"    \"dns_base_dir\": \"/var/dnssec\",\n"
	"    \"seeds\": [ \"selfdns.org\", \"uk1.selfdns.org\", \"asia1.selfdns.org\" ]\n"
	"}\n";

int
lws_system_parse_policy(struct lws_context *cx, const char *filepath, lws_system_policy_t **_policy)
{
	struct policy_parse_ctx pctx;
	struct lejp_ctx ctx;
	lws_system_policy_t *p;
	int fd, n, m;
	uint8_t buf[256];

	*_policy = NULL;

	fd = lws_open(filepath, O_RDONLY);
	if (fd < 0) {
#if !defined(_WIN32)
		const char *pt = strrchr(filepath, '/');
		if (pt) {
			char dir[256];
			lws_strncpy(dir, filepath, sizeof(dir));
			dir[pt - filepath] = '\0';
			if (mkdir(dir, 0755) < 0)
				lwsl_debug("%s: mkdir %s failed (may exist)\n", __func__, dir);
		}
#endif
		fd = lws_open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) {
			n = (int)write(fd, default_policy, LWS_POSIX_LENGTH_CAST(strlen(default_policy)));
			close(fd);
			fd = -1;
			if (n == (int)strlen(default_policy))
				fd = lws_open(filepath, O_RDONLY);
		}
	}

	p = lws_zalloc(sizeof(*p), "policy");
	if (!p) {
		if (fd >= 0)
			close(fd);
		return 1;
	}

	pctx.p = p;
	lejp_construct(&ctx, policy_cb, &pctx, policy_paths, LWS_ARRAY_SIZE(policy_paths));

	if (fd < 0) {
		/* Fallback: parse from memory if we failed to open and failed to create */
		m = lejp_parse(&ctx, (uint8_t *)default_policy, (int)strlen(default_policy));
		if (m < 0 && m != LEJP_CONTINUE)
			goto bail;
		goto done;
	}

	do {
		n = (int)read(fd, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0)
			goto bail;

		m = lejp_parse(&ctx, buf, n);
		if (m < 0 && m != LEJP_CONTINUE)
			goto bail;

	} while (1);

done:
	if (fd >= 0)
		close(fd);
	lejp_destruct(&ctx);

	*_policy = p;
	return 0;

bail:
	if (fd >= 0)
		close(fd);
	lejp_destruct(&ctx);
	lws_system_policy_free(p);
	return 1;
}

void
lws_system_policy_free(lws_system_policy_t *policy)
{
	if (!policy)
		return;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&policy->seeds)) {
		lws_system_seed_t *s = lws_container_of(d, lws_system_seed_t, list);

		lws_dll2_remove(d);
		lws_free(s);
	} lws_end_foreach_dll_safe(d, d1);

	lws_free(policy);
}

#endif
