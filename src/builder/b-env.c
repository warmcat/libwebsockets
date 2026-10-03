/*
 * sai-builder env.c
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
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
 * The environment the builder's children (step scripts, sai-shell) start
 * with.  On unix that's a small fixed set, not the builder's own
 * environment; on Windows the child can't even find the toolchain without
 * SystemRoot and the Visual Studio vars, so it starts from ours.
 *
 * On top of that, the platform's "env" items from the builder conf are
 * applied in order, see READMEs/README-builder-env.md
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

#include "b-private.h"

#if !defined(WIN32)
static const char * const env_base[] = {
#if defined(__APPLE__)
	"PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin",
#else
	"PATH=/usr/local/bin:/usr/bin:/bin",
#endif
	"LANG=en_US.UTF-8",
	"TERM=xterm-256color",
};
#endif

/*
 * Add a conf env item to the platform.  value NULL means pass on the
 * builder's own value of name, if it has one.  value must already be in
 * the conf lwsac, name is copied into it.
 */

int
saib_env_add(sai_plat_t *sp, struct lwsac **ac, const char *name,
	     size_t nlen, const char *value)
{
	saib_env_t *e;
	char *p;

	if (!nlen || memchr(name, '=', nlen)) {
		lwsl_err("%s: invalid env var name '%.*s'\n", __func__,
			 (int)nlen, name);
		return 1;
	}

	e = lwsac_use_zero(ac, sizeof(*e), 512);
	p = lwsac_use(ac, nlen + 1, 512);
	if (!e || !p)
		return 1;

	memcpy(p, name, nlen);
	p[nlen] = '\0';
	e->name = p;
	e->value = value;

	lws_dll2_add_tail(&e->list, &sp->env_head);

	/* the value may be a secret, so we don't log it */
	lwsl_notice("%s: env %s%s\n", __func__, e->name,
		    value ? "" : " (from builder)");

	return 0;
}

static int
env_name_match(const char *e, const char *name, size_t nlen)
{
	size_t n;

	for (n = 0; n < nlen; n++) {
#if defined(WIN32)
		/* Windows env var names are case-insensitive */
		char c1 = e[n], c2 = name[n];

		if (c1 >= 'A' && c1 <= 'Z')
			c1 = (char)(c1 + ('a' - 'A'));
		if (c2 >= 'A' && c2 <= 'Z')
			c2 = (char)(c2 + ('a' - 'A'));
		if (!c1 || c1 != c2)
			return 0;
#else
		if (!e[n] || e[n] != name[n])
			return 0;
#endif
	}

	return e[nlen] == '=';
}

static int
env_find(const char **env, int count, const char *name, size_t nlen)
{
	int n;

	for (n = 0; n < count; n++)
		if (env_name_match(env[n], name, nlen))
			return n;

	return -1;
}

static int
env_name_char(char c, int first)
{
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (!first && c >= '0' && c <= '9');
}

/*
 * Expand $NAME and ${NAME} in "in" against the env being built.  $$ is a
 * literal $, and so is a $ not followed by a name.  An unset var expands to
 * nothing.  With out NULL, it just measures.  Returns the expanded length,
 * not including the terminating NUL that's appended when out is given.
 */

static size_t
env_expand(const char **env, int count, const char *in, char *out)
{
	const char *s, *v;
	size_t len = 0, nl, vl;
	int brace, n;

	while (*in) {
		if (*in != '$' || in[1] == '$') {
			if (out)
				out[len] = *in;
			len++;
			in += *in == '$' ? 2 : 1;
			continue;
		}

		brace = in[1] == '{';
		s = in + 1 + brace;
		nl = 0;
		if (brace)
			/* allows Windows names like ProgramFiles(x86) */
			while (s[nl] && s[nl] != '}' && s[nl] != '=')
				nl++;
		else
			while (env_name_char(s[nl], !nl))
				nl++;

		if (!nl || (brace && s[nl] != '}')) {
			/* not a reference, the $ is literal */
			if (out)
				out[len] = '$';
			len++;
			in++;
			continue;
		}

		in = s + nl + brace;

		n = env_find(env, count, s, nl);
		if (n < 0)
			continue;

		v = env[n] + nl + 1;
		vl = strlen(v);
		if (out)
			memcpy(out + len, v, vl);
		len += vl;
	}

	if (out)
		out[len] = '\0';

	return len;
}

/*
 * Prepare the environment for a child of platform sp (which may be NULL if
 * we don't know the platform, then it's just the base set) in ac.  Returns a
 * NULL-terminated array of "NAME=value" for lws_spawn_piped_info.env_array,
 * or NULL on OOM.  It only needs to live until lws_spawn_piped() returns.
 */

const char **
saib_env_build(const sai_plat_t *sp, struct lwsac **ac)
{
	int count = 0, max;
	const char **env;
#if defined(WIN32)
	LPCH blk = GetEnvironmentStringsA();
	const char *b;

	if (!blk)
		return NULL;

	for (b = blk; *b; b += strlen(b) + 1)
		count++;
	max = count;
#else
	max = (int)LWS_ARRAY_SIZE(env_base);
#endif

	max += (int)(sp ? sp->env_head.count : 0) + 1;

	env = lwsac_use(ac, sizeof(*env) * (size_t)max, 512);
	if (!env)
		goto bail;

#if defined(WIN32)
	count = 0;
	for (b = blk; *b; b += strlen(b) + 1) {
		size_t l = strlen(b) + 1;
		char *p = lwsac_use(ac, l, 4096);

		if (!p)
			goto bail;
		memcpy(p, b, l);
		env[count++] = p;
	}
	FreeEnvironmentStringsA(blk);
	blk = NULL;
#else
	for (count = 0; count < (int)LWS_ARRAY_SIZE(env_base); count++)
		env[count] = env_base[count];
#endif

	if (sp) {
		lws_start_foreach_dll(struct lws_dll2 *, d, sp->env_head.head) {
			const saib_env_t *e = lws_container_of(d, saib_env_t,
							       list);
			size_t nl = strlen(e->name), vl;
			const char *v = e->value;
			char *p;
			int n;

			if (!v) {
#if defined(WIN32)
				/* we started from our own env already */
				continue;
#else
				v = getenv(e->name);
				if (!v)
					continue;
				/* the builder's own value is used literally */
				vl = strlen(v);
#endif
			} else
				vl = env_expand(env, count, v, NULL);

			p = lwsac_use(ac, nl + 1 + vl + 1, 512);
			if (!p)
				goto bail;

			memcpy(p, e->name, nl);
			p[nl] = '=';
			if (e->value)
				env_expand(env, count, v, p + nl + 1);
			else
				memcpy(p + nl + 1, v, vl + 1);

			n = env_find(env, count, e->name, nl);
			if (n < 0)
				n = count++;
			env[n] = p;

		} lws_end_foreach_dll(d);
	}

	env[count] = NULL;

	return env;

bail:
#if defined(WIN32)
	if (blk)
		FreeEnvironmentStringsA(blk);
#endif
	lwsac_free(ac);

	return NULL;
}
