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

void
lws_tls_session_tag_discrete(const char *vhname, const char *host,
			      uint16_t port, char *buf, size_t len)
{
	/*
	 * We have to include the vhost name in the session tag, since
	 * different vhosts may make connections to the same endpoint using
	 * different client certs.
	 */

	lws_snprintf(buf, len, "%s_%s_%u", vhname, host, (unsigned int)port);
	lws_filename_purify_inplace(buf);
}

int
lws_tls_session_tag_from_wsi(struct lws *wsi, char *buf, size_t len)
{
	const char *host = NULL;
#if defined(LWS_WITH_CLIENT)
	unsigned int relaxed;
#endif

	if (!wsi)
		return 1;

#if defined(LWS_WITH_CLIENT)
	relaxed = wsi->tls.use_ssl & (LCCSCF_ALLOW_SELFSIGNED |
				      LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				      LCCSCF_ALLOW_EXPIRED |
				      LCCSCF_ALLOW_INSECURE);

	if (wsi->stash) {
		host = wsi->stash->cis[CIS_HOST];
		if (!host)
			host = wsi->stash->cis[CIS_ADDRESS];
	} else {
		host = wsi->cli_hostname_copy;
	}
#endif

	if (!host)
		return 1;

	lws_tls_session_tag_discrete(wsi->a.vhost->name, host, wsi->c_port,
				     buf, len);

#if defined(LWS_WITH_CLIENT)
	if (relaxed) {
		/*
		 * On resumption the server sends no Certificate, so the verify
		 * callback and hostname check never run: whatever validation
		 * the original connection did (or opted out of) is what the
		 * resuming connection inherits.  A session negotiated with
		 * relaxed validation must therefore never be resumed by a
		 * connection that asked for full validation.
		 *
		 * Segregate them by suffixing the tag with the relaxation
		 * flags: only a connection with the identical posture, to the
		 * same vhost / host / port, can find and resume it.  The
		 * plain vhost_host_port tag is reserved for fully validated
		 * sessions, so the dump / load apis (which only know those
		 * three things) never export a relaxed session, and a loaded
		 * one is only ever offered to a strict connection.
		 */
		size_t n = strlen(buf);

		if (n + 1 >= len)
			return 1;

		lws_snprintf(buf + n, len - n, "_r%x", relaxed);
	}
#endif

	lwsl_info("lws_tls_session_tag_from_wsi: generated tag '%s' for host '%s'\n", buf, host);

	return 0;
}


