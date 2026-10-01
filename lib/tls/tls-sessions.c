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

int
lws_tls_session_tag_discrete(const char *vhname, const char *host,
			      uint16_t port, char *buf, size_t len)
{
	/*
	 * We have to include the vhost name in the session tag, since
	 * different vhosts may make connections to the same endpoint using
	 * different client certs.
	 *
	 * The tag has to be exact (C-654).  Truncated, it is the same for
	 * every host that shares its first 80-odd characters, whatever the
	 * port: a session one of them issued, eg, to a strict connection made
	 * to an attacker's look-alike name, would be offered to, and resumed
	 * with no certificate check by, a later strict connection to another
	 * one through the same attacker.  So a host too long for the tag gets
	 * no tag: its sessions are neither cached nor resumed.
	 */

	if (lws_snprintf(buf, len, "%s_%s_%u", vhname, host,
			 (unsigned int)port) >= (int)len) {
		if (len)
			*buf = '\0';

		return 1;
	}

	lws_filename_purify_inplace(buf);

	return 0;
}

/*
 * Append the transport and validation posture to a vhost_host_port tag.
 *
 * The plain vhost_host_port tag is reserved for fully validated tls over tcp
 * sessions: quic ones get "_q", and relaxed ones "_r<flags>", so a session is
 * only ever found by, and resumed on, a connection over the same transport
 * with the identical posture.  The dump / load apis can address the quic tag,
 * but have no way to name a relaxed one, so they never export or import it.
 *
 * The suffix must not be truncated: "_r" alone, or a "_r1" that lost its last
 * nibble, makes every relaxed posture that shares the prefix land in one
 * cache slot, which is exactly the aliasing the segregation exists to
 * prevent.  If it does not fit, there is no tag, so nothing is cached or
 * resumed.
 */

static int
lws_tls_session_tag_suffix(char *buf, size_t len, int quic,
			   unsigned int relaxed)
{
	size_t n = strlen(buf), sl = 0;
	char sfx[16];

	if (quic)
		sl = (size_t)lws_snprintf(sfx, sizeof(sfx), "_q");

	if (relaxed)
		sl += (size_t)lws_snprintf(sfx + sl, sizeof(sfx) - sl, "_r%x",
					   relaxed);

	if (!sl)
		return 0;

	if (n + sl + 1 > len) {
		*buf = '\0';

		return 1;
	}

	memcpy(buf + n, sfx, sl + 1);

	return 0;
}

int
lws_tls_session_tag_dump(const struct lws_vhost *vh, const char *host,
			 uint16_t port, unsigned int flags, char *buf,
			 size_t len)
{
	if (flags & ~(unsigned int)LWS_TLS_SESSION_DUMP_F_QUIC)
		return 1;

#if !defined(LWS_ROLE_QUIC)
	if (flags & LWS_TLS_SESSION_DUMP_F_QUIC)
		/* no connection could make or resume it */
		return 1;
#endif

	if (lws_tls_session_tag_discrete(vh->name, host, port, buf, len))
		return 1;

	return lws_tls_session_tag_suffix(buf, len,
				!!(flags & LWS_TLS_SESSION_DUMP_F_QUIC), 0);
}

int
lws_tls_session_dump_save(struct lws_vhost *vh, const char *host, uint16_t port,
			  lws_tls_sess_cb_t cb_save, void *opq)
{
	return lws_tls_session_dump_save_flags(vh, host, port, 0, cb_save, opq);
}

int
lws_tls_session_dump_load(struct lws_vhost *vh, const char *host, uint16_t port,
			  lws_tls_sess_cb_t cb_load, void *opq)
{
	return lws_tls_session_dump_load_flags(vh, host, port, 0, cb_load, opq);
}

int
lws_tls_session_tag_from_wsi(struct lws *wsi, char *buf, size_t len)
{
	const char *host = NULL;
#if defined(LWS_WITH_CLIENT)
	unsigned int relaxed;
	int quic = 0;
#endif

	if (!wsi)
		return 1;

#if defined(LWS_WITH_CLIENT)
	relaxed = wsi->use_ssl & (LCCSCF_ALLOW_SELFSIGNED |
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

	if (lws_tls_session_tag_discrete(wsi->a.vhost->name, host, wsi->c_port,
					 buf, len))
		return 1;

#if defined(LWS_WITH_CLIENT)
#if defined(LWS_ROLE_QUIC)
	/*
	 * A session from a quic connection is kept apart from tcp's for the
	 * same host and port, and the other way around: a client offers early
	 * data on whatever session it resumes, and a ticket from tls over tcp
	 * was issued for another alpn and carries none of the quic transport
	 * parameters 0-RTT has to be sent under (RFC 9000 7.4.1)
	 */
	quic = !!wsi->quic.qn;
#endif

	/*
	 * On resumption the server sends no Certificate, so the verify
	 * callback and hostname check never run: whatever validation the
	 * original connection did (or opted out of) is what the resuming
	 * connection inherits.  A session negotiated with relaxed validation
	 * must therefore never be resumed by a connection that asked for full
	 * validation.
	 */
	if (lws_tls_session_tag_suffix(buf, len, quic, relaxed))
		return 1;
#endif

	lwsl_info("lws_tls_session_tag_from_wsi: generated tag '%s' for host '%s'\n", buf, host);

	return 0;
}


