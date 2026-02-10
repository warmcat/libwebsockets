/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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



struct lws_interceptor_cidr {
	struct lws_interceptor_cidr	*next;
	lws_sockaddr46			sa46;
	int				len;
};

struct vhd_interceptor {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	struct lws_jwk			jwk;
	const char			*cookie_name;
	const char			*jwt_issuer;
	const char			*jwt_audience;
	const char			*asset_dir;
	char				jwt_alg[32];
	int				jwt_expiry;
	int				pre_delay_ms;
	int				post_delay_ms;
	const struct lws_interceptor_ops	*ops;

	unsigned int			count_served;
	unsigned int			count_passed;
	unsigned int			count_valid;

	unsigned int			last_served;
	unsigned int			last_passed;
	unsigned int			last_valid;
	char				loadavg[16];

	const char			*auth_header_name;
	int				always_pass;

	lws_sorted_usec_list_t		sul_stats;
	struct lws_interceptor_cidr	*cidr_head;
	int				stats_logging;
};

struct pss_interceptor {
	lws_sorted_usec_list_t		sul;
	struct lws			*wsi;
};

static void
lws_interceptor_init_jwt_cookie(struct lws_jwt_sign_set_cookie *ck,
			    struct vhd_interceptor *vhd, const char *ip,
			    const char *cookie_name)
{
	memset(ck, 0, sizeof(*ck));
	ck->alg		= vhd->jwt_alg;
	ck->iss		= vhd->jwt_issuer;
	ck->aud		= vhd->jwt_audience;
	ck->jwk		= &vhd->jwk;
	if (ip)
		lws_strncpy(ck->sub, ip, sizeof(ck->sub));
	ck->cookie_name	= cookie_name;
}

static void
stats_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_interceptor *vhd = lws_container_of(sul, struct vhd_interceptor,
						   sul_stats);
#if defined(__linux__)
	int fd = open("/proc/loadavg", O_RDONLY);

	vhd->loadavg[0] = '\0';
	if (fd >= 0) {
		int n = (int)read(fd, vhd->loadavg, sizeof(vhd->loadavg) - 1);
		close(fd);
		if (n > 0) {
			char *sp;

			vhd->loadavg[n] = '\0';
			sp = strchr(vhd->loadavg, ' ');
			if (sp)
				*sp = '\0';
		}
	}
#endif

	vhd->last_served = vhd->count_served;
	vhd->last_passed = vhd->count_passed;
	vhd->last_valid = vhd->count_valid;

	if (vhd->stats_logging &&
	    (vhd->count_served || vhd->count_passed || vhd->count_valid)) {
		lwsl_vhost_notice(vhd->vhost, "interceptor stats: protocol %s, "
				  "served: %u, passed: %u, valid_jwt: %u, load: %s",
				  vhd->ops ? vhd->ops->name : "none",
				  vhd->count_served, vhd->count_passed,
				  vhd->count_valid, vhd->loadavg);
	}

	vhd->count_served = 0;
	vhd->count_passed = 0;
	vhd->count_valid = 0;

	lws_sul_schedule(vhd->context, 0, &vhd->sul_stats, stats_cb,
			 60LL * LWS_USEC_PER_SEC);
}

static void
lws_interceptor_inject_header(struct lws *wsi, struct vhd_interceptor *vhd, const char *value)
{
	char h[256];
	int n, cur_len = 0;
	char *p;

	if (!vhd->auth_header_name)
		return;

	/* Authoritatively remove any existing copy of the header to prevent spoofing */
	lws_http_zap_header(wsi, vhd->auth_header_name);

	n = lws_snprintf(h, sizeof(h), "%s: %s\x0d\x0a", vhd->auth_header_name,
			 value ? value : "");

	if (wsi->http.extra_onward_headers)
		cur_len = (int)strlen(wsi->http.extra_onward_headers);

	p = lws_realloc(wsi->http.extra_onward_headers, (size_t)cur_len + (size_t)n + 1,
			"extra headers");
	if (!p)
		return;

	wsi->http.extra_onward_headers = p;
	memcpy(p + cur_len, h, (size_t)n);
	p[cur_len + n] = '\0';
}

static int
lws_interceptor_issue_cookie(struct lws *wsi)
{
	struct vhd_interceptor *vhd = (struct vhd_interceptor *)lws_protocol_vh_priv_get(
			lws_get_vhost(wsi), lws_get_protocol(wsi));
	char buf[LWS_PRE + 2048], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;
	struct lws_jwt_sign_set_cookie ck;
	char ip[64], uri[512], *p2;
	int n, args_len, space;

	lws_get_peer_simple(wsi, ip, sizeof(ip));

	lws_interceptor_init_jwt_cookie(&ck, vhd, ip, vhd->cookie_name);
	ck.expiry_unix_time	= (unsigned long)vhd->jwt_expiry;

	if (lws_add_http_header_status(wsi, HTTP_STATUS_SEE_OTHER,
				(unsigned char **)&p, (unsigned char *)end))
		return 1;

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"text/html", 9,
				(unsigned char **)&p, (unsigned char *)end))
		return 1;

	if (lws_add_http_header_content_length(wsi, 0,
				(unsigned char **)&p, (unsigned char *)end))
		return 1;

	if (lws_jwt_sign_token_set_http_cookie(wsi, &ck, (uint8_t **)&p,
				(uint8_t *)end)) {
		lwsl_vhost_err(vhd->vhost, "%s: failed to sign JWT", __func__);
		return 1;
	}

	if (vhd->ops && vhd->ops->on_delay_expired)
		vhd->ops->on_delay_expired(wsi);

	/* Redirect back to the same URL plus lws_interceptor_ok=1 (reloading it) */
	n = lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI);
	if (n <= 0)
		n = lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_POST_URI);
	if (n > 0) {
		args_len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_URI_ARGS);
		p2 = uri + n;
		space = (int)sizeof(uri) - n - 1;

		if (args_len > 0) {
			*p2++ = '?';
			n = lws_hdr_copy(wsi, p2, space, WSI_TOKEN_HTTP_URI_ARGS);
			if (n > 0) {
				p2 += n;
				*p2++ = '&';
				strcpy(p2, "lws_interceptor_ok=1");
			}
		} else
			strcpy(p2, "?lws_interceptor_ok=1");

		if (lws_add_http_header_by_token(
					wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)uri,
					(int)strlen(uri),
					(unsigned char **)&p, (unsigned char *)end))
			return 1;
	}

	if (lws_finalize_http_header(wsi, (unsigned char **)&p,
				(unsigned char *)end))
		return 1;

	lws_write(wsi, (unsigned char *)buf + LWS_PRE,
			lws_ptr_diff_size_t(p, buf + LWS_PRE),
			LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);

	vhd->count_passed++;

	return lws_http_transaction_completed(wsi);
}

static void
interceptor_cb(lws_sorted_usec_list_t *sul)
{
	struct pss_interceptor *pss = lws_container_of(sul, struct pss_interceptor, sul);

	lws_interceptor_issue_cookie(pss->wsi);
}

int
lws_interceptor_check(struct lws *wsi, const struct lws_protocols *prot)
{
	char buf[LWS_PRE + 2048], junk[256], ip[64], sub_claim[64];
	struct lws_jwt_sign_set_cookie ck;
	struct vhd_interceptor *vhd = NULL;
	size_t s, claim_len;
	const char *cp;

	vhd = (struct vhd_interceptor *)lws_protocol_vh_priv_get(
			lws_get_vhost(wsi), prot);


	if (!vhd) {
		lwsl_vhost_notice(lws_get_vhost(wsi), "%s: vhd not found", __func__);
		return 1;
	}

	lws_interceptor_init_jwt_cookie(&ck, vhd, NULL, vhd->cookie_name);

	s = sizeof(buf);
	if (lws_jwt_get_http_cookie_validate_jwt(wsi, &ck, buf, &s)) {
		lws_interceptor_inject_header(wsi, vhd, NULL);
		return vhd->always_pass ? 0 : 1;
	}

	cp = lws_json_simple_find(buf, s, "\"sub\":", &claim_len);
	if (!cp) {
		lwsl_vhost_notice(vhd->vhost, "%s: sub claim missing in JWT", __func__);
		return 1;
	}

	if (claim_len >= sizeof(sub_claim))
		claim_len = sizeof(sub_claim) - 1;

	memcpy(sub_claim, cp, claim_len);
	sub_claim[claim_len] = '\0';

	lws_get_peer_simple(wsi, ip, sizeof(ip));
	if (strcmp(sub_claim, ip)) {
		struct lws_interceptor_cidr *cidr = vhd->cidr_head;
		lws_sockaddr46 sa46;
		int allow = 0;

		lws_sockfd_type fd = lws_get_socket_fd(wsi);

		if (lws_get_peer_addresses(wsi, fd,
				NULL, 0, ip, sizeof(ip))) {
			lwsl_vhost_err(vhd->vhost, "%s: get peer ads fail", __func__);
			return 1;
		}

		if (!lws_sa46_parse_numeric_address(ip, &sa46)) {
			while (cidr) {
				if (!lws_sa46_on_net(&sa46, &cidr->sa46, cidr->len)) {
					allow = 1;
					break;
				}
				cidr = cidr->next;
			}
		}

		if (!allow) {
			lwsl_vhost_notice(vhd->vhost, "%s: IP mismatch %s vs %s", __func__, sub_claim, ip);
			lws_interceptor_inject_header(wsi, vhd, NULL);
			return vhd->always_pass ? 0 : 1;
		}
	}

	lwsl_vhost_notice(vhd->vhost, "%s: valid JWT for %s: exp %lu, now %lu (expires in %lds)",
		    __func__, sub_claim, ck.expiry_unix_time, lws_now_secs(),
		    (long)(ck.expiry_unix_time - lws_now_secs()));

	if (lws_get_urlarg_by_name(wsi, "lws_interceptor_ok", junk, sizeof(junk))) {
		lws_interceptor_inject_header(wsi, vhd, sub_claim);
		return 1;
	}

	vhd->count_valid++;
	lws_interceptor_inject_header(wsi, vhd, sub_claim);

	return 0;
}

int
lws_interceptor_handle_http(struct lws *wsi, void *user, const struct lws_interceptor_ops *ops)
{
	struct pss_interceptor *pss = (struct pss_interceptor *)user;
	struct vhd_interceptor *vhd = (struct vhd_interceptor *)lws_protocol_vh_priv_get(
			lws_get_vhost(wsi), lws_get_protocol(wsi));
	char buf[LWS_PRE + 2048], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;
	char argbuf[256] = "", junk[256], ip[64], uri[512], vbuf[1024], *pv, *vend;
	const char *ctype = "text/html", *file_part, *iat_p;
	struct lws_jwt_sign_set_cookie vck;
	int n, frag = 0, first = 1, js_len, auth_valid = 0;
	char js_buf[512], *p1, *p2, sub_claim[64];
	size_t vs, iat_len, claim_len;
	const char *cp_sub;
	long long iat;

	sub_claim[0] = '\0';
	lws_interceptor_init_jwt_cookie(&vck, vhd, NULL, vhd->cookie_name);
	vs = sizeof(buf);
	if (!lws_jwt_get_http_cookie_validate_jwt(wsi, &vck, buf, &vs)) {
		auth_valid = 1;
		cp_sub = lws_json_simple_find(buf, vs, "\"sub\":", &claim_len);
		if (cp_sub) {
			if (claim_len >= sizeof(sub_claim))
				claim_len = sizeof(sub_claim) - 1;
			memcpy(sub_claim, cp_sub, claim_len);
			sub_claim[claim_len] = '\0';
		}
	}

	n = lws_hdr_copy(wsi, (char *)uri, sizeof(uri), WSI_TOKEN_GET_URI);
	if (n <= 0)
		n = lws_hdr_copy(wsi, (char *)uri, sizeof(uri), WSI_TOKEN_POST_URI);
	if (n < 0) {
		lwsl_vhost_notice(vhd->vhost, "%s: can't get URI", __func__);
		return 1;
	}

	lws_get_peer_simple(wsi, ip, sizeof(ip));


	if (lws_get_urlarg_by_name(wsi, "lws_interceptor_ok", junk, sizeof(junk))) {
		p2 = uri + n;

		while (lws_hdr_copy_fragment(wsi, argbuf, sizeof(argbuf),
					     WSI_TOKEN_HTTP_URI_ARGS, frag++) >= 0) {
			if (!strncmp(argbuf, "lws_interceptor_ok", 18))
				continue;
			*p2++ = first ? '?' : '&';
			first = 0;
			strcpy(p2, argbuf);
			p2 += strlen(argbuf);
		}
		*p2 = '\0';

		if (lws_add_http_header_status(wsi, HTTP_STATUS_SEE_OTHER,
					(unsigned char **)&p, (unsigned char *)end))
			return 1;
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
					(unsigned char *)uri, (int)strlen(uri),
					(unsigned char **)&p, (unsigned char *)end))
			return 1;
		if (lws_finalize_http_header(wsi, (unsigned char **)&p,
					(unsigned char *)end))
			return 1;

		lws_write(wsi, (unsigned char *)buf + LWS_PRE,
				lws_ptr_diff_size_t(p, buf + LWS_PRE),
				LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);

		return lws_http_transaction_completed(wsi);
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI)) {
		file_part = uri;

		p1 = strrchr(uri, '/');
		if (p1)
			file_part = p1 + 1;

		if (file_part[0] && strcmp(file_part, "..") &&
		    strcmp(file_part, ".") && !strstr(file_part, "..")) {

			if (lws_nstrstr(file_part, strlen(file_part), "interceptor-config.js", 21)) {
				js_len = lws_snprintf(js_buf, sizeof(js_buf),
						"var lws_interceptor_pre_delay_ms = %d;\n"
						"var lws_interceptor_post_delay_ms = %d;\n"
						"var lws_auth_user = \"%s\";\n"
						"var lws_auth_valid = %d;\n"
						"var lws_interceptor_served = %u;\n"
						"var lws_interceptor_passed = %u;\n"
						"var lws_interceptor_valid = %u;\n"
						"var lws_system_load = \"%s\";\n",
						vhd->pre_delay_ms, vhd->post_delay_ms,
						sub_claim, auth_valid,
						vhd->last_served, vhd->last_passed,
						vhd->last_valid, vhd->loadavg);

				if (ops && ops->get_config_js)
					js_len += ops->get_config_js(wsi, js_buf + js_len,
								     sizeof(js_buf) - (size_t)js_len);

				if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, (unsigned char **)&p, (unsigned char *)end))
					return 1;
				if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
								 (unsigned char *)"application/javascript", 22,
								 (unsigned char **)&p, (unsigned char *)end))
					return 1;
				if (lws_add_http_header_content_length(wsi, (lws_filepos_t)js_len, (unsigned char **)&p,
									(unsigned char *)end))
					return 1;
				if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
					return 1;

				lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
				lws_write(wsi, (unsigned char *)js_buf, (size_t)js_len, LWS_WRITE_HTTP_FINAL);

				return lws_http_transaction_completed(wsi);
			}

			lws_snprintf(argbuf, sizeof(argbuf), "%s/%s",
				     vhd->asset_dir ? vhd->asset_dir : ".", file_part);

			lws_fop_flags_t flags = LWS_O_RDONLY;
			lws_fop_fd_t ffd;

			ctype = lws_get_mimetype(argbuf, lws_find_mount(wsi, uri, (int)n));
			if (!ctype)
				ctype = "text/html";


			ffd = lws_vfs_file_open(wsi->a.context->fops, argbuf, &flags);
			if (ffd) {
				lws_vfs_file_close(&ffd);
				if (!lws_serve_http_file(wsi, argbuf, ctype, NULL, 0))
					return 0;
			}
		}

		ctype = "text/html";
		lws_snprintf(argbuf, sizeof(argbuf), "%s/index.html",
			     vhd->asset_dir ? vhd->asset_dir : ".");

		vhd->count_served++;

		pv = vbuf;
		vend = vbuf + sizeof(vbuf) - 1;

		lws_interceptor_init_jwt_cookie(&vck, vhd, ip, "lws_interceptor_v");
		vck.expiry_unix_time = 3600; /* valid for 1h */

		if (ops && ops->init_visit_cookie) {
			/* Plugin can add its own claims here if it wants */
			char ebuf[512];

			ebuf[0] = '\0';
			if (!ops->init_visit_cookie(wsi, ebuf, sizeof(ebuf))) {
				vck.extra_json = ebuf;
				vck.extra_json_len = strlen(ebuf);
			}
		}

		if (!lws_jwt_sign_token_set_http_cookie(wsi, &vck, (uint8_t **)&pv, (uint8_t *)vend)) {
			*pv = '\0';
			return lws_serve_http_file(wsi, argbuf, ctype, vbuf, lws_ptr_diff(pv, vbuf));
		}

		lwsl_vhost_err(vhd->vhost, "%s: failed to sign visit cookie", __func__);
		goto serve_file;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
		vs = sizeof(vbuf);

		lws_interceptor_init_jwt_cookie(&vck, vhd, ip, "lws_interceptor_v");

		if (lws_jwt_get_http_cookie_validate_jwt(wsi, &vck, vbuf, &vs)) {
			lwsl_vhost_notice(vhd->vhost, "%s: POST: missing or invalid visit cookie", __func__);
			return 1;
		}

		iat_p = lws_json_simple_find(vbuf, vs, "\"iat\":", &iat_len);
		if (!iat_p) {
			lwsl_vhost_notice(vhd->vhost, "%s: POST: visit cookie missing iat", __func__);
			return 1;
		}
		iat = atoll(iat_p);

		if (lws_now_secs() < (unsigned long)iat + (unsigned long)(vhd->pre_delay_ms / 1000)) {
			lwsl_vhost_notice(vhd->vhost, "%s: POST: pre-delay not met", __func__);
			return 1;
		}

		if (ops && ops->verify) {
			lws_interceptor_result_t res = ops->verify(wsi, NULL, 0);
			if (res == LWS_INTERCEPTOR_RET_REJECT)
				return 1;
			if (res == LWS_INTERCEPTOR_RET_PASS)
				return lws_interceptor_issue_cookie(wsi);

			/* RET_DELAYED falls through to timer setup */
		}

		lws_set_timeout(wsi, PENDING_TIMEOUT_CLIENT_CONN_IDLE, 25);
		pss->wsi = wsi;
		lws_sul_schedule(vhd->context, 0, &pss->sul, interceptor_cb,
				(lws_usec_t)vhd->post_delay_ms * LWS_US_PER_MS);
		return 0;
	}

serve_file:
	if (lws_serve_http_file(wsi, argbuf, ctype, NULL, 0))
		return 1;

	return 0;
}

int
lws_callback_interceptor(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len,
		     const struct lws_interceptor_ops *ops)
{
	struct vhd_interceptor *vhd = (struct vhd_interceptor *)lws_protocol_vh_priv_get(
			lws_get_vhost(wsi), lws_get_protocol(wsi));
	struct pss_interceptor *pss = (struct pss_interceptor *)user;
	const struct lws_protocol_vhost_options *pvo;
	const char *cp;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd_interceptor));
		if (!vhd)
			return -1;

		vhd->context		= lws_get_context(wsi);
		vhd->vhost		= lws_get_vhost(wsi);
		vhd->cookie_name	= "lws_interceptor_jwt";
		vhd->jwt_expiry		= 600; /* 10 mins */
		vhd->pre_delay_ms	= 2000;
		vhd->post_delay_ms	= 5000;
		vhd->jwt_issuer		= "lws";
		vhd->jwt_audience	= "lws";
		lws_strncpy(vhd->jwt_alg, "HS256", sizeof(vhd->jwt_alg));
		vhd->ops		= ops;

		if (!lws_pvo_get_str(in, "jwt-issuer", &vhd->jwt_issuer))
			lwsl_vhost_info(vhd->vhost, "Using default jwt-issuer");

		if (!lws_pvo_get_str(in, "jwt-audience", &vhd->jwt_audience))
			lwsl_vhost_info(vhd->vhost, "Using default jwt-audience");

		if (!lws_pvo_get_str(in, "jwt-alg", &cp))
			lws_strncpy(vhd->jwt_alg, cp, sizeof(vhd->jwt_alg));

		if (!lws_pvo_get_str(in, "jwt-expiry", &cp))
			vhd->jwt_expiry = atoi(cp);

		if (!lws_pvo_get_str(in, "pre-delay-ms", &cp))
			vhd->pre_delay_ms = atoi(cp);

		if (!lws_pvo_get_str(in, "post-delay-ms", &cp))
			vhd->post_delay_ms = atoi(cp);

		if (!lws_pvo_get_str(in, "cookie-name", &cp))
			vhd->cookie_name = cp;

		if (!lws_pvo_get_str(in, "jwt-jwk", &cp)) {
			if (cp[0] == '{' || lws_jwk_load(&vhd->jwk, cp, NULL, NULL)) {
				if (lws_jwk_import(&vhd->jwk, NULL, NULL, cp, strlen(cp))) {
					lwsl_vhost_err(vhd->vhost, "%s: failed to load/import JWK", __func__);
					return -1;
				}
			}
		} else {
			lwsl_vhost_warn(vhd->vhost, "%s: jwt-jwk PVO required", __func__);
			return -1;
		}

		if (!lws_pvo_get_str(in, "asset-dir", &vhd->asset_dir))
			if (!strncmp(vhd->asset_dir, "file://", 7))
				vhd->asset_dir += 7;

		if (!lws_pvo_get_str(in, "stats-logging", &cp))
			vhd->stats_logging = !!atoi(cp);

		lws_sul_schedule(vhd->context, 0, &vhd->sul_stats,
				 stats_cb, 60LL * LWS_USEC_PER_SEC);

		if (!lws_pvo_get_str(in, "auth-header-name", &vhd->auth_header_name))
			lwsl_vhost_info(vhd->vhost, "Auth header injection enabled: %s",
				  vhd->auth_header_name);

		if (!lws_pvo_get_str(in, "always-pass", &cp))
			vhd->always_pass = !!atoi(cp);

		pvo = lws_pvo_search(in, "cidr-allow");
		while (pvo) {
			struct lws_interceptor_cidr *cidr =
				malloc(sizeof(*cidr));

			if (!cidr) {
				lwsl_vhost_err(vhd->vhost, "%s: OOM", __func__);
				return -1;
			}

			if (lws_parse_cidr(pvo->value, &cidr->sa46, &cidr->len)) {
				lwsl_vhost_err(vhd->vhost, "%s: Bad CIDR %s", __func__,
						pvo->value);
				free(cidr);
				return -1;
			}

			cidr->next = vhd->cidr_head;
			vhd->cidr_head = cidr;

			pvo = lws_pvo_search(pvo->next, "cidr-allow");
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			lws_sul_cancel(&vhd->sul_stats);
			lws_jwk_destroy(&vhd->jwk);
			while (vhd->cidr_head) {
				struct lws_interceptor_cidr *cidr = vhd->cidr_head;

				vhd->cidr_head = cidr->next;
				free(cidr);
			}
		}
		break;

	case LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK:
		return lws_interceptor_check(wsi, (const struct lws_protocols *)in);

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss)
			lws_sul_cancel(&pss->sul);
		break;

	case LWS_CALLBACK_HTTP:
		return lws_interceptor_handle_http(wsi, pss, ops);

	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		return 0;

	default:
		break;
	}

	return 0;
}
