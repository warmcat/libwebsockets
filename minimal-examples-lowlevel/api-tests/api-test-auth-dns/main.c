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

#include <libwebsockets.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc, const char **argv)
{
	struct lws_context_creation_info cx_info;
	struct lws_auth_dns_sign_info info;
	struct lws_context *cx;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int res = 1;

	lws_set_log_level(logs, NULL);

	memset(&cx_info, 0, sizeof(cx_info));
	cx_info.port = CONTEXT_PORT_NO_LISTEN;
	cx = lws_create_context(&cx_info);
	if (!cx)
		return 1;

	memset(&info, 0, sizeof(info));
	info.cx = cx;
	info.input_filepath	= "./test.zone.in";
	info.output_filepath	= "./test.zone.signed";
	info.jws_filepath	= "./test.zone.signed.jws";
	info.ksk_jwk_filepath	= "./ksk.jwk";
	info.zsk_jwk_filepath	= "./zsk.jwk";

	const char *sn[] = { "MHWC_DYNAMIC" };
	const char *sv[] = { "127.0.0.1" };
	info.subst_names = sn;
	info.subst_values = sv;
	info.num_substs = 1;

	lwsl_user("Starting test for LWS Authoritative DNS Zone Signer\n");

	if (lws_auth_dns_sign_zone(&info)) {
		lwsl_err("lws_auth_dns_sign_zone failed\n");
		goto bail;
	}

	lwsl_user("lws_auth_dns_sign_zone: ok\n");
	
	/* Verify the generated zone file RRSIGs directly */
	memset(&info, 0, sizeof(info));
	info.cx = cx;
	info.input_filepath	= "./test.zone.signed";
	info.jws_filepath	= "./test.zone.signed.jws";
	info.zsk_jwk_filepath	= "./zsk.jwk";
	info.ksk_jwk_filepath	= "./ksk.jwk";

	if (lws_auth_dns_verify_zone(&info)) {
		lwsl_err("lws_auth_dns_verify_zone failed\n");
		goto bail;
	}

	lwsl_user("lws_auth_dns_verify_zone: ok\n");

	/* Verify the outer JWS signature */
	{
		struct lws_jwk jwk;
		struct lws_jws_map map;
		char temp[32768];
		int temp_len = sizeof(temp);
		struct stat st;
		
		int fd = open(info.jws_filepath, LWS_O_RDONLY);
		if (fd < 0 || fstat(fd, &st) < 0) {
			lwsl_err("Failed to open JWS file\n");
			goto bail;
		}
		
		char *buf = malloc((size_t)st.st_size + 1);
		if (!buf || read(fd, buf, (size_t)st.st_size) != st.st_size) {
			if (buf) free(buf);
			close(fd);
			lwsl_err("Failed to read JWS file\n");
			goto bail;
		}
		buf[st.st_size] = '\0';
		close(fd);
		
		if (lws_jwk_load(&jwk, info.zsk_jwk_filepath, NULL, NULL)) {
			free(buf);
			lwsl_err("Failed to load JWK for verification\n");
			goto bail;
		}
		
		if (lws_jws_sig_confirm_compact_b64(buf, (size_t)st.st_size, &map, &jwk, cx, temp, &temp_len)) {
			lws_jwk_destroy(&jwk);
			free(buf);
			lwsl_err("Failed to verify outer JWS signature\n");
			goto bail;
		}
		
		lwsl_user("JWS signature verified: ok\n");
		lws_jwk_destroy(&jwk);
		free(buf);
	}


	res = 0;

bail:
	lws_context_destroy(cx);
	return res;
}
