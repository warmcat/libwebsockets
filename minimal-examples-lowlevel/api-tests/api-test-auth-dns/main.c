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
#if defined(WIN32) || defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

/*
 * A zone file may write $ORIGIN with or without the trailing root dot.  The
 * parser has to bring both to the same, fully-qualified owner names: a
 * dotless origin that reached the signer as-is would be appended to names
 * that already end in it, and the whole NSEC3 chain would be hashed over
 * "x.example.com.example.com".
 *
 * So we sign the same zone body under both spellings of $ORIGIN, and require
 * the two signed zones to agree on every owner name and on every non-RRSIG
 * rdata (which is where the NSEC3 owner hashes and next-hashes live).  The
 * RRSIG rdata carries a fresh ECDSA signature each time, so it is compared
 * only for its owner name and type.
 */

static const char *zone_body =
	"$TTL 1200\n"
	"@ IN SOA ns1.example.com. hostmaster.example.com. (\n"
	"        2026090801 60 120 1209600 120 )\n"
	"@			IN	NS	ns1.example.com.\n"
	"ns1			IN	A	127.0.0.1\n"
	"www			IN	A	127.0.0.2\n"
	"x.deeper		IN	A	127.0.0.3\n"
	"@			IN	TXT	\"v=spf1 -all\"\n";

static int
write_zone(const char *path, const char *origin_line)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600), r = 1;
	size_t l = strlen(origin_line), b = strlen(zone_body);

	if (fd < 0)
		return 1;

	if (write(fd, origin_line, l) == (ssize_t)l &&
	    write(fd, zone_body, b) == (ssize_t)b)
		r = 0;

	close(fd);

	return r;
}

static int
load_zone(struct auth_dns_zone *z, const char *path)
{
	int fd = open(path, LWS_O_RDONLY), r = 1;
	struct stat st;
	char *buf;

	memset(z, 0, sizeof(*z));

	if (fd < 0)
		return 1;

	if (fstat(fd, &st) || st.st_size <= 0) {
		close(fd);

		return 1;
	}

	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);

		return 1;
	}

	if (read(fd, buf, (size_t)st.st_size) == st.st_size) {
		buf[st.st_size] = '\0';
		r = lws_auth_dns_parse_zone_buf(buf, (size_t)st.st_size, z,
						NULL, NULL);
	}

	free(buf);
	close(fd);

	return r;
}

/* sign \p in to \p out with a fixed validity, so the result is reproducible */

static int
sign_zone_to(struct lws_context *cx, const char *in, const char *out,
	     const char *jws)
{
	struct lws_auth_dns_sign_info info;

	memset(&info, 0, sizeof(info));
	info.cx			= cx;
	info.input_filepath	= in;
	info.output_filepath	= out;
	info.jws_filepath	= jws;
	info.ksk_jwk_filepath	= "./ksk.jwk";
	info.zsk_jwk_filepath	= "./zsk.jwk";
	info.sign_validity_start_time = (time_t)1767225600;
	info.sign_validity_duration = 30 * 24 * 3600;

	return lws_auth_dns_sign_zone(&info);
}

static int
test_dotless_origin(struct lws_context *cx)
{
	struct auth_dns_zone zd, zn;
	struct lws_dll2 *p, *q;
	int r = 1, nsec3 = 0;
	size_t l;

	if (write_zone("./test-dotted.zone.in", "$ORIGIN example.com.\n") ||
	    write_zone("./test-dotless.zone.in", "$ORIGIN example.com\n")) {
		lwsl_err("%s: unable to write test zones\n", __func__);

		return 1;
	}

	if (sign_zone_to(cx, "./test-dotted.zone.in", "./test-dotted.zone.signed",
			 "./test-dotted.zone.signed.jws") ||
	    sign_zone_to(cx, "./test-dotless.zone.in", "./test-dotless.zone.signed",
			 "./test-dotless.zone.signed.jws")) {
		lwsl_err("%s: signing failed\n", __func__);

		return 1;
	}

	memset(&zd, 0, sizeof(zd));
	memset(&zn, 0, sizeof(zn));

	if (load_zone(&zd, "./test-dotted.zone.signed") ||
	    load_zone(&zn, "./test-dotless.zone.signed")) {
		lwsl_err("%s: unable to reload signed zones\n", __func__);
		goto bail;
	}

	/* the dotless origin must have been normalised */

	l = strlen(zn.origin);
	if (!l || zn.origin[l - 1] != '.' || strcmp(zn.origin, zd.origin)) {
		lwsl_err("%s: origin '%s' not normalised\n", __func__, zn.origin);
		goto bail;
	}

	if (lws_dll2_get_head(&zd.rrset_list) == NULL ||
	    lws_dll2_count(&zd.rrset_list) != lws_dll2_count(&zn.rrset_list)) {
		lwsl_err("%s: rrset count %u vs %u\n", __func__,
			 (unsigned int)lws_dll2_count(&zd.rrset_list),
			 (unsigned int)lws_dll2_count(&zn.rrset_list));
		goto bail;
	}

	p = lws_dll2_get_head(&zd.rrset_list);
	q = lws_dll2_get_head(&zn.rrset_list);

	while (p && q) {
		struct auth_dns_rrset *a = lws_container_of(p,
						struct auth_dns_rrset, list);
		struct auth_dns_rrset *b = lws_container_of(q,
						struct auth_dns_rrset, list);
		struct lws_dll2 *ra, *rb;

		l = strlen(b->name);
		if (!l || b->name[l - 1] != '.') {
			lwsl_err("%s: owner name '%s' not fully qualified\n",
				 __func__, b->name);
			goto bail;
		}

		if (strcmp(a->name, b->name) || a->type != b->type) {
			lwsl_err("%s: '%s'/%u vs '%s'/%u\n", __func__,
				 a->name, a->type, b->name, b->type);
			goto bail;
		}

		if (a->type == 50)
			nsec3++;

		/* RRSIG rdata is a fresh signature each run, don't compare */

		if (a->type != 46) {
			ra = lws_dll2_get_head(&a->rr_list);
			rb = lws_dll2_get_head(&b->rr_list);

			while (ra && rb) {
				struct auth_dns_rr *x = lws_container_of(ra,
						struct auth_dns_rr, list);
				struct auth_dns_rr *y = lws_container_of(rb,
						struct auth_dns_rr, list);

				if (!x->rdata || !y->rdata ||
				    strcmp(x->rdata, y->rdata)) {
					lwsl_err("%s: %s rdata '%s' vs '%s'\n",
						 __func__, a->name,
						 x->rdata ? x->rdata : "(null)",
						 y->rdata ? y->rdata : "(null)");
					goto bail;
				}

				ra = lws_dll2_get_next(ra);
				rb = lws_dll2_get_next(rb);
			}

			if (ra || rb) {
				lwsl_err("%s: %s rr count differs\n", __func__,
					 a->name);
				goto bail;
			}
		}

		p = lws_dll2_get_next(p);
		q = lws_dll2_get_next(q);
	}

	if (!nsec3) {
		lwsl_err("%s: no NSEC3 rrsets to compare\n", __func__);
		goto bail;
	}

	lwsl_user("dotless $ORIGIN normalisation: ok (%d NSEC3 rrsets)\n", nsec3);
	r = 0;

bail:
	lws_auth_dns_free_zone(&zd);
	lws_auth_dns_free_zone(&zn);

	return r;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info cx_info;
	struct lws_auth_dns_sign_info info;
	struct lws_context *cx;
	
	int res = 1;

	lws_context_info_defaults(&cx_info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &cx_info);

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

		if (lws_jwk_load(&jwk, info.ksk_jwk_filepath, NULL, NULL)) {
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

	if (test_dotless_origin(cx))
		goto bail;

	res = 0;

bail:
	lws_context_destroy(cx);
	return res;
}
