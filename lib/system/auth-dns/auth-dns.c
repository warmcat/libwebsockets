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

#include "private-lib-core.h"
#include "private-lib-system-auth-dns.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#if defined(LWS_WITH_AUTHORITATIVE_DNS)

static int
strexp_cb(void *priv, const char *name, char *out, size_t *pos,
	  size_t olen, size_t *exp_ofs)
{
	struct lws_auth_dns_sign_info *info = (struct lws_auth_dns_sign_info *)priv;
	int n;
	size_t l;

	for (n = 0; n < info->num_substs; n++) {
		if (!strcmp(name, info->subst_names[n])) {
			l = strlen(info->subst_values[n]);

			if (*exp_ofs >= l)
				return LSTRX_DONE;

			if (*pos >= olen)
				return LSTRX_FILLED_OUT;

			l -= *exp_ofs;
			if (l > olen - *pos)
				l = olen - *pos;

			memcpy(out + *pos, info->subst_values[n] + *exp_ofs, l);
			*pos += l;
			*exp_ofs += l;

			if (*exp_ofs == strlen(info->subst_values[n]))
				return LSTRX_DONE;

			return LSTRX_FILLED_OUT;
		}
	}

	lwsl_warn("%s: unknown substitution variable: %s\n", __func__, name);

	return LSTRX_FATAL_NAME_UNKNOWN;
}

int
lws_auth_dns_parse_zone_buf(const char *buf, size_t len, struct auth_dns_zone *zone)
{
	const char *p = buf, *end = buf + len;
	char last_name[256];
	int in_parens = 0;
	int in_comment = 0;
	
	memset(zone, 0, sizeof(*zone));
	last_name[0] = '\0';

	char line_accum[4096];
	size_t lptr = 0;

	while (p <= end) {
		if (p < end && *p == '(' && !in_comment)
			in_parens = 1;
		else if (p < end && *p == ')' && !in_comment)
			in_parens = 0;
		else if (p < end && *p == ';')
			in_comment = 1;

		/* if newline and we're not inside parenthesis, we have a logical line */
		if (*p == '\n')
			in_comment = 0;

		if (p == end || (*p == '\n' && !in_parens)) {
			in_comment = 0;
			line_accum[lptr] = '\0';
			
			if (lptr > 0) {
				lws_tokenize_t ts;
				lws_tokenize_elem e;
				char toks[8][256];
				int num_toks = 0, name_inherited = 0, n;

				if (line_accum[0] == ' ' || line_accum[0] == '\t')
					name_inherited = 1;

				lws_tokenize_init(&ts, line_accum, LWS_TOKENIZE_F_HASH_COMMENT | LWS_TOKENIZE_F_DOT_NONTERM | LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_SLASH_NONTERM | LWS_TOKENIZE_F_COLON_NONTERM | LWS_TOKENIZE_F_EQUALS_NONTERM | LWS_TOKENIZE_F_PLUS_NONTERM);
				ts.len = lptr;

				do {
					e = lws_tokenize(&ts);
					if (e == LWS_TOKZE_ENDED)
						break;

					if (e == LWS_TOKZE_TOKEN || e == LWS_TOKZE_QUOTED_STRING || e == LWS_TOKZE_INTEGER) {
						if (num_toks < 8) {
							n = (int)ts.token_len;
							if (n > (int)sizeof(toks[0]) - 1)
								n = sizeof(toks[0]) - 1;
							memcpy(toks[num_toks], ts.token, (size_t)n);
							toks[num_toks][n] = '\0';
						}
						num_toks++;
					}
				} while (e > 0);

				if (!strncmp(line_accum, "$ORIGIN", 7)) {
					const char *v = line_accum + 7;
					while (*v == ' ' || *v == '\t') v++;
					lws_strncpy(zone->origin, v, sizeof(zone->origin));
					char *sp = strchr(zone->origin, ' ');
					if (!sp) sp = strchr(zone->origin, '\t');
					if (sp) *sp = '\0';
				} else if (!strncmp(line_accum, "$TTL", 4)) {
					const char *v = line_accum + 4;
					while (*v == ' ' || *v == '\t') v++;
					lws_strncpy(zone->default_ttl, v, sizeof(zone->default_ttl));
					char *sp = strchr(zone->default_ttl, ' ');
					if (!sp) sp = strchr(zone->default_ttl, '\t');
					if (sp) *sp = '\0';
				} else if (num_toks > 0) {
					{
						/* RR parsing */
						int type_idx = 0;
						struct auth_dns_rrset *rrset = NULL;
						struct auth_dns_rr *rr;
						char cur_name[256];
						uint32_t ttl = 0;
						uint16_t class_ = 1;
						uint16_t type = 0;

						/* Fix: check if the line started with @ as a delimiter since lws_tokenize skips it */
						int started_with_at = 0;
						for (int i = 0; line_accum[i]; i++) {
							if (line_accum[i] == ' ' || line_accum[i] == '\t') continue;
							if (line_accum[i] == '@') started_with_at = 1;
							break;
						}

						if (name_inherited) {
							lws_strncpy(cur_name, last_name, sizeof(cur_name));
						} else if (started_with_at) {
							lws_strncpy(cur_name, "@", sizeof(cur_name));
							lws_strncpy(last_name, "@", sizeof(last_name));
							/* we didn't consume it as a token, so type_idx is 0 */
						} else {
							lws_strncpy(cur_name, toks[0], sizeof(cur_name));
							lws_strncpy(last_name, toks[0], sizeof(last_name));
							type_idx++;
						}

						/* canonicalize name: lowercase and append origin if relative */
						if (!strcmp(cur_name, "@") && zone->origin[0]) {
							lws_strncpy(cur_name, zone->origin, sizeof(cur_name));
						} else if (cur_name[0] && cur_name[strlen(cur_name) - 1] != '.' && zone->origin[0]) {
							char t[256];
							lws_snprintf(t, sizeof(t), "%s.%s", cur_name, zone->origin);
							lws_strncpy(cur_name, t, sizeof(cur_name));
						}
						for (char *c = cur_name; *c; c++)
							*c = (char)tolower((unsigned char)*c);

						if (type_idx < num_toks) {
							/* check for TTL (numeric) */
							const char *cp = toks[type_idx];
							while (*cp && *cp >= '0' && *cp <= '9') cp++;
							if (!*cp && toks[type_idx][0]) {
								ttl = (uint32_t)atoi(toks[type_idx]);
								type_idx++;
							} else {
								if (zone->default_ttl[0])
									ttl = (uint32_t)atoi(zone->default_ttl);
							}
						}

						if (type_idx < num_toks && !strcmp(toks[type_idx], "IN")) {
							class_ = 1;
							type_idx++;
						}

						if (type_idx < num_toks) {
							/* simplistic type assignment */
							if (!strcmp(toks[type_idx], "A")) type = 1;
							else if (!strcmp(toks[type_idx], "NS")) type = 2;
							else if (!strcmp(toks[type_idx], "SOA")) type = 6;
							else if (!strcmp(toks[type_idx], "MX")) type = 15;
							else if (!strcmp(toks[type_idx], "TXT")) type = 16;
							else if (!strcmp(toks[type_idx], "AAAA")) type = 28;
							else if (!strcmp(toks[type_idx], "RRSIG")) type = 46;
							else if (!strcmp(toks[type_idx], "DNSKEY")) type = 48;
							else if (!strcmp(toks[type_idx], "NSEC3")) type = 50;
							else if (!strcmp(toks[type_idx], "NSEC3PARAM")) type = 51;
							else if (!strcmp(toks[type_idx], "TLSA")) type = 52;
							else type = 0; /* unknown */
							type_idx++;
						}

						/* find existing rrset */
						lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&zone->rrset_list)) {
							struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
							if (rs->type == type && rs->class_ == class_ && !strcmp(rs->name, cur_name)) {
								rrset = rs;
								break;
							}
						} lws_end_foreach_dll(d);

						if (!rrset) {
							rrset = lws_zalloc(sizeof(*rrset), "auth_dns_rrset");
							if (!rrset)
								return 1;
							rrset->name = lws_strdup(cur_name);
							rrset->type = type;
							rrset->class_ = class_;
							rrset->ttl = ttl;
							lws_dll2_add_tail(&rrset->list, &zone->rrset_list);
						}

						rr = lws_zalloc(sizeof(*rr), "auth_dns_rr");
						if (!rr)
							return 1;

						/* The remainder of the line is rdata. */
						{
							char *rd = strstr(line_accum, toks[type_idx - 1]);
							if (rd) {
								rd += strlen(toks[type_idx - 1]);
								while (*rd == ' ' || *rd == '\t') rd++;
								rr->rdata = lws_strdup(rd);
								if (rr->rdata)
									rr->rdata_len = strlen(rr->rdata);
							}
						}

						lws_dll2_add_tail(&rr->list, &rrset->rr_list);
						if (lws_auth_dns_rdata_to_wire(zone, rr, rrset->type))
							lwsl_err("Failed to wire-encode rdata for %s\n", rrset->name);

						lwsl_info("Parsed RR: name=%s type=%d ttl=%u rdata=%s\n", rrset->name, rrset->type, rrset->ttl, rr->rdata ? rr->rdata : "");
					}
				}
			}

			lptr = 0;
		} else {
			if (lptr < sizeof(line_accum) - 1)
				line_accum[lptr++] = *p;
		}
		p++;
	}
	return 0;
}

void
lws_auth_dns_free_zone(struct auth_dns_zone *z)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);

		lws_start_foreach_dll_safe(struct lws_dll2 *, d2, d3, lws_dll2_get_head(&rs->rr_list)) {
			struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
			lws_dll2_remove(&rr->list);
			if (rr->rdata)
				lws_free(rr->rdata);
			if (rr->wire_rdata)
				lws_free(rr->wire_rdata);
			lws_free(rr);
		} lws_end_foreach_dll_safe(d2, d3);

		lws_dll2_remove(&rs->list);
		if (rs->name)
			lws_free(rs->name);
		lws_free(rs);
	} lws_end_foreach_dll_safe(d, d1);
}

int
lws_auth_dns_sign_zone(struct lws_auth_dns_sign_info *info)
{
	char temp[16384], compact[16384], obuf[2048]; /* simple large enough buffer for test */
	int fd, n, ofd = -1, n_alg, res_wr, temp_len = sizeof(temp);
	size_t uin = 0, uout = 0;
	lws_strexp_t exp;
	struct stat st;
	char *buf, *expbuf;
	ssize_t ns;
	struct lws_jwk jwk;
	struct lws_jose jose;
	struct lws_jws jws;
	struct stat ost;
	char *outbuf = NULL;

	lwsl_info("%s: starting zone signing from %s\n", __func__, info->input_filepath);

	fd = open(info->input_filepath, LWS_O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: unable to open %s\n", __func__, info->input_filepath);
		return 1;
	}

	if (fstat(fd, &st) < 0) {
		close(fd);
		return 1;
	}

	buf = lws_malloc((size_t)st.st_size + 1, "auth_dns_in");
	if (!buf) {
		close(fd);
		return 1;
	}

	ns = read(fd, buf, (unsigned int)st.st_size);
	close(fd);

	if (ns != st.st_size) {
		lws_free(buf);
		return 1;
	}

	buf[st.st_size] = '\0';

	expbuf = lws_malloc((size_t)st.st_size * 2, "auth_dns_exp");
	if (!expbuf) {
		lws_free(buf);
		return 1;
	}

	lws_strexp_init(&exp, info, strexp_cb, expbuf, (size_t)st.st_size * 2);
	if (lws_strexp_expand(&exp, buf, (size_t)st.st_size, &uin, &uout) != LSTRX_DONE) {
		lwsl_err("%s: lws_strexp_expand failed or filled out buffer\n", __func__);
		lws_free(expbuf);
		lws_free(buf);

		return 1;
	}

	expbuf[uout] = '\0';

	struct auth_dns_zone zone;
	memset(&zone, 0, sizeof(zone));

	if (lws_auth_dns_parse_zone_buf(expbuf, uout, &zone)) {
		lwsl_err("Failed to parse zone\n");
		goto bail;
	}

	lws_auth_dns_inject_mock_keys(info, &zone);
	lws_auth_dns_sort_zone(info, &zone);
	lws_auth_dns_sign_rrsets(info, &zone);

	/* Write canonical sorted and combined zone into output_filepath (or fallback to user output string dump) */
	fd = open(info->output_filepath ? info->output_filepath : "signed.zone", LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0644);
	if (fd < 0) {
		lwsl_err("Failed to open output file for signing results\n");
		goto bail;
	}
	
	/* Write generic setup string at top */
	n = lws_snprintf(obuf, sizeof(obuf), "$ORIGIN %s\n$TTL %u\n\n", zone.origin, atoi(zone.default_ttl) ? atoi(zone.default_ttl) : 3600);
	(void)write(fd, obuf, (unsigned int)n);

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&zone.rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
		
		const char *ts = "UNKNOWN";
		switch (rs->type) {
			case 1: ts = "A"; break;
			case 2: ts = "NS"; break;
			case 6: ts = "SOA"; break;
			case 15: ts = "MX"; break;
			case 16: ts = "TXT"; break;
			case 28: ts = "AAAA"; break;
			case 46: ts = "RRSIG"; break;
			case 48: ts = "DNSKEY"; break;
			case 50: ts = "NSEC3"; break;
			case 51: ts = "NSEC3PARAM"; break;
		}

		lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&rs->rr_list)) {
			struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
			
			n = lws_snprintf(obuf, sizeof(obuf), "%-30s\t%u\tIN\t%s\t%s\n", 
				rs->name, rs->ttl, ts, rr->rdata ? rr->rdata : "");
			(void)write(fd, obuf, (unsigned int)n);
		} lws_end_foreach_dll(d2);
	} lws_end_foreach_dll(d);


	close(fd);
	lwsl_info("lws_auth_dns_sign_zone succeeded! Wrote to %s\n", info->output_filepath ? info->output_filepath : "signed.zone");

	if (!info->jws_filepath || !info->zsk_jwk_filepath) {
		lwsl_err("Missing jws_filepath or zsk_jwk_filepath\n");
		goto bail_jws;
	}

	lwsl_info("Starting JWS generation for %s\n", info->jws_filepath);

	if (lws_jwk_load(&jwk, info->zsk_jwk_filepath, NULL, NULL)) {
		lwsl_err("Failed loading jwk\n");
		goto bail_jws;
	}

	ofd = open(info->output_filepath ? info->output_filepath : "signed.zone", LWS_O_RDONLY);
	if (ofd < 0 || fstat(ofd, &ost) || ost.st_size <= 0 || ost.st_size >= 10000) {
		lwsl_err("Failed file open/stat ofd=%d st_size=%ld\n", ofd, (long)ost.st_size);
		goto bail_jwk;
	}

	outbuf = lws_malloc((size_t)ost.st_size, "auth_dns_out_jws");
	if (!outbuf || read(ofd, outbuf, (unsigned int)ost.st_size) != ost.st_size) {
		lwsl_err("Failed read or malloc\n");
		goto bail_ofd;
	}

	lws_jws_init(&jws, &jwk, info->cx);
	lws_jose_init(&jose);

	if (lws_jws_alloc_element(&jws.map, LJWS_JOSE, lws_concat_temp(temp, temp_len), &temp_len, 256, 0)) {
		lwsl_err("Failed JWS alloc JOSE\n");
		goto bail_jose;
	}

	n_alg = lws_snprintf((char *)jws.map.buf[LJWS_JOSE], 256, "{\"alg\":\"ES256\"}");
	jws.map.len[LJWS_JOSE] = (uint32_t)n_alg;

	jws.map.buf[LJWS_PYLD] = (const char *)outbuf;
	jws.map.len[LJWS_PYLD] = (uint32_t)ost.st_size;

	if (lws_jws_encode_b64_element(&jws.map_b64, LJWS_PYLD, lws_concat_temp(temp, temp_len), &temp_len, jws.map.buf[LJWS_PYLD], jws.map.len[LJWS_PYLD]) || 
		lws_jws_encode_b64_element(&jws.map_b64, LJWS_JOSE, lws_concat_temp(temp, temp_len), &temp_len, jws.map.buf[LJWS_JOSE], jws.map.len[LJWS_JOSE])) {
		lwsl_err("Failed JWS b64 encode\n");
		goto bail_jose;
	}

	if (lws_jws_parse_jose(&jose, (const char *)jws.map.buf[LJWS_JOSE], (int)jws.map.len[LJWS_JOSE], lws_concat_temp(temp, temp_len), &temp_len) < 0) {
		lwsl_err("Failed JWS parse JOSE\n");
		goto bail_jose;
	}

	if (lws_jws_alloc_element(&jws.map_b64, LJWS_SIG, lws_concat_temp(temp, temp_len), &temp_len, 256, 0)) {
		lwsl_err("Failed JWS alloc SIG\n");
		goto bail_jose;
	}

	n = lws_jws_sign_from_b64(&jose, &jws, (char *)jws.map_b64.buf[LJWS_SIG], jws.map_b64.len[LJWS_SIG]);
	if (n < 0) {
		lwsl_err("Failed JWS sign from b64: %d\n", n);
		goto bail_jose;
	}

	jws.map_b64.len[LJWS_SIG] = (uint32_t)n;
	res_wr = lws_jws_write_compact(&jws, compact, sizeof(compact));
	if (res_wr) {
		lwsl_err("Failed JWS compact write\n");
		goto bail_jose;
	}

	{
		int jfd = open(info->jws_filepath, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0644);
		if (jfd >= 0) {
			size_t clen = strlen(compact);
			(void)write(jfd, compact, (unsigned int)clen);
			close(jfd);
			lwsl_info("Wrote outer signature JWS to %s\n", info->jws_filepath);
		} else {
			lwsl_err("Failed opening JWS output file\n");
		}
	}

bail_jose:
	lws_jose_destroy(&jose);
bail_ofd:
	if (outbuf)
		lws_free(outbuf);
	if (ofd >= 0)
		close(ofd);
bail_jwk:
	lws_jwk_destroy(&jwk);
bail_jws:
	lws_free(expbuf);
	lws_free(buf);

	return 0;

bail:
	if (expbuf)
		lws_free(expbuf);
	if (buf)
		lws_free(buf);

	return 1;
}

#endif
