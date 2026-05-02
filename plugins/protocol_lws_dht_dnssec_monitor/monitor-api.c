/*
 * libwebsockets - protocol - dht_dnssec_monitor
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 */

#include "private.h"

signed char
monitor_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct monitor_req_args *a = (struct monitor_req_args *)ctx->user;

	if (reason == LEJPCB_VAL_STR_START) {
		if (ctx->path_match - 1 == LRP_ZONE) {
			a->zone_len = 0;
		}
	}

	if (reason == LEJPCB_VAL_NUM_INT) {
		if (ctx->path_match - 1 == LRP_PORT) {
			a->port = atoi(ctx->buf);
			lwsl_notice("[ACME] monitor_req_cb: Parsed port natively from JSON INT: %d\n", a->port);
		}
	}

	if (reason == LEJPCB_VAL_TRUE) {
		if (ctx->path_match - 1 == LRP_ENABLED) a->enabled = 1;
		if (ctx->path_match - 1 == LRP_PRODUCTION) a->production = 1;
	}

	if (reason == LEJPCB_VAL_FALSE) {
		if (ctx->path_match - 1 == LRP_ENABLED) a->enabled = 0;
		if (ctx->path_match - 1 == LRP_PRODUCTION) a->production = 0;
	}

	if (reason == LEJPCB_VAL_STR_CHUNK || reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case LRP_REQ:
			lws_strncpy(a->req, ctx->buf, sizeof(a->req));
			break;
		case LRP_DOMAIN:
			lws_strncpy(a->domain, ctx->buf, sizeof(a->domain));
			break;
		case LRP_SUBDOMAIN:
			lws_strncpy(a->subdomain, ctx->buf, sizeof(a->subdomain));
			break;
		case LRP_EMAIL:
			lws_strncpy(a->email, ctx->buf, sizeof(a->email));
			break;
		case LRP_ORG:
			lws_strncpy(a->organization, ctx->buf, sizeof(a->organization));
			break;
		case LRP_DIR_URL:
			lws_strncpy(a->directory_url, ctx->buf, sizeof(a->directory_url));
			break;
		case LRP_ZONE:
			if (!a->zone_buf) {
				a->zone_alloc = 8192;
				a->zone_buf = malloc((size_t)a->zone_alloc);
				if (!a->zone_buf) return -1;
			}
			if (a->zone_len + ctx->npos >= a->zone_alloc) {
				a->zone_alloc *= 2;
				char *nb = realloc(a->zone_buf, (size_t)a->zone_alloc);
				if (!nb) return -1;
				a->zone_buf = nb;
			}
			memcpy(a->zone_buf + a->zone_len, ctx->buf, ctx->npos);
			a->zone_len += ctx->npos;
			if (reason == LEJPCB_VAL_STR_END) {
				a->zone_buf[a->zone_len] = '\0';
			}
			break;
		case LRP_JWT:
			lws_strncpy(a->jwt, ctx->buf, sizeof(a->jwt));
			break;
		case LRP_SUFFIX:
			lws_strncpy(a->suffix, ctx->buf, sizeof(a->suffix));
			break;
		case LRP_KEY_TYPE:
			lws_strncpy(a->key_type, ctx->buf, sizeof(a->key_type));
			break;
		case LRP_PORT:
			a->port = atoi(ctx->buf);
			break;
		case LRP_COUNTRY:
			lws_strncpy(a->country, ctx->buf, sizeof(a->country));
			break;
		case LRP_STATE:
			lws_strncpy(a->state, ctx->buf, sizeof(a->state));
			break;
		case LRP_LOCALITY:
			lws_strncpy(a->locality, ctx->buf, sizeof(a->locality));
			break;
		case LRP_PROFILE:
			lws_strncpy(a->profile, ctx->buf, sizeof(a->profile));
			break;
		}
	}

	if (reason == LEJPCB_FAILED) {
		lwsl_err("[ACME] monitor_req_cb: LEJP JSON Parse FAILED at struct offset %d\n", (int)ctx->st[ctx->sp].s);
	}

	return 0;
}

static int cmp_str(const void *a, const void *b) {
	return strcmp(*(const char **)a, *(const char **)b);
}

static void
handle_req_status(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"status\",\"status\":\"ok\"}\n");
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_domains(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char path[1024];
	DIR *d;
	struct dirent *de;

	lws_snprintf(path, sizeof(path), "%s/domains", vhd->base_dir);
	d = opendir(path);
	if (!d) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_domains\",\"status\":\"error\",\"msg\":\"Cannot open base_dir\"}\n");
	} else {
		char **doms = NULL;
		size_t count = 0, alloc = 0;

		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') continue;
			if (de->d_type == DT_DIR || de->d_type == DT_UNKNOWN) {
				if (count >= alloc) {
					alloc = alloc ? alloc * 2 : 16;
					char **ndoms = realloc(doms, alloc * sizeof(char *));
					if (!ndoms) break;
					doms = ndoms;
				}
				doms[count++] = strdup(de->d_name);
			}
		}
		closedir(d);

		if (count) {
			qsort(doms, count, sizeof(char *), cmp_str);
		}

		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_domains\",\"status\":\"ok\",\"domains\":[");
		for (size_t i = 0; i < count; i++) {
			char whois_path[1024], whois_buf[2048] = "{}";
			char local_ds[256] = "";

			if (i > 0) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");

			lws_snprintf(whois_path, sizeof(whois_path), "%s/domains/%s/whois.json", vhd->base_dir, doms[i]);
			int fd_w = open(whois_path, O_RDONLY);
			if (fd_w >= 0) {
				ssize_t nw = read(fd_w, whois_buf, sizeof(whois_buf) - 1);
				if (nw > 0) whois_buf[nw] = '\0';
				close(fd_w);
			}



			char alg_buf[32] = "";
			char zsk_path[1024];
			lws_snprintf(zsk_path, sizeof(zsk_path), "%s/domains/%s/%s.zsk.private.jwk", vhd->base_dir, doms[i], doms[i]);
			int fd_z = open(zsk_path, O_RDONLY);
			if (fd_z >= 0) {
				char jwk_buf[2048];
				ssize_t nj = read(fd_z, jwk_buf, sizeof(jwk_buf) - 1);
				if (nj > 0) {
					jwk_buf[nj] = '\0';
					char *p = strstr(jwk_buf, "\"alg\"");
					if (p) {
						p = strchr(p, ':');
						if (p) {
							while (*p == ':' || *p == ' ' || *p == '"' || *p == '\t' || *p == '\n') p++;
							char *end = strchr(p, '"');
							if (end && (end - p) < (int)sizeof(alg_buf)) {
								lws_strncpy(alg_buf, p, lws_ptr_diff_size_t(end, p) + 1);
							}
						}
					} else {
						if (strstr(jwk_buf, "\"P-256\"")) lws_strncpy(alg_buf, "ES256", sizeof(alg_buf));
						else if (strstr(jwk_buf, "\"P-384\"")) lws_strncpy(alg_buf, "ES384", sizeof(alg_buf));
						else if (strstr(jwk_buf, "\"RSA\"")) lws_strncpy(alg_buf, "RS256", sizeof(alg_buf));
					}
				}
				close(fd_z);
			}

			calc_local_ds(vhd, doms[i], local_ds, sizeof(local_ds));

			char dns_ds[512] = "";
			char dns_ds_path[1024];
			lws_snprintf(dns_ds_path, sizeof(dns_ds_path), "%s/domains/%s/dns_ds.txt", vhd->base_dir, doms[i]);
			int fd_ds = open(dns_ds_path, O_RDONLY);
			if (fd_ds >= 0) {
				ssize_t nw = read(fd_ds, dns_ds, sizeof(dns_ds) - 1);
				if (nw > 0) dns_ds[nw] = '\0';
				close(fd_ds);
			}

			char dns_ds_global[512] = "";
			char dns_ds_global_path[1024];
			lws_snprintf(dns_ds_global_path, sizeof(dns_ds_global_path), "%s/domains/%s/dns_ds_8888.txt", vhd->base_dir, doms[i]);
			int fd_ds_g = open(dns_ds_global_path, O_RDONLY);
			if (fd_ds_g >= 0) {
				ssize_t nw = read(fd_ds_g, dns_ds_global, sizeof(dns_ds_global) - 1);
				if (nw > 0) dns_ds_global[nw] = '\0';
				close(fd_ds_g);
			}

			char acme_dis_path[1024];
			lws_snprintf(acme_dis_path, sizeof(acme_dis_path), "%s/domains/%s/acme_disabled", vhd->base_dir, doms[i]);
			int acme_enabled = 1;
			int fd_a = open(acme_dis_path, O_RDONLY);
			if (fd_a >= 0) {
				acme_enabled = 0;
				close(fd_a);
			}

			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx),
				"{\"name\":\"%s\",\"whois\":%s,\"local_ds\":\"%s\",\"dns_ds\":\"%s\",\"dns_ds_global\":\"%s\",\"alg\":\"%s\",\"acme_enabled\":%s}",
				doms[i], whois_buf[0] ? whois_buf : "{}", local_ds, dns_ds, dns_ds_global, alg_buf, acme_enabled ? "true" : "false");
			free(doms[i]);
		}
		if (doms) free(doms);
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "]}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_create_domain(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	int r = 0;

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s", vhd->base_dir, a->domain);
	if (mkdir(d_path, 0755) < 0 && errno != EEXIST)
		r = -1;

	if (r) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Failed making dirs\"}\n", a->req);
	} else {
		int fd;
		lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s.zone", vhd->base_dir, a->domain, a->domain);
		fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) close(fd);
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_delete_domain(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s", vhd->base_dir, a->domain);
	lws_dir(d_path, NULL, lws_dir_rm_rf_cb);
	rmdir(d_path);

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_zone(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s.zone", vhd->base_dir, a->domain, a->domain);
	int fd = open(d_path, O_RDONLY);
	if (fd >= 0) {
		struct stat st;
		if (!fstat(fd, &st) && st.st_size >= 0) {
			size_t sz = (size_t)st.st_size;
			char *z = malloc(sz + 1);
			if (z) {
				if (read(fd, z, sz) == (ssize_t)sz) {
					z[sz] = '\0';
					tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"zone\":\"", a->req);
					for (size_t i = 0; i < sz; i++) {
						if (tx >= tx_end - 6) break;
						if (z[i] == '\n') { *tx++ = '\\'; *tx++ = 'n'; }
						else if (z[i] == '\r') { *tx++ = '\\'; *tx++ = 'r'; }
						else if (z[i] == '"') { *tx++ = '\\'; *tx++ = '"'; }
						else if (z[i] == '\\') { *tx++ = '\\'; *tx++ = '\\'; }
						else if (z[i] == '\t') { *tx++ = '\\'; *tx++ = 't'; }
						else *tx++ = z[i];
					}
					tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\"}\n");
				}
				free(z);
			}
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Zone missing\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_update_zone(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	if (!a->zone_buf) goto fail;

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s.zone", vhd->base_dir, a->domain, a->domain);
	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) {
		if (write(fd, a->zone_buf, (size_t)a->zone_len) == (ssize_t)a->zone_len) {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Partial write failure\"}\n", a->req);
		}
		close(fd);
	} else {
fail:
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Could not open zone for writing\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_acme_config(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/acme_config.json", vhd->base_dir);
	int fd = open(d_path, O_RDONLY);
	if (fd >= 0) {
		char buf[4096];
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_config\",\"status\":\"ok\",\"config\":%s}\n", buf);
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_config\",\"status\":\"ok\",\"config\":{}}\n");
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_config\",\"status\":\"ok\",\"config\":{}}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_set_acme_config(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	char buf[4096];
	int n, fd;

	lws_snprintf(d_path, sizeof(d_path), "%s/acme_config.json", vhd->base_dir);
	fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) {
		n = lws_snprintf(buf, sizeof(buf),
			"{\n  \"enabled\": %s,\n  \"production\": %s,\n  \"email\": \"%s\",\n"
			"  \"organization\": \"%s\",\n  \"country\": \"%s\",\n  \"state\": \"%s\",\n"
			"  \"locality\": \"%s\",\n  \"profile\": \"%s\"\n}\n",
			a->enabled ? "true" : "false",
			a->production ? "true" : "false",
			a->email, a->organization, a->country, a->state, a->locality, a->profile);

		if (write(fd, buf, (size_t)n) == (ssize_t)n) {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"set_acme_config\",\"status\":\"ok\"}\n");
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"set_acme_config\",\"status\":\"error\",\"msg\":\"Write failed\"}\n");
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"set_acme_config\",\"status\":\"error\",\"msg\":\"Could not open config\"}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_set_domain_acme(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/acme_disabled", vhd->base_dir, a->domain);
	if (a->enabled) {
		unlink(d_path);
	} else {
		int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) close(fd);
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"set_domain_acme\",\"status\":\"ok\"}\n");
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_acme_log(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/acme.log", vhd->base_dir);
	int fd = open(d_path, O_RDONLY);
	if (fd >= 0) {
		char buf[4096];
		lws_filepos_t size = (lws_filepos_t)lseek(fd, 0, SEEK_END);
		lws_filepos_t start = 0;
		if (size > 4000) start = size - 4000;
		if (lseek(fd, (off_t)start, SEEK_SET) >= 0) {
			ssize_t n = read(fd, buf, sizeof(buf) - 1);
			if (n > 0) {
				buf[n] = '\0';
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_log\",\"status\":\"ok\",\"log\":\"");
				for (ssize_t i = 0; i < n; i++) {
					if (buf[i] == '\n') tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\\n");
					else if (buf[i] == '"') tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\\\"");
					else if (buf[i] == '\\') tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\\\\");
					else if (buf[i] >= 32 && buf[i] <= 126) *tx++ = buf[i];
				}
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\"}\n");
			} else {
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_log\",\"status\":\"ok\",\"log\":\"\"}\n");
			}
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_log\",\"status\":\"ok\",\"log\":\"No log found.\"}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_save_acme_file(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a, const char *dir_suffix, int mode)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	if (!a->zone_buf || !a->domain[0] || !a->subdomain[0]) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing payload, domain, or filename\"}\n", a->req);
		goto done;
	}

	char dir_path[1024];
	lws_snprintf(dir_path, sizeof(dir_path), "%s/domains/%s/%s", vhd->base_dir, a->domain, dir_suffix);
	lws_snprintf(d_path, sizeof(d_path), "%s/%s", dir_path, a->subdomain);

	uid_t u = (uid_t)-1; gid_t g = (uid_t)-1;
	if (vhd->stub_uid[0]) {
		if (isdigit(vhd->stub_uid[0])) u = (uid_t)atoi(vhd->stub_uid);
		else { struct passwd *pw = getpwnam(vhd->stub_uid); if (pw) u = pw->pw_uid; }
	}
	if (vhd->stub_gid[0]) {
		if (isdigit(vhd->stub_gid[0])) g = (gid_t)atoi(vhd->stub_gid);
		else { struct group *gr = getgrnam(vhd->stub_gid); if (gr) g = gr->gr_gid; }
	}

	char p[1024];
	lws_strncpy(p, dir_path, sizeof(p));
	char *q = strchr(p + 1, '/');
	while (q) {
		*q = '\0';
		if (mkdir(p, 0700) < 0 && errno != EEXIST)
			lwsl_err("%s: Failed to create directory %s\n", __func__, p);
		if (u != (uid_t)-1) chown(p, u, g);
		*q = '/';
		q = strchr(q + 1, '/');
	}
	if (mkdir(p, 0700) < 0 && errno != EEXIST)
		lwsl_err("%s: Failed to create directory %s\n", __func__, p);
	if (u != (uid_t)-1) chown(p, u, g);

	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, mode);
	if (fd >= 0) {
		if (write(fd, a->zone_buf, (size_t)a->zone_len) == (ssize_t)a->zone_len) {
#if !defined(WIN32)
			if (u != (uid_t)-1) fchown(fd, u, g);
			fchmod(fd, (mode_t)mode);
#endif
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);

			const char *ext = strrchr(a->subdomain, '.');
			char base[256];
			lws_strncpy(base, a->subdomain, sizeof(base));
			char *dash = strrchr(base, '-');
			if (ext && dash && (!strcmp(ext, ".crt") || !strcmp(ext, ".key"))) {
				*dash = '\0';
				char latest_link[1024], previous_link[1024];
				lws_snprintf(latest_link, sizeof(latest_link), "%s/%s-latest%s", dir_path, base, ext);
				lws_snprintf(previous_link, sizeof(previous_link), "%s/%s-previous%s", dir_path, base, ext);

#if !defined(WIN32)
				char target[1024];
				ssize_t link_len = readlink(latest_link, target, sizeof(target) - 1);
				if (link_len > 0) {
					target[link_len] = '\0';
					unlink(previous_link);
					symlink(target, previous_link);
					if (u != (uid_t)-1) lchown(previous_link, u, g);
				}

				unlink(latest_link);
				symlink(a->subdomain, latest_link);
				if (u != (uid_t)-1) lchown(latest_link, u, g);
#endif
			}
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Partial write failure\"}\n", a->req);
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Could not open file for writing\"}\n", a->req);
	}
done:
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void handle_req_save_auth_key(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a) { handle_req_save_acme_file(vhd, root_pss, a, "", 0600); }
static void handle_req_save_cert(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a) { handle_req_save_acme_file(vhd, root_pss, a, vhd->acme_production ? "certs/production/crt" : "certs/staging/crt", 0640); }
static void handle_req_save_key(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a) { handle_req_save_acme_file(vhd, root_pss, a, vhd->acme_production ? "certs/production/key" : "certs/staging/key", 0600); }

static void
handle_req_update_whois(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	if (a->domain[0] && a->zone_buf) {
		char path[1024];
		lws_snprintf(path, sizeof(path), "%s/domains/%s/whois.json", vhd->base_dir, a->domain);
		int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) {
			char decoded[8192];
			int n = lws_b64_decode_string(a->zone_buf, decoded, sizeof(decoded));
			if (n > 0) write(fd, decoded, (size_t)n);
			close(fd);
		}
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_regen_keys(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;

	if (vhd->ops && vhd->ops->keygen) {
		struct lws_dht_dnssec_keygen_args kargs;
		memset(&kargs, 0, sizeof(kargs));
		char wd[1024];
		lws_snprintf(wd, sizeof(wd), "%s/domains/%s", vhd->base_dir, a->domain);
		kargs.domain = a->domain;
		kargs.workdir = wd;

		if (!strcmp(a->key_type, "ES256")) { kargs.type = "EC"; kargs.curve = "P-256"; kargs.bits = 256; }
		else if (!strcmp(a->key_type, "ES384")) { kargs.type = "EC"; kargs.curve = "P-384"; kargs.bits = 384; }
		else if (!strcmp(a->key_type, "R1024")) { kargs.type = "RSA"; kargs.bits = 1024; }
		else if (!strcmp(a->key_type, "R2048")) { kargs.type = "RSA"; kargs.bits = 2048; }
		else { kargs.type = "EC"; kargs.curve = "P-256"; kargs.bits = 256; }

		if (!vhd->ops->keygen(vhd->context, &kargs)) {
			char signed_path[1024];
			lws_snprintf(signed_path, sizeof(signed_path), "%s/%s.zone.signed", wd, a->domain);
			unlink(signed_path);
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Key generation failed\"}\n", a->req);
		}
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Keygen unsupported\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_tls(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	DIR *d;
	struct dirent *de;

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d", vhd->base_dir, a->domain);
	d = opendir(d_path);
	if (!d) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"tls\":[]}\n", a->req);
	} else {
		int first = 1;
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"tls\":[", a->req);
		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') continue;
			if (strstr(de->d_name, ".port")) {
				char p_path[1024], sub[256];
				lws_strncpy(sub, de->d_name, sizeof(sub));
				char *ext = strstr(sub, ".port");
				if (ext) *ext = '\0';
				lws_snprintf(p_path, sizeof(p_path), "%s/%s", d_path, de->d_name);
				int fd = open(p_path, O_RDONLY);
				if (fd >= 0) {
					char buf[64];
					ssize_t n = read(fd, buf, sizeof(buf) - 1);
					if (n > 0) {
						buf[n] = '\0';
						if (!first) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");
						tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"fqdn\":\"%s\",\"port\":%d}", sub, atoi(buf));
						first = 0;
					}
					close(fd);
				}
			}
		}
		closedir(d);
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "]}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_create_tls(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d", vhd->base_dir, a->domain);
	mkdir(d_path, 0755);
	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d/%s.port", vhd->base_dir, a->domain, a->subdomain);
	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) {
		char buf[64];
		int n = lws_snprintf(buf, sizeof(buf), "%d\n", a->port);
		write(fd, buf, (size_t)n);
		close(fd);
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_delete_tls(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d/%s.port", vhd->base_dir, a->domain, a->subdomain);
	unlink(d_path);
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_ipv6_suffix(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char path[1024], suffix[64] = {0};
	lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt", vhd->base_dir);
	int fd = open(path, O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, suffix, sizeof(suffix) - 1);
		if (n > 0) {
			suffix[n] = '\0';
			for (int i = (int)strlen(suffix) - 1; i >= 0 && (suffix[i] == '\n' || suffix[i] == '\r' || suffix[i] == ' '); i--) suffix[i] = '\0';
		}
		close(fd);
	}
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"suffix\":\"%s\"}\n", a->req, suffix);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_set_ipv6_suffix(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char path[1024];
	lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt", vhd->base_dir);
	if (!a->suffix[0]) unlink(path);
	else {
		int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) {
			write(fd, a->suffix, strlen(a->suffix));
			close(fd);
		}
	}
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_provisioning_bundle(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536;
	char path[512], *ca = NULL, *crt = NULL, *key = NULL;
	struct stat st;
	int fd;

	if (!a->domain[0] || !a->subdomain[0]) {
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing domain or subdomain\"}\n", a->req);
		return;
	}

	lws_snprintf(path, sizeof(path), "%s/pki/distribution-ca.crt", vhd->base_dir);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			ca = malloc((size_t)st.st_size + 1);
			if (ca && read(fd, ca, (size_t)st.st_size) == (ssize_t)st.st_size) ca[st.st_size] = '\0';
			else { free(ca); ca = NULL; }
		}
		close(fd);
	}

	lws_snprintf(path, sizeof(path), "%s/domains/%s/dist-client/distribution-client-%s.crt", vhd->base_dir, a->domain, a->subdomain);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			crt = malloc((size_t)st.st_size + 1);
			if (crt && read(fd, crt, (size_t)st.st_size) == (ssize_t)st.st_size) crt[st.st_size] = '\0';
			else { free(crt); crt = NULL; }
		}
		close(fd);
	}

	lws_snprintf(path, sizeof(path), "%s/domains/%s/dist-client/distribution-client-%s.key", vhd->base_dir, a->domain, a->subdomain);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			key = malloc((size_t)st.st_size + 1);
			if (key && read(fd, key, (size_t)st.st_size) == (ssize_t)st.st_size) key[st.st_size] = '\0';
			else { free(key); key = NULL; }
		}
		close(fd);
	}

	if (!ca || !crt || !key) {
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Certificate files not found on server\"}\n", a->req);
		goto bail;
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"subdomain\":\"%s\",\"ca\":\"", a->req, a->subdomain);
	char *p = ca; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\",\"cert\":\"");
	p = crt; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\",\"key\":\"");
	p = key; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\"}\n");

bail:
	if (ca)
		free(ca);
	if (crt)
		free(crt);
	if (key)
		free(key);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void handle_req_check_cert(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	struct lws_client_connect_info i;
	memset(&i, 0, sizeof(i));
	i.context = vhd->context;
	struct lws_vhost *vh = lws_get_vhost_by_name(vhd->context, "root-monitor-dummy");
	i.vhost = vh ? vh : vhd->vhost;
	i.address = a->subdomain;
	i.port = a->port;
	i.ssl_connection = LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	int starttls = (a->port == 25 || a->port == 587);
	if (!starttls) i.ssl_connection |= LCCSCF_USE_SSL;
	i.alpn = "http/1.1"; i.method = "RAW"; i.path = "/"; i.host = i.address; i.origin = i.address; i.protocol = "lws-dht-dnssec-monitor";
	struct cert_check_info *cci = malloc(sizeof(*cci));
	if (cci) {
		memset(cci, 0, sizeof(*cci));
		cci->magic = CERT_CHECK_MAGIC;
		lws_strncpy(cci->fqdn, a->subdomain, sizeof(cci->fqdn));
		lws_strncpy(cci->domain, a->domain, sizeof(cci->domain));
		cci->port = a->port; cci->starttls_state = starttls ? 1 : 0;
		i.opaque_user_data = cci;
	}
	if (!cci || !lws_client_connect_via_info(&i)) {
		if (cci) free(cci);
		struct cert_check_result *cr = malloc(sizeof(*cr));
		if (cr) {
			memset(cr, 0, sizeof(*cr));
			lws_strncpy(cr->fqdn, a->subdomain, sizeof(cr->fqdn));
			lws_strncpy(cr->msg, "Connection failed", sizeof(cr->msg));
			cr->port = a->port; cr->status_err = 1;
			lws_dll2_add_tail(&cr->list, &vhd->completed_checks);
			lws_callback_on_writable_all_protocol(vhd->context, lws_get_protocol(root_pss->wsi));
		}
	}
}

static void
handle_req_trigger_resign(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;

	lwsl_notice("%s: ACME client triggered immediate re-sign for all zones\n", __func__);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_scan, root_dnssec_scan_timer_cb, 100 * LWS_US_PER_MS);

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"trigger_resign\",\"status\":\"ok\"}\n");
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}


struct lws * handle_req_get_acme_profiles(struct vhd *vhd, struct pss *root_pss, const char *directory_url)
{
	struct lws_client_connect_info i;
	memset(&i, 0, sizeof(i));
	i.context = vhd->context;
	struct lws_vhost *vh = lws_get_vhost_by_name(vhd->context, "root-monitor-dummy");
	i.vhost = vh ? vh : vhd->vhost;

	const char *url = (vhd->acme_production) ?
		"https://acme-v02.api.letsencrypt.org/directory" :
		"https://acme-staging-v02.api.letsencrypt.org/directory";

	i.address = vhd->acme_production ? "acme-v02.api.letsencrypt.org" : "acme-staging-v02.api.letsencrypt.org";
	i.port = 443;
	i.ssl_connection = LCCSCF_USE_SSL;
	i.alpn = "http/1.1";
	i.method = "GET";
	i.path = "/directory";
	i.host = i.address;
	i.origin = i.address;
	i.protocol = "lws-dht-dnssec-monitor";

	struct acme_profiles_fetch_info *afi = malloc(sizeof(*afi));
	if (afi) {
		memset(afi, 0, sizeof(*afi));
		afi->magic = ACME_PROFILES_MAGIC;
		afi->root_pss = root_pss; // Note: if pss closes early, we might write to dead memory. We should be careful or just broadcast.
		i.opaque_user_data = afi;
	}

	lwsl_notice("%s: Fetching ACME directory from %s\n", __func__, url);
	struct lws *wsi = lws_client_connect_via_info(&i);
	if (!wsi && afi) {
		free(afi);
		// Send failure to UI
		char *tx = (char *)&root_pss->tx[LWS_PRE];
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"get_acme_profiles\",\"status\":\"error\",\"msg\":\"Failed to connect to ACME directory\"}\n");
		lws_callback_on_writable_all_protocol(vhd->context, lws_get_protocol(root_pss->wsi));
	}
	return wsi;
}

static void handle_get_acme_profiles_wrapper(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	handle_req_get_acme_profiles(vhd, root_pss, NULL);
}

static const struct monitor_req_map req_map[] = {
	{ "status", handle_req_status },
	{ "get_domains", handle_req_get_domains },
	{ "create_domain", handle_req_create_domain },
	{ "delete_domain", handle_req_delete_domain },
	{ "get_zone", handle_req_get_zone },
	{ "update_zone", handle_req_update_zone },
	{ "get_acme_config", handle_req_get_acme_config },
	{ "set_acme_config", handle_req_set_acme_config },
	{ "set_domain_acme", handle_req_set_domain_acme },
	{ "get_acme_log", handle_req_get_acme_log },
	{ "update_whois", handle_req_update_whois },
	{ "save_auth_key", handle_req_save_auth_key },
	{ "save_cert", handle_req_save_cert },
	{ "save_key", handle_req_save_key },
	{ "get_ipv6_suffix", handle_req_get_ipv6_suffix },
	{ "set_ipv6_suffix", handle_req_set_ipv6_suffix },
	{ "regen_keys", handle_req_regen_keys },
	{ "get_tls", handle_req_get_tls },
	{ "create_tls", handle_req_create_tls },
	{ "delete_tls", handle_req_delete_tls },
	{ "provisioning_bundle", handle_req_provisioning_bundle },
	{ "check_cert", handle_req_check_cert },
	{ "trigger_resign", handle_req_trigger_resign },
	{ "get_acme_profiles", handle_get_acme_profiles_wrapper }
};

void
handle_monitor_request(struct vhd *vhd, struct pss *root_pss, const char *in, size_t len)
{
	struct monitor_req_args a;
	struct lejp_ctx jctx;
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	const size_t req_map_size = LWS_ARRAY_SIZE(req_map);
	uint64_t start = (uint64_t)lws_now_usecs();

	lwsl_notice("[ROOT-DAEMON] %s: Handling IPC request at %llu: %.*s\n", __func__, (unsigned long long)start, (int)len, in);
	memset(&a, 0, sizeof(a));
	lejp_construct(&jctx, monitor_req_cb, &a, monitor_req_paths, LWS_ARRAY_SIZE(monitor_req_paths));
	int m = lejp_parse(&jctx, (uint8_t *)in, (int)len);
	lejp_destruct(&jctx);

	if (m < 0 && m != LEJP_REJECT_UNKNOWN) {
		lwsl_err("[ROOT-DAEMON] %s: JSON parse failed: %d\n", __func__, m);
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"JSON parse failed: %d\"}\n", a.req[0] ? a.req : "unknown", m);
		goto done;
	}
	if (!a.req[0]) {
		lwsl_err("[ROOT-DAEMON] %s: Missing 'req' in JSON\n", __func__);
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"status\":\"error\",\"msg\":\"Missing req\"}\n");
		goto done;
	}

	lwsl_notice("[ROOT-DAEMON] %s: Processing req '%s'\n", __func__, a.req);

	if (vhd->auth_jwk.kty == LWS_GENCRYPTO_KTY_OCT) {
		char jwt_out[2048], jwt_temp[2048];
		size_t jwt_out_len = sizeof(jwt_out);
		unsigned long exp_time;
		if (!a.jwt[0]) {
			lwsl_err("[ROOT-DAEMON] %s: Missing JWT in request\n", __func__);
			root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"status\":\"error\",\"msg\":\"Missing JWT\"}\n");
			goto done;
		}
		if (lws_jwt_signed_validate(vhd->context, &vhd->auth_jwk, "HS256", a.jwt, strlen(a.jwt), jwt_temp, sizeof(jwt_temp), jwt_out, &jwt_out_len)) {
			lwsl_err("[ROOT-DAEMON] %s: JWT signature validation failed\n", __func__);
			root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"status\":\"error\",\"msg\":\"JWT validation failed\"}\n");
			goto done;
		}
		if (lws_jwt_token_sanity(jwt_out, jwt_out_len, "acme-ipc", "dnssec-monitor", NULL, NULL, 0, &exp_time)) {
			lwsl_err("[ROOT-DAEMON] %s: JWT token sanity check failed (aud/iss mismatch or expired)\n", __func__);
			root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"status\":\"error\",\"msg\":\"JWT sanity check failed\"}\n");
			goto done;
		}
		lwsl_notice("[ROOT-DAEMON] %s: Authentication successful\n", __func__);
	}

	if (strchr(a.domain, '/') || strstr(a.domain, "..") || strchr(a.subdomain, '/') || strstr(a.subdomain, "..")) {
		lwsl_err("[ROOT-DAEMON] %s: Rejecting request with suspicious domain/subdomain chars: %s/%s\n", __func__, a.domain, a.subdomain);
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Invalid chars in domain\"}\n", a.req);
		goto done;
	}

	for (size_t i = 0; i < req_map_size; i++) {
		if (!strcmp(a.req, req_map[i].name)) {
			lwsl_notice("[ROOT-DAEMON] %s: Calling handler for '%s'\n", __func__, a.req);
			req_map[i].cb(vhd, root_pss, &a);
			goto done;
		}
	}
	lwsl_err("[ROOT-DAEMON] %s: Unknown request type: %s\n", __func__, a.req);
	root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"unknown\",\"status\":\"error\",\"msg\":\"Unknown req %s\"}\n", a.req);

done:
	if (a.zone_buf) free(a.zone_buf);
}
