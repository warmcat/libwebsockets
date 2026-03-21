/*
 * libwebsockets - protocol - dht_dnssec_monitor
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 *  This plugin monitors a config directory and a zone directory to automate
 *  DNSSEC signing tasks over operations exported by lws-dht-dnssec.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/wait.h>
#endif

struct pss {
	struct lws *wsi;
	struct lws *cwsi;

	/* TX (proxy -> root) buffer */
	uint8_t tx[4096];
	size_t tx_len;

	/* RX (root -> proxy) buffer */
	uint8_t rx[4096];
	size_t rx_len;
};

struct vhd {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_dht_dnssec_ops *ops;

	char *base_dir;
	const char *uds_path;
	uint32_t signature_duration;

	lws_sorted_usec_list_t sul_timer;
	struct lws_dir_notify *dn;

	struct lws_spawn_piped *lsp;
	int root_process_active;

	/* UDS raw rx buffer for server */
	uint8_t rx[4096];
	size_t rx_len;
};

extern const struct lws_protocols lws_dht_dnssec_monitor_protocols[];

/* Helper for when the child process exits */
static void
lws_dht_dnssec_monitor_reap_cb(void *opaque, const struct lws_spawn_resource_us *res,
			       siginfo_t *si, int we_killed_him)
{
	struct vhd *vhd = (struct vhd *)opaque;
	lwsl_notice("%s: Spawned root monitor process terminated (killed: %d)\n", __func__, we_killed_him);
	vhd->root_process_active = 0;
	vhd->lsp = NULL;
}

struct parsed_config {
	struct vhd *vhd;
	char common_name[256];
	char email[256];
};

static const char * const config_paths[] = {
	"common-name",
	"email",
};

enum enum_config_paths {
	LEJP_CONF_COMMON_NAME,
	LEJP_CONF_EMAIL,
};

static signed char
cb_conf(struct lejp_ctx *ctx, char reason)
{
	struct parsed_config *pc = (struct parsed_config *)ctx->user;

	if (reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case LEJP_CONF_COMMON_NAME:
			lws_strncpy(pc->common_name, ctx->buf, sizeof(pc->common_name));
			break;
		case LEJP_CONF_EMAIL:
			lws_strncpy(pc->email, ctx->buf, sizeof(pc->email));
			break;
		}
	}

	return 0;
}

static int
scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	char filepath[1024];
	int fd;
	struct stat st;
	char *buf;
	struct parsed_config pc;
	struct lejp_ctx jctx;

	if (lde->type != LDOT_DIR)
		return 0;

	if (lde->name[0] == '.')
		return 0;

	lws_snprintf(filepath, sizeof(filepath), "%s/%s/conf.d/%s.json", dirpath, lde->name, lde->name);

	fd = open(filepath, O_RDONLY);
	if (fd < 0)
		return 0;

	if (fstat(fd, &st) < 0 || st.st_size == 0) {
		close(fd);
		return 0;
	}

	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		return 0;
	}

	if (read(fd, buf, (size_t)st.st_size) != st.st_size) {
		free(buf);
		close(fd);
		return 0;
	}
	buf[st.st_size] = '\0';
	close(fd);

	memset(&pc, 0, sizeof(pc));
	pc.vhd = vhd;
	lejp_construct(&jctx, cb_conf, &pc, config_paths, LWS_ARRAY_SIZE(config_paths));
	int m = lejp_parse(&jctx, (uint8_t *)buf, (int)st.st_size);
	lejp_destruct(&jctx);
	free(buf);

	if (m < 0 && m != LEJP_REJECT_UNKNOWN) {
		lwsl_err("%s: JSON decode failed for %s: %d\n", __func__, filepath, m);
		return 0;
	}

	if (pc.common_name[0]) {
		if (strchr(pc.common_name, '/') || strstr(pc.common_name, "..")) {
			lwsl_err("%s: Invalid common-name containing path traversal characters: %s\n", __func__, pc.common_name);
			return 0;
		}

		lwsl_info("%s: Parsed domain %s from %s\n", __func__, pc.common_name, filepath);

		/* Directory format requires <base_dir>/domains/<common_name>/dns/ */
		char key_path[1024];

		/* Check ZSK */
		lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/dns/%s.zsk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);
		int has_zsk = (access(key_path, F_OK) == 0);

		/* Check KSK */
		lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/dns/%s.ksk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);
		int has_ksk = (access(key_path, F_OK) == 0);

		if (!has_zsk || !has_ksk) {
			lwsl_notice("%s: Missing keys for %s, automatically generating...\n", __func__, pc.common_name);
			char wd[512];
			lws_snprintf(wd, sizeof(wd), "%s/domains/%s/dns", vhd->base_dir, pc.common_name);

			struct lws_dht_dnssec_keygen_args kargs;
			memset(&kargs, 0, sizeof(kargs));
			kargs.domain = pc.common_name;
			kargs.workdir = wd;

			/* Assume ES256 fallback if unspecified (or whatever dnssec module defaults to) */
			kargs.curve = "P-256";

			if (vhd->ops->keygen(vhd->context, &kargs))
				lwsl_err("%s: Failed to generate keys for %s\n", __func__, pc.common_name);
		}

		/* Check resign triggers */
		char input_path[1024];
		char output_path[1024];
		char jws_path[1024];
		char zsk_path[1024];
		char ksk_path[1024];

		lws_snprintf(input_path, sizeof(input_path), "%s/domains/%s/dns/%s.zone", vhd->base_dir, pc.common_name, pc.common_name);
		lws_snprintf(output_path, sizeof(output_path), "%s/domains/%s/dns/%s.zone.signed", vhd->base_dir, pc.common_name, pc.common_name);
		lws_snprintf(jws_path, sizeof(jws_path), "%s/domains/%s/dns/%s.zone.signed.jws", vhd->base_dir, pc.common_name, pc.common_name);
		lws_snprintf(zsk_path, sizeof(zsk_path), "%s/domains/%s/dns/%s.zsk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);
		lws_snprintf(ksk_path, sizeof(ksk_path), "%s/domains/%s/dns/%s.ksk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);

		char acme_path[1024];
		lws_snprintf(acme_path, sizeof(acme_path), "%s.acme", input_path);
		struct stat st_acme;
		int has_acme = (stat(acme_path, &st_acme) == 0);

		int needs_resign = 0;
		struct stat st_in, st_out;

		if (stat(input_path, &st_in) == 0) {
			if (stat(output_path, &st_out) != 0) {
				/* output doesn't exist */
				lwsl_user("dnssec_monitor: %s does not exist! Triggering resign!\n", output_path);
				needs_resign = 1;
			} else {
				if (st_in.st_mtime > st_out.st_mtime) {
					/* unsigned zone is newer than signed zone */
					lwsl_user("dnssec-monitor: unsigned zone %s (mtime %lu) is newer than signed zone %s (mtime %lu)! Triggering resign!\n", input_path, (unsigned long)st_in.st_mtime, output_path, (unsigned long)st_out.st_mtime);
					needs_resign = 1;
				} else if (has_acme && st_acme.st_mtime > st_out.st_mtime) {
					lwsl_user("dnssec-monitor: .acme challenge file %s (mtime %lu) is newer than signed zone %s (mtime %lu)! Triggering resign!\n", acme_path, (unsigned long)st_acme.st_mtime, output_path, (unsigned long)st_out.st_mtime);
					needs_resign = 1;
				} else {
					lwsl_info("dnssec-monitor: unsigned zone %s (mtime %lu) is NOT newer than signed zone %s (mtime %lu), skipping resign.\n", input_path, (unsigned long)st_in.st_mtime, output_path, (unsigned long)st_out.st_mtime);
				}
				/* TODO: 75% lifetime exhaustion check, but requires parsing the signature. */
			}
		} else {
			lwsl_info("%s: Missing domain %s base zone config, skipping resign\n", __func__, input_path);
		}

		if (needs_resign) {
			char wd[512];
			lws_snprintf(wd, sizeof(wd), "%s/domains/%s/dns", vhd->base_dir, pc.common_name);

			lwsl_user("%s: Signing zone for %s\n", __func__, pc.common_name);
			struct lws_dht_dnssec_signzone_args sargs;
			memset(&sargs, 0, sizeof(sargs));
			sargs.domain = pc.common_name;
			sargs.workdir = wd;
			sargs.sign_validity_duration = vhd->signature_duration;

			if (vhd->ops->signzone(vhd->context, &sargs)) {
				lwsl_user("%s: Failed signing zone for %s\n", __func__, pc.common_name);
			} else {
				lwsl_user("%s: Successfully signed zone for %s\n", __func__, pc.common_name);
			}
		}
	}

	return 0;
}

#if defined(LWS_WITH_DIR)
static void
dir_notify_cb(const char *path, int is_file, void *user)
{
	struct vhd *vhd = (struct vhd *)user;
	char scan_path[1024];

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);

	lwsl_user("%s: Detected inotify filesystem change %s (file: %d), manually rescanning domains: %s\n", __func__, path, is_file, scan_path);

	lws_dir(scan_path, vhd, scan_dir_cb);
}
#endif

static int
parent_scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	if (lde->type != LDOT_DIR || lde->name[0] == '.') return 0;

	char jws_path[1024], pub_path[1024];
	lws_snprintf(jws_path, sizeof(jws_path), "%s/domains/%s/dns/%s.zone.signed.jws", vhd->base_dir, lde->name, lde->name);
	lws_snprintf(pub_path, sizeof(pub_path), "%s.published", jws_path);

	struct stat st_jws, st_pub;
	if (stat(jws_path, &st_jws) == 0) {
		if (stat(pub_path, &st_pub) != 0 || st_jws.st_mtime > st_pub.st_mtime) {
			lwsl_notice("%s: Parent detected new JWS for %s! Triggering DHT publication loop.\n", __func__, lde->name);
			if (vhd->ops && vhd->ops->publish_jws) {
				vhd->ops->publish_jws(vhd->vhost, jws_path);
				int fd = open(pub_path, O_CREAT|O_WRONLY|O_TRUNC, 0666);
				if (fd >= 0) close(fd);
			}
		}
	}
	return 0;
}

static void
parent_dnssec_monitor_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer);
	char scan_path[1024];

	// lwsl_notice("%s: Parent timer fired!\n", __func__);

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, parent_scan_dir_cb);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 5 * LWS_US_PER_SEC);
}

static void
dnssec_monitor_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer);
	char scan_path[1024];

	// lwsl_notice("%s: Child timer fired!\n", __func__);

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_dir_cb);

	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, dnssec_monitor_timer_cb, 5 * LWS_US_PER_SEC);
}

static int
callback_dht_dnssec_monitor(struct lws *wsi, enum lws_callback_reasons reason,
			    void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	const struct lws_protocols *protocol = lws_get_protocol(wsi);
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(vhost, protocol);
	const struct lws_protocol_vhost_options *pvo;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		lwsl_notice("dnssec_monitor: PROTOCOL_INIT called! (in=%p)\n", in);
		{
			struct lws_context *cx = lws_get_context(wsi);
			const char *p = lws_cmdline_option_cx(cx, "--lws-dht-dnssec-monitor-root");

			if (!in)
				return 0;

			/* Root monitor spawned proxy branch */
			if (p) {
				/* Yes, we are the root spawned UDS process! */
				lwsl_notice("%s: Started as UDS root monitor\n", __func__);

#if !defined(WIN32)
				const char *u_uid = lws_cmdline_option_cx(cx, "--uid");
				const char *u_gid = lws_cmdline_option_cx(cx, "--gid");

				if (u_gid && atoi(u_gid)) {
					if (setgid((gid_t)atoi(u_gid)) < 0)
						lwsl_err("%s: setgid failed\n", __func__);
				}
				if (u_uid && atoi(u_uid)) {
					if (setuid((uid_t)atoi(u_uid)) < 0)
						lwsl_err("%s: setuid failed\n", __func__);
				}
#endif

				/* Only the FIRST protocol in the list handles this, so we don't duplicate vhosts
				 * We'll use vhd presence to guard it if needed. Actually we'll just check if we
				 * already created the UDS vhost to avoid doing it per-protocol INIT.
				 * lws_cmdline_option_cx requires us to look for uds-path.
				 */
				const char *uds_path = lws_cmdline_option_cx(cx, "--uds-path");
				if (!uds_path) uds_path = "/var/run/lws-dnssec-monitor.sock";

				struct lws_context_creation_info info;
				memset(&info, 0, sizeof(info));
				info.vhost_name = "dnssec_monitor_uds";
				info.port = 0; /* raw socket UDS */
				info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW;
				info.iface = uds_path;

				/* We only want this protocol to run on the UDS */
				static const struct lws_protocols *pprotocols[] = {
					&lws_dht_dnssec_monitor_protocols[0],
					&lws_dht_dnssec_monitor_protocols[1],
					NULL
				};
				info.pprotocols = pprotocols;

				/* We need to ensure we don't loop indefinitely creating vhosts.
				 * If lws_get_vhost_by_name finds our vhost, we don't create it again.
				 */
				struct lws_vhost *vh = lws_get_vhost_by_name(cx, info.vhost_name);
				if (!vh) {
					unlink(uds_path);
					vh = lws_create_vhost(cx, &info);
					if (!vh) {
						lwsl_err("%s: Failed to create UDS vhost on %s\n", __func__, uds_path);
						return -1;
					}
					lwsl_notice("%s: Created UDS vhost on %s\n", __func__, uds_path);
				}

				static int timer_armed = 0;
				if (!timer_armed) {
					vhd = lws_protocol_vh_priv_zalloc(vhost, protocol, sizeof(*vhd));
					if (vhd) {
						lwsl_notice("%s: Successfully allocated vhd on %s\n", __func__, lws_get_vhost_name(vhost));
						vhd->context = cx;
						vhd->vhost = vhost;

						{
							lws_system_policy_t *policy;
							if (lws_system_parse_policy(cx, "/etc/lwsws/policy", &policy)) {
								lwsl_vhost_notice(vh, "dnssec_monitor: couldn't parse policy.");
								return -1;
							}
							vhd->base_dir = strdup(policy->dns_base_dir);
							lws_system_policy_free(policy);
						}

						vhd->uds_path = uds_path;
						vhd->signature_duration = 31536000;

						/* Borrow ops from the invoking vhost that originally had it configured */
						const struct lws_protocols *prot = lws_vhost_name_to_protocol(vhost, "lws-dht-dnssec");
						if (!prot) {
							struct lws_vhost *vhdflt = lws_get_vhost_by_name(cx, "default");
							if (vhdflt)
								prot = lws_vhost_name_to_protocol(vhdflt, "lws-dht-dnssec");
						}
						if (prot && prot->user)
							vhd->ops = (const struct lws_dht_dnssec_ops *)prot->user;

						if (vhd->ops) {
							char scan_path[1024];
							lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);

							/* Guarantee absolute discovery independently of Unix kernel notify boundaries */
							/* Deferred to cleanly drop execution permissions naturally inside the loop */
							lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, dnssec_monitor_timer_cb, 1 * LWS_US_PER_SEC);
							timer_armed = 1;

#if defined(LWS_WITH_DIR)
							vhd->dn = lws_dir_notify_create(cx, scan_path, dir_notify_cb, vhd);
							if (!vhd->dn)
								lwsl_err("%s: Failed to attach lws_dir_notify to %s\n", __func__, scan_path);
#endif
						} else {
							lwsl_err("%s: Skipped scheduling timer on %s because vhd->ops is NULL!\n", __func__, lws_get_vhost_name(vhost));
							/* It will organically retry when the next vhost runs PROTOCOL_INIT */
						}
					} else {
						lwsl_err("%s: FAILED to allocate vhd on %s\n", __func__, lws_get_vhost_name(vhost));
					}
				}

				return 0;
			}

			if (!in)
				return 0;

			/* Fast path: Prevent duplicate instantiation */
			if (lws_protocol_vh_priv_get(vhost, protocol))
				return 0;

			vhd = lws_protocol_vh_priv_zalloc(vhost, protocol, sizeof(*vhd));
			if (!vhd)
				return -1;

			vhd->context = lws_get_context(wsi);
			vhd->vhost = vhost;
			vhd->signature_duration = 31536000; /* 1 year default fallback */

			/* Load standard PVOs */
			const char *uid = "0", *gid = "0";

			{
				lws_system_policy_t *policy;
				if (lws_system_parse_policy(vhd->context, "/etc/lwsws/policy", &policy)) {
					lwsl_vhost_notice(vhost, "dnssec_monitor: couldn't parse policy.");
					return -1;
				}
				vhd->base_dir = strdup(policy->dns_base_dir);
				lws_system_policy_free(policy);
			}

			if ((pvo = lws_pvo_search(in, "uds-path")))
				vhd->uds_path = pvo->value;
			if ((pvo = lws_pvo_search(in, "signature-duration")))
				vhd->signature_duration = (uint32_t)atoi(pvo->value);
			if ((pvo = lws_pvo_search(in, "uid")))
				uid = pvo->value;
			if ((pvo = lws_pvo_search(in, "gid")))
				gid = pvo->value;

			if (!vhd->base_dir) {
				lwsl_err("%s: base-dir pvo is required\n", __func__);
				return -1;
			}
			if (!vhd->uds_path)
				vhd->uds_path = "/var/run/lws-dnssec-monitor.sock";

			/* Locate the operational ops struct off the prerequisite plugin */
			const struct lws_protocols *prot = lws_vhost_name_to_protocol(vhd->vhost, "lws-dht-dnssec");
			if (!prot || !prot->user) {
				lwsl_err("%s: prerequisite protocol lws-dht-dnssec is missing or has no ops exported\n", __func__);
				return -1;
			}
			vhd->ops = (const struct lws_dht_dnssec_ops *)prot->user;

			lwsl_notice("%s: initialized monitor proxy (base-dir: %s, uds-path: %s)\n", __func__, vhd->base_dir, vhd->uds_path);

			/* Spawn the root monitor process */
			struct lws_spawn_piped_info spawn_info;
			memset(&spawn_info, 0, sizeof(spawn_info));

			const char *exec_array[15];
			char arg_uds[1024];
			char arg_uid[128];
			char arg_gid[128];
			int n = 0;
			/* Rely on the original host application executable context path instead of
			 * guessing paths. `argv[0]` guarantees relative/absolute execution fidelity. */
			char plat_exe_buf[256];
			const char *exe_path = lws_cmdline_option_cx_argv0(vhd->context);

			if (!exe_path || exe_path[0] != '/') {
#if defined(__linux__)
				int m = (int)readlink("/proc/self/exe", plat_exe_buf, sizeof(plat_exe_buf) - 1);
				if (m > 0) {
					plat_exe_buf[m] = '\0';
					exe_path = plat_exe_buf;
				} else
#endif
				{
					exe_path = "/usr/local/bin/lwsws";
				}
			}

			if ((pvo = lws_pvo_search(in, "exe-path")))
				exe_path = pvo->value;

			exec_array[n++] = exe_path;
			exec_array[n++] = "--lws-dht-dnssec-monitor-root";

			const char *conf_dir = lws_cmdline_option_cx(vhd->context, "-c");
			if (conf_dir) {
				exec_array[n++] = "-c";
				exec_array[n++] = conf_dir;
			}

			const char *debug_lvl = lws_cmdline_option_cx(vhd->context, "-d");
			if (debug_lvl) {
				exec_array[n++] = "-d";
				exec_array[n++] = debug_lvl;
			}

			/* no --base-dir needed since the root spawnee will look up the policy itself! */
			if (vhd->uds_path) {
				lws_snprintf(arg_uds, sizeof(arg_uds), "--uds-path=%s", vhd->uds_path);
				exec_array[n++] = arg_uds;
			}
			if (uid) {
				lws_snprintf(arg_uid, sizeof(arg_uid), "--uid=%s", uid);
				exec_array[n++] = arg_uid;
			}
			if (gid) {
				lws_snprintf(arg_gid, sizeof(arg_gid), "--gid=%s", gid);
				exec_array[n++] = arg_gid;
			}
			exec_array[n++] = NULL;

			for (int i = 0; i < n; i++)
				lwsl_notice("%s: exec_array[%d]: '%s'\n", __func__, i, exec_array[i]);

			if (exec_array[0]) {
				spawn_info.exec_array = exec_array;
				spawn_info.timeout_us = 0; /* runs forever */
				spawn_info.plsp = &vhd->lsp;
				spawn_info.reap_cb = lws_dht_dnssec_monitor_reap_cb;
				spawn_info.protocol_name = "lws-dht-dnssec-stdwsi";
				spawn_info.vh = vhd->vhost;

				lwsl_notice("dnssec_monitor: Executing root process: %s\n", exec_array[0]);

				vhd->lsp = lws_spawn_piped(&spawn_info);
				if (!vhd->lsp) {
					lwsl_err("%s: Failed to spawn root monitor process\n", __func__);
					return -1;
				}
				vhd->root_process_active = 1;
				lwsl_notice("%s: Spawned root monitor process successfully\n", __func__);

				/* Engage parent monitor to execute DHT publications off completed JWS child drops cleanly */
				lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 1 * LWS_US_PER_SEC);
			} else {
				lwsl_err("%s: Cannot spawn argv[0] because it is NULL\n", __func__);
			}
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
		lws_sul_cancel(&vhd->sul_timer);
#if defined(LWS_WITH_DIR)
			if (vhd->dn) {
				lws_dir_notify_destroy(&vhd->dn);
			}
#endif
		if (vhd->lsp) {
			lws_spawn_piped_kill_child_process(vhd->lsp);
		}
		if (vhd->base_dir) {
			free(vhd->base_dir);
			vhd->base_dir = NULL;
		}
		break;

	case LWS_CALLBACK_ESTABLISHED:
		if (vhd && vhd->root_process_active) {
			/* We are the unprivileged proxy, and a UI WebSocket just connected.
			 * Establish onward Raw UDS connection */
			struct lws_client_connect_info i;
			char uds_path[1024];

			memset(&i, 0, sizeof(i));
			i.method = "RAW";
			i.context = vhd->context;

			/* LWS client connection paths prefix with '+' for Unix Domain Socket */
			lws_snprintf(uds_path, sizeof(uds_path), "+%s", vhd->uds_path);
			i.address = uds_path;
			i.port = 0;
			i.host = "localhost";
			i.origin = "localhost";
			i.local_protocol_name = "lws-dht-dnssec-monitor";
			i.opaque_user_data = pss;
			i.pwsi = &pss->cwsi;

			if (!lws_client_connect_via_info(&i)) {
				lwsl_err("%s: failed to connect UI WS proxy to UDS server\n", __func__);
				return -1;
			}
			pss->wsi = wsi;
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (vhd && vhd->root_process_active) {
			if (pss->cwsi) {
				lws_wsi_close(pss->cwsi, LWS_TO_KILL_ASYNC);
				pss->cwsi = NULL;
			}
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (vhd && vhd->root_process_active && pss->cwsi) {
			if (len > sizeof(pss->tx)) {
				lwsl_err("%s: WS UI request too large\n", __func__);
				return -1;
			}
			memcpy(pss->tx, in, len);
			pss->tx_len = len;
			lws_callback_on_writable(pss->cwsi); /* Write proxy -> root */
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (vhd && vhd->root_process_active && pss->rx_len) {
			if (lws_write(wsi, pss->rx, pss->rx_len, LWS_WRITE_TEXT) < 0) {
				lwsl_err("%s: Failed writing to WS UI\n", __func__);
				return -1;
			}
			pss->rx_len = 0;
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);
			if (wpss) {
				wpss->cwsi = NULL;
			}
		}
		break;

	case LWS_CALLBACK_RAW_ADOPT:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);
			if (wpss) {
				lwsl_notice("%s: UDS proxy client connection established\n", __func__);
				wpss->cwsi = wsi;
			} else {
				lwsl_notice("%s: UDS connection established to server\n", __func__);
			}
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);

			if (wpss) {
				/* 1: Proxy Unprivileged Client: root server just replied. */
				if (len > sizeof(wpss->rx)) return -1;
				memcpy(wpss->rx, in, len);
				wpss->rx_len = len;
				lws_callback_on_writable(wpss->wsi); /* trigger WS write */
			} else {
				/* 2: Root Server: UI proxy just gave us a request. */
				const char *req;
				size_t req_len;

				if (len > sizeof(vhd->rx) - 1) return -1;
				memcpy(vhd->rx, in, len);
				vhd->rx[len] = '\0';
				vhd->rx_len = len;

				req = lws_json_simple_find((const char *)vhd->rx, len, "\"req\":", &req_len);
				if (!req) {
					lwsl_err("%s: Missing 'req'\n", __func__);
					return -1;
				}

				if (!strncmp(req, "status", req_len)) {
					lwsl_notice("%s: Processed 'status' req on UDS server\n", __func__);
				} else if (!strncmp(req, "keygen", req_len)) {
					lwsl_notice("%s: Processed 'keygen' req on UDS server\n", __func__);
				}

				/* Tell server socket to reply */
				lws_callback_on_writable(wsi);
			}
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);

			if (wpss) {
				/* 1: Proxy Client sending request -> Root Server */
				if (wpss->tx_len) {
					if (lws_write(wsi, wpss->tx, wpss->tx_len, LWS_WRITE_RAW) < 0) return -1;
					wpss->tx_len = 0;
				}
			} else {
				/* 2: Root Server sending response -> Proxy Client */
				uint8_t buf[256];
				int n = lws_snprintf((char *)buf, sizeof(buf), "{\"status\":\"ok\"}\n");
				if (lws_write(wsi, buf, (size_t)n, LWS_WRITE_RAW) != n) {
					lwsl_err("%s: Failed writing to UDS proxy\n", __func__);
					return -1;
				}
			}
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);
			if (wpss) wpss->cwsi = NULL;
			lwsl_notice("%s: UDS connection closed\n", __func__);
		}
		break;

	default:
		break;
	}

	return 0;
}

static int
callback_monitor_stdwsi(struct lws *wsi, enum lws_callback_reasons reason,
                    void *user, void *in, size_t len)
{
        uint8_t buf[2048];
        int ilen;

        switch (reason) {
        case LWS_CALLBACK_RAW_CLOSE_FILE:
                break;

        case LWS_CALLBACK_RAW_RX_FILE:
                ilen = (int)read((int)(intptr_t)lws_get_socket_fd(wsi), buf, sizeof(buf) - 1);
                if (ilen < 1) {
                        return -1;
                }
                buf[ilen] = '\0';
                lwsl_notice("root-monitor: %s", buf);
                return 0;

        default:
                break;
        }

        return 0;
}

LWS_VISIBLE const struct lws_protocols lws_dht_dnssec_monitor_protocols[] = {
	{
		.name = "lws-dht-dnssec-stdwsi",
		.callback = callback_monitor_stdwsi,
	},
	{
		.name = "lws-dht-dnssec-monitor",
		.callback = callback_dht_dnssec_monitor,
		.per_session_data_size = sizeof(struct pss),
	},
};
LWS_VISIBLE const lws_plugin_protocol_t lws_dht_dnssec_monitor = {
	.hdr = {
		"dht dnssec monitor",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC,
		10 /* priority */
	},
	.protocols = lws_dht_dnssec_monitor_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_dht_dnssec_monitor_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
