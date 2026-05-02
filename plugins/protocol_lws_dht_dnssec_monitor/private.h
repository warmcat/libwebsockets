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

#if !defined(__LWS_DHT_DNSSEC_MONITOR_PRIVATE_H__)
#define __LWS_DHT_DNSSEC_MONITOR_PRIVATE_H__

#define _GNU_SOURCE
#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#include <ctype.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dirent.h>

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/wait.h>
#include <grp.h>
#include <sys/types.h>
#endif

struct monitor_req_args {
	char req[32];
	char domain[128];
	char subdomain[128];
	char email[128];
	char organization[128];
	char directory_url[256];
	char *zone_buf;
	int zone_len;
	int zone_alloc;
	char jwt[2048];
	char suffix[64];
	char key_type[32];
	int port;
	int enabled;
	int production;
	char country[8];
	char state[128];
	char locality[128];
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

	char cookie_name[64];
	char jwk_path[256];
	struct lws_jwk jwk;

	uint8_t rx[LWS_PRE + 65536];
	size_t rx_len;

	char auth_token[129];
	struct lws_jwk auth_jwk;

	lws_dll2_owner_t ui_clients;
	struct lws_smd_peer *smd_peer;
	char ext_ips[256];
	lws_dll2_owner_t completed_checks;
	lws_dll2_owner_t whois_queries;
	lws_dll2_owner_t published_jws;
	lws_sorted_usec_list_t sul_timer_scan;
	lws_sorted_usec_list_t sul_timer_proxy_scan;

	int acme_enabled;
	int acme_production;
	char acme_email[128];
	char acme_organization[128];
	char acme_country[8];
	char acme_state[128];
	char acme_locality[128];
	lws_dll2_owner_t active_probes;
	lws_dll2_owner_t dns_queries;
	int root_daemon;
};

struct pss {
	struct lws *wsi;
	struct lws *cwsi;
	lws_sorted_usec_list_t sul;
	int retry_count;
	uint8_t tx[LWS_PRE + 65536];
	size_t tx_len;
	uint8_t rx[LWS_PRE + 65536];
	size_t rx_len;
	lws_dll2_t list;
	int send_ext_ips;
};

struct whois_query_info {
	lws_dll2_t list;
	char domain[128];
	struct vhd *vhd;
};

struct published_jws_info {
	lws_dll2_t list;
	char domain[128];
	time_t mtime;
};

struct cert_check_info {
	lws_dll2_t active_list;
	uint32_t magic;
	char domain[128];
	char fqdn[128];
	int port;
	int starttls_state;
	int is_automated;
};
#define CERT_CHECK_MAGIC 0xCE87C4EC

struct cert_check_result {
	lws_dll2_t list;
	char fqdn[128];
	char msg[128];
	char local_msg[128];
	char issuer[128];
	int port;
	int status_err;
};

struct parsed_config {
	struct vhd *vhd;
	char common_name[256];
	char email[256];
	char key_type[64];
	char key_curve[64];
	int key_bits;
};

struct dns_req {
	lws_dll2_t list;
	struct vhd *vhd;
	char domain[128];
	int port;
};

struct scan_tls_ctx {
	struct vhd *vhd;
	const char *domain;
};

static const char * const monitor_req_paths[] = {
	"req",
	"domain",
	"subdomain",
	"email",
	"organization",
	"directory_url",
	"zone",
	"jwt",
	"suffix",
	"key_type",
	"port",
	"enabled",
	"production",
	"country",
	"state",
	"locality"
};

enum enum_req_paths {
	LRP_REQ,
	LRP_DOMAIN,
	LRP_SUBDOMAIN,
	LRP_EMAIL,
	LRP_ORG,
	LRP_DIR_URL,
	LRP_ZONE,
	LRP_JWT,
	LRP_SUFFIX,
	LRP_KEY_TYPE,
	LRP_PORT,
	LRP_ENABLED,
	LRP_PRODUCTION,
	LRP_COUNTRY,
	LRP_STATE,
	LRP_LOCALITY
};

static const char * const tls_config_paths[] = {
	"challenge-type",
	"port",
	"email",
	"acme.directory-url",
};

enum enum_tls_config_paths {
	LTC_CHALLENGE_TYPE,
	LTC_PORT,
	LTC_EMAIL,
	LTC_DIRECTORY_URL,
};

struct acme_pvo_alloc {
	struct lws_protocol_vhost_options pvo_core;
	struct lws_protocol_vhost_options pvo_acme;
	struct lws_protocol_vhost_options pvo1;
	struct lws_protocol_vhost_options pvo2;
	struct lws_protocol_vhost_options pvo3;
	struct lws_protocol_vhost_options pvo4;
	struct lws_protocol_vhost_options pvo5;
	char root_domain[256];
	char common_name[256];
};

typedef void (*monitor_req_handler_t)(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a);

struct monitor_req_map {
	const char *name;
	monitor_req_handler_t cb;
};

/* monitor-pki.c */
void pki_init(struct vhd *vhd);
void generate_dist_pki(struct vhd *vhd);
void generate_client_cert(struct vhd *vhd, const char *domain, const char *subdomain);
void scan_subdomains_for_certs(struct vhd *vhd, const char *domain);

/* monitor-acme.c */
void acme_vhost_finalize(struct lws_vhost *vh, void *arg);
int acme_vhost_spawn(struct vhd *vhd, const char *domain, const char *subdomain, const char *email);

/* monitor-utils.c */
void force_external_dns(struct lws_context *cx, const char *external_ip);
int calc_local_ds(struct vhd *vhd, const char *domain, char *out, size_t out_len);

/* monitor-whois.c */
int whois_trigger(struct vhd *vhd, const char *domain);

/* monitor-dnssec.c */
void extract_and_queue_cert_result(struct lws *wsi, struct vhd *vhd, struct cert_check_info *cci, const struct lws_protocols *protocol);
struct lws * dnssec_state_dns_cb(struct lws *wsi, const char *ads, const struct addrinfo *result, int n, void *opaque);
int scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde);
void root_dnssec_scan_timer_cb(struct lws_sorted_usec_list *sul);
void root_monitor_stdin_check_cb(struct lws_sorted_usec_list *sul);

/* monitor-proxy.c */
int scan_whois_cb(const char *dirpath, void *user, struct lws_dir_entry *lde);
void dir_notify_cb(const char *path, int is_file, void *user);
void proxy_dnssec_scan_timer_cb(struct lws_sorted_usec_list *sul);
void parent_dnssec_monitor_timer_cb(struct lws_sorted_usec_list *sul);

/* monitor-api.c */
signed char monitor_req_cb(struct lejp_ctx *ctx, char reason);
void handle_monitor_request(struct vhd *vhd, struct pss *root_pss, const char *in, size_t len);

#endif
