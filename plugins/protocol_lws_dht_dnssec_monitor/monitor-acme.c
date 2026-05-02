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

void
acme_vhost_finalize(struct lws_vhost *vh, void *arg)
{
	lwsl_notice("%s: Finalizing ACME vhost %s (arg: %p)\n", __func__, vh ? lws_get_vhost_name(vh) : "NULL", arg);
	if (arg)
		free(arg);
}

int
acme_vhost_spawn(struct vhd *vhd, const char *domain, const char *subdomain, const char *email)
{
	char vh_name[256];
	struct lws_context_creation_info info;
	struct acme_pvo_alloc *pa;

	lws_snprintf(vh_name, sizeof(vh_name), "acme_%s", subdomain);
	if (lws_get_vhost_by_name(vhd->context, vh_name))
		return 0;

	char dis_path[1024];
	lws_snprintf(dis_path, sizeof(dis_path), "%s/domains/%s/acme_disabled", vhd->base_dir, domain);
	int fd = open(dis_path, O_RDONLY);
	if (fd >= 0) {
		lwsl_notice("%s: ACME explicitly disabled for domain %s\n", __func__, domain);
		close(fd);
		return 0;
	}

	pa = malloc(sizeof(*pa));
	if (!pa) {
		lwsl_err("%s: OOM allocating ACME PVOs\n", __func__);
		return -1;
	}
	memset(pa, 0, sizeof(*pa));
	lws_strncpy(pa->root_domain, domain, sizeof(pa->root_domain));
	lws_strncpy(pa->common_name, subdomain, sizeof(pa->common_name));

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN_SERVER;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.vhost_name = vh_name;

	pa->pvo_core.name = "lws-acme-client-core";
	pa->pvo_core.next = &pa->pvo_acme;

	pa->pvo_acme.name = "lws-acme-client-dns";
	pa->pvo_acme.options = &pa->pvo1;
	info.pvo = &pa->pvo_core;

	pa->pvo1.name = "root-domain";
	pa->pvo1.value = pa->root_domain;
	pa->pvo1.next = &pa->pvo2;

	pa->pvo2.name = "common-name";
	pa->pvo2.value = pa->common_name;
	pa->pvo2.next = &pa->pvo3;

	pa->pvo3.name = "email";
	pa->pvo3.value = email && email[0] ? email : (vhd->acme_email[0] ? vhd->acme_email : "admin@domain.com");
	pa->pvo3.next = &pa->pvo4;

	pa->pvo4.name = "directory-url";
	pa->pvo4.value = vhd->acme_production ? "https://acme-v02.api.letsencrypt.org/directory" : "https://acme-staging-v02.api.letsencrypt.org/directory";
	pa->pvo4.next = &pa->pvo5;

	pa->pvo5.name = "uds-path";
	pa->pvo5.value = vhd->uds_path;
	pa->pvo5.next = vhd->acme_profile[0] ? &pa->pvo6 : NULL;

	if (vhd->acme_profile[0]) {
		pa->pvo6.name = "profile";
		pa->pvo6.value = vhd->acme_profile;
		pa->pvo6.next = NULL;
	}

	info.finalize = acme_vhost_finalize;
	info.finalize_arg = pa;

	if (lws_create_vhost(vhd->context, &info)) {
		lwsl_notice("%s: ACME vhost %s spawned natively\n", __func__, vh_name);
		return 0;
	}

	lwsl_err("%s: Failed to spawn ACME vhost %s\n", __func__, vh_name);
	free(pa);
	return -1;
}
