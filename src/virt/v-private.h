/*
 * Sai virt definitions src/virt/v-private.h
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 */

#ifndef SAI_VIRT_V_PRIVATE_H
#define SAI_VIRT_V_PRIVATE_H

#include "../common/include/private.h"
#include <pthread.h>

struct sai_virt;

struct saiv_vm;

typedef struct sai_virt_ops {
	const char *name;
	int (*init)(struct sai_virt *virt);
	int (*spawn)(struct sai_virt *virt, struct saiv_vm *vm);
	int (*destroy)(struct sai_virt *virt, struct saiv_vm *vm);
	/* 1 = running, 0 = gone / can't make progress, -1 = can't tell */
	int (*alive)(struct sai_virt *virt, struct saiv_vm *vm);
} sai_virt_ops_t;

/* a VM that never contacts us at all is given up on after this */
#define SAIV_VM_FIRST_CONTACT_US	(5 * 60 * LWS_US_PER_SEC)
/* builders poll /stay every 20s, tolerate a few late polls under load */
#define SAIV_VM_STAY_TIMEOUT_US		(90 * LWS_US_PER_SEC)
/* how often we check our VMs still exist, and retry failed spawns */
#define SAIV_WATCH_INTERVAL_US		(15 * LWS_US_PER_SEC)
/* retry interval for a VM the hypervisor didn't confirm destroyed */
#define SAIV_DESTROY_RETRY_US		(10 * LWS_US_PER_SEC)

typedef struct saiv_plat {
	lws_dll2_t		list;
	char			name[64];
	char			platform[128];
	char			base_image[128];
	char			overlay_size[32];

	int			wait_magnification;

	lws_dll2_owner_t	vm_owner;
} saiv_plat_t;

typedef struct saiv_vm {
	lws_dll2_t		list;
	saiv_plat_t		*plat;
	char			name[64];
	int			vm_index;
	lws_sorted_usec_list_t	sul_timeout;
	lws_sorted_usec_list_t	sul_destroy;
} saiv_vm_t;

/*
 * Represents the virt process state
 */
struct sai_virt {
	lws_dll2_owner_t	sai_server_owner; /* servers we connect to */
	lws_dll2_owner_t	plat_owner;	  /* platforms we can spawn */
	struct lws_context	*context;
	struct lws_vhost	*vhost;

	const sai_virt_ops_t	*ops;

	lws_sorted_usec_list_t	sul_watch;

	int			running_vms;
	int			max_vms;

	const char		*bind;		/* iface or address builders reach us on */
	const char		*perms;		/* user:group */
	int			port;		/* port builders reach us on */

	/* fleet secret shared with sai-server ("link-key" in conf) */
	const char		*link_key;

	char			hostname[64];

	struct lwsac		*pending_tasks_ac;
	struct sai_platform_pending_tasks *pending_tasks;
};

typedef struct saiv_server {
	lws_dll2_t		list;
	struct lws_ss_handle	*ss;
	const char		*url;
	const char		*name;
} saiv_server_t;

LWS_SS_USER_TYPEDEF
	char			payload[200];
	size_t			size;
	size_t			pos;
	struct lws_buflist	*bl_tx;
} saiv_server_link_t;

extern struct sai_virt virt;
extern const lws_ss_info_t ssi_saiv_server_link_t;
extern const sai_virt_ops_t ops_libvirt;
extern const struct lws_protocols virt_protocols[];

int saiv_config(struct sai_virt *virt, const char *d);
int saiv_config_global(struct sai_virt *virt, const char *filepath);
void saiv_servers_start(struct sai_virt *virt);

void
saiv_vm_timeout_cb(lws_sorted_usec_list_t *sul);

void
saiv_vm_destroy_cb(lws_sorted_usec_list_t *sul);

void
saiv_watch_cb(lws_sorted_usec_list_t *sul);

void
saiv_try_spawn(void);

#endif
