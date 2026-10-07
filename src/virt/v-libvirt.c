/*
 * sai-virt - v-libvirt.c
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#include "v-private.h"

static virConnectPtr conn;

static char *
replace_string(const char *orig, const char *rep, const char *with)
{
	char *result;
	char *ins;
	char *tmp;
	size_t len_rep;
	size_t len_with;
	size_t len_front;
	size_t count;

	if (!orig || !rep)
		return NULL;
	len_rep = strlen(rep);
	if (len_rep == 0)
		return NULL;
	if (!with)
		with = "";
	len_with = strlen(with);

	ins = (char *)orig;
	for (count = 0; (tmp = strstr(ins, rep)); ++count) {
		ins = tmp + len_rep;
	}

	tmp = result = malloc(strlen(orig) + (count * len_with) + 1);
	if (!result)
		return NULL;

	while (count--) {
		ins = strstr(orig, rep);
		len_front = lws_ptr_diff_size_t(ins, orig);
		tmp = strncpy(tmp, orig, len_front) + len_front;
		tmp = strcpy(tmp, with) + len_with;
		orig += len_front + len_rep;
	}
	strcpy(tmp, orig);
	return result;
}

static void
strip_xml_tags(char *xml, const char *start_tag, const char *end_tag)
{
	char *start;
	while ((start = strstr(xml, start_tag))) {
		char *end = strstr(start, end_tag);
		if (!end)
			break;
		end += strlen(end_tag);
		memmove(start, end, strlen(end) + 1);
	}
}

/*
 * libvirtd / virtqemud can restart, or our connection can otherwise go stale,
 * under us.  A dead connection stays dead, so check it and reopen on demand
 * before every operation.
 */

static virConnectPtr
saiv_libvirt_conn(void)
{
	if (conn) {
		if (virConnectIsAlive(conn) == 1)
			return conn;

		lwsl_warn("%s: libvirt connection is dead, reopening\n",
			  __func__);
		virConnectClose(conn);
		conn = NULL;
	}

	conn = virConnectOpen("qemu:///system");
	if (!conn)
		lwsl_err("%s: Failed to open connection to qemu:///system\n",
			 __func__);

	return conn;
}

/*
 * After a failed lookup / action, distinguish "the domain doesn't exist" from
 * "we couldn't find out" (eg, connection trouble)
 */

static int
saiv_libvirt_no_domain(void)
{
	virErrorPtr e = virGetLastError();

	return e && e->code == VIR_ERR_NO_DOMAIN;
}

static void
saiv_libvirt_delete_overlay(virConnectPtr c, const char *vm_name)
{
	virStoragePoolPtr pool;
	virStorageVolPtr vol;
	char vol_name[128];

	pool = virStoragePoolLookupByName(c, "sai_shm");
	if (!pool)
		return;

	lws_snprintf(vol_name, sizeof(vol_name), "%s.qcow2", vm_name);
	vol = virStorageVolLookupByName(pool, vol_name);
	if (vol) {
		if (virStorageVolDelete(vol, 0) < 0)
			lwsl_err("%s: failed to delete overlay %s\n",
				 __func__, vol_name);
		virStorageVolFree(vol);
	}
	virStoragePoolFree(pool);
}

/*
 * Show what disk images a domain's XML refers to, for whoever has to fix a
 * base_image that matches none of them
 */

static void
saiv_libvirt_log_disk_sources(const char *xml)
{
	const char *p = xml, *e;

	while ((p = strstr(p, "<source file='"))) {
		p += 14;
		e = strchr(p, '\'');
		if (!e)
			break;

		lwsl_err("%s:   basis domain has: %.*s\n", __func__,
			 (int)(e - p), p);
		p = e;
	}
}

/*
 * Is this a domain name we would generate, ie, "sai-vm-<plat name>-<n>"?
 */

static int
saiv_libvirt_name_is_ours(struct sai_virt *virt, const char *name)
{
	char pfx[96];
	size_t n;

	lws_start_foreach_dll(struct lws_dll2 *, d, virt->plat_owner.head) {
		saiv_plat_t *vp = lws_container_of(d, saiv_plat_t, list);
		const char *q;

		n = (size_t)lws_snprintf(pfx, sizeof(pfx), "sai-vm-%s-",
					 vp->name);
		if (strncmp(name, pfx, n) || !name[n])
			continue;

		for (q = name + n; *q >= '0' && *q <= '9'; q++)
			;
		if (!*q)
			return 1;
	} lws_end_foreach_dll(d);

	return 0;
}

static int
ops_libvirt_init(struct sai_virt *virt)
{
	virDomainPtr *doms = NULL;
	virConnectPtr c;
	int n, i;

	c = saiv_libvirt_conn();
	if (!c)
		return 1;

	/*
	 * VMs left running by a previous sai-virt instance are unknown to us:
	 * their /stay and /auto-power-off would be ignored, so they would run
	 * forever, and their names would clash with what we spawn.
	 */

	n = virConnectListAllDomains(c, &doms,
				     VIR_CONNECT_LIST_DOMAINS_TRANSIENT);
	for (i = 0; i < n; i++) {
		const char *name = virDomainGetName(doms[i]);

		if (name && saiv_libvirt_name_is_ours(virt, name)) {
			lwsl_warn("%s: destroying orphaned VM %s\n",
				  __func__, name);
			if (virDomainDestroy(doms[i]) < 0)
				lwsl_err("%s: failed to destroy %s\n",
					 __func__, name);
			saiv_libvirt_delete_overlay(c, name);
		}
		virDomainFree(doms[i]);
	}
	free(doms);

	lwsl_notice("%s: libvirt ops initialized\n", __func__);

	return 0;
}

static int
ops_libvirt_spawn(struct sai_virt *virt, struct saiv_vm *vm)
{
	virDomainPtr dom;
	virStoragePoolPtr pool;
	virStorageVolPtr vol;
	virConnectPtr c;
	char *xml, *xml2, *xml3;
	char vol_xml[1024];
	char overlay_path[256];
	char orig_name_tag[128];
	char new_name_tag[128];
	char orig_source_tag[256];
	char new_source_tag[256];
	const char *shm_pool_xml = "<pool type='dir'><name>sai_shm</name><target><path>/dev/shm</path></target></pool>";

	lwsl_notice("%s: Spawning ephemeral VM %s for platform: %s (base %s)\n", 
			__func__, vm->name, vm->plat->name, vm->plat->base_image);

	c = saiv_libvirt_conn();
	if (!c)
		return 1;

	/*
	 * We pick a name nothing of ours is using... if the hypervisor still
	 * has a domain by that name, it's a leftover nobody will ever clean
	 * up, and it would make the create fail
	 */
	dom = virDomainLookupByName(c, vm->name);
	if (dom) {
		lwsl_warn("%s: stale domain %s exists, destroying it\n",
			  __func__, vm->name);
		if (virDomainDestroy(dom) < 0 && !saiv_libvirt_no_domain() &&
		    virDomainIsActive(dom) != 0) {
			lwsl_err("%s: unable to destroy stale domain %s\n",
				 __func__, vm->name);
			virDomainFree(dom);
			return 1;
		}
		virDomainFree(dom);
	}

	/* 1. Ensure the /dev/shm storage pool exists */
	pool = virStoragePoolLookupByName(c, "sai_shm");
	if (!pool) {
		pool = virStoragePoolCreateXML(c, shm_pool_xml, 0);
		if (!pool) {
			lwsl_err("Failed to create transient shm storage pool\n");
			return 1;
		}
	} else {
		/* If it exists but is inactive, start it */
		int active = virStoragePoolIsActive(pool);
		if (active == 0)
			virStoragePoolCreate(pool, 0);
	}

	long capacity_size = 20;
	const char *capacity_unit = "G";
	if (vm->plat->overlay_size[0]) {
		char *p;
		capacity_size = strtol(vm->plat->overlay_size, &p, 10);
		if (p && *p)
			capacity_unit = p;
	}

	/* 2. Create the overlay volume using libvirt API */
	lws_snprintf(vol_xml, sizeof(vol_xml),
		"<volume>"
		"  <name>%s.qcow2</name>"
		"  <capacity unit='%s'>%ld</capacity>"
		"  <target><format type='qcow2'/></target>"
		"  <backingStore>"
		"    <path>%s</path>"
		"    <format type='qcow2'/>"
		"  </backingStore>"
		"</volume>",
		vm->name, 
		capacity_unit, capacity_size,
		vm->plat->base_image);

	/* Ensure no stale volume exists */
	char vol_name[128];
	lws_snprintf(vol_name, sizeof(vol_name), "%s.qcow2", vm->name);
	vol = virStorageVolLookupByName(pool, vol_name);
	if (vol) {
		lwsl_notice("Stale storage volume %s found, deleting...\n", vol_name);
		virStorageVolDelete(vol, 0);
		virStorageVolFree(vol);
	}

	vol = virStorageVolCreateXML(pool, vol_xml, 0);
	if (!vol) {
		lwsl_err("Failed to create libvirt storage volume for overlay\n");
		virStoragePoolFree(pool);
		return 1;
	}
	virStorageVolFree(vol);
	virStoragePoolFree(pool);

	lws_snprintf(overlay_path, sizeof(overlay_path), "/dev/shm/%s.qcow2", vm->name);

	/* 3. Get base domain XML and manipulate it */
	dom = virDomainLookupByName(c, vm->plat->name);
	if (!dom) {
		lwsl_err("Failed to find base domain %s\n", vm->plat->name);
		goto bail;
	}

	/*
	 * Its disk is the backing file of every VM we spawn from it: if
	 * something is writing it, the overlays on it get corrupted
	 */
	if (virDomainIsActive(dom) == 1) {
		lwsl_err("%s: basis domain %s is running, refusing to spawn "
			 "VMs backed by its disk\n", __func__, vm->plat->name);
		virDomainFree(dom);
		goto bail;
	}

	xml = virDomainGetXMLDesc(dom, 0);
	virDomainFree(dom);

	if (!xml) {
		lwsl_err("Failed to get XML for base domain\n");
		goto bail;
	}

	/* Replace <name>base</name> with <name>vm->name</name> */
	lws_snprintf(orig_name_tag, sizeof(orig_name_tag), "<name>%s</name>", vm->plat->name);
	lws_snprintf(new_name_tag, sizeof(new_name_tag), "<name>%s</name>", vm->name);
	xml2 = replace_string(xml, orig_name_tag, new_name_tag);
	free(xml);

	/* Replace <source file='base_image'/> with <source file='overlay_path'/> */
	lws_snprintf(orig_source_tag, sizeof(orig_source_tag), "file='%s'", vm->plat->base_image);
	lws_snprintf(new_source_tag, sizeof(new_source_tag), "file='%s'", overlay_path);
	xml3 = replace_string(xml2, orig_source_tag, new_source_tag);
	free(xml2);

	if (!xml3) {
		lwsl_err("Failed to manipulate XML\n");
		goto bail;
	}

	/*
	 * If base_image in our conf doesn't match the basis domain's disk
	 * exactly, nothing was replaced, and the VM would boot writing the
	 * basis image itself, as would every other one we spawn
	 */
	if (!strstr(xml3, new_source_tag)) {
		lwsl_err("%s: base_image %s is not a disk of basis domain %s, "
			 "refusing to spawn\n", __func__, vm->plat->base_image,
			 vm->plat->name);
		saiv_libvirt_log_disk_sources(xml3);
		free(xml3);
		goto bail;
	}

	/* Remove UUID so libvirt generates a new one, avoiding conflicts with the base VM */
	strip_xml_tags(xml3, "<uuid>", "</uuid>");
	/*
	 * Remove MAC addresses so libvirt generates new ones, avoiding network
	 * conflicts.  The builder inside finds out which VM it is by asking
	 * us, and we recognize it by the address that gets it, see
	 * ops_libvirt_has_addr()
	 */
	strip_xml_tags(xml3, "<mac address=", "/>");

	/* 4. Boot the transient domain */
	dom = virDomainCreateXML(c, xml3, 0);
	free(xml3);

	if (!dom) {
		lwsl_err("Failed to create transient domain %s\n", vm->name);
		goto bail;
	}

	virDomainFree(dom);
	lwsl_notice("Successfully spawned ephemeral VM %s\n", vm->name);

	return 0;

bail:
	saiv_libvirt_delete_overlay(c, vm->name);

	return 1;
}

/*
 * Returns 0 only if the domain is confirmed gone (and its overlay deleted).
 * Otherwise the caller must keep the VM's name reserved and retry later.
 */

static int
ops_libvirt_destroy(struct sai_virt *virt, struct saiv_vm *vm)
{
	virDomainPtr dom;
	virConnectPtr c;

	lwsl_notice("%s: Destroying ephemeral VM: %s\n", __func__, vm->name);

	c = saiv_libvirt_conn();
	if (!c)
		return 1;

	dom = virDomainLookupByName(c, vm->name);
	if (dom) {
		if (virDomainDestroy(dom) < 0 && !saiv_libvirt_no_domain() &&
		    virDomainIsActive(dom) != 0) {
			lwsl_err("%s: failed to destroy %s\n", __func__,
				 vm->name);
			virDomainFree(dom);
			return 1;
		}
		virDomainFree(dom);
	} else {
		if (!saiv_libvirt_no_domain()) {
			lwsl_err("%s: unable to look up %s\n", __func__,
				 vm->name);
			return 1;
		}
		lwsl_notice("%s: domain %s already gone\n", __func__,
			    vm->name);
	}

	saiv_libvirt_delete_overlay(c, vm->name);

	return 0;
}

static int
ops_libvirt_alive(struct sai_virt *virt, struct saiv_vm *vm)
{
	int state, reason, r = 1;
	virDomainPtr dom;
	virConnectPtr c;

	c = saiv_libvirt_conn();
	if (!c)
		return -1;

	dom = virDomainLookupByName(c, vm->name);
	if (!dom)
		return saiv_libvirt_no_domain() ? 0 : -1;

	if (virDomainGetState(dom, &state, &reason, 0) < 0) {
		r = saiv_libvirt_no_domain() ? 0 : -1;
		goto out;
	}

	switch (state) {
	case VIR_DOMAIN_SHUTOFF:
	case VIR_DOMAIN_CRASHED:
		r = 0;
		break;
	case VIR_DOMAIN_PAUSED:
		/* it won't progress again, it's no use to anybody */
		if (reason == VIR_DOMAIN_PAUSED_IOERROR) {
			lwsl_err("%s: %s paused on I/O error (is the overlay "
				 "storage in /dev/shm full?)\n", __func__,
				 vm->name);
			r = 0;
		}
		if (reason == VIR_DOMAIN_PAUSED_CRASHED) {
			lwsl_err("%s: %s guest crashed\n", __func__, vm->name);
			r = 0;
		}
		break;
	}

out:
	virDomainFree(dom);

	return r;
}

/*
 * Does this VM have the address ip?  We ask what libvirt's DHCP server leased
 * it, and failing that, what the host's ARP table has for its NICs' MACs,
 * which also covers networks libvirt doesn't run DHCP on.  The VM has just
 * talked to us from that address, so the ARP entry will be there.
 */

static int
ops_libvirt_has_addr(struct sai_virt *virt, struct saiv_vm *vm, const char *ip)
{
	static const unsigned int srcs[] = {
		VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE,
		VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_ARP,
	};
	virDomainInterfacePtr *ifs;
	int s, n, i, found = 0;
	virDomainPtr dom;
	virConnectPtr c;
	unsigned int j;

	c = saiv_libvirt_conn();
	if (!c)
		return -1;

	dom = virDomainLookupByName(c, vm->name);
	if (!dom)
		return saiv_libvirt_no_domain() ? 0 : -1;

	for (s = 0; s < (int)LWS_ARRAY_SIZE(srcs) && !found; s++) {
		ifs = NULL;
		n = virDomainInterfaceAddresses(dom, &ifs, srcs[s], 0);

		for (i = 0; i < n; i++) {
			for (j = 0; j < ifs[i]->naddrs; j++)
				if (ifs[i]->addrs[j].addr &&
				    !strcmp(ifs[i]->addrs[j].addr, ip))
					found = 1;

			virDomainInterfaceFree(ifs[i]);
		}
		free(ifs);
	}

	virDomainFree(dom);

	return found;
}

const sai_virt_ops_t ops_libvirt = {
	.name = "libvirt",
	.init = ops_libvirt_init,
	.spawn = ops_libvirt_spawn,
	.destroy = ops_libvirt_destroy,
	.alive = ops_libvirt_alive,
	.has_addr = ops_libvirt_has_addr,
};
