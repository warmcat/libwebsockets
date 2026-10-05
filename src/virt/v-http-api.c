/*
 * sai-virt - v-http-api.c
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

#include "v-private.h"

static saiv_vm_t *
saiv_find_vm(const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, virt.plat_owner.head) {
		saiv_plat_t *vp = lws_container_of(d, saiv_plat_t, list);

		lws_start_foreach_dll(struct lws_dll2 *, v, vp->vm_owner.head) {
			saiv_vm_t *vm = lws_container_of(v, saiv_vm_t, list);

			if (!strcmp(vm->name, name))
				return vm;
		} lws_end_foreach_dll(v);
	} lws_end_foreach_dll(d);

	return NULL;
}

static int
saiv_http_reply_text(struct lws *wsi, const char *text)
{
	uint8_t buf[LWS_PRE + 512], *start = buf + LWS_PRE, *p = start,
		*end = buf + sizeof(buf);
	size_t len = strlen(text);

	if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"text/plain", 10, &p, end) ||
	    lws_add_http_header_content_length(wsi, len, &p, end) ||
	    lws_finalize_http_header(wsi, &p, end))
		return -1;

	if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
		      LWS_WRITE_HTTP_HEADERS) < 0)
		return -1;

	if (lws_write(wsi, (uint8_t *)text, len, LWS_WRITE_HTTP_FINAL) !=
								(int)len)
		return -1;

	return -1; /* hang up */
}

int
callback_virt_http(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	const char *path;
	char vm_id[64];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		path = (const char *)in;
		if (len > 16 && !strncmp(path, "/auto-power-off/", 16)) {
			saiv_vm_t *found_vm;

			lws_strncpy(vm_id, path + 16, sizeof(vm_id));
			lwsl_notice("%s: Received auto-power-off for %s\n", __func__, vm_id);

			found_vm = saiv_find_vm(vm_id);
			if (!found_vm)
				/* builder must not wait for a power-off that won't come */
				return saiv_http_reply_text(wsi, "NAK: unknown VM");

			/* Delay destruction by 2s so sai-builder can cleanly flush its TCP FIN to sai-server */
			lws_sul_schedule(virt.context, 0, &found_vm->sul_destroy,
					 saiv_vm_destroy_cb, 2 * LWS_US_PER_SEC);

			/* sai-builder only proceeds on an "ACK:" reply, like sai-power's */
			return saiv_http_reply_text(wsi, "ACK: destroying VM in 2s");
		}

		if (len > 6 && !strncmp(path, "/stay/", 6)) {
			saiv_vm_t *found_vm;

			lws_strncpy(vm_id, path + 6, sizeof(vm_id));
			lwsl_info("%s: stay request for %s\n", __func__, vm_id);

			found_vm = saiv_find_vm(vm_id);
			if (found_vm)
				/* Extend the safety timeout since the VM is alive and communicating */
				lws_sul_schedule(virt.context, 0, &found_vm->sul_timeout,
						 saiv_vm_timeout_cb, SAIV_VM_STAY_TIMEOUT_US);
			else
				lwsl_warn("%s: stay request from unknown VM %s\n",
					  __func__, vm_id);

			/* We never return stay = true for ephemeral VMs */
			return saiv_http_reply_text(wsi, "0");
		}

		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		return -1;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

const struct lws_protocols virt_protocols[] = {
	{
		"http-only",
		callback_virt_http,
		0,
		0,
	},
	{ NULL, NULL, 0, 0 } /* terminator */
};
