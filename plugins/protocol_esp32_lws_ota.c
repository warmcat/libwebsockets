/*
 * ESP32 OTA update protocol handler
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
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
 */
#include <string.h>
#include <esp_partition.h>
#include <esp_ota_ops.h>
#include <nvs.h>

struct per_session_data__esplws_ota {
	struct lws_spa *spa;
	char filename[32];
	char result[LWS_PRE + 512];
	int result_len;
	int filename_length;
	esp_ota_handle_t otahandle;
	const esp_partition_t *part;
	long file_length;
	long last_rep;
	nvs_handle nvh;
	TimerHandle_t reboot_timer;
};

struct per_vhost_data__esplws_ota {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
};

static const char * const ota_param_names[] = {
	"upload",
};

enum enum_ota_param_names {
	EPN_UPLOAD,
};

static void ota_reboot_timer_cb(TimerHandle_t t)
{
	esp_restart();
}

const esp_partition_t *
ota_choose_part(void)
{
	const esp_partition_t *bootpart, *part = NULL;
	esp_partition_iterator_t i;

	bootpart = lws_esp_ota_get_boot_partition();
	i = esp_partition_find(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, NULL);
	while (i) {
		part = esp_partition_get(i);

		/* cannot update ourselves */
		if (part == bootpart)
			goto next;

		/* OTA Partition numbering is from _OTA_MIN to less than _OTA_MAX */
		if (part->subtype < ESP_PARTITION_SUBTYPE_APP_OTA_MIN ||
		    part->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX)
			goto next;

		break;

next:
		i = esp_partition_next(i);
	}

	if (!i) {
		lwsl_err("Can't find good OTA part\n");
		return NULL;
	}
	lwsl_notice("Directing OTA to part type %d/%d start 0x%x\n",
			part->type, part->subtype,
			(uint32_t)part->address);

	return part;
}

static int
ota_file_upload_cb(void *data, const char *name, const char *filename,
	       char *buf, int len, enum lws_spa_fileupload_states state)
{
	struct per_session_data__esplws_ota *pss =
			(struct per_session_data__esplws_ota *)data;

	switch (state) {
	case LWS_UFS_OPEN:
		lwsl_notice("LWS_UFS_OPEN Filename %s\n", filename);
		lws_strncpy(pss->filename, filename, sizeof(pss->filename));
		if (strcmp(name, "ota"))
			return 1;

		pss->part = ota_choose_part();
		if (!pss->part)
			return 1;

		if (esp_ota_begin(pss->part, OTA_SIZE_UNKNOWN, &pss->otahandle) != ESP_OK) {
			lwsl_err("OTA: Failed to begin\n");
			return 1;
		}

		pss->file_length = 0;
		pss->last_rep = -1;
		break;

	case LWS_UFS_FINAL_CONTENT:
	case LWS_UFS_CONTENT:
		if (pss->file_length + len > pss->part->size) {
			lwsl_err("OTA: incoming file too large\n");
			return 1;
		}

		if ((pss->file_length & ~0xffff) != (pss->last_rep & ~0xffff)) {
			lwsl_notice("writing 0x%lx...\n",
					pss->part->address + pss->file_length);
			pss->last_rep = pss->file_length;
		}
		if (esp_ota_write(pss->otahandle, buf, len) != ESP_OK) {
			lwsl_err("OTA: Failed to write\n");
			return 1;
		}
		pss->file_length += len;

		if (state == LWS_UFS_CONTENT)
			break;

		lwsl_notice("LWS_UFS_FINAL_CONTENT\n");
		if (esp_ota_end(pss->otahandle) != ESP_OK) {
			lwsl_err("OTA: end failed\n");
			return 1;
		}

		if (esp_ota_set_boot_partition(pss->part) != ESP_OK) {
			lwsl_err("OTA: set boot part failed\n");
			return 1;
		}

		pss->reboot_timer = xTimerCreate("x", pdMS_TO_TICKS(250), 0, NULL,
						 ota_reboot_timer_cb);
		xTimerStart(pss->reboot_timer, 0);
		break;
	}

	return 0;
}

static int
callback_esplws_ota(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__esplws_ota *pss =
			(struct per_session_data__esplws_ota *)user;
	struct per_vhost_data__esplws_ota *vhd =
			(struct per_vhost_data__esplws_ota *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	unsigned char buf[LWS_PRE + 384], *start = buf + LWS_PRE - 1, *p = start,
	     *end = buf + sizeof(buf) - 1;
	int n;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__esplws_ota));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
		break;

	/* OTA POST handling */

	case LWS_CALLBACK_HTTP_BODY:
		/* create the POST argument parser if not already existing */
		// lwsl_notice("LWS_CALLBACK_HTTP_BODY (ota) %d %d %p\n", (int)pss->file_length, (int)len, pss->spa);
		lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 30);
		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, ota_param_names,
					ARRAY_SIZE(ota_param_names), 4096,
					ota_file_upload_cb, pss);
			if (!pss->spa)
				return -1;

			pss->filename[0] = '\0';
			pss->file_length = 0;
		}
		lws_esp32.upload = 1;

		/* let it parse the POST data */
		if (lws_spa_process(pss->spa, in, len))
			return -1;
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_notice("LWS_CALLBACK_HTTP_BODY_COMPLETION (ota)\n");
		/* call to inform no more payload data coming */
		lws_spa_finalize(pss->spa);

		pss->result_len = snprintf(pss->result + LWS_PRE, sizeof(pss->result) - LWS_PRE - 1,
			"Rebooting after OTA update");

		if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end))
			goto bail;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"text/html", 9, &p, end))
			goto bail;
		if (lws_add_http_header_content_length(wsi, pss->result_len, &p, end))
			goto bail;
		if (lws_finalize_http_header(wsi, &p, end))
			goto bail;

		n = lws_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);
		if (n < 0)
			goto bail;

		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->result_len)
			break;
		lwsl_debug("LWS_CALLBACK_HTTP_WRITEABLE: sending %d\n",
			   pss->result_len);
		n = lws_write(wsi, (unsigned char *)pss->result + LWS_PRE,
			      pss->result_len, LWS_WRITE_HTTP);
		if (n < 0)
			return 1;

		if (lws_http_transaction_completed(wsi))
			return 1;

		/* stop further service so we don't serve the probe GET to see if we rebooted */
		while (1);

		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		/* called when our wsi user_space is going to be destroyed */
		if (pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		lws_esp32.upload = 0;
		break;

	default:
		break;
	}

	return 0;

bail:
	return 1;
}

#define LWS_PLUGIN_PROTOCOL_ESPLWS_OTA \
	{ \
		"esplws-ota", \
		callback_esplws_ota, \
		sizeof(struct per_session_data__esplws_ota), \
		4096, 0, NULL, 900 \
	}

