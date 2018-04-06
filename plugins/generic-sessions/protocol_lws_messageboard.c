/*
 * ws protocol handler plugin for messageboard "generic sessions" demo
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation:
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 */

#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"

#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>

struct per_vhost_data__gs_mb {
	struct lws_vhost *vh;
	const struct lws_protocols *gsp;
	sqlite3 *pdb;
	char message_db[256];
	unsigned long last_idx;
};

struct per_session_data__gs_mb {
	void *pss_gs; /* for use by generic-sessions */
	struct lws_session_info sinfo;
	struct lws_spa *spa;
	unsigned long last_idx;
	unsigned int our_form:1;
	char second_http_part;
};

static const char * const param_names[] = {
	"send",
	"msg",
};
enum {
	MBSPA_SUBMIT,
	MBSPA_MSG,
};

#define MAX_MSG_LEN 512

struct message {
	unsigned long idx;
	unsigned long time;
	char username[32];
	char email[100];
	char ip[72];
	char content[MAX_MSG_LEN];
};

static int
lookup_cb(void *priv, int cols, char **col_val, char **col_name)
{
	struct message *m = (struct message *)priv;
	int n;

	for (n = 0; n < cols; n++) {

		if (!strcmp(col_name[n], "idx") ||
		    !strcmp(col_name[n], "MAX(idx)")) {
			if (!col_val[n])
				m->idx = 0;
			else
				m->idx = atol(col_val[n]);
			continue;
		}
		if (!strcmp(col_name[n], "time")) {
			m->time = atol(col_val[n]);
			continue;
		}
		if (!strcmp(col_name[n], "username")) {
			lws_strncpy(m->username, col_val[n], sizeof(m->username));
			continue;
		}
		if (!strcmp(col_name[n], "email")) {
			lws_strncpy(m->email, col_val[n], sizeof(m->email));
			continue;
		}
		if (!strcmp(col_name[n], "ip")) {
			lws_strncpy(m->ip, col_val[n], sizeof(m->ip));
			continue;
		}
		if (!strcmp(col_name[n], "content")) {
			lws_strncpy(m->content, col_val[n], sizeof(m->content));
			continue;
		}
	}
	return 0;
}

static unsigned long
get_last_idx(struct per_vhost_data__gs_mb *vhd)
{
	struct message m;

	if (sqlite3_exec(vhd->pdb, "SELECT MAX(idx) FROM msg;",
			 lookup_cb, &m, NULL) != SQLITE_OK) {
		lwsl_err("Unable to lookup token: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 0;
	}

	return m.idx;
}

static int
post_message(struct lws *wsi, struct per_vhost_data__gs_mb *vhd,
	     struct per_session_data__gs_mb *pss)
{
	struct lws_session_info sinfo;
	char s[MAX_MSG_LEN + 512];
	char esc[MAX_MSG_LEN + 256];

	vhd->gsp->callback(wsi, LWS_CALLBACK_SESSION_INFO,
			   pss->pss_gs, &sinfo, 0);

	lws_snprintf((char *)s, sizeof(s) - 1,
		 "insert into msg(time, username, email, ip, content)"
		 " values (%lu, '%s', '%s', '%s', '%s');",
		 (unsigned long)lws_now_secs(), sinfo.username, sinfo.email, sinfo.ip,
		 lws_sql_purify(esc, lws_spa_get_string(pss->spa, MBSPA_MSG),
			        sizeof(esc) - 1));
	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to insert msg: %s\n", sqlite3_errmsg(vhd->pdb));
		return 1;
	}
	vhd->last_idx = get_last_idx(vhd);

	/* let everybody connected by this protocol on this vhost know */
	lws_callback_on_writable_all_protocol_vhost(lws_get_vhost(wsi),
						    lws_get_protocol(wsi));

	return 0;
}

static int
callback_messageboard(struct lws *wsi, enum lws_callback_reasons reason,
		      void *user, void *in, size_t len)
{
	struct per_session_data__gs_mb *pss = (struct per_session_data__gs_mb *)user;
	const struct lws_protocol_vhost_options *pvo;
	struct per_vhost_data__gs_mb *vhd = (struct per_vhost_data__gs_mb *)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	unsigned char *p, *start, *end, buffer[LWS_PRE + 256];
	char s[512];
	int n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
			lws_get_protocol(wsi), sizeof(struct per_vhost_data__gs_mb));
		if (!vhd)
			return 1;
		vhd->vh = lws_get_vhost(wsi);
		vhd->gsp = lws_vhost_name_to_protocol(vhd->vh,
						"protocol-generic-sessions");
		if (!vhd->gsp) {
			lwsl_err("messageboard: requires generic-sessions\n");
			return 1;
		}

		pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "message-db"))
				strncpy(vhd->message_db, pvo->value,
					sizeof(vhd->message_db) - 1);
			pvo = pvo->next;
		}
		if (!vhd->message_db[0]) {
			lwsl_err("messageboard: \"message-db\" pvo missing\n");
			return 1;
		}

		if (sqlite3_open_v2(vhd->message_db, &vhd->pdb,
				    SQLITE_OPEN_READWRITE |
				    SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
			lwsl_err("Unable to open message db %s: %s\n",
				 vhd->message_db, sqlite3_errmsg(vhd->pdb));

			return 1;
		}
		if (sqlite3_exec(vhd->pdb, "create table if not exists msg ("
				 " idx integer primary key, time integer,"
				 " username varchar(32), email varchar(100),"
				 " ip varchar(80), content blob);",
				 NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("Unable to create msg table: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return 1;
		}

		vhd->last_idx = get_last_idx(vhd);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd && vhd->pdb)
			sqlite3_close(vhd->pdb);
		goto passthru;

	case LWS_CALLBACK_ESTABLISHED:
		vhd->gsp->callback(wsi, LWS_CALLBACK_SESSION_INFO,
				   pss->pss_gs, &pss->sinfo, 0);
		if (!pss->sinfo.username[0]) {
			lwsl_notice("messageboard ws attempt with no session\n");

			return -1;
		}

		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		{
			struct message m;
			char j[MAX_MSG_LEN + 512], e[MAX_MSG_LEN + 512],
				*p = j + LWS_PRE, *start = p,
				*end = j + sizeof(j) - LWS_PRE;

			if (pss->last_idx == vhd->last_idx)
				break;

			/* restrict to last 10 */
			if (!pss->last_idx)
				if (vhd->last_idx >= 10)
					pss->last_idx = vhd->last_idx - 10;

			sprintf(s, "select idx, time, username, email, ip, content "
				   "from msg where idx > %lu order by idx limit 1;",
				   pss->last_idx);
			if (sqlite3_exec(vhd->pdb, s, lookup_cb, &m, NULL) != SQLITE_OK) {
				lwsl_err("Unable to lookup msg: %s\n",
					 sqlite3_errmsg(vhd->pdb));
				return 0;
			}

			/* format in JSON */
			p += lws_snprintf(p, end - p,
					"{\"idx\":\"%lu\",\"time\":\"%lu\",",
					m.idx, m.time);
			p += lws_snprintf(p, end - p, " \"username\":\"%s\",",
				lws_json_purify(e, m.username, sizeof(e)));
			p += lws_snprintf(p, end - p, " \"email\":\"%s\",",
				lws_json_purify(e, m.email, sizeof(e)));
			p += lws_snprintf(p, end - p, " \"ip\":\"%s\",",
				lws_json_purify(e, m.ip, sizeof(e)));
			p += lws_snprintf(p, end - p, " \"content\":\"%s\"}",
				lws_json_purify(e, m.content, sizeof(e)));

			if (lws_write(wsi, (unsigned char *)start, p - start,
				      LWS_WRITE_TEXT) < 0)
				return -1;

			pss->last_idx = m.idx;
			if (pss->last_idx == vhd->last_idx)
				break;

			lws_callback_on_writable(wsi); /* more to do */
		}
		break;

	case LWS_CALLBACK_HTTP:
		pss->our_form = 0;

		/* ie, it's our messageboard new message form */
		if (!strcmp((const char *)in, "/msg")) {
			pss->our_form = 1;
			break;
		}

		goto passthru;

	case LWS_CALLBACK_HTTP_BODY:
		if (!pss->our_form)
			goto passthru;

		if (len < 2)
			break;
		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
						ARRAY_SIZE(param_names),
						MAX_MSG_LEN + 1024, NULL, NULL);
			if (!pss->spa)
				return -1;
		}

		if (lws_spa_process(pss->spa, in, len)) {
			lwsl_notice("spa process blew\n");
			return -1;
		}
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->second_http_part)
			break;
		s[0] = '0';
		n = lws_write(wsi, (unsigned char *)s, 1, LWS_WRITE_HTTP);
		if (n != 1)
			return -1;

		goto try_to_reuse;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (!pss->our_form)
			goto passthru;

		if (post_message(wsi, vhd, pss))
			return -1;

		p = buffer + LWS_PRE;
		start = p;
		end = p + sizeof(buffer) - LWS_PRE;

		if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end))
			return -1;
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"text/plain", 10, &p, end))
			return -1;
		if (lws_add_http_header_content_length(wsi, 1, &p, end))
			return -1;
		if (lws_finalize_http_header(wsi, &p, end))
			return -1;
		n = lws_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS);
		if (n != (p - start)) {
			lwsl_err("_write returned %d from %ld\n", n, (long)(p - start));
			return -1;
		}
		pss->second_http_part = 1;

		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		if (!pss || pss->pss_gs)
			break;

		pss->pss_gs = malloc(vhd->gsp->per_session_data_size);
		if (!pss->pss_gs)
			return -1;

		memset(pss->pss_gs, 0, vhd->gsp->per_session_data_size);
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		if (vhd->gsp->callback(wsi, reason, pss ? pss->pss_gs : NULL, in, len))
			return -1;

		if (pss && pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		if (pss && pss->pss_gs) {
			free(pss->pss_gs);
			pss->pss_gs = NULL;
		}
		break;

	default:
passthru:
		if (!pss || !vhd)
			break;
		return vhd->gsp->callback(wsi, reason, pss->pss_gs, in, len);
	}

	return 0;


try_to_reuse:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"protocol-lws-messageboard",
		callback_messageboard,
		sizeof(struct per_session_data__gs_mb),
		4096,
	},
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_messageboard(struct lws_context *context,
			       struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_lws_messageboard(struct lws_context *context)
{
	return 0;
}
