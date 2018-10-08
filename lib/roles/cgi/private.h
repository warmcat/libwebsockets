/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
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
 *  This is included from core/private.h if LWS_ROLE_WS
 */

extern struct lws_role_ops role_ops_cgi;

#define lwsi_role_cgi(wsi) (wsi->role_ops == &role_ops_cgi)

#define LWS_HTTP_CHUNK_HDR_SIZE 16

enum {
	SIGNIFICANT_HDR_CONTENT_LENGTH,
	SIGNIFICANT_HDR_LOCATION,
	SIGNIFICANT_HDR_STATUS,
	SIGNIFICANT_HDR_TRANSFER_ENCODING,

	SIGNIFICANT_HDR_COUNT
};

struct lws;

/* wsi who is master of the cgi points to an lws_cgi */

struct lws_cgi {
	struct lws_cgi *cgi_list;
	struct lws *stdwsi[3]; /* points to the associated stdin/out/err wsis */
	struct lws *wsi; /* owner */
	unsigned char *headers_buf;
	unsigned char *headers_start;
	unsigned char *headers_pos;
	unsigned char *headers_dumped;
	unsigned char *headers_end;

	char summary[128];

	lws_filepos_t content_length;
	lws_filepos_t content_length_seen;

	int pipe_fds[3][2];
	int match[SIGNIFICANT_HDR_COUNT];
	char l[12];
	int pid;
	int response_code;
	int lp;

	unsigned char being_closed:1;
	unsigned char explicitly_chunked:1;

	unsigned char chunked_grace;
};
