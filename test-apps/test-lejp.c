/*
 * Lightweight Embedded JSON Parser
 *
 * Copyright (C) 2013-2017 Andy Green <andy@warmcat.com>
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
 */

#include <libwebsockets.h>
#include <string.h>


static const char * const reason_names[] = {
	"LEJPCB_CONSTRUCTED",
	"LEJPCB_DESTRUCTED",
	"LEJPCB_START",
	"LEJPCB_COMPLETE",
	"LEJPCB_FAILED",
	"LEJPCB_PAIR_NAME",
	"LEJPCB_VAL_TRUE",
	"LEJPCB_VAL_FALSE",
	"LEJPCB_VAL_NULL",
	"LEJPCB_VAL_NUM_INT",
	"LEJPCB_VAL_NUM_FLOAT",
	"LEJPCB_VAL_STR_START",
	"LEJPCB_VAL_STR_CHUNK",
	"LEJPCB_VAL_STR_END",
	"LEJPCB_ARRAY_START",
	"LEJPCB_ARRAY_END",
	"LEJPCB_OBJECT_START",
	"LEJPCB_OBJECT_END",
};

static const char * const tok[] = {
	"dummy___"
};

static signed char
cb(struct lejp_ctx *ctx, char reason)
{
	char buf[1024], *p = buf, *end = &buf[sizeof(buf)];
	int n;

	if (reason & LEJP_FLAG_CB_IS_VALUE) {
		p += lws_snprintf(p, p - end, "   value '%s' ", ctx->buf);
		if (ctx->ipos) {
			p += lws_snprintf(p, p - end, "(array indexes: ");
			for (n = 0; n < ctx->ipos; n++)
				p += lws_snprintf(p, p - end, "%d ", ctx->i[n]);
			p += lws_snprintf(p, p - end, ") ");
		}
		lwsl_notice("%s (%s)\r\n", buf,
		       reason_names[(unsigned int)
			(reason) & (LEJP_FLAG_CB_IS_VALUE - 1)]);
		return 0;
	}

	switch (reason) {
	case LEJPCB_COMPLETE:
		lwsl_notice("Parsing Completed (LEJPCB_COMPLETE)\n");
		break;
	case LEJPCB_PAIR_NAME:
		lwsl_notice("path: '%s' (LEJPCB_PAIR_NAME)\n", ctx->path);
		break;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int fd, n = 1, ret = 1, m;
	struct lejp_ctx ctx;
	char buf[128];

	lws_set_log_level(7, NULL);

	lwsl_notice("libwebsockets-test-lejp  (C) 2017 - 2018 andy@warmcat.com\n");
	lwsl_notice("  usage: cat my.json | libwebsockets-test-lejp\n\n");

	lejp_construct(&ctx, cb, NULL, tok, ARRAY_SIZE(tok));

	fd = 0;

	while (n > 0) {
		n = read(fd, buf, sizeof(buf));
		if (n <= 0)
			continue;

		m = lejp_parse(&ctx, (uint8_t *)buf, n);
		if (m < 0 && m != LEJP_CONTINUE) {
			lwsl_err("parse failed %d\n", m);
			goto bail;
		}
	}
	lwsl_notice("okay\n");
	ret = 0;
bail:
	lejp_destruct(&ctx);

	return ret;
}
