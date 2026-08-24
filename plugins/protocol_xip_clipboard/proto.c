#include <libwebsockets.h>

#include <stdlib.h>
#include <string.h>

#include "proto.h"
#include "hash.h"

/* ------------------------------------------------------------------ */
/* builders                                                            */
/* ------------------------------------------------------------------ */

int
xip_json_escape(char *buf, size_t cap, const char *s)
{
	size_t o = 0;

	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (o + 7 >= cap)
			return -1;
		switch (c) {
		case '"':
			buf[o++] = '\\'; buf[o++] = '"';
			break;
		case '\\':
			buf[o++] = '\\'; buf[o++] = '\\';
			break;
		case '\b':
			buf[o++] = '\\'; buf[o++] = 'b';
			break;
		case '\f':
			buf[o++] = '\\'; buf[o++] = 'f';
			break;
		case '\n':
			buf[o++] = '\\'; buf[o++] = 'n';
			break;
		case '\r':
			buf[o++] = '\\'; buf[o++] = 'r';
			break;
		case '\t':
			buf[o++] = '\\'; buf[o++] = 't';
			break;
		default:
			if (c < 0x20) {
				static const char hex[] = "0123456789abcdef";
				buf[o++] = '\\'; buf[o++] = 'u';
				buf[o++] = '0'; buf[o++] = '0';
				buf[o++] = hex[(c >> 4) & 0xf];
				buf[o++] = hex[c & 0xf];
			} else
				buf[o++] = (char)c;
			break;
		}
	}
	buf[o] = '\0';

	return (int)o;
}

static int
put(char *buf, size_t cap, size_t *pos, const char *s)
{
	size_t l = strlen(s);

	if (*pos + l + 1 > cap)
		return -1;
	memcpy(buf + *pos, s, l);
	*pos += l;

	return 0;
}

static int
put_escaped(char *buf, size_t cap, size_t *pos, const char *s)
{
	int n = xip_json_escape(buf + *pos, cap - *pos, s);

	if (n < 0)
		return -1;
	*pos += (size_t)n;

	return 0;
}

static int
finish(char *buf, size_t cap, size_t *pos)
{
	if (*pos + 1 > cap)
		return -1;
	buf[*pos] = '\0';

	return (int)*pos;
}

int
xip_build_hello(char *buf, size_t cap, const char *token, const char *name)
{
	size_t p = 0;

	if (put(buf, cap, &p, "{\"t\":\"hello\",\"proto\":1,\"token\":\"") ||
	    put_escaped(buf, cap, &p, token) ||
	    put(buf, cap, &p, "\",\"name\":\"") ||
	    put_escaped(buf, cap, &p, name) ||
	    put(buf, cap, &p, "\"}"))
		return -1;

	return finish(buf, cap, &p);
}

int
xip_build_welcome(char *buf, size_t cap, unsigned id, const char *hash_or_null)
{
	size_t p = 0;
	char num[32];

	lws_snprintf(num, sizeof(num), "%u", id);
	if (put(buf, cap, &p, "{\"t\":\"welcome\",\"id\":") ||
	    put(buf, cap, &p, num))
		return -1;
	if (hash_or_null && hash_or_null[0]) {
		if (put(buf, cap, &p, ",\"hash\":\"") ||
		    put_escaped(buf, cap, &p, hash_or_null) ||
		    put(buf, cap, &p, "\""))
			return -1;
	}

	if (put(buf, cap, &p, "}"))
		return -1;

	return finish(buf, cap, &p);
}

int
xip_build_fetch(char *buf, size_t cap)
{
	size_t p = 0;

	if (put(buf, cap, &p, "{\"t\":\"fetch\"}"))
		return -1;

	return finish(buf, cap, &p);
}

int
xip_build_bye(char *buf, size_t cap)
{
	size_t p = 0;

	if (put(buf, cap, &p, "{\"t\":\"bye\"}"))
		return -1;

	return finish(buf, cap, &p);
}

int
xip_build_error(char *buf, size_t cap, const char *reason)
{
	size_t p = 0;

	if (put(buf, cap, &p, "{\"t\":\"error\",\"reason\":\"") ||
	    put_escaped(buf, cap, &p, reason) ||
	    put(buf, cap, &p, "\"}"))
		return -1;

	return finish(buf, cap, &p);
}

int
xip_build_clip(char *buf, size_t cap, const char *mime, const char *hash,
	       unsigned seq, unsigned i, unsigned n,
	       const char *b64, size_t b64len)
{
	size_t p = 0;
	char nums[96];

	lws_snprintf(nums, sizeof(nums),
		     "\",\"seq\":%u,\"i\":%u,\"n\":%u,\"d\":\"", seq, i, n);

	if (put(buf, cap, &p, "{\"t\":\"clip\",\"mime\":\"") ||
	    put_escaped(buf, cap, &p, mime) ||
	    put(buf, cap, &p, "\",\"hash\":\"") ||
	    put_escaped(buf, cap, &p, hash) ||
	    put(buf, cap, &p, nums))
		return -1;

	if (p + b64len + 2 > cap)
		return -1;
	memcpy(buf + p, b64, b64len);
	p += b64len;

	if (put(buf, cap, &p, "\"}"))
		return -1;

	return finish(buf, cap, &p);
}

/* ------------------------------------------------------------------ */
/* streaming parser                                                    */
/* ------------------------------------------------------------------ */

static void
set_str(char *dst, size_t dstmax, const char *src)
{
	size_t l = strlen(src);

	if (l >= dstmax)
		l = dstmax - 1;
	memcpy(dst, src, l);
	dst[l] = '\0';
}

static int
acc_append(struct xip_parser *p, const char *s)
{
	size_t l = strlen(s);

	if (p->acc_len + l + 1 > p->acc_cap) {
		size_t nc = p->acc_cap ? p->acc_cap : 4096;
		char *nb;

		while (nc < p->acc_len + l + 1)
			nc *= 2;
		nb = (char *)realloc(p->acc, nc);
		if (!nb)
			return -1;
		p->acc = nb;
		p->acc_cap = nc;
	}
	memcpy(p->acc + p->acc_len, s, l);
	p->acc_len += l;
	p->acc[p->acc_len] = '\0';

	return 0;
}

static signed char
lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct xip_parser *p = (struct xip_parser *)ctx->user;
	const char *v = ctx->buf;

	switch ((enum lejp_callbacks)reason) {
	case LEJPCB_PAIR_NAME:
		/* the parsed name is in ctx->path (buf holds stale data) */
		set_str(p->field, sizeof(p->field), ctx->path);
		break;

	case LEJPCB_VAL_STR_START:
		if (!strcmp(p->field, "d")) {
			p->acc_active = 1;
			p->acc_len = 0;
		}
		break;

	/* intermediate chunk of a long string */
	case LEJPCB_VAL_STR_CHUNK:
		if (p->acc_active && acc_append(p, v) < 0)
			return -1;
		break;

	case LEJPCB_VAL_STR_END:
		if (p->acc_active) {
			if (acc_append(p, v) < 0)
				return -1;
			p->acc_active = 0;
			break;
		}
		if (!strcmp(p->field, "t")) {
			if (!strcmp(v, "hello"))
				p->msg.type = XIP_MSG_HELLO;
			else if (!strcmp(v, "welcome"))
				p->msg.type = XIP_MSG_WELCOME;
			else if (!strcmp(v, "fetch"))
				p->msg.type = XIP_MSG_FETCH;
			else if (!strcmp(v, "clip"))
				p->msg.type = XIP_MSG_CLIP;
			else if (!strcmp(v, "error"))
				p->msg.type = XIP_MSG_ERROR;
			else if (!strcmp(v, "bye"))
				p->msg.type = XIP_MSG_BYE;
		} else if (!strcmp(p->field, "token"))
			set_str(p->msg.token, sizeof(p->msg.token), v);
		else if (!strcmp(p->field, "name"))
			set_str(p->msg.name, sizeof(p->msg.name), v);
		else if (!strcmp(p->field, "mime"))
			set_str(p->msg.mime, sizeof(p->msg.mime), v);
		else if (!strcmp(p->field, "hash")) {
			set_str(p->msg.hash, sizeof(p->msg.hash), v);
			p->msg.have_hash = 1;
		} else if (!strcmp(p->field, "reason"))
			set_str(p->msg.reason, sizeof(p->msg.reason), v);
		break;

	case LEJPCB_VAL_NUM_INT: {
		unsigned long uv = (unsigned long)strtoul(v, NULL, 10);

		if (!strcmp(p->field, "proto"))
			p->msg.proto = (unsigned)uv;
		else if (!strcmp(p->field, "id"))
			p->msg.id = (unsigned)uv;
		else if (!strcmp(p->field, "seq"))
			p->msg.seq = (unsigned)uv;
		else if (!strcmp(p->field, "i"))
			p->msg.i = (unsigned)uv;
		else if (!strcmp(p->field, "n"))
			p->msg.n = (unsigned)uv;
		break;
	}

	case LEJPCB_FAILED:
		p->failed = 1;
		break;

	case LEJPCB_COMPLETE:
		if (p->acc_len) {
			/* decode accumulated base64 payload */
			p->msg.data = (uint8_t *)malloc(p->acc_len + 4);
			if (!p->msg.data) {
				p->failed = 1;
				break;
			}
			p->msg.data_len = (size_t)lws_b64_decode_string_len(
					p->acc, (int)p->acc_len,
					(char *)p->msg.data,
					(int)(p->acc_len + 4));
			if ((ssize_t)p->msg.data_len < 0) {
				free(p->msg.data);
				p->msg.data = NULL;
				p->msg.data_len = 0;
				p->failed = 1;
			}
		}
		p->complete = 1;
		break;

	default:
		break;
	}

	return 0;
}

void
xip_parser_init(struct xip_parser *p)
{
	memset(p, 0, sizeof(*p));
	lejp_construct(&p->lejp, lejp_cb, p, NULL, 0);
}

void
xip_parser_reset(struct xip_parser *p)
{
	free(p->msg.data);
	free(p->acc);
	memset(&p->msg, 0, sizeof(p->msg));
	p->field[0] = '\0';
	p->acc = NULL;
	p->acc_len = p->acc_cap = 0;
	p->acc_active = 0;
	p->complete = p->failed = 0;
	lejp_construct(&p->lejp, lejp_cb, p, NULL, 0);
}

int
xip_parser_feed(struct xip_parser *p, const void *data, size_t len)
{
	int n = lejp_parse(&p->lejp, (const unsigned char *)data, (int)len);

	if (p->failed)
		return -1;
	if (n == LEJP_CONTINUE)
		return 0;
	if (n >= 0)
		return p->complete ? 1 : 0;

	return -1;
}
