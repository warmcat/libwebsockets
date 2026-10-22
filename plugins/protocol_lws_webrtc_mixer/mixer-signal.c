/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Peer signalling messages the mixer relays to another participant.
 *
 * Nothing a peer sends is ever passed on to another peer as it was received:
 * the mixer and the receiving browser do not agree on what a JSON message
 * says (the mixer's lws_json_simple_find() takes the first "type" in the
 * bytes, JSON.parse() the last of duplicate keys, and neither the nesting nor
 * escapes in key names mean the same to both).  So a relayed message is
 * parsed strictly into the members it is allowed to carry, and the mixer
 * composes a fresh message from those.
 */

#include <libwebsockets.h>

#include <string.h>

#include "mixer-signal.h"

/* a set_control is ~100 bytes; nothing legitimate comes near this */
#define MIXER_SIGNAL_MAX_LEN		512

static const char * const msc_paths[] = {
	"type",
	"target",
	"kind",
	"id",
	"val",
};

enum {
	MSC_TYPE,
	MSC_TARGET,
	MSC_KIND,
	MSC_ID,
	MSC_VAL,

	MSC_COUNT
};

#define MSC_ALL ((1u << MSC_COUNT) - 1)

struct msc_parse {
	struct mixer_set_control	*sc;
	unsigned int			named;	/* member names seen */
	unsigned int			valued;	/* member values taken */
	int				objects;
};

/*
 * Decimal digits, optionally with a leading '-' if `neg_ok`, and nothing
 * else, into an int64_t no further than `max` from zero either way.
 */
static int
msc_decimal(const char *s, size_t n, int neg_ok, int64_t max, int64_t *out)
{
	int neg = 0;
	int64_t v = 0;

	if (n && *s == '-') {
		if (!neg_ok)
			return -1;
		neg = 1;
		s++;
		n--;
	}

	/* no "", no "-", no leading zeros */
	if (!n || n > 10 || (*s == '0' && n > 1))
		return -1;

	while (n--) {
		if (*s < '0' || *s > '9')
			return -1;
		v = (v * 10) + (*s++ - '0');
	}

	if (v > max + neg) /* INT32_MIN is one further than INT32_MAX */
		return -1;

	*out = neg ? -v : v;

	return 0;
}

static signed char
msc_cb(struct lejp_ctx *ctx, char reason)
{
	struct msc_parse *a = (struct msc_parse *)ctx->user;
	struct mixer_set_control *sc = a->sc;
	unsigned int bit;
	int64_t v;

	switch (reason) {
	case LEJPCB_CONSTRUCTED:
	case LEJPCB_DESTRUCTED:
	case LEJPCB_START:
	case LEJPCB_COMPLETE:
	case LEJPCB_FAILED:
	case LEJPCB_OBJECT_END:
	case LEJPCB_VAL_STR_START:
		return 0;

	case LEJPCB_OBJECT_START:
		/* only the one, outer, object: no member is an object */
		return ++a->objects == 1 ? 0 : -1;

	case LEJPCB_PAIR_NAME:
		/* only the members we know, and each of those only once */
		if (!ctx->path_match)
			return -1;
		bit = 1u << (ctx->path_match - 1);
		if (a->named & bit)
			return -1;
		a->named |= bit;

		return 0;

	case LEJPCB_VAL_TRUE:
	case LEJPCB_VAL_FALSE:
	case LEJPCB_VAL_NULL:
	case LEJPCB_VAL_NUM_INT:
	case LEJPCB_VAL_NUM_FLOAT:
	case LEJPCB_VAL_STR_END:
		break;

	default:
		/*
		 * Arrays, and string chunks: none of the members is anywhere
		 * near a chunk long
		 */
		return -1;
	}

	if (!ctx->path_match)
		return -1;

	switch (ctx->path_match - 1) {
	case MSC_TYPE:
		if (reason != LEJPCB_VAL_STR_END || ctx->npos != 11 ||
		    memcmp(ctx->buf, "set_control", 11))
			return -1;
		break;

	case MSC_TARGET:
		if (reason != LEJPCB_VAL_STR_END || !ctx->npos ||
		    ctx->npos >= sizeof(sc->target) ||
		    memchr(ctx->buf, '\0', ctx->npos))
			return -1;
		memcpy(sc->target, ctx->buf, ctx->npos);
		sc->target[ctx->npos] = '\0';
		break;

	case MSC_KIND:
		if (reason != LEJPCB_VAL_STR_END || ctx->npos != 5)
			return -1;
		if (!memcmp(ctx->buf, "video", 5))
			sc->kind = MIXER_CONTROL_VIDEO;
		else if (!memcmp(ctx->buf, "audio", 5))
			sc->kind = MIXER_CONTROL_AUDIO;
		else
			return -1;
		break;

	case MSC_ID:
		/* the browser keeps control ids as strings */
		if ((reason != LEJPCB_VAL_NUM_INT &&
		     reason != LEJPCB_VAL_STR_END) ||
		    msc_decimal(ctx->buf, ctx->npos, 0, UINT32_MAX, &v))
			return -1;
		sc->id = (uint32_t)v;
		break;

	case MSC_VAL:
		if (reason != LEJPCB_VAL_NUM_INT ||
		    msc_decimal(ctx->buf, ctx->npos, 1, INT32_MAX, &v))
			return -1;
		sc->val = (int32_t)v;
		break;

	default:
		return -1;
	}

	a->valued |= 1u << (ctx->path_match - 1);

	return 0;
}

int
mixer_set_control_parse(const char *in, size_t len,
			struct mixer_set_control *sc)
{
	struct lejp_ctx ctx;
	struct msc_parse a;
	int m;

	memset(sc, 0, sizeof(*sc));

	if (!in || !len || len > MIXER_SIGNAL_MAX_LEN)
		return -1;

	memset(&a, 0, sizeof(a));
	a.sc = sc;

	lejp_construct(&ctx, msc_cb, &a, msc_paths, LWS_ARRAY_SIZE(msc_paths));
	ctx.flags |= LEJP_FLAG_FEAT_STRICT_KEY_CHARS;
	m = lejp_parse(&ctx, (const unsigned char *)in, (int)len);
	lejp_destruct(&ctx);

	/*
	 * It must have been one complete object using all of the input, with
	 * every member present and holding a value of the right kind
	 */
	if (m || a.objects != 1 || a.named != MSC_ALL || a.valued != MSC_ALL) {
		memset(sc, 0, sizeof(*sc));
		return -1;
	}

	return 0;
}

int
mixer_set_control_compose(char *buf, size_t len, const char *from,
			  const struct mixer_set_control *sc)
{
	char esc_from[(MIXER_SIGNAL_ID_MAX * 6) + 1];
	int n;

	if (!len)
		return -1;

	lws_json_purify(esc_from, from, (int)sizeof(esc_from), NULL);

	n = lws_snprintf(buf, len, "{\"type\":\"set_control\",\"from\":\"%s\","
			 "\"kind\":\"%s\",\"id\":%u,\"val\":%d}", esc_from,
			 sc->kind == MIXER_CONTROL_AUDIO ? "audio" : "video",
			 (unsigned int)sc->id, (int)sc->val);

	if (n < 0 || (size_t)n >= len) /* lws_snprintf() truncated it */
		return -1;

	return n;
}

int
mixer_text_ok(const char *s, size_t len)
{
	unsigned char st = 0;

	return !memchr(s, '\0', len) &&
	       !lws_check_utf8(&st, (const unsigned char *)s, len) && !st;
}

int
mixer_json_str(char *dest, size_t dest_len, const char *v, size_t al)
{
	/*
	 * lws_json_simple_find() already strips the quotes and hands back the
	 * exact length, so there is nothing to fix up afterwards.  The old
	 * `if (*v == '"') { v++; nl -= 2; }` idiom fired precisely on an empty
	 * value ("", where the returned pointer is the closing quote and alen
	 * is 0) and underflowed the length to SIZE_MAX.
	 */
	if (!v || !al || al >= dest_len || !mixer_text_ok(v, al))
		return -1;

	memcpy(dest, v, al);
	dest[al] = '\0';

	return 0;
}

int
mixer_json_list_add(char **p, const char *end, size_t reserve, int *count,
		    const char *ent, size_t ent_len)
{
	size_t need = ent_len + (*count ? 1u : 0u) + reserve;

	if (*p > end || need > lws_ptr_diff_size_t(end, *p))
		return -1;

	if (*count)
		*(*p)++ = ',';
	memcpy(*p, ent, ent_len);
	*p += ent_len;
	(*count)++;

	return 0;
}

lws_usec_t
mixer_gate_wait(const struct mixer_gate *g, lws_usec_t now)
{
	if (!g->last || now < g->last || now - g->last >= g->interval)
		return 0;

	return g->interval - (now - g->last);
}
