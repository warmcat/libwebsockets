/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
 */

#include "private-lib-core.h"

#ifdef LWS_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <signal.h>

void
lws_ser_wu16be(uint8_t *b, uint16_t u)
{
	*b++ = (uint8_t)(u >> 8);
	*b = (uint8_t)u;
}

void
lws_ser_wu32be(uint8_t *b, uint32_t u32)
{
	*b++ = (uint8_t)(u32 >> 24);
	*b++ = (uint8_t)(u32 >> 16);
	*b++ = (uint8_t)(u32 >> 8);
	*b = (uint8_t)u32;
}

void
lws_ser_wu64be(uint8_t *b, uint64_t u64)
{
	lws_ser_wu32be(b, (uint32_t)(u64 >> 32));
	lws_ser_wu32be(b + 4, (uint32_t)u64);
}

uint16_t
lws_ser_ru16be(const uint8_t *b)
{
	return (uint16_t)((b[0] << 8) | b[1]);
}

uint32_t
lws_ser_ru32be(const uint8_t *b)
{
	return (unsigned int)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

uint64_t
lws_ser_ru64be(const uint8_t *b)
{
	return (((uint64_t)lws_ser_ru32be(b)) << 32) | lws_ser_ru32be(b + 4);
}

int
lws_vbi_encode(uint64_t value, void *buf)
{
	uint8_t *p = (uint8_t *)buf, b;

	if (value > 0xfffffff) {
		assert(0);
		return -1;
	}

	do {
		b = value & 0x7f;
		value >>= 7;
		if (value)
			*p++ = (0x80 | b);
		else
			*p++ = b;
	} while (value);

	return lws_ptr_diff(p, buf);
}

int
lws_vbi_decode(const void *buf, uint64_t *value, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf, *end = p + len;
	uint64_t v = 0;
	int s = 0;

	while (p < end) {
		v |= (((uint64_t)(*p)) & 0x7f) << s;
		if (*p & 0x80) {
			*value = v;

			return lws_ptr_diff(p, buf);
		}
		s += 7;
		if (s >= 64)
			return 0;
		p++;
	}

	return 0;
}

signed char char_to_hex(const char c)
{
	if (c >= '0' && c <= '9')
		return (signed char)(c - '0');

	if (c >= 'a' && c <= 'f')
		return (signed char)(c - 'a' + 10);

	if (c >= 'A' && c <= 'F')
		return (signed char)(c - 'A' + 10);

	return (signed char)-1;
}

int
lws_hex_len_to_byte_array(const char *h, size_t hlen, uint8_t *dest, int max)
{
	uint8_t *odest = dest;

	while (max-- && hlen > 1) {
		int t = char_to_hex(*h++), t1;

		if (!*h || t < 0)
			return -1;

		t1 = char_to_hex(*h++);
		if (t1 < 0)
			return -1;

		*dest++ = (uint8_t)((t << 4) | t1);
		hlen -= 2;
	}

	if (max < -1)
		return -1;

	return lws_ptr_diff(dest, odest);
}

int
lws_hex_to_byte_array(const char *h, uint8_t *dest, int max)
{
	return lws_hex_len_to_byte_array(h, strlen(h), dest, max);
}

static char *hexch = "0123456789abcdef";

void
lws_hex_from_byte_array(const uint8_t *src, size_t slen, char *dest, size_t len)
{
	char *end = &dest[len - 1];

	while (slen-- && dest != end) {
		uint8_t b = *src++;
		*dest++ = hexch[b >> 4];
		if (dest == end)
			break;
		*dest++ = hexch[b & 0xf];
	}

	*dest = '\0';
}

int
lws_hex_random(struct lws_context *context, char *dest, size_t len)
{
	size_t n = ((len - 1) / 2) + 1;
	uint8_t b, *r = (uint8_t *)dest + len - n;

	if (lws_get_random(context, r, n) != n)
		return 1;

	while (len >= 3) {
		b = *r++;
		*dest++ = hexch[b >> 4];
		*dest++ = hexch[b & 0xf];
		len -= 2;
	}

	if (len == 2)
		*dest++ = hexch[(*r) >> 4];

	*dest = '\0';

	return 0;
}

#if defined(_DEBUG)
void
lws_assert_fourcc(uint32_t fourcc, uint32_t expected)
{
	if (fourcc == expected)
		return;

	lwsl_err("%s: fourcc mismatch, expected %c%c%c%c, saw %c%c%c%c\n",
			__func__, (int)(expected >> 24), (int)((expected >> 16) & 0xff),
			(int)((expected >> 8) & 0xff),(int)( expected & 0xff),
			(int)(fourcc >> 24), (int)((fourcc >> 16) & 0xff),
			(int)((fourcc >> 8) & 0xff), (int)(fourcc & 0xff));

	assert(0);
}
#endif

#if !defined(LWS_PLAT_OPTEE) && !defined(LWS_PLAT_BAREMETAL)

#if defined(LWS_WITH_FILE_OPS)
int lws_open(const char *__file, int __oflag, ...)
{
	va_list ap;
	int n;

	va_start(ap, __oflag);
	if (((__oflag & O_CREAT) == O_CREAT)
#if defined(O_TMPFILE)
		|| ((__oflag & O_TMPFILE) == O_TMPFILE)
#endif
	)
#if defined(WIN32)
		/* last arg is really a mode_t.  But windows... */
		n = open(__file, __oflag, va_arg(ap, uint32_t));
#else
		/* ... and some other toolchains...
		 *
		 * error: second argument to 'va_arg' is of promotable type 'mode_t'
		 * (aka 'unsigned short'); this va_arg has undefined behavior because
		 * arguments will be promoted to 'int'
		 */
		n = open(__file, __oflag, (mode_t)va_arg(ap, unsigned int));
#endif
	else
		n = open(__file, __oflag);
	va_end(ap);

	if (n != -1 && lws_plat_apply_FD_CLOEXEC(n)) {
		close(n);

		return -1;
	}

	return n;
}
#endif
#endif

int
lws_pthread_self_to_tsi(struct lws_context *context)
{
#if defined(LWS_WITH_NETWORK) && LWS_MAX_SMP > 1
	pthread_t ps = pthread_self();
	struct lws_context_per_thread *pt = &context->pt[0];
	int n;

	/* case that we have SMP build, but don't use it */
	if (context->count_threads == 1)
		return 0;

	for (n = 0; n < context->count_threads; n++) {
		if (pthread_equal(ps, pt->self))
			return n;
		pt++;
	}

	return -1;
#else
	return 0;
#endif
}

void *
lws_context_user(struct lws_context *context)
{
	return context->user_space;
}

void
lws_explicit_bzero(void *p, size_t len)
{
	volatile uint8_t *vp = p;

	while (len--)
		*vp++ = 0;
}

#if !(defined(LWS_PLAT_OPTEE) && !defined(LWS_WITH_NETWORK))

/**
 * lws_now_secs() - seconds since 1970-1-1
 *
 */
unsigned long
lws_now_secs(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (unsigned long)tv.tv_sec;
}

#endif

#if defined(LWS_WITH_SERVER)
const char *
lws_canonical_hostname(struct lws_context *context)
{
	return (const char *)context->canonical_hostname;
}
#endif

int
lws_get_count_threads(struct lws_context *context)
{
	return context->count_threads;
}

static const unsigned char e0f4[] = {
	0xa0 | ((2 - 1) << 2) | 1, /* e0 */
	0x80 | ((4 - 1) << 2) | 1, /* e1 */
	0x80 | ((4 - 1) << 2) | 1, /* e2 */
	0x80 | ((4 - 1) << 2) | 1, /* e3 */
	0x80 | ((4 - 1) << 2) | 1, /* e4 */
	0x80 | ((4 - 1) << 2) | 1, /* e5 */
	0x80 | ((4 - 1) << 2) | 1, /* e6 */
	0x80 | ((4 - 1) << 2) | 1, /* e7 */
	0x80 | ((4 - 1) << 2) | 1, /* e8 */
	0x80 | ((4 - 1) << 2) | 1, /* e9 */
	0x80 | ((4 - 1) << 2) | 1, /* ea */
	0x80 | ((4 - 1) << 2) | 1, /* eb */
	0x80 | ((4 - 1) << 2) | 1, /* ec */
	0x80 | ((2 - 1) << 2) | 1, /* ed */
	0x80 | ((4 - 1) << 2) | 1, /* ee */
	0x80 | ((4 - 1) << 2) | 1, /* ef */
	0x90 | ((3 - 1) << 2) | 2, /* f0 */
	0x80 | ((4 - 1) << 2) | 2, /* f1 */
	0x80 | ((4 - 1) << 2) | 2, /* f2 */
	0x80 | ((4 - 1) << 2) | 2, /* f3 */
	0x80 | ((1 - 1) << 2) | 2, /* f4 */

	0,			   /* s0 */
	0x80 | ((4 - 1) << 2) | 0, /* s2 */
	0x80 | ((4 - 1) << 2) | 1, /* s3 */
};

int
lws_check_byte_utf8(unsigned char state, unsigned char c)
{
	unsigned char s = state;

	if (!s) {
		if (c >= 0x80) {
			if (c < 0xc2 || c > 0xf4)
				return -1;
			if (c < 0xe0)
				return 0x80 | ((4 - 1) << 2);
			else
				return e0f4[c - 0xe0];
		}

		return s;
	}
	if (c < (s & 0xf0) || c >= (s & 0xf0) + 0x10 + ((s << 2) & 0x30))
		return -1;

	return e0f4[21 + (s & 3)];
}

int
lws_check_utf8(unsigned char *state, unsigned char *buf, size_t len)
{
	unsigned char s = *state;

	while (len--) {
		unsigned char c = *buf++;

		if (!s) {
			if (c >= 0x80) {
				if (c < 0xc2 || c > 0xf4)
					return 1;
				if (c < 0xe0)
					s = 0x80 | ((4 - 1) << 2);
				else
					s = e0f4[c - 0xe0];
			}
		} else {
			if (c < (s & 0xf0) ||
			    c >= (s & 0xf0) + 0x10 + ((s << 2) & 0x30))
				return 1;
			s = e0f4[21 + (s & 3)];
		}
	}

	*state = s;

	return 0;
}


char *
lws_strdup(const char *s)
{
	size_t l = strlen(s) + 1;
	char *d = lws_malloc(l, "strdup");

	if (d)
		memcpy(d, s, l);

	return d;
}

const char *
lws_nstrstr(const char *buf, size_t len, const char *name, size_t nl)
{
	const char *end = buf + len - nl + 1;
	size_t n;

	if (nl > len)
		/* it cannot be found if the needle is longer than the haystack */
		return NULL;

	while (buf < end) {
		if (*buf != name[0]) {
			buf++;
			continue;
		}

		if (nl == 1)
			/* single char match, we are done */
			return buf;

		if (buf[nl - 1] == name[nl - 1]) {
			/*
			 * This is looking interesting then... the first
			 * and last chars match, let's check the insides
			 */
			n = 1;
			while (n < nl && buf[n] == name[n])
				n++;

			if (n == nl)
				/* it's a hit */
				return buf;
		}

		buf++;
	}

	return NULL;
}

/*
 * name wants to be something like "\"myname\":"
 */

const char *
lws_json_simple_find(const char *buf, size_t len, const char *name, size_t *alen)
{
	size_t nl = strlen(name);
	const char *np = lws_nstrstr(buf, len, name, nl),
		   *end = buf + len, *as;
	int qu = 0;

	if (!np)
		return NULL;

	np += nl;

	while (np < end && (*np == ' ' || *np == '\t'))
		np++;

	if (np >= end)
		return NULL;

	/*
	 * The arg could be lots of things after "name": with JSON, commonly a
	 * string like "mystring", true, false, null, [...] or {...} ... we want
	 * to handle common, simple cases cheaply with this; the user can choose
	 * a full JSON parser like lejp if it's complicated.  So if no opening
	 * quote, return until a terminator like , ] }.  If there's an opening
	 * quote, return until closing quote, handling escaped quotes.
	 */

	if (*np == '\"') {
		qu = 1;
		np++;
	}

	as = np;
	while (np < end &&
	       (!qu || *np != '\"') && /* end quote is EOT if quoted */
	       (qu || (*np != '}' && *np != ']' && *np != ',')) /* delimiters */
	) {
		if (qu && *np == '\\') /* skip next char if quoted escape */
			np++;
		np++;
	}

	*alen = (unsigned int)lws_ptr_diff(np, as);

	return as;
}

int
lws_json_simple_strcmp(const char *buf, size_t len, const char *name,
		       const char *comp)
{
	size_t al;
	const char *hit = lws_json_simple_find(buf, len, name, &al);

	if (!hit)
		return -1;

	if (al != strlen(comp))
		return -1;

	return strncmp(hit, comp, al);
}

static const char *hex = "0123456789ABCDEF";

const char *
lws_sql_purify(char *escaped, const char *string, size_t len)
{
	const char *p = string;
	char *q = escaped;

	while (*p && len-- > 2) {
		if (*p == '\'') {
			*q++ = '\'';
			*q++ = '\'';
			len --;
			p++;
		} else
			*q++ = *p++;
	}
	*q = '\0';

	return escaped;
}

int
lws_sql_purify_len(const char *p)
{
	int olen = 0;

	while (*p) {
		if (*p++ == '\'')
			olen++;
		olen++;
	}

	return olen;
}

const char *
lws_json_purify(char *escaped, const char *string, int len, int *in_used)
{
	const char *p = string;
	char *q = escaped;

	if (!p) {
		escaped[0] = '\0';
		return escaped;
	}

	while (*p && len-- > 6) {
		if (*p == '\t') {
			p++;
			*q++ = '\\';
			*q++ = 't';
			continue;
		}

		if (*p == '\n') {
			p++;
			*q++ = '\\';
			*q++ = 'n';
			continue;
		}

		if (*p == '\r') {
			p++;
			*q++ = '\\';
			*q++ = 'r';
			continue;
		}

		if (*p == '\\') {
			p++;
			*q++ = '\\';
			*q++ = '\\';
			continue;
		}

		if (*p == '\"' || *p < 0x20) {
			*q++ = '\\';
			*q++ = 'u';
			*q++ = '0';
			*q++ = '0';
			*q++ = hex[((*p) >> 4) & 15];
			*q++ = hex[(*p) & 15];
			len -= 5;
			p++;
		} else
			*q++ = *p++;
	}
	*q = '\0';

	if (in_used)
		*in_used = lws_ptr_diff(p, string);

	return escaped;
}

int
lws_json_purify_len(const char *string)
{
	int len = 0;
	const char *p = string;

	while (*p) {
		if (*p == '\t' || *p == '\n' || *p == '\r') {
			p++;
			len += 2;
			continue;
		}

		if (*p == '\"' || *p == '\\' || *p < 0x20) {
			len += 6;
			p++;
			continue;
		}
		p++;
		len++;
	}

	return len;
}

void
lws_filename_purify_inplace(char *filename)
{
	while (*filename) {

		if (*filename == '.' && filename[1] == '.') {
			*filename = '_';
			filename[1] = '_';
		}

		if (*filename == ':' ||
#if !defined(WIN32)
		    *filename == '\\' ||
#endif
		    *filename == '$' ||
		    *filename == '%')
			*filename = '_';

		filename++;
	}
}

const char *
lws_urlencode(char *escaped, const char *string, int len)
{
	const char *p = string;
	char *q = escaped;

	while (*p && len-- > 3) {
		if (*p == ' ') {
			*q++ = '+';
			p++;
			continue;
		}
		if ((*p >= '0' && *p <= '9') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= 'a' && *p <= 'z')) {
			*q++ = *p++;
			continue;
		}
		*q++ = '%';
		*q++ = hex[(*p >> 4) & 0xf];
		*q++ = hex[*p & 0xf];

		len -= 2;
		p++;
	}
	*q = '\0';

	return escaped;
}

int
lws_urldecode(char *string, const char *escaped, int len)
{
	int state = 0, n;
	char sum = 0;

	while (*escaped && len) {
		switch (state) {
		case 0:
			if (*escaped == '%') {
				state++;
				escaped++;
				continue;
			}
			if (*escaped == '+') {
				escaped++;
				*string++ = ' ';
				len--;
				continue;
			}
			*string++ = *escaped++;
			len--;
			break;
		case 1:
			n = char_to_hex(*escaped);
			if (n < 0)
				return -1;
			escaped++;
			sum = (char)(n << 4);
			state++;
			break;

		case 2:
			n = char_to_hex(*escaped);
			if (n < 0)
				return -1;
			escaped++;
			*string++ = (char)(sum | n);
			len--;
			state = 0;
			break;
		}

	}
	*string = '\0';

	return 0;
}

/*
 * Copy the url formof rel into dest, using base to fill in missing context
 *
 * If base is https://x.com/y/z.html
 *
 *   a.html               -> https://x.com/y/a/html
 *   ../b.html            -> https://x.com/b.html
 *   /c.html              -> https://x.com/c.html
 *   https://y.com/a.html -> https://y.com/a.html
 */

int
lws_http_rel_to_url(char *dest, size_t len, const char *base, const char *rel)
{
	size_t n = 0, ps = 0;
	char d = 0;

	// lwsl_err("%s: base %s, rel %s\n", __func__, base, rel);

	if (!strncmp(rel, "https://", 8) ||
	    !strncmp(rel, "http://", 7) ||
	    !strncmp(rel, "file://", 7)) {
		/* rel is already a full url, just copy it */
		lws_strncpy(dest, rel, len);
		return 0;
	}

	/* we're going to be using the first part of base at least */

	while (n < len - 2 && base[n]) {
		dest[n] = base[n];
		if (d && base[n] == '/') {
			n++;
			ps = n;
			//if (rel[0] == '/') {
				break;
			//}
		}
		if (n && base[n] == '/' && base[n - 1] == '/')
			d = 1;
		n++;
	}

	if (!n || n >= len - 2)
		return 1;

	/* if we did not have a '/' after the hostname, add one */
	if (dest[n - 1] != '/') {
		ps = n;
		dest[n++] = '/';
	}

	/* is rel an absolute path we should just use with the hostname? */
	if (rel[0] != '/') {

		/*
		 * Apply the rest of the basename, without the file part,
		 * end with last / if any
		 */

		ps = n;
		while (n < len - 2 && base[n]) {
			dest[n] = base[n];
			n++;
			if (base[n] == '/')
				ps = n;
		}

		n = ps;

		if (n >= len - 2)
			return 1;

		/* if we did not have a '/' after the base path, add one */
		if (dest[n - 1] != '/')
			dest[n++] = '/';
	}

	/* append rel */

	if (len - n < strlen(rel) + 2)
		return 1;

	lws_strncpy(dest + n, rel, len - n);

	return 0;
}

int
lws_finalize_startup(struct lws_context *context)
{
	if (lws_check_opt(context->options, LWS_SERVER_OPTION_EXPLICIT_VHOSTS))
		if (lws_plat_drop_app_privileges(context, 1))
			return 1;

	return 0;
}

#if !defined(LWS_PLAT_FREERTOS)
void
lws_get_effective_uid_gid(struct lws_context *context, uid_t *uid, gid_t *gid)
{
	*uid = context->uid;
	*gid = context->gid;
}
#endif

int
lws_snprintf(char *str, size_t size, const char *format, ...)
{
	va_list ap;
	int n;

	if (!str || !size)
		return 0;

	va_start(ap, format);
	n = vsnprintf(str, size, format, ap);
	va_end(ap);

	if (n >= (int)size)
		return (int)size;

	return n;
}

char *
lws_strncpy(char *dest, const char *src, size_t size)
{
	strncpy(dest, src, size - 1);
	dest[size - 1] = '\0';

	return dest;
}

int
lws_timingsafe_bcmp(const void *a, const void *b, uint32_t len)
{
	const uint8_t *pa = a, *pb = b;
	uint8_t sum = 0;

	while (len--)
		sum |= (uint8_t)(*pa++ ^ *pb++);

	return sum;
}

lws_tokenize_elem
lws_tokenize(struct lws_tokenize *ts)
{
	const char *rfc7230_delims = "(),/:;<=>?@[\\]{}";
	char c, flo = 0, d_minus = '-', d_dot = '.', d_star = '*', s_minus = '\0',
	     s_dot = '\0', s_star = '\0', d_eq = '=', s_eq = '\0', skipping = 0;
	signed char num = (ts->flags & LWS_TOKENIZE_F_NO_INTEGERS) ? 0 : -1;
	int utf8 = 0;

	/* for speed, compute the effect of the flags outside the loop */

	if (ts->flags & LWS_TOKENIZE_F_MINUS_NONTERM) {
		d_minus = '\0';
		s_minus = '-';
	}
	if (ts->flags & LWS_TOKENIZE_F_DOT_NONTERM) {
		d_dot = '\0';
		s_dot = '.';
	}
	if (ts->flags & LWS_TOKENIZE_F_ASTERISK_NONTERM) {
		d_star = '\0';
		s_star = '*';
	}
	if (ts->flags & LWS_TOKENIZE_F_EQUALS_NONTERM) {
		d_eq = '\0';
		s_eq = '=';
	}

	if (!ts->dry)
		ts->token = ts->collect;
	ts->dry = 0;

	if (ts->reset_token) {
		ts->effline = ts->line;
		ts->state = LWS_TOKZS_LEADING_WHITESPACE;
		ts->token_len = 0;
		ts->reset_token = 0;
	}

	while (ts->len) {
		c = *ts->start++;
		ts->len--;

		utf8 = lws_check_byte_utf8((unsigned char)utf8, (unsigned char)c);
		if (utf8 < 0)
			return LWS_TOKZE_ERR_BROKEN_UTF8;

		if (!c)
			break;

		if (skipping) {
			if (c != '\r' && c != '\n')
				continue;
			else
				skipping = 0;
		}

		/* comment */

		if (ts->flags & LWS_TOKENIZE_F_HASH_COMMENT &&
		    ts->state != LWS_TOKZS_QUOTED_STRING &&
		    c == '#') {
			skipping = 1;
			continue;
		}

		/* whitespace */

		if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
		    c == '\f') {
			if (c == '\r' && !ts->crlf)
				ts->line++;
			if (c == '\n') {
				ts->line++;
				ts->crlf = 1;
			}
			switch (ts->state) {
			case LWS_TOKZS_LEADING_WHITESPACE:
			case LWS_TOKZS_TOKEN_POST_TERMINAL:
				continue;
			case LWS_TOKZS_QUOTED_STRING:
				goto agg;
			case LWS_TOKZS_TOKEN:
				/* we want to scan forward to look for = */

				ts->state = LWS_TOKZS_TOKEN_POST_TERMINAL;
				continue;
			}
		} else
			ts->crlf = 0;

		/* quoted string */

		if (c == '\"') {
			if (ts->state == LWS_TOKZS_QUOTED_STRING) {
				ts->reset_token = 1;

				return LWS_TOKZE_QUOTED_STRING;
			}

			/* starting a quoted string */

			if (ts->flags & LWS_TOKENIZE_F_COMMA_SEP_LIST) {
				if (ts->delim == LWSTZ_DT_NEED_DELIM)
					return LWS_TOKZE_ERR_COMMA_LIST;
				ts->delim = LWSTZ_DT_NEED_DELIM;
			}

			ts->state = LWS_TOKZS_QUOTED_STRING;
			ts->token = ts->collect;
			ts->token_len = 0;

			continue;
		}

		/* token= aggregation */

		if (!(ts->flags & LWS_TOKENIZE_F_EQUALS_NONTERM) &&
		    c == '=' && (ts->state == LWS_TOKZS_TOKEN_POST_TERMINAL ||
				 ts->state == LWS_TOKZS_TOKEN)) {

			ts->reset_token = 1;

			if (num == 1)
				return LWS_TOKZE_ERR_NUM_ON_LHS;
			/* swallow the = */
			return LWS_TOKZE_TOKEN_NAME_EQUALS;
		}

		/* optional token: aggregation */

		if ((ts->flags & LWS_TOKENIZE_F_AGG_COLON) && c == ':' &&
		    (ts->state == LWS_TOKZS_TOKEN_POST_TERMINAL ||
		     ts->state == LWS_TOKZS_TOKEN)) {
			ts->reset_token = 1;

			/* swallow the : */
			return LWS_TOKZE_TOKEN_NAME_COLON;
		}

		/* aggregate . in a number as a float */

		if (c == '.' && !(ts->flags & LWS_TOKENIZE_F_NO_FLOATS) &&
		    ts->state == LWS_TOKZS_TOKEN && num == 1) {
			if (flo)
				return LWS_TOKZE_ERR_MALFORMED_FLOAT;
			flo = 1;
			goto agg;
		}

		/*
		 * Delimiter... by default anything that:
		 *
		 *  - isn't matched earlier, or
		 *  - is [A-Z, a-z, 0-9, _], and
		 *  - is not a partial utf8 char
		 *
		 * is a "delimiter", it marks the end of a token and is itself
		 * reported as a single LWS_TOKZE_DELIMITER each time.
		 *
		 * However with LWS_TOKENIZE_F_RFC7230_DELIMS flag, tokens may
		 * contain any noncontrol character that isn't defined in
		 * rfc7230_delims, and only characters listed there are treated
		 * as delimiters.
		 */

		if (!utf8 &&
		     ((ts->flags & LWS_TOKENIZE_F_RFC7230_DELIMS &&
		       strchr(rfc7230_delims, c) && c > 32) ||
		       ((!(ts->flags & LWS_TOKENIZE_F_RFC7230_DELIMS) &&
		        (c < '0' || c > '9') && (c < 'A' || c > 'Z') &&
		        (c < 'a' || c > 'z') && c != '_') &&
		        c != s_minus && c != s_dot && c != s_star && c != s_eq) ||
		        c == d_minus ||
			c == d_dot ||
			c == d_star ||
			c == d_eq
		    ) &&
		    !((ts->flags & LWS_TOKENIZE_F_COLON_NONTERM) && c == ':') &&
		    !((ts->flags & LWS_TOKENIZE_F_SLASH_NONTERM) && c == '/')) {
			switch (ts->state) {
			case LWS_TOKZS_LEADING_WHITESPACE:
				if (ts->flags & LWS_TOKENIZE_F_COMMA_SEP_LIST) {
					if (c != ',' ||
					    ts->delim != LWSTZ_DT_NEED_DELIM)
						return LWS_TOKZE_ERR_COMMA_LIST;
					ts->delim = LWSTZ_DT_NEED_NEXT_CONTENT;
				}

				ts->token = ts->start - 1;
				ts->token_len = 1;
				ts->reset_token = 1;

				return LWS_TOKZE_DELIMITER;

			case LWS_TOKZS_QUOTED_STRING:
agg:
				ts->collect[ts->token_len++] = c;
				if (ts->token_len == sizeof(ts->collect) - 1)
					return LWS_TOKZE_TOO_LONG;
				ts->collect[ts->token_len] = '\0';
				continue;

			case LWS_TOKZS_TOKEN_POST_TERMINAL:
			case LWS_TOKZS_TOKEN:
				/* report the delimiter next time */
				ts->start--;
				ts->len++;
				goto token_or_numeric;
			}
		}

		/* anything that's not whitespace or delimiter is payload */

		switch (ts->state) {
		case LWS_TOKZS_LEADING_WHITESPACE:

			if (ts->flags & LWS_TOKENIZE_F_COMMA_SEP_LIST) {
				if (ts->delim == LWSTZ_DT_NEED_DELIM) {
					ts->reset_token = 1;

					return LWS_TOKZE_ERR_COMMA_LIST;
				}
				ts->delim = LWSTZ_DT_NEED_DELIM;
			}

			ts->state = LWS_TOKZS_TOKEN;
			ts->reset_token = 1;

			ts->token = ts->collect; //ts->start - 1;
			ts->collect[0] = c;
			ts->token_len = 1;
			goto checknum;

		case LWS_TOKZS_QUOTED_STRING:
		case LWS_TOKZS_TOKEN:
			ts->collect[ts->token_len++] = c;
			if (ts->token_len == sizeof(ts->collect) - 1)
				return LWS_TOKZE_TOO_LONG;
			ts->collect[ts->token_len] = '\0';
checknum:
			if (!(ts->flags & LWS_TOKENIZE_F_NO_INTEGERS)) {
				if (c < '0' || c > '9')
					num = 0;
				else
					if (num < 0)
						num = 1;
			}
			continue;

		case LWS_TOKZS_TOKEN_POST_TERMINAL:
			/* report the new token next time */
			ts->start--;
			ts->len++;
			goto token_or_numeric;
		}
	}

	/* we ran out of content */

	if (ts->flags & LWS_TOKENIZE_F_EXPECT_MORE) {
		ts->reset_token = 0;
		ts->dry = 1;
		return LWS_TOKZE_WANT_READ;
	}

	if (utf8) /* ended partway through a multibyte char */
		return LWS_TOKZE_ERR_BROKEN_UTF8;

	if (ts->state == LWS_TOKZS_QUOTED_STRING)
		return LWS_TOKZE_ERR_UNTERM_STRING;

	if (ts->state != LWS_TOKZS_TOKEN_POST_TERMINAL &&
	    ts->state != LWS_TOKZS_TOKEN) {
		if ((ts->flags & LWS_TOKENIZE_F_COMMA_SEP_LIST) &&
		     ts->delim == LWSTZ_DT_NEED_NEXT_CONTENT)
			return LWS_TOKZE_ERR_COMMA_LIST;

		return LWS_TOKZE_ENDED;
	}

	/* report the pending token */

token_or_numeric:

	ts->reset_token = 1;

	if (num != 1)
		return LWS_TOKZE_TOKEN;
	if (flo)
		return LWS_TOKZE_FLOAT;

	return LWS_TOKZE_INTEGER;
}


int
lws_tokenize_cstr(struct lws_tokenize *ts, char *str, size_t max)
{
	if (ts->token_len + 1 >= max)
		return 1;

	memcpy(str, ts->token, ts->token_len);
	str[ts->token_len] = '\0';

	return 0;
}

void
lws_tokenize_init(struct lws_tokenize *ts, const char *start, int flags)
{
	ts->start = start;
	ts->len = 0x7fffffff;
	ts->flags = (uint16_t)(unsigned int)flags;
	ts->delim = LWSTZ_DT_NEED_FIRST_CONTENT;
	ts->token = NULL;
	ts->token_len = 0;
	ts->line = 0;
	ts->effline = 0;
	ts->dry = 0;
	ts->reset_token = 0;
	ts->crlf = 0;
	ts->state = LWS_TOKZS_LEADING_WHITESPACE;
}


typedef enum {
	LWS_EXPS_LITERAL,
	LWS_EXPS_OPEN_OR_LIT,
	LWS_EXPS_NAME_OR_CLOSE,
	LWS_EXPS_DRAIN,
} lws_strexp_state;

void
lws_strexp_init(lws_strexp_t *exp, void *priv, lws_strexp_expand_cb cb,
		 char *out, size_t olen)
{
	memset(exp, 0, sizeof(*exp));
	exp->cb = cb;
	exp->out = out;
	exp->olen = olen;
	exp->state = LWS_EXPS_LITERAL;
	exp->priv = priv;
}

void
lws_strexp_reset_out(lws_strexp_t *exp, char *out, size_t olen)
{
	exp->out = out;
	exp->olen = olen;
	exp->pos = 0;
}

int
lws_strexp_expand(lws_strexp_t *exp, const char *in, size_t len,
		  size_t *pused_in, size_t *pused_out)
{
	size_t used = 0;
	int n;

	while (used < len) {

		switch (exp->state) {
		case LWS_EXPS_LITERAL:
			if (*in == '$') {
				exp->state = LWS_EXPS_OPEN_OR_LIT;
				break;
			}

			if (exp->out)
				exp->out[exp->pos] = *in;
			exp->pos++;
			if (exp->olen - exp->pos < 1) {
				*pused_in = used + 1;
				*pused_out = exp->pos;
				return LSTRX_FILLED_OUT;
			}
			break;

		case LWS_EXPS_OPEN_OR_LIT:
			if (*in == '{') {
				exp->state = LWS_EXPS_NAME_OR_CLOSE;
				exp->name_pos = 0;
				exp->exp_ofs = 0;
				break;
			}
			/* treat as a literal */
			if (exp->olen - exp->pos < 3)
				return -1;

			if (exp->out) {
				exp->out[exp->pos++] = '$';
				exp->out[exp->pos++] = *in;
			} else
				exp->pos += 2;
			if (*in != '$')
				exp->state = LWS_EXPS_LITERAL;
			break;

		case LWS_EXPS_NAME_OR_CLOSE:
			if (*in == '}') {
				exp->name[exp->name_pos] = '\0';
				exp->state = LWS_EXPS_DRAIN;
				goto drain;
			}
			if (exp->name_pos >= sizeof(exp->name) - 1)
				return LSTRX_FATAL_NAME_TOO_LONG;

			exp->name[exp->name_pos++] = *in;
			break;

		case LWS_EXPS_DRAIN:
drain:
			*pused_in = used;
			n = exp->cb(exp->priv, exp->name, exp->out, &exp->pos,
				    exp->olen, &exp->exp_ofs);
			*pused_out = exp->pos;
			if (n == LSTRX_FILLED_OUT ||
			    n == LSTRX_FATAL_NAME_UNKNOWN)
				return n;

			exp->state = LWS_EXPS_LITERAL;
			break;
		}

		used++;
		in++;
	}

	if (exp->out)
		exp->out[exp->pos] = '\0';
	*pused_in = used;
	*pused_out = exp->pos;

	return LSTRX_DONE;
}

int
lws_strcmp_wildcard(const char *wildcard, size_t wlen, const char *check,
		    size_t clen)
{
	const char *match[3], *wc[3], *wc_end = wildcard + wlen,
		   *cend = check + clen;
	int sp = 0;

	do {

		if (wildcard == wc_end) {
			/*
			 * We reached the end of wildcard, but not of check,
			 * and the last thing in wildcard was not a * or we
			 * would have completed already... if we can rewind,
			 * let's try that...
			 */
			if (sp) {
				wildcard = wc[sp - 1];
				check = match[--sp];

				continue;
			}

			/* otherwise it's the end of the road for this one */

			return 1;
		}

		if (*wildcard == '*') {

			if (++wildcard == wc_end)
				 /*
				  * Wildcard ended on a *, so we know we will
				  * match unconditionally
				  */
				return 0;

			/*
			 * Now we need to stick wildcard here and see if there
			 * is any remaining match exists, for eg b of "a*b"
			 */

			if (sp == LWS_ARRAY_SIZE(match)) {
				lwsl_err("%s: exceeds * stack\n", __func__);
				return 1; /* we can't deal with it */
			}

			wc[sp] = wildcard;
			/* if we ever pop and come back here, pick up from +1 */
			match[sp++] = check + 1;
			continue;
		}

		if (*(check++) == *wildcard) {

			if (wildcard == wc_end)
				return 0;
			/*
			 * We're still compatible with wildcard... keep going
			 */
			wildcard++;

			continue;
		}

		if (!sp)
			/*
			 * We're just trying to match literals, and failed...
			 */
			return 1;

		/* we're looking for a post-* match... keep looking... */

	} while (check < cend);

	/*
	 * We reached the end of check, if also at end of wildcard we're OK
	 */

	return wildcard != wc_end;
}

#if defined(LWS_WITH_NETWORK) && LWS_MAX_SMP > 1

void
lws_mutex_refcount_init(struct lws_mutex_refcount *mr)
{
	pthread_mutex_init(&mr->lock, NULL);
	mr->last_lock_reason = NULL;
	mr->lock_depth = 0;
	mr->metadata = 0;
#ifdef __PTW32_H
	/* If we use implementation of PThreads for Win that is
	 * distributed by VCPKG */
	memset(&mr->lock_owner, 0, sizeof(pthread_t));
#else
	mr->lock_owner = 0;
#endif
}

void
lws_mutex_refcount_destroy(struct lws_mutex_refcount *mr)
{
	pthread_mutex_destroy(&mr->lock);
}

void
lws_mutex_refcount_lock(struct lws_mutex_refcount *mr, const char *reason)
{
	/* if true, this sequence is atomic because our thread has the lock
	 *
	 *  - if true, only guy who can race to make it untrue is our thread,
	 *    and we are here.
	 *
	 *  - if false, only guy who could race to make it true is our thread,
	 *    and we are here
	 *
	 *  - it can be false and change to a different tid that is also false
	 */
#ifdef __PTW32_H
	/* If we use implementation of PThreads for Win that is
	 * distributed by VCPKG */
	if (pthread_equal(mr->lock_owner, pthread_self()))
#else
	if (mr->lock_owner == pthread_self())
#endif
	{
		/* atomic because we only change it if we own the lock */
		mr->lock_depth++;
		return;
	}

	pthread_mutex_lock(&mr->lock);
	/* atomic because only we can have the lock */
	mr->last_lock_reason = reason;
	mr->lock_owner = pthread_self();
	mr->lock_depth = 1;
	//lwsl_notice("tid %d: lock %s\n", mr->tid, reason);
}

void
lws_mutex_refcount_unlock(struct lws_mutex_refcount *mr)
{
	if (--mr->lock_depth)
		/* atomic because only thread that has the lock can unlock */
		return;

	mr->last_lock_reason = "free";
#ifdef __PTW32_H
	/* If we use implementation of PThreads for Win that is
	 * distributed by VCPKG */
	memset(&mr->lock_owner, 0, sizeof(pthread_t));
#else
	mr->lock_owner = 0;
#endif
	// lwsl_notice("tid %d: unlock %s\n", mr->tid, mr->last_lock_reason);
	pthread_mutex_unlock(&mr->lock);
}

void
lws_mutex_refcount_assert_held(struct lws_mutex_refcount *mr)
{
#ifdef __PTW32_H
	/* If we use implementation of PThreads for Win that is
	 * distributed by VCPKG */
	assert(pthread_equal(mr->lock_owner, pthread_self()) && mr->lock_depth);
#else
	assert(mr->lock_owner == pthread_self() && mr->lock_depth);
#endif
}

#endif /* SMP */


const char *
lws_cmdline_option(int argc, const char **argv, const char *val)
{
	size_t n = strlen(val);
	int c = argc;

	while (--c > 0) {

		if (!strncmp(argv[c], val, n)) {
			if (c < argc - 1 && !*(argv[c] + n)) {
				/* coverity treats unchecked argv as "tainted" */
				if (!argv[c + 1] || strlen(argv[c + 1]) > 1024)
					return NULL;
				return argv[c + 1];
			}

			if (argv[c][n] == '=')
				return &argv[c][n + 1];
			return argv[c] + n;
		}
	}

	return NULL;
}

static const char * const builtins[] = {
	"-d",
	"--fault-injection",
	"--fault-seed",
	"--ignore-sigterm",
	"--ssproxy-port",
	"--ssproxy-iface",
	"--ssproxy-ads",
};

enum opts {
	OPT_DEBUGLEVEL,
	OPT_FAULTINJECTION,
	OPT_FAULT_SEED,
	OPT_IGNORE_SIGTERM,
	OPT_SSPROXY_PORT,
	OPT_SSPROXY_IFACE,
	OPT_SSPROXY_ADS,
};

#if !defined(LWS_PLAT_FREERTOS)
static void
lws_sigterm_catch(int sig)
{
}
#endif

void
_lws_context_info_defaults(struct lws_context_creation_info *info,
			  const char *sspol)
{
	memset(info, 0, sizeof *info);
        info->fd_limit_per_thread = 1 + 6 + 1;
#if defined(LWS_WITH_NETWORK)
        info->port = CONTEXT_PORT_NO_LISTEN;
#endif
#if defined(LWS_WITH_SECURE_STREAMS) && !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
        info->pss_policies_json = sspol;
#endif
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
        if (!sspol)
        	info->protocols = lws_sspc_protocols;
#endif
       	info->options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
       		LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW |
       		LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
}

void
lws_default_loop_exit(struct lws_context *cx)
{
	if (cx) {
		cx->interrupted = 1;
#if defined(LWS_WITH_NETWORK)
		lws_cancel_service(cx);
#endif
	}
}

#if defined(LWS_WITH_NETWORK)
void
lws_context_default_loop_run_destroy(struct lws_context *cx)
{
        /* the default event loop, since we didn't provide an alternative one */

        while (!cx->interrupted && lws_service(cx, 0) >= 0)
        	;

        lws_context_destroy(cx);
}
#endif

int
lws_cmdline_passfail(int argc, const char **argv, int actual)
{
	int expected = 0;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "--expected-exit")))
		expected = atoi(p);

	if (actual == expected) {
		lwsl_user("Completed: OK (seen expected %d)\n", actual);

		return 0;
	}

	lwsl_err("Completed: failed: exit %d, expected %d\n", actual, expected);

	return 1;
}

void
lws_cmdline_option_handle_builtin(int argc, const char **argv,
				  struct lws_context_creation_info *info)
{
	const char *p;
	int n, m, logs = info->default_loglevel ? info->default_loglevel :
				LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	uint64_t seed = (uint64_t)lws_now_usecs();
#endif

	for (n = 0; n < (int)LWS_ARRAY_SIZE(builtins); n++) {
		p = lws_cmdline_option(argc, argv, builtins[n]);
		if (!p)
			continue;

		m = atoi(p);

		switch (n) {
		case OPT_DEBUGLEVEL:
			logs = m;
			break;

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
		case OPT_SSPROXY_PORT:
			/* connect to ssproxy via UDS by default, else via
			 * tcp connection to this port */
			info->ss_proxy_port = (uint16_t)atoi(p);
			break;

		case OPT_SSPROXY_IFACE:
			/* UDS "proxy.ss.lws" in abstract namespace, else this socket
			 * path; when -p given this can specify the network interface
			 * to bind to */
			info->ss_proxy_bind = p;
			break;

		case OPT_SSPROXY_ADS:
			info->ss_proxy_address = p;
			break;
#endif

		case OPT_FAULTINJECTION:
#if !defined(LWS_WITH_SYS_FAULT_INJECTION)
			lwsl_err("%s: FAULT_INJECTION not built\n", __func__);
#endif
			lws_fi_deserialize(&info->fic, p);
			break;

		case OPT_FAULT_SEED:
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			seed = (uint64_t)atoll(p);
#endif
			break;

		case OPT_IGNORE_SIGTERM:
#if !defined(LWS_PLAT_FREERTOS)
			signal(SIGTERM, lws_sigterm_catch);
#endif
			break;
		}
	}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	lws_xos_init(&info->fic.xos, seed);
#endif
	lws_set_log_level(logs, NULL);

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	if (info->fic.fi_owner.count)
		lwsl_notice("%s: Fault Injection seed %llu\n", __func__,
				(unsigned long long)seed);
#endif
}


const lws_humanize_unit_t humanize_schema_si[] = {
	{ "Pi", LWS_PI }, { "Ti", LWS_TI }, { "Gi", LWS_GI },
	{ "Mi", LWS_MI }, { "Ki", LWS_KI }, { "", 1 },
	{ NULL, 0 }
};
const lws_humanize_unit_t humanize_schema_si_bytes[] = {
	{ "PiB", LWS_PI }, { "TiB", LWS_TI }, { "GiB", LWS_GI },
	{ "MiB", LWS_MI }, { "KiB", LWS_KI }, { "B", 1 },
	{ NULL, 0 }
};
const lws_humanize_unit_t humanize_schema_us[] = {
	{ "y",  (uint64_t)365 * 24 * 3600 * LWS_US_PER_SEC },
	{ "d",  (uint64_t)24 * 3600 * LWS_US_PER_SEC },
	{ "hr", (uint64_t)3600 * LWS_US_PER_SEC },
	{ "min", 60 * LWS_US_PER_SEC },
	{ "s", LWS_US_PER_SEC },
	{ "ms", LWS_US_PER_MS },
#if defined(WIN32)
	{ "us", 1 },
#else
	{ "μs", 1 },
#endif
	{ NULL, 0 }
};

/* biggest ull is 18446744073709551615 (20 chars) */

static int
decim(char *r, uint64_t v, char chars, char leading)
{
	uint64_t q = 1;
	char *ro = r;
	int n = 1;

	while ((leading || v > (q * 10) - 1) && n < 20 && n < chars) {
		q = q * 10;
		n++;
	}

	/* n is how many chars needed */

	while (n--) {
		*r++ = (char)('0' + (char)((v / q) % 10));
		q = q / 10;
	}

	*r = '\0';

	return lws_ptr_diff(r, ro);
}

int
lws_humanize(char *p, size_t len, uint64_t v, const lws_humanize_unit_t *schema)
{
	char *obuf = p, *end = p + len;

	do {
		if (v >= schema->factor || schema->factor == 1) {
			if (schema->factor == 1) {
				p += decim(p, v, 4, 0);
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
						    "%s", schema->name);
				return lws_ptr_diff(p, obuf);
			}

			p += decim(p, v / schema->factor, 4, 0);
			*p++ = '.';
			p += decim(p, (v % schema->factor) /
					(schema->factor / 1000), 3, 1);

			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					    "%s", schema->name);
			return lws_ptr_diff(p, obuf);
		}
		schema++;
	} while (schema->name);

	assert(0);
	strncpy(p, "unknown value", len);

	return 0;
}

/*
 * -1 = fail
 *  0 = continue
 *  1 = hit
 */

#define LWS_MINILEX_FAIL_CODING 8

int
lws_minilex_parse(const uint8_t *lex, int16_t *ps, const uint8_t c, int *match)
{
	if (*ps == (int16_t)-1)
		return LWS_MINILEX_FAIL;

	while (1) {
		if (lex[*ps] & (1 << 7)) {
			/* 1-byte, fail on mismatch */
			if ((lex[*ps] & 0x7f) != c)
				goto nope;

			/* go forward */
			if (lex[++(*ps)] == LWS_MINILEX_FAIL_CODING)
				goto nope;

			if (lex[*ps] < LWS_MINILEX_FAIL_CODING) {
				/* this is a terminal marker */
				*match = (int)lex[++(*ps)];
				return LWS_MINILEX_MATCH;
			}

			return LWS_MINILEX_CONTINUE;
		}

		if (lex[*ps] == LWS_MINILEX_FAIL_CODING)
			goto nope;

		/* b7 = 0, end or 3-byte */
		if (lex[*ps] < LWS_MINILEX_FAIL_CODING) {
			/* this is a terminal marker */
			*match = (int)lex[++(*ps)];
			return LWS_MINILEX_MATCH;
		}

		if (lex[*ps] == c) { /* goto-on-match */
			*ps = (int16_t)(*ps + (lex[(*ps) + 1]) +
					      (lex[(*ps) + 2] << 8));
			return LWS_MINILEX_CONTINUE;
		}

		/* fall thru to next */
		*ps = (int16_t)((*ps) + 3);
	}

nope:
	*ps = (int16_t)-1;

	return LWS_MINILEX_FAIL;
}

unsigned int
lws_sigbits(uintptr_t u)
{
	uintptr_t mask = (uintptr_t)(0xffllu << ((sizeof(u) - 1) * 8)),
		  m1   = (uintptr_t)(0x80llu << ((sizeof(u) - 1) * 8));
	unsigned int n;

	for (n = sizeof(u) * 8; n > 0; n -= 8) {
		if (u & mask)
			break;
		mask >>= 8;
		m1 >>= 8;
	}

	if (!n)
		return 1; /* not bits are set, we need at least 1 to represent */

	while (!(u & m1)) {
		n--;
		m1 >>= 1;
	}

	return n;
}

const lws_fx_t *
lws_fx_add(lws_fx_t *r, const lws_fx_t *a, const lws_fx_t *b)
{
	int32_t w, sf;

	w = a->whole + b->whole;
	sf = a->frac + b->frac;
	if (sf >= 100000000) {
		w++;
		r->frac = sf - 100000000;
	} else if (sf < -100000000) {
		w--;
		r->frac = sf + 100000000;
	} else
		r->frac = sf;

	r->whole = w;

	return r;
}

const lws_fx_t *
lws_fx_sub(lws_fx_t *r, const lws_fx_t *a, const lws_fx_t *b)
{
	int32_t w;

	if (a->whole >= b->whole) {
		w = a->whole - b->whole;
		if (a->frac >= b->frac)
			r->frac = a->frac - b->frac;
		else {
			w--;
			r->frac = (100000000 + a->frac) - b->frac;
		}
	} else {
		w = -(b->whole - a->whole);
		if (b->frac >= a->frac)
			r->frac = b->frac - a->frac;
		else {
			w++;
			r->frac = (100000000 + b->frac) - a->frac;
		}
	}
	r->whole = w;

	return r;
}

const lws_fx_t *
lws_fx_mul(lws_fx_t *r, const lws_fx_t *a, const lws_fx_t *b)
{
	int64_t _c1, _c2;
	int32_t w, t;
	char neg = 0;

	assert(a->frac < LWS_FX_FRACTION_MSD);
	assert(b->frac < LWS_FX_FRACTION_MSD);

	/* we can't use r as a temp, because it may alias on to a, b */

	w = a->whole * b->whole;

	if (!lws_neg(a) && !lws_neg(b)) {
		_c2 = (((int64_t)((int64_t)a->frac) * (int64_t)b->frac) /
							LWS_FX_FRACTION_MSD);
		_c1 = ((int64_t)a->frac * ((int64_t)b->whole)) +
		        (((int64_t)a->whole) * (int64_t)b->frac) + _c2;
		w += (int32_t)(_c1 / LWS_FX_FRACTION_MSD);
	} else
		if (lws_neg(a) && !lws_neg(b)) {
			_c2 = (((int64_t)((int64_t)-a->frac) * (int64_t)b->frac) /
								LWS_FX_FRACTION_MSD);
			_c1 = ((int64_t)-a->frac * (-(int64_t)b->whole)) +
			       (((int64_t)a->whole) * (int64_t)b->frac) - _c2;
			w += (int32_t)(_c1 / LWS_FX_FRACTION_MSD);
			neg = 1;
		} else
			if (!lws_neg(a) && lws_neg(b)) {
				_c2 = (((int64_t)((int64_t)a->frac) * (int64_t)-b->frac) /
									LWS_FX_FRACTION_MSD);
				_c1 = ((int64_t)a->frac * ((int64_t)b->whole)) -
				       (((int64_t)a->whole) * (int64_t)-b->frac) - _c2;
				w += (int32_t)(_c1 / LWS_FX_FRACTION_MSD);
				neg = 1;
			} else {
				_c2 = (((int64_t)((int64_t)-a->frac) * (int64_t)-b->frac) /
									LWS_FX_FRACTION_MSD);
				_c1 = ((int64_t)-a->frac * ((int64_t)b->whole)) +
				       (((int64_t)a->whole) * (int64_t)-b->frac) - _c2;
				w -= (int32_t)(_c1 / LWS_FX_FRACTION_MSD);
			}

	t = (int32_t)(_c1 % LWS_FX_FRACTION_MSD);
	r->whole = w; /* don't need a,b any further... now we can write to r */
	if (neg ^ !!(t < 0))
		r->frac = -t;
	else
		r->frac = t;

	return r;
}

const lws_fx_t *
lws_fx_div(lws_fx_t *r, const lws_fx_t *a, const lws_fx_t *b)
{
	int64_t _a = lws_fix64_abs(a), _b = lws_fix64_abs(b), q = 0, d, m;

	if (!_b)
		_a = 0;
	else {
		int c = 64 / 2 + 1;

		while (_a && c >= 0) {
			d = _a / _b;
			m = (_a % _b);
			if (m < 0)
				m = -m;
			_a = m << 1;
			q += d << (c--);
		}
		_a = q >> 1;
	}

	if (lws_neg(a) ^ lws_neg(b)) {
		r->whole = -(int32_t)(_a >> 32);
		r->frac = -(int32_t)((100000000 * (_a & 0xffffffff)) >> 32);
	} else {
		r->whole = (int32_t)(_a >> 32);
		r->frac = (int32_t)((100000000 * (_a & 0xffffffff)) >> 32);
	}

	return r;
}

const lws_fx_t *
lws_fx_sqrt(lws_fx_t *r, const lws_fx_t *a)
{
	uint64_t t, q = 0, b = 1ull << 62, v = ((uint64_t)a->whole << 32) +
	    	 (((uint64_t)a->frac << 32) / LWS_FX_FRACTION_MSD);

	while (b > 0x40) {
		t = q + b;
		if (v >= t) {
			v -= t;
			q = t + b;
		}
		v <<= 1;
		b >>= 1;
	}

	r->whole = (int32_t)(q >> 48);
	r->frac = (int32_t)((((q >> 16) & 0xffffffff) *
					LWS_FX_FRACTION_MSD) >> 32);

	return r;
}

/* returns < 0 if a < b, >0 if a > b, or 0 if exactly equal */

int
lws_fx_comp(const lws_fx_t *a, const lws_fx_t *b)
{
	if (a->whole < b->whole)
		return -1;
	if (a->whole > b->whole)
                return 1;

	if (a->frac < b->frac)
		return -1;

	if (a->frac > b->frac)
		return 1;

	return 0;
}

int
lws_fx_roundup(const lws_fx_t *a)
{
	if (!a->frac)
		return a->whole;

	if (lws_neg(a))
		return a->whole - 1;

	return a->whole + 1;
}

LWS_VISIBLE LWS_EXTERN int
lws_fx_rounddown(const lws_fx_t *a)
{
	return a->whole;
}

LWS_VISIBLE LWS_EXTERN const char *
lws_fx_string(const lws_fx_t *a, char *buf, size_t size)
{
	int n, m = 7;

	if (lws_neg(a))
		n = lws_snprintf(buf, size - 1, "-%d.%08d",
				 (int)(a->whole < 0 ? -a->whole : a->whole),
				 (int)(a->frac < 0 ? -a->frac : a->frac));
	else
		n = lws_snprintf(buf, size - 1, "%d.%08d", (int)a->whole,
				 (int)a->frac);

	while (m-- && buf[n - 1] == '0')
		n--;

	buf[n] = '\0';

	return buf;
}
