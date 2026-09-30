/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

#define LWS_MAX_ELEM_NAME 32

enum urldecode_stateful {
	US_NAME,
	US_IDLE,
	US_PC1,
	US_PC2,

	MT_LOOK_BOUND_IN,
	MT_HNAME,
	MT_DISP,
	MT_TYPE,
	MT_IGNORE1,
	MT_IGNORE2,
	MT_BOUND_TAIL,
	MT_BOUND_DASH,
	MT_COMPLETED,
};

static struct mp_hdr {
	const char * const	hdr;
	uint8_t			hdr_len;
} mp_hdrs[] = {
	{ "content-disposition: ", 21 },
	{ "content-type: ", 14 },
	{ "\x0d\x0a", 2 }
};

struct lws_spa;

typedef int (*lws_urldecode_stateful_cb)(struct lws_spa *spa,
		const char *name, char **buf, int len, int final);

struct lws_urldecode_stateful {
	char *out;
	struct lws_spa *data;
	struct lws *wsi;
	char name[LWS_MAX_ELEM_NAME];
	char temp[LWS_MAX_ELEM_NAME];
	char content_type[32];
	char content_disp[32];
	char content_disp_filename[256];
	char mime_boundary[128];
	int out_len;
	int pos;
	int hdr_idx;
	int mp;
	int sum;

	uint8_t matchable;

	uint8_t multipart_form_data:1;
	uint8_t inside_quote:1;
	uint8_t subname:1;
	uint8_t boundary_real_crlf:1;
	uint8_t disp_seen:1; /* this part had its Content-Disposition */

	enum urldecode_stateful state;

	lws_urldecode_stateful_cb output;
};

struct lws_spa {
	struct lws_urldecode_stateful *s;
	lws_spa_create_info_t i;
	int *param_length;
	char finalized;
	char **params;
	char *storage;
	char *end;
};

static struct lws_urldecode_stateful *
lws_urldecode_s_create(struct lws_spa *spa, struct lws *wsi, char *out,
		       int out_len, lws_urldecode_stateful_cb output)
{
	struct lws_urldecode_stateful *s;
	char buf[205], *p;
	int m = 0;

	if (spa->i.ac)
		s = lwsac_use_zero(spa->i.ac, sizeof(*s), spa->i.ac_chunk_size);
	else
		s = lws_zalloc(sizeof(*s), "stateful urldecode");

	if (!s)
		return NULL;

	s->out = out;
	s->out_len  = out_len;
	s->output = output;
	s->pos = 0;
	s->sum = 0;
	s->mp = 0;
	s->state = US_NAME;
	s->name[0] = '\0';
	s->data = spa;
	s->wsi = wsi;

	if (lws_hdr_copy(wsi, buf, sizeof(buf),
			 WSI_TOKEN_HTTP_CONTENT_TYPE) > 0) {
	/* multipart/form-data;
	 * boundary=----WebKitFormBoundarycc7YgAPEIHvgE9Bf */

		if (!strncmp(buf, "multipart/form-data", 19) ||
		    !strncmp(buf, "multipart/related", 17)) {
			s->multipart_form_data = 1;
			s->state = MT_LOOK_BOUND_IN;
			s->mp = 2;
			p = (char *)strstr(buf, "boundary=");
			if (p) {
				p += 9;
				s->mime_boundary[m++] = '\x0d';
				s->mime_boundary[m++] = '\x0a';
				s->mime_boundary[m++] = '-';
				s->mime_boundary[m++] = '-';
				if (*p == '\"')
					p++;
				while (m < (int)sizeof(s->mime_boundary) - 1 &&
				       *p && *p != ' ' && *p != ';' && *p != '\"')
					s->mime_boundary[m++] = *p++;
				s->mime_boundary[m] = '\0';

				// lwsl_notice("boundary '%s'\n", s->mime_boundary);
			}
		}
	}

	return s;
}

/*
 * Only in these states is there a value being collected at s->out, with
 * s->pos its length so far.  In US_NAME s->pos indexes s->name, and the
 * multipart header states hold nothing at s->out: a flush from there would
 * report bytes nobody wrote as a value.
 */

static int
lws_urldecode_s_collecting(const struct lws_urldecode_stateful *s)
{
	return s->state == US_IDLE || s->state == US_PC1 ||
	       s->state == US_PC2 || s->state == MT_LOOK_BOUND_IN;
}

/*
 * The close delimiter ends the form.  Where the request says how long its
 * body is (Content-Length, chunked, or on h2 / h3 the stream's END_STREAM),
 * only that says where the body ends: whatever follows the form is its
 * epilogue, still delivered, and so stepped over, by the connection's own
 * framing.  Ending the body here instead would leave the rest of the declared
 * body to be read as the next request.
 *
 * An h1 body with no framing at all (lws_client_http_body_pending() sends
 * one like that) has no end other than the close delimiter, so for that alone
 * the form ending is the body ending.
 */

static void
lws_urldecode_s_form_ended(struct lws_urldecode_stateful *s)
{
	struct lws *wsi = s->wsi;

	s->state = MT_COMPLETED;

	if (!wsi->mux_substream && !wsi->http.content_length_given &&
	    !wsi->http.rx_chunked)
		wsi->http.rx_content_remain = 0;
}

static int
lws_urldecode_s_process(struct lws_urldecode_stateful *s, const char *in,
			int len)
{
	int n, hit;
	char c;

	while (len--) {
		if (lws_urldecode_s_collecting(s) &&
		    s->pos >= s->out_len - s->mp - 1) {
			if (s->output(s->data, s->name, &s->out, s->pos,
				      LWS_UFS_CONTENT))
				return -1;

			s->pos = 0;
		}

		switch (s->state) {

		/* states for url arg style */

		case US_NAME:
			s->inside_quote = 0;
			if (*in == '=') {
				s->name[s->pos] = '\0';
				s->pos = 0;
				s->state = US_IDLE;
				in++;
				continue;
			}
			if (*in == '&') {
				/*
				 * A name with no '=' is the parameter with an
				 * empty value.  s->pos is the name's length
				 * here: nothing was written at s->out for it,
				 * so what it reports is a zero-length value.
				 * The next name follows directly.
				 */
				s->name[s->pos] = '\0';
				if (s->pos && s->output(s->data, s->name,
							&s->out, 0,
							LWS_UFS_FINAL_CONTENT))
					return -1;
				s->pos = 0;
				in++;
				continue;
			}
			if (s->pos >= (int)sizeof(s->name) - 1) {
				lwsl_hexdump_notice(s->name, (size_t)s->pos);
				lwsl_notice("Name too long...\n");
				return -1;
			}
			s->name[s->pos++] = *in++;
			break;
		case US_IDLE:
			if (*in == '%') {
				s->state++;
				in++;
				continue;
			}
			if (*in == '&') {
				s->out[s->pos] = '\0';
				if (s->output(s->data, s->name, &s->out,
					      s->pos, LWS_UFS_FINAL_CONTENT))
					return -1;
				s->pos = 0;
				s->state = US_NAME;
				in++;
				continue;
			}
			if (*in == '+') {
				in++;
				s->out[s->pos++] = ' ';
				continue;
			}
			s->out[s->pos++] = *in++;
			break;
		case US_PC1:
			n = char_to_hex(*in);
			if (n < 0)
				return -1;

			in++;
			s->sum = n << 4;
			s->state++;
			break;

		case US_PC2:
			n = char_to_hex(*in);
			if (n < 0)
				return -1;

			in++;
			s->out[s->pos++] = (char)(s->sum | n);
			s->state = US_IDLE;
			break;


		/* states for multipart / mime style */

		case MT_LOOK_BOUND_IN:
			while (s->mp) {
				if (*in == s->mime_boundary[s->mp] &&
				    s->mime_boundary[s->mp]) {
					break;
				}

				n = 0;
				if (!s->boundary_real_crlf)
					n = 2;
				if (s->mp >= n) {
					int extra = s->mp - n;
					int ext_pos = 0;

					while (extra) {
						int chunk;

						if (s->pos >= s->out_len - 1) {
							if (s->output(s->data, s->name,
								      &s->out, s->pos,
								      LWS_UFS_CONTENT))
								return -1;
							s->pos = 0;
							if (s->out_len <= 1)
								return -1;
						}

						chunk = extra;
						if (chunk > s->out_len - s->pos - 1)
							chunk = s->out_len - s->pos - 1;

						memcpy(s->out + s->pos,
						       s->mime_boundary + n + ext_pos,
						       (unsigned int)chunk);

						s->pos += chunk;
						ext_pos += chunk;
						extra -= chunk;
					}
					s->mp = 0;
					continue;
				}
				break;
			}

			if (*in == s->mime_boundary[s->mp] &&
			    s->mime_boundary[s->mp]) {
				in++;
				s->mp++;
				if (!s->mime_boundary[s->mp]) {
					s->mp = 0;
					s->state = MT_BOUND_TAIL;

					if (s->output(s->data, s->name,
						      &s->out, s->pos,
						      LWS_UFS_FINAL_CONTENT))
						return -1;

					s->pos = 0;

					s->content_disp[0] = '\0';
					s->name[0] = '\0';
					s->content_disp_filename[0] = '\0';
					s->boundary_real_crlf = 1;
					s->disp_seen = 0;
				}
				continue;
			}

			s->out[s->pos++] = *in;
			in++;
			s->mp = 0;
			break;

		case MT_HNAME:
			c =*in;
			if (c >= 'A' && c <= 'Z')
				c = (char)(c + 'a' - 'A');
			if (!s->mp)
				/* initially, any of them might match */
				s->matchable = (1 << LWS_ARRAY_SIZE(mp_hdrs)) - 1; 

			hit = -1;
			for (n = 0; n < (int)LWS_ARRAY_SIZE(mp_hdrs); n++) {

				if (!(s->matchable & (1 << n)))
					continue;
				/* this guy is still in contention... */

				if (s->mp >= mp_hdrs[n].hdr_len) {
					/* he went past the end of it */
					s->matchable &= (uint8_t)~(1 << n);
					continue;
				}

				if (c != mp_hdrs[n].hdr[s->mp]) {
					/* mismatched a char */
					s->matchable &= (uint8_t)~(1 << n);
					continue;
				}

				if (s->mp + 1 == mp_hdrs[n].hdr_len) {
					/* we have a winner... */
					hit = n;
					break;
				}
			}

			in++;
			if (hit == -1 && !s->matchable) {
				/* We ruled them all out */
				s->state = MT_IGNORE1;
				s->mp = 0;
				continue;
			}

			s->mp++;
			if (hit < 0)
				continue;

			/* we matched the one in hit */

			if (hit == 0) { /* content-disposition */
				/*
				 * A part has one Content-Disposition.  A
				 * second one would announce its file again
				 * (LWS_UFS_OPEN) with nothing to close the
				 * first
				 */
				if (s->disp_seen)
					return -1;
				s->disp_seen = 1;
			}

			s->mp = 0;
			s->temp[0] = '\0';
			s->subname = 0;

			if (hit == 2)
				s->state = MT_LOOK_BOUND_IN;
			else
				s->state += (unsigned int)hit + 1u;
			break;

		case MT_DISP:
			/* form-data; name="file"; filename="t.txt" */

			if (*in == '\x0d') {
				if (s->content_disp_filename[0])
					if (s->output(s->data, s->name,
						      &s->out, s->pos,
						      LWS_UFS_OPEN))
						return -1;
				s->state = MT_IGNORE2;
				goto done_l;
			}
			if (*in == ';') {
				s->subname = 1;
				s->temp[0] = '\0';
				s->mp = 0;
				goto done_l;
			}

			if (*in == '\"') {
				s->inside_quote = !!((s->inside_quote ^ 1) & 1);
				goto done_l;
			}

			if (s->subname) {
				if (*in == '=') {
					s->temp[s->mp] = '\0';
					s->subname = 0;
					s->mp = 0;
					goto done_l;
				}
				if (s->mp < (int)sizeof(s->temp) - 1 &&
				    (*in != ' ' || s->inside_quote))
					s->temp[s->mp++] = *in;
				goto done_l;
			}

			if (!s->temp[0]) {
				if (s->mp < (int)sizeof(s->content_disp) - 1)
					s->content_disp[s->mp++] = *in;
				if (s->mp < (int)sizeof(s->content_disp))
					s->content_disp[s->mp] = '\0';
				goto done_l;
			}

			if (!strcmp(s->temp, "name")) {
				if (s->mp < (int)sizeof(s->name) - 1)
					s->name[s->mp++] = *in;
				else
					s->mp = (int)sizeof(s->name) - 1;
				s->name[s->mp] = '\0';
				goto done_l;
			}

			if (!strcmp(s->temp, "filename")) {
				if (s->mp < (int)sizeof(s->content_disp_filename) - 1)
					s->content_disp_filename[s->mp++] = *in;
				s->content_disp_filename[s->mp] = '\0';
				goto done_l;
			}
done_l:
			in++;
			break;

		case MT_TYPE:
			if (*in == '\x0d')
				s->state = MT_IGNORE2;
			else {
				if (s->mp < (int)sizeof(s->content_type) - 1)
					s->content_type[s->mp++] = *in;
				s->content_type[s->mp] = '\0';
			}
			in++;
			break;

		case MT_IGNORE1:
			if (*in == '\x0d')
				s->state = MT_IGNORE2;
			in++;
			break;

		case MT_IGNORE2:
			s->mp = 0;
			if (*in == '\x0a')
				s->state = MT_HNAME;
			in++;
			break;

		/*
		 * Right after a boundary: "--" makes it the close delimiter,
		 * else the rest of the line (transport padding) is ignored up
		 * to its CRLF, and the next part's headers follow
		 */

		case MT_BOUND_TAIL:
			if (*in == '-')
				s->state = MT_BOUND_DASH;
			else
				s->state = *in == '\x0d' ? MT_IGNORE2 :
							   MT_IGNORE1;
			in++;
			break;

		case MT_BOUND_DASH:
			if (*in == '-')
				lws_urldecode_s_form_ended(s);
			else
				s->state = *in == '\x0d' ? MT_IGNORE2 :
							   MT_IGNORE1;
			in++;
			break;

		case MT_COMPLETED:
			/* the epilogue, if any: ignored */
			return 0;
		}
	}

	return 0;
}

static int
lws_urldecode_s_destroy(struct lws_spa *spa, struct lws_urldecode_stateful *s)
{
	int ret = 0;

	if (s->state == US_NAME && s->pos) {
		/* the body ended on a name with no '=': an empty value */
		s->name[s->pos] = '\0';
		s->pos = 0;
		s->state = US_IDLE;
	}

	if (s->state != US_IDLE)
		ret = -1;

	if (!ret)
		if (s->output(s->data, s->name, &s->out, s->pos,
			      LWS_UFS_FINAL_CONTENT))
			ret = -1;

	if (s->output(s->data, s->name, NULL, 0, LWS_UFS_CLOSE))
		return -1;

	if (!spa->i.ac)
		lws_free(s);

	return ret;
}

static int
lws_urldecode_spa_lookup(struct lws_spa *spa, const char *name)
{
	const char * const *pp = spa->i.param_names;
	int n;

	for (n = 0; n < spa->i.count_params; n++) {
		if (!*pp && !spa->i.param_names_stride && spa->i.ac) {
			unsigned int len = (unsigned int)strlen(name);
			char **ptr = (char**)spa->i.param_names;

			/* Use NULLs at end of list to dynamically create
			 * unknown entries */

			ptr[n] = lwsac_use(spa->i.ac, len + 1, spa->i.ac_chunk_size);
			if (!ptr[n])
				return -1;

			memcpy(ptr[n], name, len);
			ptr[n][len] = '\0';

			return n;
		}
		if (*pp && !strcmp(*pp, name))
			return n;

		if (spa->i.param_names_stride)
			pp = (const char * const *)(((char *)pp) + spa->i.param_names_stride);
		else
			pp++;
	}

	return -1;
}

static int
lws_urldecode_spa_cb(struct lws_spa *spa, const char *name, char **buf, int len,
		     int final)
{
	int n;

	if (final == LWS_UFS_CLOSE || spa->s->content_disp_filename[0]) {
		if (spa->i.opt_cb) {
			n = spa->i.opt_cb(spa->i.opt_data, name,
					spa->s->content_disp_filename,
					buf ? *buf : NULL, len, (enum lws_spa_fileupload_states)final);

			if (n < 0)
				return -1;
		}
		return 0;
	}
	/* a value with no name is not a parameter */
	if (!name[0])
		return 0;

	n = lws_urldecode_spa_lookup(spa, name);
	if (n == -1) /* unrecognized */
		return 0;

	/*
	 * A parameter that ends with nothing collected is present with an
	 * empty value: it gets "" if it has no value yet.  A zero-length
	 * flush that does not end the value adds nothing.
	 */
	if (!len && (final != LWS_UFS_FINAL_CONTENT || spa->params[n]))
		return 0;

	if (!spa->i.ac) {
		/*
		 * Refuse it before publishing it: the app reads params[n] as a
		 * C string once the spa is finalized, whether or not this
		 * failed, and it is not terminated until the '\0' below
		 */
		if ((*buf) + len >= spa->end) {
			lwsl_info("%s: exceeded storage\n", __func__);
			return -1;
		}

		if (!spa->params[n])
			spa->params[n] = *buf;

		/* move it on inside storage */
		(*buf) += len;
		*((*buf)++) = '\0';

		spa->s->out_len -= len + 1;
	} else {
		spa->params[n] = lwsac_use(spa->i.ac, (unsigned int)len + 1,
					   spa->i.ac_chunk_size);
		if (!spa->params[n])
			return -1;

		memcpy(spa->params[n], *buf, (unsigned int)len);
		spa->params[n][len] = '\0';
	}

	spa->param_length[n] += len;

	return 0;
}

struct lws_spa *
lws_spa_create_via_info(struct lws *wsi, const lws_spa_create_info_t *i)
{
	struct lws_spa *spa;

	if (i->ac)
		spa = lwsac_use_zero(i->ac, sizeof(*spa), i->ac_chunk_size);
	else
		spa = lws_zalloc(sizeof(*spa), "spa");

	if (!spa)
		return NULL;

	spa->i = *i;
	if (!spa->i.max_storage)
		spa->i.max_storage = 512;

	/*
	 * Zeroed: a value is only ever published over bytes the parser wrote,
	 * but if that ever slips, what shows is zeros, not old heap
	 */
	if (i->ac)
		spa->storage = lwsac_use_zero(i->ac,
					      (unsigned int)spa->i.max_storage,
					      i->ac_chunk_size);
	else
		spa->storage = lws_zalloc((unsigned int)spa->i.max_storage,
					  "spa");

	if (!spa->storage)
		goto bail2;

	spa->end = spa->storage + spa->i.max_storage - 1;

	if (i->count_params) {
		if (i->ac)
			spa->params = lwsac_use_zero(i->ac,
				sizeof(char *) * (unsigned int)i->count_params, i->ac_chunk_size);
		else
			spa->params = lws_zalloc(sizeof(char *) * (unsigned int)i->count_params,
					 "spa params");
		if (!spa->params)
			goto bail3;
	}

	spa->s = lws_urldecode_s_create(spa, wsi, spa->storage, spa->i.max_storage,
					lws_urldecode_spa_cb);
	if (!spa->s)
		goto bail4;

	if (i->count_params) {
		if (i->ac)
			spa->param_length = lwsac_use_zero(i->ac,
				sizeof(int) * (unsigned int)i->count_params, i->ac_chunk_size);
		else
			spa->param_length = lws_zalloc(sizeof(int) * (unsigned int)i->count_params,
						"spa param len");
		if (!spa->param_length)
			goto bail5;
	}

	// lwsl_notice("%s: Created SPA %p\n", __func__, spa);

	return spa;

bail5:
	lws_urldecode_s_destroy(spa, spa->s);
bail4:
	if (!i->ac)
		lws_free(spa->params);
bail3:
	if (!i->ac)
		lws_free(spa->storage);
bail2:
	if (!i->ac)
		lws_free(spa);

	if (i->ac)
		lwsac_free(i->ac);

	return NULL;
}

struct lws_spa *
lws_spa_create(struct lws *wsi, const char * const *param_names,
	       int count_params, int max_storage,
	       lws_spa_fileupload_cb opt_cb, void *opt_data)
{
	lws_spa_create_info_t i;

	memset(&i, 0, sizeof(i));
	i.count_params = count_params;
	i.max_storage = max_storage;
	i.opt_cb = opt_cb;
	i.opt_data = opt_data;
	i.param_names = param_names;

	return lws_spa_create_via_info(wsi, &i);
}

int
lws_spa_process(struct lws_spa *spa, const char *in, int len)
{
	if (!spa) {
		lwsl_err("%s: NULL spa\n", __func__);
		return -1;
	}
	/* we reject any junk after the last part arrived and we finalized */
	if (spa->finalized)
		return 0;

	return lws_urldecode_s_process(spa->s, in, len);
}

int
lws_spa_get_length(struct lws_spa *spa, int n)
{
	if (n >= spa->i.count_params)
		return 0;

	return spa->param_length[n];
}

const char *
lws_spa_get_string(struct lws_spa *spa, int n)
{
	if (n >= spa->i.count_params)
		return NULL;

	return spa->params[n];
}

int
lws_spa_finalize(struct lws_spa *spa)
{
	if (!spa)
		return 0;

	if (spa->s) {
		lws_urldecode_s_destroy(spa, spa->s);
		spa->s = NULL;
	}

	spa->finalized = 1;

	return 0;
}

int
lws_spa_destroy(struct lws_spa *spa)
{
	int n = 0;

	lwsl_info("%s: destroy spa %p\n", __func__, spa);

	if (spa->s)
		lws_urldecode_s_destroy(spa, spa->s);

	if (spa->i.ac)
		lwsac_free(spa->i.ac);
	else {
		lws_free(spa->param_length);
		lws_free(spa->params);
		lws_free(spa->storage);
		lws_free(spa);
	}

	return n;
}
