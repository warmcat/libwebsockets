/*
 * libwebsockets - Stateful urldecode for POST
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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

#include "core/private.h"

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
	MT_IGNORE3,
	MT_COMPLETED,
};

static const char * const mp_hdr[] = {
	"content-disposition: ",
	"content-type: ",
	"\x0d\x0a"
};

typedef int (*lws_urldecode_stateful_cb)(void *data,
		const char *name, char **buf, int len, int final);

struct lws_urldecode_stateful {
	char *out;
	void *data;
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

	unsigned int multipart_form_data:1;
	unsigned int inside_quote:1;
	unsigned int subname:1;
	unsigned int boundary_real_crlf:1;

	enum urldecode_stateful state;

	lws_urldecode_stateful_cb output;
};

static struct lws_urldecode_stateful *
lws_urldecode_s_create(struct lws *wsi, char *out, int out_len, void *data,
		       lws_urldecode_stateful_cb output)
{
	struct lws_urldecode_stateful *s = lws_zalloc(sizeof(*s),
						"stateful urldecode");
	char buf[200], *p;
	int m = 0;

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
	s->data = data;
	s->wsi = wsi;

	if (lws_hdr_copy(wsi, buf, sizeof(buf),
			 WSI_TOKEN_HTTP_CONTENT_TYPE) > 0) {
	/* multipart/form-data; boundary=----WebKitFormBoundarycc7YgAPEIHvgE9Bf */

		if (!strncmp(buf, "multipart/form-data", 19)) {
			s->multipart_form_data = 1;
			s->state = MT_LOOK_BOUND_IN;
			s->mp = 2;
			p = strstr(buf, "boundary=");
			if (p) {
				p += 9;
				s->mime_boundary[m++] = '\x0d';
				s->mime_boundary[m++] = '\x0a';
				s->mime_boundary[m++] = '-';
				s->mime_boundary[m++] = '-';
				while (m < (int)sizeof(s->mime_boundary) - 1 &&
				       *p && *p != ' ')
					s->mime_boundary[m++] = *p++;

				s->mime_boundary[m] = '\0';

				lwsl_info("boundary '%s'\n", s->mime_boundary);
			}
		}
	}

	return s;
}

static int
lws_urldecode_s_process(struct lws_urldecode_stateful *s, const char *in,
			int len)
{
	int n, m, hit = 0;
	char c, was_end = 0;

	while (len--) {
		if (s->pos == s->out_len - s->mp - 1) {
			if (s->output(s->data, s->name, &s->out, s->pos, 0))
				return -1;

			was_end = s->pos;
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
				s->name[s->pos] = '\0';
				if (s->output(s->data, s->name, &s->out,
					      s->pos, 1))
					return -1;
				s->pos = 0;
				s->state = US_IDLE;
				in++;
				continue;
			}
			if (s->pos >= (int)sizeof(s->name) - 1) {
				lwsl_notice("Name too long\n");
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
					      s->pos, 1))
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
			s->out[s->pos++] = s->sum | n;
			s->state = US_IDLE;
			break;


		/* states for multipart / mime style */

		case MT_LOOK_BOUND_IN:
retry_as_first:
			if (*in == s->mime_boundary[s->mp] &&
			    s->mime_boundary[s->mp]) {
				in++;
				s->mp++;
				if (!s->mime_boundary[s->mp]) {
					s->mp = 0;
					s->state = MT_IGNORE1;

					if (s->pos || was_end)
						if (s->output(s->data, s->name,
						      &s->out, s->pos, 1))
							return -1;

					s->pos = 0;

					s->content_disp[0] = '\0';
					s->name[0] = '\0';
					s->content_disp_filename[0] = '\0';
					s->boundary_real_crlf = 1;
				}
				continue;
			}
			if (s->mp) {
				n = 0;
				if (!s->boundary_real_crlf)
					n = 2;
				if (s->mp >= n) {
					memcpy(s->out + s->pos,
					       s->mime_boundary + n, s->mp - n);
					s->pos += s->mp;
					s->mp = 0;
					goto retry_as_first;
				}
			}

			s->out[s->pos++] = *in;
			in++;
			s->mp = 0;
			break;

		case MT_HNAME:
			m = 0;
			c =*in;
			if (c >= 'A' && c <= 'Z')
				c += 'a' - 'A';
			for (n = 0; n < (int)ARRAY_SIZE(mp_hdr); n++)
				if (c == mp_hdr[n][s->mp]) {
					m++;
					hit = n;
				}
			in++;
			if (!m) {
				s->mp = 0;
				continue;
			}

			s->mp++;
			if (m != 1)
				continue;

			if (mp_hdr[hit][s->mp])
				continue;

			s->mp = 0;
			s->temp[0] = '\0';
			s->subname = 0;

			if (hit == 2)
				s->state = MT_LOOK_BOUND_IN;
			else
				s->state += hit + 1;
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
				goto done;
			}
			if (*in == ';') {
				s->subname = 1;
				s->temp[0] = '\0';
				s->mp = 0;
				goto done;
			}

			if (*in == '\"') {
				s->inside_quote ^= 1;
				goto done;
			}

			if (s->subname) {
				if (*in == '=') {
					s->temp[s->mp] = '\0';
					s->subname = 0;
					s->mp = 0;
					goto done;
				}
				if (s->mp < (int)sizeof(s->temp) - 1 &&
				    (*in != ' ' || s->inside_quote))
					s->temp[s->mp++] = *in;
				goto done;
			}

			if (!s->temp[0]) {
				if (s->mp < (int)sizeof(s->content_disp) - 1)
					s->content_disp[s->mp++] = *in;
				s->content_disp[s->mp] = '\0';
				goto done;
			}

			if (!strcmp(s->temp, "name")) {
				if (s->mp < (int)sizeof(s->name) - 1)
					s->name[s->mp++] = *in;
				else
					s->mp = (int)sizeof(s->name) - 1;
				s->name[s->mp] = '\0';
				goto done;
			}

			if (!strcmp(s->temp, "filename")) {
				if (s->mp < (int)sizeof(s->content_disp_filename) - 1)
					s->content_disp_filename[s->mp++] = *in;
				s->content_disp_filename[s->mp] = '\0';
				goto done;
			}
done:
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
			if (*in == '-')
				s->state = MT_IGNORE3;
			in++;
			break;

		case MT_IGNORE2:
			s->mp = 0;
			if (*in == '\x0a')
				s->state = MT_HNAME;
			in++;
			break;

		case MT_IGNORE3:
			if (*in == '\x0d')
				s->state = MT_IGNORE1;
			if (*in == '-') {
				s->state = MT_COMPLETED;
				s->wsi->http.rx_content_remain = 0;
			}
			in++;
			break;
		case MT_COMPLETED:
			break;
		}
	}

	return 0;
}

static int
lws_urldecode_s_destroy(struct lws_urldecode_stateful *s)
{
	int ret = 0;

	if (s->state != US_IDLE)
		ret = -1;

	if (!ret)
		if (s->output(s->data, s->name, &s->out, s->pos, 1))
			ret = -1;

	lws_free(s);

	return ret;
}

struct lws_spa {
	struct lws_urldecode_stateful *s;
	lws_spa_fileupload_cb opt_cb;
	const char * const *param_names;
	int count_params;
	char **params;
	int *param_length;
	void *opt_data;

	char *storage;
	char *end;
	int max_storage;

	char finalized;
};

static int
lws_urldecode_spa_lookup(struct lws_spa *spa,
			 const char *name)
{
	int n;

	for (n = 0; n < spa->count_params; n++)
		if (!strcmp(spa->param_names[n], name))
			return n;

	return -1;
}

static int
lws_urldecode_spa_cb(void *data, const char *name, char **buf, int len,
		     int final)
{
	struct lws_spa *spa =
			(struct lws_spa *)data;
	int n;

	if (spa->s->content_disp_filename[0]) {
		if (spa->opt_cb) {
			n = spa->opt_cb(spa->opt_data, name,
					spa->s->content_disp_filename,
					*buf, len, final);

			if (n < 0)
				return -1;
		}
		return 0;
	}
	n = lws_urldecode_spa_lookup(spa, name);

	if (n == -1 || !len) /* unrecognized */
		return 0;

	if (!spa->params[n])
		spa->params[n] = *buf;

	if ((*buf) + len >= spa->end) {
		lwsl_notice("%s: exceeded storage\n", __func__);
		return -1;
	}

	spa->param_length[n] += len;

	/* move it on inside storage */
	(*buf) += len;
	*((*buf)++) = '\0';

	spa->s->out_len -= len + 1;

	return 0;
}

LWS_VISIBLE LWS_EXTERN struct lws_spa *
lws_spa_create(struct lws *wsi, const char * const *param_names,
			 int count_params, int max_storage,
			 lws_spa_fileupload_cb opt_cb, void *opt_data)
{
	struct lws_spa *spa = lws_zalloc(sizeof(*spa), "spa");

	if (!spa)
		return NULL;

	spa->param_names = param_names;
	spa->count_params = count_params;
	spa->max_storage = max_storage;
	spa->opt_cb = opt_cb;
	spa->opt_data = opt_data;

	spa->storage = lws_malloc(max_storage, "spa");
	if (!spa->storage)
		goto bail2;
	spa->end = spa->storage + max_storage - 1;

	spa->params = lws_zalloc(sizeof(char *) * count_params, "spa params");
	if (!spa->params)
		goto bail3;

	spa->s = lws_urldecode_s_create(wsi, spa->storage, max_storage, spa,
					lws_urldecode_spa_cb);
	if (!spa->s)
		goto bail4;

	spa->param_length = lws_zalloc(sizeof(int) * count_params,
					"spa param len");
	if (!spa->param_length)
		goto bail5;

	lwsl_info("%s: Created SPA %p\n", __func__, spa);

	return spa;

bail5:
	lws_urldecode_s_destroy(spa->s);
bail4:
	lws_free(spa->params);
bail3:
	lws_free(spa->storage);
bail2:
	lws_free(spa);

	return NULL;
}

LWS_VISIBLE LWS_EXTERN int
lws_spa_process(struct lws_spa *ludspa, const char *in, int len)
{
	if (!ludspa) {
		lwsl_err("%s: NULL spa\n", __func__);
		return -1;
	}
	/* we reject any junk after the last part arrived and we finalized */
	if (ludspa->finalized)
		return 0;

	return lws_urldecode_s_process(ludspa->s, in, len);
}

LWS_VISIBLE LWS_EXTERN int
lws_spa_get_length(struct lws_spa *ludspa, int n)
{
	if (n >= ludspa->count_params)
		return 0;

	return ludspa->param_length[n];
}

LWS_VISIBLE LWS_EXTERN const char *
lws_spa_get_string(struct lws_spa *ludspa, int n)
{
	if (n >= ludspa->count_params)
		return NULL;

	return ludspa->params[n];
}

LWS_VISIBLE LWS_EXTERN int
lws_spa_finalize(struct lws_spa *spa)
{
	if (spa->s) {
		lws_urldecode_s_destroy(spa->s);
		spa->s = NULL;
	}

	spa->finalized = 1;

	return 0;
}

LWS_VISIBLE LWS_EXTERN int
lws_spa_destroy(struct lws_spa *spa)
{
	int n = 0;

	lwsl_info("%s: destroy spa %p\n", __func__, spa);

	if (spa->s)
		lws_urldecode_s_destroy(spa->s);

	lwsl_debug("%s %p %p %p %p\n", __func__,
			spa->param_length,
			spa->params,
			spa->storage,
			spa);

	lws_free(spa->param_length);
	lws_free(spa->params);
	lws_free(spa->storage);
	lws_free(spa);

	return n;
}
