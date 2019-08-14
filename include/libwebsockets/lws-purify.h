/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

/*! \defgroup pur Sanitize / purify SQL and JSON helpers
 *
 * ##Sanitize / purify SQL and JSON helpers
 *
 * APIs for escaping untrusted JSON and SQL safely before use
 */
//@{

/**
 * lws_sql_purify() - like strncpy but with escaping for sql quotes
 *
 * \param escaped: output buffer
 * \param string: input buffer ('/0' terminated)
 * \param len: output buffer max length
 *
 * Because escaping expands the output string, it's not
 * possible to do it in-place, ie, with escaped == string
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_sql_purify(char *escaped, const char *string, int len);

/**
 * lws_json_purify() - like strncpy but with escaping for json chars
 *
 * \param escaped: output buffer
 * \param string: input buffer ('/0' terminated)
 * \param len: output buffer max length
 *
 * Because escaping expands the output string, it's not
 * possible to do it in-place, ie, with escaped == string
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_json_purify(char *escaped, const char *string, int len);

/**
 * lws_filename_purify_inplace() - replace scary filename chars with underscore
 *
 * \param filename: filename to be purified
 *
 * Replace scary characters in the filename (it should not be a path)
 * with underscore, so it's safe to use.
 */
LWS_VISIBLE LWS_EXTERN void
lws_filename_purify_inplace(char *filename);

LWS_VISIBLE LWS_EXTERN int
lws_plat_write_cert(struct lws_vhost *vhost, int is_key, int fd, void *buf,
			int len);
LWS_VISIBLE LWS_EXTERN int
lws_plat_write_file(const char *filename, void *buf, int len);

LWS_VISIBLE LWS_EXTERN int
lws_plat_read_file(const char *filename, void *buf, int len);

LWS_VISIBLE LWS_EXTERN int
lws_plat_recommended_rsa_bits(void);
///@}
