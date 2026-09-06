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
lws_sql_purify(char *escaped, const char *string, size_t len);

/**
 * lws_sql_purify_len() - return length of purified version of input string
 *
 * \param p: input buffer ('/0' terminated)
 *
 * Calculates any character escaping without writing it anywhere and returns the
 * calculated length of the purified string.
 */
int
lws_sql_purify_len(const char *p);

/**
 * lws_json_purify() - like strncpy but with escaping for json chars
 *
 * \param escaped: output buffer
 * \param string: input buffer ('/0' terminated)
 * \param len: output buffer max length
 * \param in_used: NULL, or pointer to input cap on entry and the number of
 *		   bytes of string we could escape in len on output
 *
 * Because escaping expands the output string, it's not
 * possible to do it in-place, ie, with escaped == string
 *
 * If \p in_used is non-NULL, then on entry a positive value is taken as a cap
 * on the number of bytes of \p string that may be processed; this allows
 * processing non-NUL-terminated data like blobs in bounded chunks.  A zero or
 * negative value on entry means no cap.  On return, it's set to the number of
 * input bytes that were actually processed.
 *
 * Escaped output is always truncated on an escape boundary, so the output is
 * always syntactically valid however small \p len is.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_json_purify(char *escaped, const char *string, int len, int *in_used);

/**
 * lws_json_purify_flags() - lws_json_purify() with additional options
 *
 * \param escaped: output buffer
 * \param string: input buffer ('/0' terminated)
 * \param len: output buffer max length
 * \param in_used: NULL, or pointer to input cap on entry and the number of
 *		   bytes of string we could escape in len on output
 * \param flags: OR of LWS_JSON_PURIFY_FLAG_*
 *
 * Performs the same job as lws_json_purify() with extra behaviours selected
 * using \p flags.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_json_purify_flags(char *escaped, const char *string, int len, int *in_used,
		      int flags);

/*
 * Also escape chars that, while legal in JSON strings, would be interpreted
 * as markup if the JSON is inlined into an HTML page.  Use this if the JSON
 * output ends up embedded in HTML, eg, inside a <div> rather than fetched
 * over XHR.
 */
#define LWS_JSON_PURIFY_FLAG_HTML_SAFE 1

/**
 * lws_json_purify_len() - find out the escaped length of a string
 *
 * \param string: input buffer ('/0' terminated)
 *
 * JSON may have to expand escapes by up to 6x the original depending on what
 * it is.  This doesn't actually do the escaping but goes through the motions
 * and computes the length of the escaped string.
 */
LWS_VISIBLE LWS_EXTERN int
lws_json_purify_len(const char *string);

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
			size_t len);
LWS_VISIBLE LWS_EXTERN int
lws_plat_write_file(const char *filename, void *buf, size_t len);

LWS_VISIBLE LWS_EXTERN int
lws_plat_read_file(const char *filename, void *buf, size_t len);

LWS_VISIBLE LWS_EXTERN int
lws_plat_recommended_rsa_bits(void);
///@}
