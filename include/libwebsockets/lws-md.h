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
 * Streaming markdown to structured events renderer
 *
 * Hostile-input-hardened, alloc-free, streaming renderer for the well-behaved
 * markdown subset used by readme and blog content: headings, paragraphs,
 * fenced and indented code blocks, blockquotes, lists, pipe tables, rules,
 * inline code / emphasis / strong, links, images and autolinks.
 *
 * Markdown input is never passed through as markup: the driver only issues
 * structural events from a closed vocabulary plus data events for text, urls,
 * image alt text and fence info strings.  All markup synthesis and all
 * security decisions about data bytes belong to the sink; the stock html sink
 * (lws_md_html_t) entity-escapes everything and applies a url scheme policy,
 * producing strict-CSP-compatible output with no inline styles or scripts.
 *
 * Structure that cannot be decided without a line of lookahead (is this the
 * table header row?) is held in a side buffer and the decision deferred until
 * the start of the next line; giving up on the decision past the hold cap
 * reclassifies the held line as text, it never drops content.
 */

#if !defined(LMD_LINE_MAX)
#define LMD_LINE_MAX			  8192
#endif
#if !defined(LMD_HOLD_MAX)
#define LMD_HOLD_MAX			  LMD_LINE_MAX
#endif
#if !defined(LMD_INFO_MAX)
#define LMD_INFO_MAX			  32
#endif
#if !defined(LMD_NEST_MAX)
#define LMD_NEST_MAX			  24
#endif
#if !defined(LMD_TEXT_PIECE)
#define LMD_TEXT_PIECE			  256
#endif

/*! structural elements the driver can open and close */
typedef enum {
	LMD_EL_NONE,		/**< unused */

	LMD_EL_H,		/**< heading; BEGIN aux = level 1..6 */
	LMD_EL_P,		/**< paragraph */
	LMD_EL_BQ,		/**< blockquote; nestable, one per level */
	LMD_EL_UL,		/**< unordered list */
	LMD_EL_OL,		/**< ordered list */
	LMD_EL_LI,		/**< list item */
	LMD_EL_TABLE,		/**< pipe table */
	LMD_EL_TR,		/**< table row */
	LMD_EL_CELL,		/**< table cell; BEGIN aux bit 0 = header cell */
	LMD_EL_HR,		/**< horizontal rule */
	LMD_EL_CODE,		/**< fenced code block; INFO datum first */

	/* inline */

	LMD_EL_EM,		/**< emphasis */
	LMD_EL_STRONG,		/**< strong emphasis */
	LMD_EL_CS,		/**< inline code span */
	LMD_EL_A,		/**< link; URL datum before the text */
	LMD_EL_IMG,		/**< image; URL datum then ALT datum */
} lws_md_el_t;

/*! event kinds issued to the sink */
typedef enum {
	LMD_EV_TEXT = 1,	/**< data = text bytes, escaped by the sink */
	LMD_EV_URL,		/**< data = url datum for the open A / IMG */
	LMD_EV_ALT,		/**< data = alt text datum for the open IMG */
	LMD_EV_INFO,		/**< data = fence info string, after BEGIN CODE */
	LMD_EV_BEGIN,		/**< aux = lws_md_el_t (+ level / header bit) */
	LMD_EV_END,		/**< aux = lws_md_el_t */
} lws_md_ev_t;

/**
 * lws_md_ev_cb() - markdown event sink callback
 *
 * \param user: opaque pointer set at lws_md_construct()
 * \param ev: the event kind
 * \param el: the element for LMD_EV_BEGIN / LMD_EV_END
 * \param aux: for LMD_EL_H, the heading level 1..6; for LMD_EL_CELL, bit 0
 *	       marks a header cell
 * \param data: the datum bytes for the data events, else NULL
 * \param len: the number of datum bytes at \p data
 *
 * Text, url, alt and info data are passed in pieces of at most
 * LMD_TEXT_PIECE bytes.  Ordering obligations: LMD_EV_INFO only appears
 * between BEGIN CODE and its first LMD_EV_TEXT; LMD_EV_URL only appears
 * after BEGIN A / BEGIN IMG and before the element text or END.
 *
 * Return LWS_SRET_OK to continue, or a nonzero lws_stateful_ret_t (for
 * example LWS_SRET_WANT_OUTPUT) to stop rendering at this event.  Rendering
 * resumes by re-issuing the same event on the next lws_md_parse() /
 * lws_md_finish() call; accepted events are never re-issued.
 */
typedef lws_stateful_ret_t (*lws_md_ev_cb)(void *user, lws_md_ev_t ev,
					   lws_md_el_t el, unsigned int aux,
					   const uint8_t *data, size_t len);

/**
 * lws_md_ctx_t:  markdown renderer context
 *
 * The context is allocated by the caller (its size is known from this header
 * and is around 2 x LMD_LINE_MAX bytes) and requires no heap.  Fields below
 * \p user are private.
 */
typedef struct lws_md_ctx {
	lws_md_ev_cb		cb;
	void			*user;

	/* private below */

	uint32_t		evseq;	/* issue index within the txn in flight */
	uint32_t		evdone;	/* watermark of accepted events */

	uint8_t			txn;	/* 0 idle, 1 line, 2 hold flush, 3 finish */
	uint8_t			in_link;/* inside link text: no nested links */

	uint8_t			para;	/* paragraph open */
	uint8_t			list;	/* 0 none, else LMD_EL_UL / _OL */
	uint8_t			li;	/* inside a list item */
	uint8_t			table;	/* inside a table */
	uint8_t			hold;	/* line held for table decision */
	uint8_t			bq;	/* open blockquote depth */
	uint8_t			code_ind;/* inside an indented code block */

	uint8_t			fence;	/* inside a fenced code block */
	uint8_t			fchr;	/* the fence character */
	uint8_t			flen;	/* the opening fence length */
	uint8_t			fmatch;	/* fence chars matched at line start */
	uint8_t			fbol;	/* at start of a fence body line */
	uint8_t			fclose;	/* swallowing a closing fence line */
	uint8_t			fq;	/* quote markers seen on this body line */
	uint8_t			fqsp;	/* after a marker: optional space next */

	uint8_t			over;	/* past the cap, streaming a line */

	uint8_t			fin_n;	/* finish: closers remaining */
	uint8_t			fin_list[3 + 2 * LMD_NEST_MAX];

	uint32_t		llen;	/* staged line length */
	uint32_t		hlen;	/* held line length */

	uint32_t		infolen;
	char			info[LMD_INFO_MAX];

	char			line[LMD_LINE_MAX];
	char			holdb[LMD_HOLD_MAX];
} lws_md_ctx_t;

/**
 * lws_md_construct() - prepare an lws_md_ctx for use
 *
 * \param ctx: the markdown context to prepare
 * \param cb: the event sink callback
 * \param user: opaque pointer passed to the callback
 *
 * Prepares a caller-allocated context.  Returns 0 for OK or nonzero on bad
 * arguments.
 */
LWS_VISIBLE LWS_EXTERN int
lws_md_construct(lws_md_ctx_t *ctx, lws_md_ev_cb cb, void *user);

/**
 * lws_md_parse() - render a chunk of markdown to events
 *
 * \param ctx: the markdown context
 * \param buf: pointer to pointer to the start of the chunk
 * \param len: pointer to the number of bytes available at *\p buf
 *
 * Consumes as much of *\p buf as it can, issuing events to the sink.
 * Fragments may be of any size including zero or one byte; line content is
 * staged in the context so fragments need not align to lines.  On return,
 * *\p buf and *\p len are adjusted to describe the input that has not yet
 * been consumed-and-emitted.
 *
 * Returns LWS_SRET_OK if all input was consumed (keep calling with more
 * input, or call lws_md_finish()); the nonzero return from the event sink if
 * it deferred an event (call again later, with the same unconsumed input, to
 * resume); or LWS_SRET_FATAL on bad arguments.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_md_parse(lws_md_ctx_t *ctx, const uint8_t **buf, size_t *len);

/**
 * lws_md_finish() - signal end of input and close out open structure
 *
 * \param ctx: the markdown context
 *
 * Must be called once after the last input fragment.  Any staged or held
 * line is rendered, open fences, lists, tables, paragraphs and blockquotes
 * are closed, and best-guess events are issued for constructs left
 * unterminated by the end of input.  If the event sink defers, the nonzero
 * return is passed back and lws_md_finish() must be called again.
 *
 * After a successful return the context is reset and may be reused for new
 * input.
 *
 * Returns LWS_SRET_OK, the nonzero return from the event sink, or
 * LWS_SRET_FATAL on bad arguments.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_md_finish(lws_md_ctx_t *ctx);

#if !defined(LMD_URL_MAX)
#define LMD_URL_MAX			  768
#endif
#if !defined(LMD_HTML_BUF)
#define LMD_HTML_BUF			  4096
#endif

typedef lws_stateful_ret_t (*lws_md_write_cb)(void *user, const uint8_t *buf,
					      size_t len);

/**
 * lws_md_resolve_cb() - repo-relative url resolver callback
 *
 * \param user: opaque pointer set at lws_md_html_construct()
 * \param is_image: nonzero if the url is for an image
 * \param url: the relative url bytes from the markdown
 * \param len: the number of bytes at \p url
 * \param dest: buffer to write the resolved url into
 * \param dest_len: bytes available at \p dest
 *
 * The stock html sink gives relative urls to the resolver for rewriting (eg,
 * to a git web ui path).  Return the number of bytes written to \p dest, or
 * 0 to leave the url as it appeared in the markdown.
 */
typedef size_t (*lws_md_resolve_cb)(void *user, int is_image,
				    const char *url, size_t len,
				    char *dest, size_t dest_len);

#if defined(LWS_WITH_HL)
#include "lws-hl.h"
#endif

/**
 * lws_md_html_t:  stock event sink producing CSP-safe html markup
 *
 * The context is allocated by the caller (its size is known from this
 * header).  Pass lws_md_html_event() as the lws_md event callback with this
 * struct as the callback \p user pointer.  Text, alt text and fence content
 * are entity-escaped, urls are restricted to http(s), mailto, fragments,
 * absolute paths and resolver output, and each event's markup is emitted
 * atomically through the write callback so deferred events are retried
 * without loss or duplication.
 *
 * When lws was built with LWS_WITH_HL, fenced code blocks whose info string
 * names a known language are streamed through the lws-hl tokenizer, so
 * fenced code in readmes is highlighted exactly like the file views.
 */
typedef struct lws_md_html {
	/* private */
	lws_md_write_cb		wc;
	void			*user;
	lws_md_resolve_cb	resolve;
	void			*resolve_user;

#if defined(LWS_WITH_HL)
	lws_hl_ctx_t		hlctx;
	lws_hl_html_t		hlhtml;
	uint8_t			hl_on;	/* bridging a fenced code block */
	uint8_t			hl_fin; /* hl finish issued */
	uint8_t			hl_closed;
	uint8_t			hl_hold; /* a byte held for the tokenizer */
	uint8_t			hl_holdb;
	size_t			hl_off;	/* fed offset into current TEXT */
#endif

	char			url[LMD_URL_MAX];
	size_t			url_len;
	uint8_t			url_over;	/* url too long: emitted as # */
	uint8_t			pending;	/* 0 none, 1 A, 2 IMG */
	uint8_t			a_open;		/* the <a...> tag flushed */
	uint8_t			alt_open;	/* inside the img alt attr */
	uint8_t			code_open;	/* inside a fence */
	uint8_t			pre_done;	/* the <pre><code> flushed */
	char			info[LMD_INFO_MAX];
	uint8_t			infolen;

	char			buf[LMD_HTML_BUF];
	size_t			buflen;
} lws_md_html_t;

/**
 * lws_md_html_construct() - prepare an html emit context
 *
 * \param h: the html emit context to prepare
 * \param wc: the output write callback
 * \param user: opaque pointer passed to \p wc
 * \param resolve: relative url resolver, or NULL to pass relative urls
 *		 through unmodified
 * \param resolve_user: opaque pointer passed to \p resolve
 *
 * Returns 0 for OK or nonzero on bad arguments.
 */
LWS_VISIBLE LWS_EXTERN int
lws_md_html_construct(lws_md_html_t *h, lws_md_write_cb wc, void *user,
		      lws_md_resolve_cb resolve, void *resolve_user);

/**
 * lws_md_html_event() - event sink for lws_md_parse() producing html markup
 *
 * \param user: pointer to the lws_md_html_t
 * \param ev: the event kind
 * \param el: the element for begin / end events
 * \param aux: heading level or header-cell flag
 * \param data: the datum bytes for data events
 * \param len: the number of datum bytes
 *
 * Emits each event's markup as a single write callback call where possible,
 * so a nonzero return from the write callback defers the event and it is
 * retried whole.  Returns LWS_SRET_OK, or the nonzero return from the write
 * callback.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_md_html_event(void *user, lws_md_ev_t ev, lws_md_el_t el,
		  unsigned int aux, const uint8_t *data, size_t len);

/**
 * lws_md_html_close() - close anything dangling after end of input
 *
 * \param h: the html emit context
 *
 * Call after lws_md_finish() returned LWS_SRET_OK; the driver closes
 * well-formed structure itself, so this only needs to act on malformed
 * event sequences.  Returns LWS_SRET_OK, or the nonzero return from the
 * write callback (in which case, call it again).
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_md_html_close(lws_md_html_t *h);
