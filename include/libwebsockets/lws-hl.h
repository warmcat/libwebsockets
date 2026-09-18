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
 * Streaming syntax highlighting tokenizer
 *
 * Hostile-input-hardened, alloc-free, streaming tokenizer for producing
 * syntax highlighting markup from arbitrary source text.  Input is fed in
 * fragments of any size (including 0 or 1 bytes); classified token pieces
 * are passed to a caller token sink callback.  A second layer provides a
 * stock token sink that emits strict-CSP-compatible HTML markup (entity-
 * escaped text wrapped in <span class=...>) through a caller write callback.
 *
 * The tokenizer never revises emitted decisions, never backtracks, and holds
 * O(1) state regardless of input; unterminated constructs at end of input are
 * closed out with a best-guess classification.
 */

#if !defined(LHL_SCRATCH_SIZE)
#define LHL_SCRATCH_SIZE		  40
#endif
#if !defined(LHL_PIECE_MAX)
#define LHL_PIECE_MAX			  96
#endif

/*! how the token piece is to be presented */
typedef enum {
	LHL_CLS_PLAIN,		/**< ws, operators, punctuation... unstyled */
	LHL_CLS_IDENT,		/**< non-keyword identifier */
	LHL_CLS_KEYWORD,	/**< language keyword */
	LHL_CLS_TYPE,		/**< builtin / well-known type name */
	LHL_CLS_NUMBER,		/**< numeric constant */
	LHL_CLS_STRING,		/**< string literal */
	LHL_CLS_CHARLIT,	/**< character literal */
	LHL_CLS_COMMENT,	/**< comment */
	LHL_CLS_PREPROC,	/**< preprocessor directive / header name */

	/* diff presentation (lines, including their newline) */

	LHL_CLS_DIFF_ADD,	/**< diff: added line */
	LHL_CLS_DIFF_REM,	/**< diff: removed line */
	LHL_CLS_DIFF_HUNK,	/**< diff: hunk header line */
	LHL_CLS_DIFF_META,	/**< diff: file header / metadata line */

	LHL_CLS_COUNT		/**< count of valid classes */
} lws_hl_class_t;

struct lws_hl_ctx;
typedef struct lws_hl_ctx lws_hl_ctx_t;

/**
 * lws_hl_token_cb() - token sink callback
 *
 * \param user: opaque pointer set at lws_hl_construct()
 * \param cls: the classification of the token piece
 * \param tok: the token piece bytes
 * \param len: the length of the token piece in bytes
 *
 * Token pieces are at most LHL_PIECE_MAX bytes; longer constructs are split
 * into consecutive pieces of the same class (which the stock HTML sink merges
 * into a single element).
 *
 * \p tok points either into the input fragment currently being parsed, or
 * into tokenizer private storage; it is only valid for the duration of the
 * callback.
 *
 * Return LWS_SRET_OK to continue, or a nonzero lws_stateful_ret_t (for
 * example LWS_SRET_WANT_OUTPUT) to stop parsing at this piece.  Parsing
 * resumes at the same piece on the next lws_hl_parse() call.
 */
typedef lws_stateful_ret_t (*lws_hl_token_cb)(void *user, lws_hl_class_t cls,
					      const uint8_t *tok, size_t len);

typedef struct lws_hl_ops {
	const char	*name;
	/**< language name */

	int		(*construct)(lws_hl_ctx_t *ctx);
	/**< initialize driver-private parts of ctx... optional, return
	 * nonzero to fail construction */

	lws_stateful_ret_t	(*parse)(lws_hl_ctx_t *ctx,
					  const uint8_t **buf, size_t *len);
	/**< consume bytes from *\p buf, adjusting them to reflect only what
	 * was consumed and emitted */

	lws_stateful_ret_t	(*finish)(lws_hl_ctx_t *ctx);
	/**< handle end of input: emit best-guess classification for anything
	 * pending; nonzero return means call it again later */
} lws_hl_ops_t;

/**
 * lws_hl_ctx_t:  highlighting tokenizer context
 *
 * The context is allocated by the caller (its size is known from this header)
 * and requires no heap.  Fields below \p user are private to the driver in
 * use and must not be touched.
 */
typedef struct lws_hl_ctx {
	const lws_hl_ops_t	*ops;
	lws_hl_token_cb		cb;
	void			*user;

	/* private below */

	const uint8_t		*chunk;		/* current input chunk base */
	size_t			pos;		/* scan cursor (offset in chunk) */
	size_t			tok;		/* current token start offset */
	size_t			epos;		/* emitted watermark offset */
	uint8_t			state;		/* driver private */
	uint8_t			scratch_pos;	/* driver private */
	uint8_t			flags;		/* driver private */
	uint8_t			tokcls;		/* driver private */
	uint8_t			scratch[LHL_SCRATCH_SIZE];
} lws_hl_ctx_t;

/**
 * lws_hl_construct() - prepare an lws_hl_ctx for use
 *
 * \param ctx: the highlighter context to prepare
 * \param lang: the language ops to use, eg, &lws_hl_lang_c
 * \param cb: the token sink callback
 * \param user: opaque pointer passed to the callbacks
 *
 * Prepares a caller-allocated context.  Returns 0 for OK, or nonzero if
 * \p lang or its required ops members are NULL, or the language construct
 * hook failed.
 */
LWS_VISIBLE LWS_EXTERN int
lws_hl_construct(lws_hl_ctx_t *ctx, const lws_hl_ops_t *lang,
		 lws_hl_token_cb cb, void *user);

/**
 * lws_hl_parse() - parse a chunk of source into classified token pieces
 *
 * \param ctx: the highlighter context
 * \param buf: pointer to pointer to the start of the chunk of source
 * \param len: pointer to the number of bytes of source available at *\p buf
 *
 * Parses as much of *\p buf as it can, emitting token pieces of at most
 * LHL_PIECE_MAX bytes to the token sink.  On return, *\p buf and *\p len are
 * adjusted to describe the input that has not yet been consumed-and-emitted;
 * when the token sink defers a piece (nonzero return from the sink), that
 * is where parsing will resume on the next call.
 *
 * Fragments may be of any size including zero or one byte; fragments need
 * not align to token boundaries.  If a decision about the final byte of a
 * fragment (for example a '/' that may start a comment) needs the next byte,
 * it is held and reconsumed on the next call... a call may consume nothing
 * but return LWS_SRET_OK for this reason; lws_hl_finish() resolves it.
 *
 * Returns LWS_SRET_OK if all input was consumed (keep calling with more
 * input, or call lws_hl_finish()); the nonzero return from the token sink if
 * it deferred a piece (call again later to resume); or LWS_SRET_FATAL on
 * bad arguments.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_hl_parse(lws_hl_ctx_t *ctx, const uint8_t **buf, size_t *len);

/**
 * lws_hl_finish() - signal end of input and close out pending state
 *
 * \param ctx: the highlighter context
 *
 * Must be called once after the last input fragment.  Constructs still open
 * at end of input (an unterminated string, comment, identifier...) are
 * emitted with their best-guess classification.  If the token sink defers,
 * the nonzero return is passed back and lws_hl_finish() must be called again.
 *
 * After a successful return the context is reset and may be reused for new
 * input.
 *
 * Returns LWS_SRET_OK, the nonzero return from the token sink, or
 * LWS_SRET_FATAL on bad arguments.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_hl_finish(lws_hl_ctx_t *ctx);

#if defined(LWS_WITH_HL_LANG_C)
/**
 * lws_hl_lang_c() - get the language ops for C
 *
 * Returns a pointer to a hostile-input-hardened C tokenizer that does not
 * attempt to track types or macros, and classifies unexpected input by
 * best guess.  Pass the result to lws_hl_construct().
 */
LWS_VISIBLE LWS_EXTERN const lws_hl_ops_t *
lws_hl_lang_c(void);
#endif

#if defined(LWS_WITH_HL_LANG_DIFF)
/**
 * lws_hl_lang_diff() - get the language ops for unified diff / git diff
 *
 * Returns a pointer to a diff tokenizer that only colours diff markup:
 * whole lines (including their newline) classified as added, removed,
 * hunk header or file metadata by their prefix, with everything else
 * plain.  It does not attempt to syntax-highlight the source inside the
 * diff.  Pass the result to lws_hl_construct().
 */
LWS_VISIBLE LWS_EXTERN const lws_hl_ops_t *
lws_hl_lang_diff(void);
#endif

#if !defined(LHL_HTML_BUF)
#define LHL_HTML_BUF			  832
#endif

typedef lws_stateful_ret_t (*lws_hl_write_cb)(void *user, const uint8_t *buf,
					      size_t len);

/**
 * lws_hl_html_t:  stock token sink producing CSP-safe inline markup
 *
 * The context is allocated by the caller (its size is known from this
 * header).  Pass lws_hl_html_token() as the lws_hl token callback with this
 * struct as the callback \p user pointer; token text is HTML-escaped and,
 * for classes with a non-NULL css class name, wrapped in
 * <span class="..."> ... </span> elements spanning consecutive same-class
 * pieces.
 */
typedef struct lws_hl_html {
	/* private */
	lws_hl_write_cb		wc;
	void			*user;
	const char * const	*cls;
	lws_hl_class_t		last;
	size_t			buflen;
	uint8_t			open;
	char			buf[LHL_HTML_BUF];
} lws_hl_html_t;

/**
 * lws_hl_html_construct() - prepare an html emit context
 *
 * \param h: the html emit context to prepare
 * \param wc: the output write callback
 * \param user: opaque pointer passed to \p wc
 * \param cls: NULL to use stock class names, or an array of LHL_CLS_COUNT
 * class name strings; NULL entries in the array are emitted unwrapped
 *
 * The class name table is not copied and must remain allocated until the
 * context is no longer used.
 *
 * Returns 0 for OK or nonzero on bad arguments.
 */
LWS_VISIBLE LWS_EXTERN int
lws_hl_html_construct(lws_hl_html_t *h, lws_hl_write_cb wc, void *user,
		      const char * const *cls);

/**
 * lws_hl_html_token() - token sink for lws_hl_parse() producing html markup
 *
 * \param user: pointer to the lws_hl_html_t
 * \param cls: the classification of the token piece
 * \param tok: the token piece bytes
 * \param len: the length of the token piece in bytes
 *
 * For each token piece, produces a single write callback call of the escaped
 * markup.  Because each piece is emitted atomically, a nonzero return from
 * the write callback safely defers the piece; the markup for the piece is
 * then retried, not duplicated.
 *
 * Returns LWS_SRET_OK, or the nonzero return from the write callback.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_hl_html_token(void *user, lws_hl_class_t cls, const uint8_t *tok,
		  size_t len);

/**
 * lws_hl_html_close() - close any dangling element after end of input
 *
 * \param h: the html emit context
 *
 * Call after lws_hl_finish() returned LWS_SRET_OK; closes a dangling
 * <span> if one is open.  Returns LWS_SRET_OK, or the nonzero return from
 * the write callback (in which case, call it again).
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_hl_html_close(lws_hl_html_t *h);

/**
 * lws_html_escape() - stream html-escaped text through a write callback
 *
 * \param wc: the output write callback
 * \param user: opaque pointer passed to \p wc
 * \param src: the bytes to escape
 * \param len: the number of bytes at \p src
 *
 * Escapes '<', '>' and '&' as html entities, and replaces NUL and other C0
 * control bytes other than TAB, LF and CR with U+FFFD.  Bytes >= 0x80 are
 * passed through unmodified, so the caller must serve the result with a
 * utf-8 charset declaration.
 *
 * The write callback should accept everything; a nonzero return aborts
 * escaping and is passed back (earlier writes may already have happened).
 *
 * Returns LWS_SRET_OK, or the nonzero return from the write callback.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_html_escape(lws_hl_write_cb wc, void *user, const uint8_t *src,
		size_t len);
