# lws syntax highlighting

`lws-hl` is a streaming, hostile-input-hardened syntax highlighting
tokenizer, with a stock sink that produces strict-CSP-compatible html markup.

It's aimed at cases like source rendering in a git web UI: the input is
attacker-controlled bytes that merely claim to be source code, it may arrive
in fragments of any size (including zero or one byte) that need not align to
token boundaries, and the output must be safely embeddable in an html page
without trusted javascript or inline styles.

Design points:

 - **No heap**: the context is caller-allocated (its size is known from the
   public header) and token pieces point either into the caller's input
   fragment or into fixed private storage.  Memory use is O(1) for any input.
 - **Never revises and never backtracks**: each classification is made
   byte-by-byte and emitted decisions are final.  Identifiers are classified
   from a table while they are short enough to be a keyword, and flushed as
   plain identifier pieces once they cannot be.
 - **Restartable at any byte**: if the token sink defers a piece (for example
   because the http write side is full), parsing stops at the start of that
   piece and resumes there later; deferred pieces are retried, never lost or
   duplicated.
 - **Failure is an option**: broken input is closed out with a deterministic
   best guess rather than an error.  An unterminated string ends at the
   newline, an unterminated block comment at end of input is a comment, and
   numbers use the C `pp-number` maximal munch rule so they can never fail.

## Api overview

```c
#include <libwebsockets/lws-hl.h>

lws_hl_ctx_t        ctx;    /* caller-allocated, zero heap */
lws_hl_class_t      cls;
lws_stateful_ret_t  r;

/* classify token pieces, or use lws_hl_html_token() from the stock sink */
lws_hl_token_cb     sink(void *user, lws_hl_class_t cls,
			 const uint8_t *tok, size_t len);

lws_hl_construct(&ctx, lws_hl_lang_c(), sink, my_opaque);

/* feed source in fragments of any size, from anywhere */
while (there_is_more_source) {
	r = lws_hl_parse(&ctx, &buf, &len); /* buf/len adjusted to the
					       unconsumed remainder */
	if (r == LWS_SRET_WANT_OUTPUT) { ... space frees up ...; continue; }
}

/* close out anything still open at end of input */
while ((r = lws_hl_finish(&ctx)) == LWS_SRET_WANT_OUTPUT)
	...;
```

`lws_hl_parse()` follows the `lws_lhp_parse()` convention: it consumes as
much of the input as it can, emitting classified token pieces of at most
`LHL_PIECE_MAX` bytes to the sink, and adjusts `buf` and `len` to describe
the input that has not yet been consumed-and-emitted.  If the sink defers a
piece, the nonzero return is passed back and the same call resumes at the
same piece later; this composes with http backpressure without buffering the
whole source.

A byte at the very end of a fragment may be held unconsumed while the
tokenizer waits for the byte that disambiguates it (a `/` that may start a
comment, a `.` that may start a number).  Such a call consumes nothing but
returns `LWS_SRET_OK`; `lws_hl_finish()` resolves any remainder.

The context resets itself after a successful `lws_hl_finish()` and can be
reused for new input.

### Token classes

Pieces are classified into `LHL_CLS_PLAIN`, `_IDENT`, `_KEYWORD`, `_TYPE`,
`_NUMBER`, `_STRING`, `_CHARLIT`, `_COMMENT`, `_PREPROC`, and, for diff
input, `_DIFF_ADD`, `_DIFF_REM`, `_DIFF_HUNK` and `_DIFF_META`.  Long
constructs are emitted as consecutive same-class pieces.

## The stock html sink

`lws_hl_html_t` implements a token sink that produces html, for use on pages
with a strict Content-Security-Policy:

```c
lws_hl_html_t        h;      /* caller-allocated */

int write(void *user, const uint8_t *buf, size_t len); /* your output */

lws_hl_html_construct(&h, write, user, NULL /* stock class names */);
lws_hl_construct(&ctx, lws_hl_lang_c(), lws_hl_html_token, &h);

...parse and finish as above...

lws_hl_html_close(&h);	/* closes any dangling element */
```

Token text is html-escaped (`<`, `>`, `&`; NUL and other C0 control bytes
other than TAB/LF/CR become `&#65533;`; bytes >= 0x80 pass through, so serve
the result with a utf-8 charset declaration) and wrapped in
`<span class="...">` elements that span consecutive same-class pieces.  The
default names are `hl-k` (keyword), `hl-t` (type), `hl-n` (number),
`hl-s` (string), `hl-ch` (charlit), `hl-cm` (comment), `hl-pp`
(preprocessor) and, for diff input, `hl-da` (added line), `hl-dr`
(removed line), `hl-dh` (hunk header) and `hl-dm` (file metadata); plain
and identifier classes are emitted unwrapped.  Pass your own table of
`LHL_CLS_COUNT` strings (NULL entries unwrapped) to
`lws_hl_html_construct()` to change them.

Each piece produces a single write callback call, so a deferred piece is
retried without partial-output duplication.

`lws_html_escape()` is also usable standalone for one-way escaping of
arbitrary bytes into html text.

## Language drivers

Language tokenizers are `lws_hl_ops_t` structs with `construct`, `parse` and
`finish` callbacks; `LWS_WITH_HL` builds the framework and stock html sink,
and drivers are individually selectable.

`LWS_WITH_HL_LANG_C` (default on) builds the C driver, which understands
keywords and common types, `pp-number` numerics, string and character
literals with escapes, line and block comments with line splices, `#`
directives (including `#include <...>` header names) and line-start rules
for `#`, without attempting to track macros or types.

`LWS_WITH_HL_LANG_DIFF` (default on) builds the unified diff / git diff
driver, which only colours diff markup: whole lines, including their
newline, are classified by prefix as added (`+`), removed (`-`), hunk
header (`@@`) or file metadata (`diff`, `index`, `+++`/`---`, and the
rename/mode/similarity words; also `\ No newline at end of file`), with
everything else, including context lines, plain.  `+++` and `---` file
headers are distinguished from added or removed lines whose content itself
starts with those markers.  It does not attempt to syntax-highlight the
source inside the diff; because the newline belongs to the line's token,
consecutive same-side lines share one element in the html output.

Additional drivers are expected as separate `LWS_WITH_HL_LANG_x`.

## Testing

`test-apps/test-hl.c` builds as `libwebsockets-test-hl` and checks

 - golden token streams for tricky C and diff constructs
 - fragmentation invariance: identical token streams for the same input
   fragmented at random boundaries, including zero- and one-byte fragments
 - token sink flow control: deferring pieces at arbitrary points then
   resuming produces the same stream
 - byte conservation: every input byte is classified into exactly one token
   piece, including for pseudo-random hostile garbage, for every built
   language driver
 - html emitter escaping and span balance
