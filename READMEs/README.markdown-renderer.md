# lws markdown renderer

`lws-md` is a streaming, hostile-input-hardened markdown renderer that
produces structured events rather than markup, with a stock sink that turns
the events into strict-CSP-compatible html.

It's aimed at cases like rendering repo readmes and blog posts in a git web
UI: the input is attacker-controlled bytes that merely claim to be markdown,
it may arrive in fragments of any size that need not align to lines, and raw
html in the markdown must never reach the output.

It follows the `lws-hl` design: the driver issues structural events from a
closed vocabulary (begin / end of heading, paragraph, blockquote, list,
table, code block...) plus data events (text, urls, image alt text, fence
info strings), and all markup synthesis belongs to the sink.  The stock html
sink entity-escapes every data byte, applies a url scheme policy, and, when
lws was built with `LWS_WITH_HL`, streams fenced code blocks whose info
string names a known language through the `lws-hl` tokenizer.

Design points:

 - **No markup channel from untrusted input**: markdown can only become
   data.  Html markup is issued solely by the stock sink from the closed
   event vocabulary, so there is nothing to defuse downstream.
 - **No heap**: the context is caller-allocated (its size is known from the
   public header, around `2 x LMD_LINE_MAX` bytes) and holds O(1) state.
 - **Restarts at any event**: if the sink defers an event, rendering stops
   there and resumes by re-issuing exactly that event; accepted events are
   never re-issued.  Transactions re-run deterministically against an
   accept watermark for this.
 - **Structure decided with one line of lookahead**: a pipe table header is
   only a header once the next line proves to be the separator row, so the
   candidate line is held in a side buffer until then.  Past the hold cap
   the decision is given up and the line is reclassified as paragraph text;
   giving up reclassifies, it never drops content.
 - **Degradation is fail-safe**: inputs beyond the documented caps (line
   length, quote and inline nesting depth, url length) render as escaped
   plain text or literal markers rather than failing or truncating.

## Api overview

```c
#include <libwebsockets.h>

lws_md_ctx_t	 ctx;	/* caller-allocated, ~2 x LMD_LINE_MAX bytes */
lws_md_html_t	 html;	/* caller-allocated stock html sink */

lws_md_html_construct(&html, my_write_cb, my_opaque,
		      my_url_resolver, my_resolver_opaque);

lws_md_construct(&ctx, lws_md_html_event, &html);

/* feed markdown in fragments of any size, from anywhere */
while (there_is_more_markdown) {
	r = lws_md_parse(&ctx, &buf, &len); /* buf/len adjusted to the
					       unconsumed remainder */
	if (r == LWS_SRET_WANT_OUTPUT) { ... space frees up ...; continue; }
}

while ((r = lws_md_finish(&ctx)) == LWS_SRET_WANT_OUTPUT)
	...;
```

Relative urls that carry no scheme are passed to the resolver callback for
rewriting (eg, to a git web ui path); schemes are matched
case-insensitively and only `http:`, `https:`, `mailto:`, fragment-only and
path-absolute urls survive, everything else (including `javascript:` in any
capitalization) is replaced with `#`.

## Coverage

The well-behaved readme / blog subset: headings, paragraphs, fenced and
indented code blocks, blockquotes (nested, capped), ordered and unordered
lists with indented continuation lines, pipe tables, rules, inline code,
emphasis, strong, links, images and autolinks.  Raw html and reference
links are not interpreted and render as text.

Fenced code info strings `c`, `h`, `cpp`, `cc`, `cxx`, `c++` and `hpp`
select the `lws-hl` C tokenizer and `diff` / `patch` the diff tokenizer;
anything else renders as escaped text.

## Testing

`test-apps/test-md.c` builds as `libwebsockets-test-md` and checks

 - golden html for the markdown subset, including hostile constructs
   (raw html, `javascript:` urls in any capitalization, control bytes,
   unterminated everything)
 - fragmentation invariance: identical html for the same input fragmented
   at random boundaries, including zero- and one-byte fragments
 - event sink flow control: deferring events at arbitrary points then
   resuming produces the same html
 - structural validation: tags from the closed set balance, void elements
   aside, and no raw markup from the input survives
 - degradation paths: deep quote nesting past the cap, and over-cap lines,
   preserve all content as escaped text
 - hostile pseudo-random garbage rounds through the stock html sink
 - the `lws-hl` bridge for fenced code with a known info string

