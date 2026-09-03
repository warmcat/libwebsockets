# lws-api-test-hls-dir

Fences the F-059 fix in the HLS plugin's media directory listing
(`lws_hls_serve_dir()` in `plugins/protocol_lws_hls/hls-dir.c`).

The listing used to be composed with the naive `p += snprintf(p, rem, ...)`
cursor pattern over a fixed 512-byte-per-entry estimate while interpolating
each untrusted (up to 255-char) media filename four times, unescaped:

 - with enough long filenames, a per-entry `snprintf` truncated, the cursor
   advanced past the heap allocation, the next `rem = size - used`
   underflowed to a huge `size_t`, and the following `snprintf` wrote
   unbounded past the buffer (heap OOB write);
 - quote / angle-bracket characters in filenames reached the page text and
   the single-quoted `href` / `data-file` attributes unescaped (stored XSS
   on the HLS origin).

The test folds the whole plugin in statically (the way test-sshd folds in
the sshd plugin), serves a fixture media dir containing the attack names
(`x'"><&.mp4`, `<svg onload=alert(1)>.mp4`, and 48 × 254-char names
that alone blow the old per-entry budget by ~18 KB), fetches the listing
with an in-process client, and asserts:

 - every entry made it into the listing, the declared content-length
   matches the body length, and the page tail is intact (nothing silently
   truncated, nothing written past the buffer);
 - HTML-significant characters in filenames appear only as entities
   (`&#39; &quot; &lt; &gt; &amp;`) in both text and attribute contexts.

## Build requirements

The lws build needs `LWS_WITH_JOSE=1` (the plugin's JWT grant check), and
the ffmpeg dev libraries the plugin requires must be discoverable via
pkg-config (`libavformat`, `libavcodec`, `libavutil`, `libswscale`,
`libswresample`).

The test creates its fixture directory under `/tmp` named after its pid,
and removes it again on exit.

## Running

The test is registered with ctest as `api-test-hls-dir`; it obtains a free
listen port at configure time and passes it via `-p`.

```
$ ctest -R api-test-hls-dir
```
