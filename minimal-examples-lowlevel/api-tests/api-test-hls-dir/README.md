# lws-api-test-hls-dir

Tests the HLS plugin's media directory listing and deletion.

It fences the F-059 fix in the media directory listing
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

Media that is not all there is in the fixture too: one still being
written, a matroska whose Segment runs past the end of the file, an mp4
with no `moov` and one whose `mdat` runs past the end.  They must be listed
as pending ("still arriving" / "incomplete") with no player link or
thumbnail, the index status must report them without building anything,
their playlist, segment and thumbnail requests must be refused, an rsync
style dotfile copy must not be listed, and a subdirectory something is
being copied into must survive the startup purge.

It then drives the delete endpoint, forwarding the login grant level the
way an `lws-login` gated proxy in front would (the vhost sets
`trust-login-headers`), and asserts:

 - a delete without the grant is refused (403) and the file stays;
 - media in a subdirectory is deleted by its path, and the subdirectory,
   stray non-media contents included, goes with it once nothing playable
   is left in it;
 - a name containing `:` `$` `%` is deleted as named.

Across the deletes it holds the listing's change feed (`events`) open: it
must first carry the generation the listing page was built with, and then a
different one once media was deleted.

With `LWS_WITH_STUB` the deletes are done by the plugin's privilege-separated
stub child, which is this executable re-run with `--lws-stub=lws-hls-stub`:
`main()` then only hosts the plugin for it, and it exits with its parent.

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
