# lws-api-test-auth-dns-rrl

Fence for security-audit finding G-289: what the authoritative-DNS plugin
(`protocol-lws-auth-dns`) sends back over UDP is bounded, so it is of little
use as a reflector towards a spoofed source.  It also covers G-280's rule
that an answer that does not fit is sent truncated as the question alone,
never in part.

The test builds the plugin in statically, writes a zone `big.example` with a
20-RR TXT RRset (~2.3KB) into a per-run zone dir `zones-rrl/<pid>`, and runs
the plugin with `rrl-responses-per-second` 5, `rrl-burst` 5 and `rrl-slip` 2.

| step | what is sent | expected |
|------|--------------|----------|
| 1 | the TXT question over UDP with EDNS0 size 4096, and again without EDNS0 | at most 1232 / 512 bytes: the question alone with `TC` set (and the OPT for the EDNS0 one) |
| 2 | the same question over TCP | answered whole, all 20 RRs, no `TC` |
| 3 | 40 queries at once from 127.0.0.1 | only a few answered (the burst), about half of the rest as empty `TC` answers, the rest dropped |
| 4 | 3 queries from another prefix (::1, or 127.0.1.1 without IPv6) | all answered |

If neither second source address can be bound, step 4 is skipped with a
notice.  The test takes about a second.

## Commandline

| option | meaning |
|--------|---------|
| `-p PORT` | auth dns port (from `lws_get_free_port()`) |
