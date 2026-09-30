These are buildable test apps that run in CI to confirm correct api operation.

|name|tests|
---|---
api-test-lwsac|LWS Allocated Chunks api
api-test-lws_struct-json|Selftests for lws_struct JSON serialization and deserialization
api-test-lws_tokenize|Generic secure string tokenizer api
api-test-stdin-cmdline|stdin folded into the commandline by `lws_system_adopt_stdin(cx, LWS_SAS_FLAG__APPEND_COMMANDLINE)`: a last token with no trailing newline resolves as a complete string, as a --switch=value, a bare --switch, a spaced value or a non-switch arg
api-test-region|Scratch buffer region ownership tracking: claims, overlaps, trims, hand-overs and stale handles
api-test-sansio-link|The sansIO half linked alone, with every unresolved symbol an error (`-DLWS_WITH_SANSIO_LINK_TEST=1`), loads and runs
api-test-random-prng|Fault injection's seeded PRNG in place of the platform random source: same seed, same bytes, a known vector, independent of other faults (`-DLWS_WITH_SYS_FAULT_INJECTION=1`)
api-test-fts|LWS Full-text Search api
api-test-gencrypto|LWS Generic Crypto apis
api-test-jose|LWS JOSE apis
api-test-dnssec-monitor-reissue|dnssec-monitor proxy's per-cert "Force reissue": answered locally, reaches LWSSMDCL_CERTS as the documented message, non-DNS names and fqdns outside the domain refused
api-test-dht-msg-parse|DHT RPC wire message parser, incl. hash token charset and NOTIFY domain-name gates
api-test-auth-dns-dnsbl|auth-dns plugin DNSBL pending-query lifetimes (F-054): late resolver replies and client disconnects vs the 5s dnsbl timeout
api-test-auth-dns-zonedir|auth-dns plugin local zone-dir trust policy (F-055): missing pvo / world-writable / symlinked dirs and foreign-uid or wrong-shape zone files refused
api-test-sshd-userauth|sshd plugin USERAUTH pubkey/sig blob walks (F-056): malformed blobs must be rejected bounded, genuine signatures still authenticate
api-test-sspc-streamtype|serialized client streamtype length cap (F-057): over-long streamtypes refused at sspc create, boundary-length still accepted
api-test-mqtt-unsub|mqtt subscribe/unsubscribe topic count cap (F-058): over-wide or zero topic lists loudly refused at the established-state tx paths, boundary-width unsubscribe still works end-to-end
api-test-http-attack|Hostile requests (what scripts/attack.sh did, h1 smuggling and slow headers, h2 framing / hpack / flood abuse, traversal out of a file mount) over h1, h2 and h3 are refused, and the server still serves after each
api-test-mtls|A vhost requiring a valid client cert refuses no cert and a cert its CA did not sign, and serves one it did, over h1 and h2 over tls and h3 over quic on the same port
api-test-tls-sessions|The client tls session cache keys sessions by an exact vhost / host / port tag: a host name too long for the tag is not cached, rather than cached under a truncated tag a look-alike host would find
api-test-oversized-headers|A request whose headers don't fit the server's header table gets 431 "Oversized headers" over h1, h2 (prior knowledge and tls) and h3, and a normal one after it is served
api-test-ws-pmd-takeover|permessage-deflate context takeover in both directions for each client offer of server_ / client_no_context_takeover: each end resets only what the negotiation says, by role, and the server's reply carries every option it took on
api-test-ss-server-upgrade|Secure Streams server ws upgrade over h1 and h2: the accepted stream, not the server template stream, hears LWSSSCS_SERVER_UPGRADE and then carries the ws tx
api-test-ss-server-accept|Secure Streams server accepted streams are destroyed with their connection, whatever the peer did: tcp connect and close, a partial h1 request, whole h1 and h2 transactions (the h2 network connection's own accepted stream too), and the user code refusing one in LWSSSCS_CREATING over tls, plaintext, raw and h2
api-test-ss-sink|Creating a Secure Stream of a local sink streamtype with no sink, or one the sink refuses at LWSSSCS_SINK_JOIN or from the accepted sink stream's CREATING / CONNECTED, fails cleanly with nothing left; an accepted one goes when its source does
api-test-ss-policy|A rejected Secure Streams JSON policy, fetched or as an overlay, is torn down cleanly and leaves the policy in force alone; a valid one still parses after it
api-test-smtp-client|The sansIO SMTP session byte for byte, then lws_smtpc end to end against a fake relay: plaintext, implicit tls and STARTTLS, refusals, deferrals, timeouts, and clients and vhosts destroyed with mail queued (`-DLWS_WITH_EMAIL=1`)
api-test-webtransport|A WebTransport client opens its session with an h3 peer whose SETTINGS enable WebTransport and HTTP Datagrams, and refuses without sending the CONNECT when the peer's SETTINGS do not (that case needs `-DLWS_WITH_SYS_FAULT_INJECTION=1`)
