These are buildable test apps that run in CI to confirm correct api operation.

|name|tests|
---|---
api-test-lwsac|LWS Allocated Chunks api
api-test-lws_struct-json|Selftests for lws_struct JSON serialization and deserialization
api-test-lws_tokenize|Generic secure string tokenizer api
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
api-test-oversized-headers|A request whose headers don't fit the server's header table gets 431 "Oversized headers" over h1, h2 (prior knowledge and tls) and h3, and a normal one after it is served
api-test-ws-pmd-takeover|permessage-deflate context takeover in both directions for each client offer of server_ / client_no_context_takeover: each end resets only what the negotiation says, by role, and the server's reply carries every option it took on
api-test-ss-server-upgrade|Secure Streams server ws upgrade over h1 and h2: the accepted stream, not the server template stream, hears LWSSSCS_SERVER_UPGRADE and then carries the ws tx
