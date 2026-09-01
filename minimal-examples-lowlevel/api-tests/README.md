These are buildable test apps that run in CI to confirm correct api operation.

|name|tests|
---|---
api-test-lwsac|LWS Allocated Chunks api
api-test-lws_struct-json|Selftests for lws_struct JSON serialization and deserialization
api-test-lws_tokenize|Generic secure string tokenizer api
api-test-fts|LWS Full-text Search api
api-test-gencrypto|LWS Generic Crypto apis
api-test-jose|LWS JOSE apis
api-test-smtp_client|SMTP client for sending emails
api-test-xip|xip clipboard plugin clip chunking, parsing and reassembly
api-test-dht-msg-parse|DHT RPC wire message parser, incl. hash token charset and NOTIFY domain-name gates
api-test-auth-dns-dnsbl|auth-dns plugin DNSBL pending-query lifetimes (F-054): late resolver replies and client disconnects vs the 5s dnsbl timeout
api-test-auth-dns-zonedir|auth-dns plugin local zone-dir trust policy (F-055): missing pvo / world-writable / symlinked dirs and foreign-uid or wrong-shape zone files refused

