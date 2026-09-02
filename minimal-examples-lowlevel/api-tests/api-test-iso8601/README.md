# lws-api-test-iso8601

Exercises `lws_parse_iso8601()`, the strict `lws_tokenize`-based parser for
ISO8601 / RFC3339-style date strings as used on whois responses.

It checks accepted forms (date-only, `T` / `t` / space separators, leap
days, fractions and zone indicators, which are validated but interpreted as
UTC) and a spread of malformed inputs that must return failure: unpadded or
out-of-range fields, partial time parts, bad separators, junk after the
zone indicator, broken utf-8 and overlong fractions.
