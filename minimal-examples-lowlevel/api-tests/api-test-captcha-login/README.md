# lws-api-test-captcha-login

`lws_captcha_ratelimit` in front of a public page, on a vhost also running
`lws-login`, with the page's mount `unauth-allow` for lws-login.  Both plugins
are built into the test.

The captcha lets a visitor with a live lws-login session holding the page's
grant skip its delays.  Anonymous visitors, who lws-login lets see the page,
must still wait them out (G-249).

The challenge page's `interceptor-config.js` tells `captcha.js` whether to
submit the challenge at once (`lws_interceptor_session_live`).  It must give
the same answer the server gives the submission, or the page loops through
challenges (G-340, G-341): so the vhost's lws-login `min-grant-level` is 2,
and the page's mount names its own `service-name`, `public-svc`.

| Visitor | Session |
|---|---|
| anon | none |
| nogrant | live, level 2 for an unrelated service |
| wrongsvc | live, level 2 for lws-login's vhost-wide service, not the page's |
| lowlevel | live, level 1 for the page's service, under min-grant-level 2 |
| live | live, level 2 for the page's service |

| Step | Request | Expected |
|---|---|---|
| visit | GET the page, no cookies | 200, the captcha page and its visit cookie |
| *who*-config | GET the page's `interceptor-config.js` with the session | `lws_interceptor_session_live` 1 only for live |
| *who*-submit | submit the challenge at once, visit cookie and session | 303, the pass cookie only for live |

```
$ ./lws-api-test-captcha-login -p 7681 --assets ../plugins/protocol_lws_captcha_ratelimit/captcha-assets
```

`--assets` names the captcha's asset directory, which holds the challenge page.
