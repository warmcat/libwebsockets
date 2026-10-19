# lws-api-test-captcha-login

`lws_captcha_ratelimit` in front of a public page, on a vhost also running
`lws-login`, with the page's mount `unauth-allow` for lws-login.  Both plugins
are built into the test.

The captcha lets a visitor with a live lws-login session holding the page's
grant skip its delays.  Anonymous visitors, who lws-login lets see the page,
must still wait them out (G-249).

| Step | Request | Expected |
|---|---|---|
| visit | GET the page, no cookies | 200, the captcha page and its visit cookie |
| anon-submit | submit the challenge at once, visit cookie only | 303, no pass cookie |
| nogrant-submit | the same plus a live session lacking the grant | 303, no pass cookie |
| live-submit | the same plus a live session with the grant | 303 and the pass cookie |

```
$ ./lws-api-test-captcha-login -p 7681 --assets ../plugins/protocol_lws_captcha_ratelimit/captcha-assets
```

`--assets` names the captcha's asset directory, which holds the challenge page.
