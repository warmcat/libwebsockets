# lws minimal http server form POST lwsac

Shows how to parse the form using an lwsac to hold the form data

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-form-post-lwsac
[2018/03/29 08:29:41:7044] USER: LWS minimal http server form POST | visit http://localhost:7681
[2018/03/29 08:29:41:7044] NOTICE: Creating Vhost 'default' port 7681, 1 protocols, IPv6 off
[2018/03/29 08:29:49:8601] USER: text1: (len 4) 'xxxx'
[2018/03/29 08:29:49:8601] USER: send: (len 6) 'Submit'
```

Visit http://localhost:7681, submit the form.

The form parameters are dumped to the log and you are redirected to a different page.

Besides `text1` and `send`, the example's parameter list leaves three slots
open (NULL): up to three parameters with names it does not know are kept too,
and logged by the name `lws_spa_get_name()` gives them.  Those names belong to
that one form's spa, never to the shared parameter list.  The spa, with the
lwsac holding everything it parsed, is freed when the form has been handled,
or when the connection goes before the body completed.
