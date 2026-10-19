# lws-api-test-aws-credentials

Checks `lws_aws_filesystem_credentials_helper()`, which reads an AWS access
key id and secret access key from a credentials file.

Each case writes a file into the directory given by `--dir`, reads it back
with the helper and checks the result:

| Case | Expected |
|---|---|
| plain `name = value` lines | both values |
| CRLF line ends, padding, no final newline | both values, trimmed |
| two profiles | the first profile's values |
| no secret, or no key id | failure, nothing allocated |
| lines without `=` | failure, nothing allocated |
| no file | failure, nothing allocated |
| a file larger than the helper reads | failure, nothing allocated |
| a path longer than the helper can hold | failure, nothing allocated |

All the while every log line is captured at every level the build has, and
the test fails if any of them carries the secret.

```
$ ./lws-api-test-aws-credentials --dir /tmp
```

Needs `-DLWS_WITH_SECURE_STREAMS=1 -DLWS_WITH_SECURE_STREAMS_AUTH_SIGV4=1`.
