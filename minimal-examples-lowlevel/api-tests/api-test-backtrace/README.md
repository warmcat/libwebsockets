# lws api test Compressed Backtraces

Tool to decompress the `lws_backtrace` compressed backtraces

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15

```
 $ echo -n "~m#ghawu9ICDldHWP9xuFCTFrDOOUzlHOLYIbqO1C3eYbrpcC3NoQo41CtHWBxkZcnU4BA1VCoANw==" | ./lws-api-test-backtrace
```

