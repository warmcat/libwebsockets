# lws minimal http client multi

## build

```
 $ cmake . && make
```

## usage

The application goes to https://warmcat.com and receives the page data
same as minimal http client.

However it does it for 8 client connections concurrently.

## Commandline Options

Option|Meaning
---|---
-s|Stagger the connections by 100ms, the last by 1s
-p|Use http/1.1 pipelining or h2 simultaneous streams
--h1|Force http/1 only
-l|Connect to server on https://localhost:7681 instead of https://warmcat.com:443

