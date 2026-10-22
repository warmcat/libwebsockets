# lws-api-test-iface-bind

A server vhost given an `iface` listens only there, or not at all: never on
the wildcard address, even when the process is out of fds as the vhost comes
up.  Looking up the interfaces (`getifaddrs()`) needs an fd itself, so running
out of them at the wrong moment must not read as "the interface is usable"
with no address filled in.

The test lowers `RLIMIT_NOFILE` and uses up the fds, then:

 - **numeric**: creates a vhost with iface `127.0.0.1` with exactly one fd
   free, which the listen socket takes, so looking up the interfaces at bind
   time fails.  A numeric address needs no interface list: it must listen on
   127.0.0.1.

 - **name** (linux only): the same with iface `lo`.  Without the interface
   list there's no address for it: the vhost must either not come up, or
   listen on 127.0.0.1, never on 0.0.0.0.

 - **deferred**: creates a vhost with iface `127.0.0.1` with no fd free, so
   its listen `socket()` fails.  The platform's periodic check must retry it,
   and still retry it after the first retry's `socket()` fails as well (the
   `listenskt` fault), so a client can connect to it once fds are available.

The `plat_periodic_ms` fault injection range makes the periodic check run
every 200ms instead of every 30s.

Needs `LWS_WITH_SYS_FAULT_INJECTION` and `LWS_WITH_IPV4`, and a posix
platform.

```
$ ./bin/lws-api-test-iface-bind
```
