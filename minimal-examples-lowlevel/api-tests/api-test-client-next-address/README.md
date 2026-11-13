# lws-api-test-client-next-address

A client whose connect to the first address the resolver gave is refused must
go on to the next address, on the same connection.

A fake nameserver on loopback, adopted into the event loop, answers every A
query with 127.0.0.1 and every AAAA query with ::1.  Two http servers listen
on kernel-chosen ports, one only on 127.0.0.1 and the other only on ::1, and a
client connects to the same name at each server's port.

Which of the two addresses a client tries first is decided by the address
sort, ie, by the host's routes, so it differs between hosts.  But both clients
get both addresses in the same order, so one of them starts on the address its
server isn't listening on, is refused, and must connect on the next one.  Both
clients must end up connected, each on the family its server listens on.

The client hears `LWS_CALLBACK_CONNECTING` for each address it tries, and
there, before the connect() has completed, `lws_get_peer_simple()` and
`lws_get_peer_addresses()` must both report the address being tried.  So the
client that is refused must have heard it for two different addresses, and
each client's last must be the one it connected to.

A host with no ipv6 loopback runs only the 127.0.0.1 leg.

## Running

The test is registered with ctest as `api-test-client-next-address`, which
gives it a free udp port for the fake nameserver in `LWS_ASYNCDNS_PORT`, the
port the resolver asks its nameservers on.  To run it by hand, set that to any
free udp port.

```
$ ctest -R api-test-client-next-address
```
