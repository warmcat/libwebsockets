# lws-api-test-dll2-guard

Exercises the `lws_dll2` `_safe` iterator runtime guard.

`lws_start_foreach_dll_safe()` has always allowed the loop body to remove the
*current* node.  But if the body removes (and frees) some *other* list member
— most damagingly the cached next node itself — the cached next pointer goes
stale and the iterator walks into freed memory, typically failing far away
from the cause.  This is the use-after-free class from the external QUIC
`close_after_rx` report.

The guard adds:

 - a monotonic `generation` counter on `lws_dll2_owner_t` bumped by every
   list mutation,
 - a guarded iterator advance that, when the generation moved, validates the
   cached next is still a live member (by pointer identity only, the suspect
   node is never dereferenced),
 - on invalidation: a loud `lwsl_err()` naming the owner and cached node, an
   `assert()` at the exact iteration step (suppressible via
   `lws_dll2_guard_quiet` for tests or apps that must not die), and recovery
   along the live list so even release builds stop walking into freed nodes.

The test covers the classic current-node-removal patterns (both macro and
`lws_dll2_foreach_safe()`), generation/membership bookkeeping, and recovery
when the body frees the cached next, the next two nodes, and both current and
next.

## Build

```
 $ cmake . -DLWS_WITH_MINIMAL_EXAMPLES=1 && make -j
 $ ./bin/lws-api-test-dll2-guard
```

## Usage

```
 $ ./lws-api-test-dll2-guard [--help]
```
