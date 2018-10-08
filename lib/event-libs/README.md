## Information for new event lib implementers

### Introduction

By default lws has built-in support for POSIX poll() as the event loop.

However either to get access to epoll() or other platform specific better
poll waits, or to integrate with existing applications already using a
specific event loop, it can be desirable for lws to use another external
event library, like libuv, libevent or libev.

### Code placement

The code specific to the event library should live in `./lib/event-libs/**lib name**`

### Allowing control over enabling event libs

All event libs should add a cmake define `LWS_WITH_**lib name**` and make its build
dependent on it in CMakeLists.txt.  Export the cmakedefine in `./cmake/lws_config.h.in`
as well so user builds can understand if the event lib is available in the lws build it is
trying to bind to.

If the event lib is disabled in cmake, nothing in its directory is built or referenced.

### Event loop ops struct

The event lib support is defined by `struct lws_event_loop_ops` in `lib/private/libwebsockets.h`,
each event lib support instantiates one of these and fills in the appropriate ops
callbacks to perform its job.  By convention that lives in
`./lib/event-libs/**lib name**/**lib_name**.c`.

### Private event lib declarations

Truly private declarations for the event lib can go in the event-libs directory as you like.
However when the declarations must be accessible to other things in lws build, eg,
the event lib support adds members to `struct lws` when enabled, they should be in the
event lib supporr directory in a file `private.h`.

Search for "bring in event libs private declarations" in `./lib/private-libwebsockets.h
and add your private event lib support file there following the style used for the other
event libs, eg,

```
#if defined(LWS_WITH_LIBUV)
 #include "event-libs/libuv/private.h"
#endif
```

If the event lib support is disabled at cmake, nothing from its private.h should be used anywhere.

### Integrating event lib assets to lws

If your event lib needs special storage in lws objects, that's no problem.  But to keep
things sane, there are some rules.

 - declare a "container struct" in your private.h for everything, eg, the libuv event
   lib support need to add its own assets in the perthread struct, it declares in its private.h

```
struct lws_pt_eventlibs_libuv {
	uv_loop_t *io_loop;
	uv_signal_t signals[8];
	uv_timer_t timeout_watcher;
	uv_timer_t hrtimer;
	uv_idle_t idle;
};
```

 - add your event lib content in one place in the related lws struct, protected by `#if defined(LWS_WITH_**lib name**)`,
   eg, again for LWS_WITH_LIBUV

```
struct lws_context_per_thread {

...

#if defined(LWS_WITH_LIBUV)
	struct lws_pt_eventlibs_libuv uv;
#endif

...
```

### Adding to lws available event libs list

Edit the NULL-terminated array `available_event_libs` at the top of `./lib/context.c` to include
a pointer to your new event lib support's ops struct, following the style already there.

```
const struct lws_event_loop_ops *available_event_libs[] = {
#if defined(LWS_WITH_POLL)
	&event_loop_ops_poll,
#endif
#if defined(LWS_WITH_LIBUV)
	&event_loop_ops_uv,
#endif
...
```

This is used to provide a list of avilable configured backends.

### Enabling event lib adoption

You need to add a `LWS_SERVER_OPTION...` flag as necessary in `./lib/libwebsockets.h`
`enum lws_context_options`, and follow the existing code in `lws_create_context()`
to convert the flag into binding your ops struct to the context.

### Implementation of the event lib bindings

Study eg libuv implementation, using the available ops in the struct lws_event_loop_ops
as a guide.

### Destruction

Ending the event loop is generally a bit tricky, because if the event loop is internal
to the lws context, you cannot destroy it while the event loop is running.

Don't add special exports... we tried that, it's a huge mess.  The same user code should be able
work with any of the event loops including poll.

The solution we found was hide the different processing necessary for the different cases in
lws_destroy_context().  To help with that there are ops available at two different places in
the context destroy processing.

