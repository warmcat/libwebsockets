# lws logging

# `lwsl_` logging apis

LWS provides logging arrangements that are not indirected through the
lws context, because logging may be needed before and after the context
existence.  For that reason it's processwide.

By default the logs are emitted on stdout, but this can be overridden
using `lws_set_log_level()` and either syslog (provided by `lwsl_emit_syslog()`)
or custom log emission is possible if you point it to your own.

Currently the following log levels are defined

|name|function|release|meaning|
|---|---|---|---|
|`LLL_ERR`|`lwsl_err()`|y|Serious operation errors anyone needs to know|
|`LLL_WARN`|`lwsl_warn()`|y|Operation errors you may need to know|
|`LLL_USER`|`lws_user()`|y|Information user code wants you to know|
|`LLL_NOTICE`|`lwsl_notice()`|y|Information about what lws is doing useful for logging|
|`LLL_INFO`|`lwsl_info()`|n|Detailed information about what lws is doing|
|`LLL_DEBUG`|`lwsl_debug()`|n|Very detailed information about what lws is doing|
|`LLL_PARSER`|`lwsl_parser()`|n|Very detailed information about parsing|
|`LLL_HEADER`|`lwsl_header()`|n|Very detailed information about header processing|
|`LLL_EXT`|`lwsl_ext()`|n|Very detailed information about ws extensions|
|`LLL_CLIENT`|`lwsl_client()`|n|Very detailed information about client connections|
|`LLL_LATENCY`|`lwsl_latency()`|n|detailed latency stats|
|`LLL_THREAD`|`lwsl_thread()`|n|detailed threadpool information|

The first four log levels are built into lws even on Release builds, the others
are only built in Debug builds.

You can select between Debug and Release builds using cmake `-DCMAKE_BUILD_TYPE=`
`DEBUG` or `Release`

`lws_set_log_level()` is used to OR together the logging bitfields you want to
see emitted, only log levels that were built in can be enabled since the code for them
is just not there otherwise.

## Finegrained control of log level build

You can deviate from the default log inclusion for release / debug by overriding it
at cmake, using `LWS_LOGGING_BITFIELD_SET` and `LWS_LOGGING_BITFIELD_CLEAR`.

For example you can set `-DLWS_LOGGING_BITFIELD_SET="LLL_INFO|LLL_DEBUG"`, which will
cause those log level traces to be built in even in Release mode.  Clear works
similarly to defeat build of specific log levels.

## Object tags in lws

Commonly logging wants to refer to an object in a repeatable way, the usual way to
do this is with `%p` to print the object pointer.  But this has a couple of drawbacks,
first the same memory may be freed and reallocated for a different instance of the same
or another object, causing confusion, and second when multiple processes are allocating
objects and logging, the same address may be allocated in different process also causing
confusion.

Lws has introduced unique tag strings to refer to object identity in logging instead, these
contain various information such as a 64-bit ordinal for the group the object belongs
to that won't repeat even if reallocated to the same address (until 2^64 allocations,
anyway).

Tags are fixed at object creation time for the whole object lifetime, although in some
cases the tag may be appended to... accepted server wsis for example don't have much
information available to form the tag until they start to indicate what they want to
do.

At their simplest the tags look like this (in a log indicating creation)

```
[2020/12/27 08:49:19:2956] N:  ++ (4) [wsi|5|h2]
```

It means a wsi has been created with the tag `[wsi|5|h2]`, and after that, there are 4
active objects in the wsi group.

The corresponding object destruction log with the tag is

```
[2020/12/27 08:49:24:4226] N:  -- (3)   5.126s [wsi|5|h2]
```

it indicates the object's tag, that it lived for 5.126s and after its destruction,
there are 3 objects in its group left.

### Compound tags

If the object has bindings, the tag can reflect that, eg

```
[2020/12/27 08:49:19:4787] N:  ++ (2) [wsiSScli|6|d_h1]
[2020/12/27 08:49:19:4793] N:  ++ (2) [wsicli|6|GET/h1/httpbin.org/([wsiSScli|6|d_h1])]
```

the first log is describing a proxied SS client connection at the proxy, and the second
is a wsi bound to the SS object from the first log to do the outgoing client action.

## Tags in user code

When user code wants to refer to a tagged object like a wsi or vhost, there are helpers
that return a `const char *` containing the tag

`lws_wsi_tag(wsi)`
`lws_vh_tag(vh)`

