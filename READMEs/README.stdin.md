# lws stdin handling

## Default

By default stdin is ignored by lws, although user code can adopt it.

## Stdin bulk RX handling

If you:

1) define `info.system_ops` at context creation time
2) set the member `.stdio_rx` to a callback that gets stdin RX fragments
3) call `lws_system_adopt_stdin(context, 0);` after creating the context

then you will receive any stdin content in the callback.  This is useful for cases
where you are receiving bulk data into the app, eg, a PNG file for a PNG decoder.

When whatever is driving stdin closes it, you will receive a callback with
a NULL buffer and length 0.

## Stdin commandline handling

As an alternative, you can have lws treat stdin as additional, invisible
commandline content.  This is very useful for situations where you are
passing secrets to the app, which must not leak eg by `ps` seeing what is
on the normal commandline.

To enable this, call `lws_system_adopt_stdin(context, LWS_SAS_FLAG__APPEND_COMMANDLINE)`
There is no need to implement any lws_system callbacks in this case, lws
will deal with the stdin data.

### Commandline access apis

There are four apis available for commandline querying:

```
LWS_VISIBLE LWS_EXTERN const char *
lws_cmdline_option(int argc, const char **argv, const char *val);
LWS_VISIBLE LWS_EXTERN const char *
lws_cmdline_options(int argc, const char * const *argv, const char *val, const char *last);
LWS_VISIBLE LWS_EXTERN const char *
lws_cmdline_options_cx(const struct lws_context *cx, const char *val, const char *last);
LWS_VISIBLE LWS_EXTERN const char *
lws_cmdline_option_cx(const struct lws_context *cx, const char *val);
```

|api|context|argc/argv|stdin|iterative|
|---|---|---|---|---|
|`lws_cmdline_option()`|n|y|n|n|
|`lws_cmdline_options()`|n|y|n|y|
|`lws_cmdline_options_cx()`|y|y|y|y|
|`lws_cmdline_option_cx()`|y|y|y|n|

### Selecting non-switch args

All four apis can be called with NULL `val`, in order to return a non-switch
argument.  You can use the `lws_cmdline_options[_cx]()` variant to interate
through the non-switch arguments for NULL `val` case too.

For example, the commandline `--switch1=abc def` would return a pointer to 
`def` if the api `lws_cmdline_options()` was called with NULL `val` and `last`.

Although switches with args like `-d 1039` are supported, if you will allow non-
switch arguments, users will have to use the forms without any space between
the switch and arg, ie:

 - `-d1039`
 - `-d=1039`
 - `--port=1234`

to allow non-switch args to be correctly distinguished.  Otherwise, eg, `1039`
and `1234` would be seen as non-switch args.

### Timing of stdin commandline access

The normal argc / argv commandline is available from main() starting.  But the
part of the commandline contributed via stdin is only available after the
event loop starts, which happens after the lws_context exists.

To help synchronize this, lws_system follows what state the system is in, and
waits to process stdin traffic before reaching the OPERATIONAL state where
user code normally runs.  See

minimal-examples-lowlevel/http-client/minimal-http-client-post/minimal-http-client-post.c

for examples of how to deal with this. 
