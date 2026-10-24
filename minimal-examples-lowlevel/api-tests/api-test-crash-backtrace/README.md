# lws api test crash-backtrace

Checks `lws_crash_backtrace_install()`, which `lws_cmdline_option_handle_builtin()`
calls in builds with `LWS_WITH_CRASH_BACKTRACE`.  Each case runs the test
again as a child, with `--crash <case>`, that crashes, reading what it writes
to stderr:

|case|the child|must|
|---|---|---|
|segv|`raise(SIGSEGV)`, or on windows an access violation exception|print its backtrace, then die of SIGSEGV, or exit with code 0xc0000005|
|abort|`abort()`, as a failed `assert()` does|print its backtrace, then die of SIGABRT, or exit with code 3|
|app|installs its own SIGSEGV handler, or unhandled exception filter, first|run only its own handler|

The test prints what each child wrote, so the backtrace format on the platform
can be seen in its output.

## build

Built with the other minimal examples, needs `LWS_WITH_CRASH_BACKTRACE`.

## usage

```
$ ./bin/lws-api-test-crash-backtrace
```

Returns 0 if all the cases pass.  `--crash <case>` is how it runs itself as
each child.
