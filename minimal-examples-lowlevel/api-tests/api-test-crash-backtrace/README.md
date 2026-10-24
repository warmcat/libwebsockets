# lws api test crash-backtrace

Checks `lws_crash_backtrace_install()`, which `lws_cmdline_option_handle_builtin()`
calls in builds with `LWS_WITH_CRASH_BACKTRACE`.  Each case runs a child that
crashes, reading what it writes to stderr:

|case|the child|must|
|---|---|---|
|segv|`raise(SIGSEGV)`|print its backtrace, then die of SIGSEGV|
|abort|`abort()`, as a failed `assert()` does|print its backtrace, then die of SIGABRT|
|app|installs its own SIGSEGV handler first|run only its own handler|

The test prints what each child wrote, so the backtrace format on the platform
can be seen in its output.

## build

Built with the other minimal examples, needs `LWS_WITH_CRASH_BACKTRACE` and a
posix platform.

## usage

```
$ ./bin/lws-api-test-crash-backtrace
```

Returns 0 if all the cases pass.
