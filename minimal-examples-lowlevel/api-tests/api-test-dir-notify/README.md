# lws api test dir notify

A directory monitor made with `lws_dir_notify_create()` must report a change
made in the directory straight after it returned, before the event loop has
run: a user such as the tls cert watch looks at its files, then starts
watching their directory, and must not miss a renewal written in between.

Each step creates a new file in `./dir-notify-test` and must be told about it
within 5s:

|step|file made|
|---|---|
|created straight after the monitor|from `main()`, before the loop has run|
|created from the loop|once the first was reported|

The callback is given the file's name, or "" where the platform can't say
which entry changed (kqueue on macOS / BSD).

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-dir-notify
[2026/10/27 12:00:00:0000] U: LWS API selftest: dir notify
[2026/10/27 12:00:00:0010] U: --- created straight after the monitor: reported as 'f0': PASS ---
[2026/10/27 12:00:00:0011] U: --- created from the loop: reported as 'f1': PASS ---
[2026/10/27 12:00:00:0011] U: --- all steps passed ---
[2026/10/27 12:00:00:0020] U: Completed: PASS
```
