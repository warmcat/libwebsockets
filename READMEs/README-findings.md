# Findings

Tasks that fuzz, or otherwise hunt for bugs, can report what they find to
sai-server through their pool (see [README-pool.md](README-pool.md)).
sai-server groups the findings into bugs, tells admins about new ones, and gives
the builders each bug's reproducer to replay, so CI keeps failing while a known
bug is still there.

Findings may be unfixed security bugs.  Their details are only ever shown to
admins in sai-web, and mail about them only says what and where, never the
report.  A task reporting findings this way should keep sanitizer reports out
of its log, since task logs are public.

## Reporting a finding

A finding is a pair of files the task leaves in `$SAI_POOL_FINDINGS/<sub>/`,
where `<sub>` is, eg, the fuzz target:

 - the input, eg, `crash-<sha1>`, as libFuzzer names it
 - the sanitizer's report about it, named the same plus `.log`

As with any finding file, write each under a name starting with `.` and rename
it when it's complete.  The builder sends them to sai-server at the next sync,
then deletes them.

## Grouping into bugs

When sai-server has both files of a finding, it works out which bug it is from
the report:

 - the kind, from the `SUMMARY:` line, eg, `AddressSanitizer: heap-buffer-overflow`
   (any leak is `AddressSanitizer: leak`)
 - the first three functions of the report's first stack trace that are in the
   code being tested.  The sanitizer runtime (names starting `__`), libFuzzer's
   own frames (`fuzzer::`) and allocator / libc functions like `malloc` and
   `memcpy` are skipped, and the trace stops at `LLVMFuzzerTestOneInput`

Only function names count, not line numbers, so the same bug stays the same bug
while unrelated code around it changes.  Findings in the same sub with the same
kind and functions are the same bug, a "group".

Each group remembers how many times it was found, when, at which commits and on
which platforms, and the smallest input that reproduced it.

## News

A group is news when it's first found, and when a group that was marked fixed is
found again (a regression).  News is:

 - flagged in sai-web until an admin acknowledges it
 - mailed to `findings-notify`, if that's set on sai-server

Further findings of an open group just count.

## Replaying known bugs

Each group's smallest reproducer is published in the pool's known namespace, at
`$SAI_POOL_KNOWN/<sub>/<sha1>`.  A task can replay them, eg, a CI fuzzing job
can replay every one for a target before fuzzing it:

 - one that still crashes is reported as a finding again (it's the same group,
   so it counts, or comes back as a regression if it was marked fixed), and the
   job should fail, so CI keeps failing while a known bug is there
 - for one that doesn't crash any more, the task leaves an empty
   `$SAI_POOL_FINDINGS/<sub>/ok-<sha1>`, and sai-server notes at which commit
   that was, so admins can see a bug is likely fixed

Groups marked fixed are still replayed, to catch them coming back.  Groups
marked "won't fix" aren't.

## In sai-web

Admins get a "findings" button under the login, which turns red with the count
of unacknowledged groups.  It opens a list of every pool's groups, with what
and where each bug is, how often it was found and when, and when its
reproducer last didn't crash.  For each group, admins can:

 - see the report and download the reproducer
 - acknowledge it
 - mark it fixed, won't fix, or reopen it

## Mail

Mail goes through the lws SMTP client of sai-server's vhost (lws needs to be
built with `LWS_WITH_EMAIL`), set up with sai-server's options:

|option|meaning|
|---|---|
|`findings-notify`|the address to mail news about findings to; no mail without it|
|`findings-from`|the address the mail comes from, default `findings-notify`|
|`findings-url`|a link to sai-web for the mail to point admins at|

and the vhost's `"lws-smtp-client"` options for the relay, eg, `smtp-host` and
`smtp-port`, default 127.0.0.1:25.

A mail only counts as sent when the relay accepted it.  Mail that couldn't be
sent, eg, because the relay was down or sai-server restarted, is tried again
every five minutes.  Mail the relay refuses outright isn't tried again, but the
group stays flagged in sai-web until it's acknowledged.
