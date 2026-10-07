# Working in the tree

## Several sessions share one working tree

Expect other agents (and the maintainer) to be editing and committing in
the same checkout at the same time as you.  Anything that touches files
other than your own edits can destroy or corrupt their work.

 - Never `git stash`, `git checkout .`, `git add -A`, or `git add -u <dir>`.
   `git add` explicit paths only.
 - Never leave your changes staged, even briefly: another session's bare
   `git commit` will sweep them into its commit.  Conversely, before you
   commit, `git diff --cached --name-only` must show only your files.
 - Make `git commit -F msg -- <paths>` your default form.  Note that
   `--only <file>` still commits the whole worktree copy of that file: if
   another session has uncommitted hunks in the same file, build a
   temporary index (`GIT_INDEX_FILE`) from HEAD plus only your hunks and
   commit from that.  Afterwards reset the shared index entries for those
   paths, or `git status` shows them `MM` (a staged revert of your commit
   waiting to be swept in by someone else).
 - Do not rebase in the shared checkout.  If history must be rewritten,
   do it in a throwaway `git worktree add --detach` and move the branch
   with `git update-ref refs/heads/<branch> <new> <old>`, which refuses if
   someone else moved it meanwhile.
 - Other sessions also rewrite their own recent commits.  Before
   reporting work as committed, check each hash is an ancestor of HEAD
   (`git merge-base --is-ancestor`).
 - In scripted edits, read before you truncate:
   `s = f(open(p).read())` then `open(p, "w").write(s)`.  The one-liner
   `open(p, "w").write(f(open(p).read()))` empties the file first, and a
   failure in `f` then loses whatever uncommitted work was in it.
 - After any temporary source toggle (before/after testing), `git diff`
   the file against the intended state before building the final test or
   committing.  Never rely on a later step of the same shell command to
   restore it.
 - `pkill -f pattern` / `pgrep -f pattern` match your own shell's command
   line if the pattern appears in it.  Kill by PID, or use the bracket
   trick (`pgrep -f '[p]roxy-fixture\.py'`).

To judge whether a test failure is yours when other sessions have
half-done edits in the tree, export HEAD (`git archive HEAD | tar -x`)
into a directory outside the repo, apply only your patch, and build and
test there.

## Commits

 - One commit per fix or finding, so the public history has boundaries.
 - Check where a commit has been pushed before amending into it.  The
   maintainer pushes to `main-dev`; Sai CI promotes it to `main` when it
   passes.  So "not on origin/main" does not mean unpublished: check
   `git ls-remote origin main-dev`.  A commit that Coverity or Sai has
   reported on is public; fix it with a normal follow-up commit, not a
   `fixup!`.
 - When fixing security findings, verify by reading and building, not by
   writing proof-of-concept attack programs or committing attack inputs.

## Behaviour changes need evidence

"All tests pass" is not evidence for a change on a path the suite does
not exercise.  The maintainer deploys HEAD to production; two changes that
were green on the full suite broke it within the hour, because no test
covered the flow (an interceptor form's real POST target; h1 pipelining
during a file transfer).  Before landing a behaviour change on anything
lwsws serves (interceptors, plugins, keepalive / pipelining, header
lifetime, proxy), add an end-to-end test of the flow first, or get a
second, independent read of the claim the change rests on (read the JS /
config that defines the protocol, not only the C).  Treat "by design" or
"not reachable" claims about plugin protocols as unverified until the
asset that defines the protocol has been read.

## Resources

The development machines are usually modest and shared with other
sessions.

 - One build tree's make + ctest at a time.  Full parallel ctest runs
   with the debug-logging fixtures have OOM-killed sessions; use modest
   `-j` and redirect output to a log file on disk.
 - Don't brute-force flaky failures with many parallel background loops.
   Read the code and do one instrumented run.  If you must loop, keep it
   to one or two loops whose script kills what it started, by PID.
 - `/tmp` may be a tmpfs: big logs there are RAM with no owning process.
   Write growing logs (`-d 1039` server runs, ctest loops) under your
   build tree on disk and delete them when done.
 - Never install system packages without asking, and never node.js at
   all.  If a tool wants an extra package, find a route that doesn't
   need it or ask.
 - Make your own build directories (`build-<you>-<purpose>`), never use
   `./build`.
