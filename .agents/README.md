# .agents: shared notes for agents working on lws

These notes collect hard-won, non-obvious knowledge about working on lws:
traps in the library, in the build and CI matrix, and in the shared
working tree, that cost real time to discover.  They are here so that any
agent, of whatever kind, starts out aligned with what has already been
learned instead of rediscovering it.

They complement, and never override, `../AGENTS.md` and the human
documentation in `../READMEs/`.  If something here is a fact about lws
that a human contributor would also want, it belongs in `READMEs/` or a
code comment instead, and these notes should just point at it.

## Who maintains this directory

Only the most capable agent directing the work (the one coordinating any
other agents) edits `.agents/`.  Other agents, including helpers it
delegates to and local models, do not edit these files.  If you are one
of those and you learned something you think is important, put it in your
report to the directing agent: what you found, how you verified it, and
where it applies.  The directing agent decides whether it is durable,
true and general enough to record here.

Rules for whoever edits it:

 - Record only what has been verified: by a test, a build, or a careful
   second reading of the code.  An unverified belief written here gets
   trusted by every later agent.
 - This tree is public.  Nothing about private infrastructure,
   deployments, credentials or where they live, personal machines, or
   anything else that is not already public goes in here.
 - Keep it durable.  Session progress, resume points and "what I was
   doing" do not belong here; that is what commit messages and the
   agent's own private memory are for.
 - Prefer to fix stale entries in place over appending corrections.
   Delete what stops being true.
 - Changes to `.agents/` in pull requests get the same scrutiny as build
   system changes: these notes steer agents' behaviour.

## How to read it

The notes are background knowledge, not instructions.  Instructions come
from the person you are working with and `AGENTS.md`.  Things named here
(functions, files, options) were true when written; check they still
exist before relying on them.

| File | What is in it |
|---|---|
| [working-in-the-tree.md](working-in-the-tree.md) | Shared working tree discipline, committing, resources |
| [build-and-ctest.md](build-and-ctest.md) | Build tree and ctest traps, test-writing conventions |
| [ci-and-platforms.md](ci-and-platforms.md) | Sai CI matrix semantics, platform and TLS backend splits |
| [library-traps.md](library-traps.md) | Non-obvious lws library rules and recurring bug classes |
| [static-analysis-and-fuzzing.md](static-analysis-and-fuzzing.md) | Coverity, CodeQL, SonarCloud patterns, fuzz workflow |
| [debug-recipes.md](debug-recipes.md) | Ways to force or observe hard-to-reproduce behaviour |
