# Pools

A pool is a named set of files belonging to a repo, that the builders running
its tasks keep synced through sai-server.  It's meant for state that work
builds up over many tasks and many builders, like fuzzing corpora: every
builder working on the repo's fuzzing adds to one shared corpus, and starts
from what all the others found.

## Asking for a pool in .sai.json

A configuration names the pool its tasks use:

```
	"fuzz": {
		"cmake":	"./fuzz/run.sh",
		"pool":		"fuzz",
		"idle":		2
	}
```

The name is up to 32 lowercase letters, digits, `-` and `_`.  Configurations
naming the same pool in the same repo share it.

## What the task sees

The builder keeps its copy of the pool under `$HOME/pools/`, and tells the
task's build steps where it is:

|variable|what it is|
|---|---|
|`SAI_POOL_DIR`|the shared files, synced both ways|
|`SAI_POOL_KNOWN`|files the server provides, eg, known reproducers; only ever synced from the server|
|`SAI_POOL_FINDINGS`|anything the task leaves in here is sent to the server, then deleted|

The builder syncs the pool before the task's first build step starts (unless it
did within the last minute), every minute while the task runs, and once more
after it ends.  The builder does it rather than the task, so a task that's
stopped, eg, because real work needed the builder, loses nothing it wrote.
Several tasks on the builder using the same pool share one copy.

### Files in SAI_POOL_DIR

Only files at `<sub>/<name>` are synced, where

 - `<sub>` is a directory name of up to 32 letters, digits, `-`, `_` and `.`,
   not starting with `.`, eg, `corpus-h2`

 - `<name>` is the 40 character lowercase hex SHA-1 of the file's content

That's how libFuzzer names its corpus files already, so a libFuzzer corpus
dir per target, eg, `$SAI_POOL_DIR/corpus-h2/`, just works.  Anything else in
there is left alone and stays local.  Files are only ever added by syncing,
never deleted, except by a replace (below).

Files arriving from the server are written somewhere else first and renamed
into place, so a fuzzer reading the directory never sees one half written.

### Findings

Files at `$SAI_POOL_FINDINGS/<sub>/<name>` are sent to the server and deleted
once it has them.  `<name>` can be anything up to 64 letters, digits, `-`, `_`
and `.`, not starting with `.`, and the file can be up to 8MiB.  Write a
finding under a name starting with `.` and rename it when it's complete, so it
isn't sent half written.

The server groups findings into bugs, and publishes each bug's reproducer in
`SAI_POOL_KNOWN` for tasks to replay: see [README-findings.md](README-findings.md).

### Replacing a sub, eg, after minimizing a corpus

Tasks can't delete shared files, since deleting one locally doesn't mean the
others should lose it.  To replace everything in a sub instead, eg, with a
corpus libFuzzer's `-merge=1` minimized:

1. read the number in `$SAI_POOL_DIR/.sai-pool-seq` before you start: it's how
   far the builder had synced from the server
2. make `$SAI_POOL_DIR/<sub>/` contain just the files you want to keep
3. write the number from step 1 into `$SAI_POOL_DIR/.sai-replace-<sub>`

At the next sync, the server removes every file in the sub it had up to that
number that isn't in the directory now, and the other builders remove them
when they next sync.  Files anyone added after that number are kept, since the
task didn't know about them.

## Sizes

A synced file can be up to 1MiB, and a pool holds up to 2 million files.

## On the server

Each repo's pool is a sqlite db next to the others,
`<database>-pool-<repo>-<pool>.sqlite3`.  Its entries are an append-only log:
each file added or removed gets the next sequence number, so a builder only
asks for what happened after the last one it saw.  A removed file leaves a
row saying so.

## Trust

Only a builder that has the fleet link key can sync, and only the pool of a
task it was given: it has to present the task's upload nonce.  But what goes
in a pool comes from the tasks, which run what's pushed to the repo, so a pool
is only as trustworthy as the people who can push to it.  Content addressed
files are checked against their names on both ends, names are checked before
they're used as paths, and sizes are capped.
