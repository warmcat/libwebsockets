# Idle tasks

Builders spend a lot of their time with nothing to do.  Idle tasks let a
project use some of that time for work that has no natural end, like
long-running fuzzing, without it ever getting in the way of real CI work.

## Asking for idle tasks in .sai.json

A configuration asks for idle tasks by giving how many it wants on each
platform it applies to:

```
	"fuzz": {
		"cmake":	"./ci/fuzz.sh $SAI_IDLE_SECS",
		"platforms":	"none, linux-debian13/x86_64-amd/gcc",
		"idle":		2
	}
```

Every event still gets the configuration's normal task, which builds and counts
towards the event's result as usual.  Each event also gets, per platform, that
many idle tasks ("lanes") for the same configuration (at most 16).  Idle tasks:

 - never count towards the event's state, so they don't change what the event,
   its rss / rss.json feed entry, or sai-push, make of it

 - only run on the "host" event of their repo and ref: the newest event on it
   whose real tasks have all finished, whether they passed or failed.  So the
   event stays the one being worked on in idle time after it completed, until a
   newer push on the same ref completes and takes over

 - run in "slices": each slice is a new run of the lane, and only the last few
   runs of a lane are kept, with their logs and artifacts

## Allowing idle tasks on a builder

Idle tasks only go to builder platforms that allow them in the builder conf,
with an `"idle"` object on the platform:

```
	{
		"name":		"linux-debian13/x86_64-amd/gcc",
		"instances":	6,
		"idle": {
			"share":	50,
			"instances":	2,
			"slice-secs":	900,
			"settle-secs":	120
		},
		"servers": [ "wss://libwebsockets.org:4444/sai/builder" ]
	}
```

|member|default|meaning|
|---|---|---|
|`share`|0|The percentage of this platform's idle time to spend on idle tasks.  0, or no `"idle"` object, means none|
|`instances`|1|How many idle tasks the platform may run at once|
|`slice-secs`|900|How long one slice of an idle task should take (at least 60)|
|`settle-secs`|120|After real work on any platform of this builder, how long before it counts as idle again|

### Share of idle time

The share is spread out through the idle time, not taken as one block.  From
the first of a platform's slices starting to the last one ending is an active
period; after it, the platform has to rest for the period times
`(100 - share) / share` before it can start another.  So with a share of 50%
and 15 minute slices, it alternates 15 minutes of idle tasks with 15 minutes of
rest.  The rest only counts down while the platform has no real tasks pending,
so it really is a share of the idle time.

sai-server keeps the accounts, so they survive the builder going away.  While
idle tasks are running, or a builder is due to start one, the platform counts as
having pending tasks for sai-power, the same as real tasks do.  So sai-power
keeps builders up for them, and brings builders that were turned off back up
when their rest is over.  Because sai-power can only turn on a platform, not a
particular builder, this is only done for a platform whose builders all allow
idle tasks.

If a builder is paid for by the hour, or you don't want it running around the
clock, don't give it an `"idle"` object.

### Real work always wins

"Idle" is about the builder as a whole.  A builder doesn't take idle tasks while
any of its platforms has real work, or had it within `settle-secs`: real tasks
tend to arrive in bursts, and their steps are offered one at a time with gaps
between.

When real work is offered to any platform of a builder, it stops all the idle
tasks it's running to make way for it, and they are reported as "yielded".
That's not a failure, the lane just waits for its next slice.  When the builder
is idle again, idle tasks start again.

## Writing an idle task

An idle task's steps are told the length of their slice in `SAI_IDLE_SECS`, and
should aim to be finished in that time.  If a step goes on much past it, the
builder stops it and the slice counts as yielded.  `SAI_IDLE_SECS` isn't set in
the normal task, so a script can use it to tell the two apart; eg,
`./ci/fuzz.sh $SAI_IDLE_SECS` expands to plain `./ci/fuzz.sh` in the normal
task.  The whole step, including any build, has to fit in the slice, so a
script that divides its time between several things should divide
`SAI_IDLE_SECS` between them.

Anything the task wants to keep between slices, like a fuzzing corpus, should go
in a pool (see [README-pool.md](README-pool.md)): the builder keeps it synced
with every other builder working on the repo, even when it has to stop a slice
to make way for real work.

## In the web UI

An event's idle tasks are shown after its real tasks, in their own group per
configuration named "idle: <configuration>".  While a slice is running, the
lane is shown at full strength and gently "breathing"; the rest of the time,
including when a slice yields to real work, it fades back.  Idle tasks aren't
included in the event's task counts or progress bar.
