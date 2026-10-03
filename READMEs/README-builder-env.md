# The environment builds run in

The processes sai-builder starts for a task (the step scripts, and the
sai-shell a viewer can open on a task) do not see the builder's own
environment.  Instead they start with a small base set:

|Platform|Base environment|
|---|---|
|Linux, BSDs|`PATH=/usr/local/bin:/usr/bin:/bin`, `LANG=en_US.UTF-8`, `TERM=xterm-256color`|
|macOS|as above, but `PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin`|
|Windows|the builder's own environment, since without `SystemRoot` and the Visual Studio variables a child can't even find `cl` or `nmake`|

The step scripts then add sai's own variables on top, like `HOME`, `CI`,
`SAI_PROJECT`, `SAI_PARALLEL`, `SAI_LOGPROXY` etc; those always have sai's
values.

## Adding to it from the builder conf

Each platform in the builder conf can have an `env` array, applied in order
on top of the base set, to everything started for that platform's tasks.  An
item is either a string, or an object of one or more names and values:

```
	"platforms": [
		{
			"name":		"linux-debian13/x86_64-amd/gcc",
			"env":	[
				"PATH=/opt/cross/bin:$PATH",
				"PKG_CONFIG_PATH=/opt/cross/lib/pkgconfig",
				{ "SAI_ARCH": "x86_64", "SAI_CROSS_BASE": "/opt/cross" },
				"CCACHE_DIR=/var/cache/ccache-${SAI_ARCH}",
				"http_proxy",
				"https_proxy"
			],
			"servers": [ "wss://libwebsockets.org:4444/sai/builder" ]
		}
	]
```

 - `"NAME=value"`, or `{ "NAME": "value" }`, sets NAME, replacing any value
   it already had.

 - A bare `"NAME"` passes on the builder's own value of NAME, if it has one
   (and does nothing if not).  That's the way to opt in to specific things
   from the builder's environment, like proxy settings, without passing all
   of it.  The value is used as it is, with no expansion.  On Windows this is
   a no-op, as the base set is already the builder's environment.

 - `$NAME` and `${NAME}` in a value are replaced with the value NAME has at
   that point, ie, from the base set plus the items before this one.  So
   `"PATH=/opt/cross/bin:$PATH"` prepends to the base PATH, and later items
   can build on earlier ones.  sai's own variables like `HOME` aren't set
   yet, so they can't be used here.  A NAME that isn't set expands to nothing.  `$$`
   is a literal `$`, as is a `$` that isn't followed by a name.  The `${NAME}`
   form allows any characters in the name apart from `}` and `=`, eg
   `${ProgramFiles(x86)}` on Windows.

The expansion is done by sai-builder itself, not a shell, so it's the same on
every platform, including Windows (where `%NAME%` is not expanded, and the
`PATH` separator is still `;`, eg `"PATH=C:\\tools;$PATH"`).  Windows names
are matched without regard to case, so `PATH` there replaces `Path`.

The values may be secrets, eg a token for a private package registry, so
sai-builder only logs the names, not the values.  They are not sent to
sai-server.  But of course, anything the build does may show them in the
task's logs, which may be public.
