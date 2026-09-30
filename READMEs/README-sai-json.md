# .sai.json format

Projects can inform Sai of what build and test variations they want to run
on push using a `.sai.json` file in the top level dir of the project.

The git push hook isolated this file from the pushed tree and passes it to
the sai-server along with the rest of the push notification information in
a signed JSON structure.

## Simple .sai.json file

```
{
	"schema": "sai-1",

	# comments are OK
	#
	"platforms": {
		"linux-ubuntu-xenial-amd64": {
			"build": "mkdir build destdir;cd build;export CCACHE_DISABLE=1;cmake .. ${cmake};make -j;make -j DESTDIR=../destdir install && ctest -j4 --output-on-failure"
		}
		# you can continue to list platforms here
	},

	"configurations": {
		"plain": {
			"cmake":	"",
		}
	}
}
```

The effect of the above is a single build using a `linux-ubuntu-xenial-amd64`
platform builder with the arguments

```
	mkdir build destdir;
	cd build;
	export CCACHE_DISABLE=1;
	cmake ..;
	make -j;
	make -j DESTDIR=../destdir install &&
	ctest -j4 --output-on-failure
```

### Platforms section and default

In the top level `"platforms"` section you describe the different build
platforms you want to build and test on... the specified platforms must have
builders that have connected themselves to the sai-server.

If you don't give a `"default": false` entry in the platform definition, the
platform is assumed to apply to all the configurations listed afterwards.  If
you do set `"default": false` on a platform, it's taken to mean you will list
configurations you want it to apply to manually and that platform is not
automatically used otherwise.

### Configuration section

#### cmake

The configuration section lists build variations, the `"cmake"` entry allows
you to give additional cmake options like `-DSOMEFEATURE=1` that together define
the build variation.  These are applied additionally to the platform-specific
cmake options where the `${cmake}` token appears.

#### platforms

You can also give a `"platforms"` entry in each configuration specifiying which
platforms should build this configuration in a comma-separated list.  If you
don't give a `"platforms"` entry on a configuration, all default platforms will
be applied.  You can also list additional, non-default platform names you
want to apply, like

```
		"platforms":	"windows-10, linkit-cross, linux-debian-buster-arm32"
```

those will be applied on top of the defaults.  Other options are to disable
given default platforms:

```
		"platforms":	"not linux-ubuntu-xenial-amd64"
```

or to disable all default platforms and just use the specified ones:

```
		"platforms":	"none, windows-10"
```

#### artifacts

You can also give a comma-separated list of build artifacts, these are
arbitrary binary files which will be uploaded to sai-server and made available
for download over https.

#### idle

A configuration can also ask for idle tasks, eg for long-running fuzzing, with
the number of them to create on each platform it applies to:

```
		"idle":		4
```

Besides the configuration's normal task, each event then has that many idle
tasks ("lanes") for it on each platform.  They do not count towards the
event's result, and only run in time builders would otherwise spend idle,
when the builder conf allows it.  See [README-idle.md](README-idle.md).

#### pool

A configuration can name a pool, a set of files shared by the repo's tasks
that the builders keep synced through sai-server, eg, a fuzzing corpus:

```
		"pool":		"fuzz"
```

See [README-pool.md](README-pool.md).
