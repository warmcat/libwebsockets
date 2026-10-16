# lws api test protocol plugins

Loads the protocol plugins the way a context does, and checks every one this
build made loaded properly: it opened, exported its header, matched lws' build
hash and the protocol plugin class, and its protocols have a name and a
callback.

Like the lib does, it looks in the dirs on `LD_LIBRARY_PATH` first, then in
`--dir`, so it loads the same copies the other tests will.  Each protocol
plugin in `--dir` must then be among the loaded plugins, even if a copy found
earlier on `LD_LIBRARY_PATH` was the one loaded.

It is built when lws has `LWS_WITH_PLUGINS` with a shared lib, and not
`LWS_WITH_PLUGINS_BUILTIN`.

## Before any test

Every test that creates a context loads all the plugins.  The first time a
newly built library is loaded can take a while on some platforms, eg, seconds
for each plugin on macOS, while the system checks it.  When ctest starts many
tests together, those servers can then take longer to start listening than
their peer tests will wait.

So ctest also runs it before starting any test, through `warm.cmake`, to have
the first loads over with once.  Later loads of the same plugins are quick.

That's done with `CTEST_CUSTOM_PRE_TEST` in the `CTestCustom.cmake` the
top-level `CMakeLists.txt` writes in the build dir, from the commands tests
register in the global property `LWS_CTEST_PRE_TEST`.  ctest runs no tests at
all if a pre-test command fails, so `warm.cmake` always succeeds; this test is
what says if a plugin didn't load.

It's not done with a multi-config generator (eg, Visual Studio or Xcode),
since the exe is in a dir per config and `CTestCustom.cmake` can't tell which
config ctest is running.

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
--dir <dir>|The dir the build put its plugins in
--suffix <suffix>|The platform's shared lib suffix, eg, `.so`, `.dylib` or `.dll`
-d <loglevel>|Debug verbosity in decimal, eg, -d1039 shows each plugin it tries

```
 $ ./bin/lws-api-test-plugins --dir ./lib --suffix .so
[2026/10/16 15:43:29:0777] U: LWS API selftest: protocol plugins load
[2026/10/16 15:43:29:1998] U: main: loaded 22 plugins in 121ms
[2026/10/16 15:43:29:2056] U: Completed: PASS
```
