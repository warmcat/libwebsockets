# Test coverage

lws can be built with gcov-format coverage instrumentation, with gcc or
clang, and a script summarizes what the ctest run actually executed.

## Locally

```
cmake .. -DLWS_WITH_GCOV=1 -DLWS_WITH_MINIMAL_EXAMPLES=1 <other options>
make -j8
ctest -j8
make coverage
```

`-DLWS_WITH_GCOV=1` adds `-fprofile-arcs -ftest-coverage` to every object in
the tree.  Each test process writes its counters (`.gcda` files next to the
objects) when it exits normally; ctest just runs the tests as usual.  Tests
that are killed, or time out, flush nothing and so contribute nothing.

`make coverage` runs `scripts/coverage-report.py`, which drives `gcov` (or
`llvm-cov gcov` for a clang-built tree) over every `.gcno` in the build
tree, merges the results per source file and prints, for `lib/`:

 - overall line and function coverage
 - a per-directory table, worst first
 - every function that was compiled but has under 50% line coverage, worst
   first, with the file and line it starts on

Counters accumulate across runs until the `.gcda` files are deleted
(`find . -name '*.gcda' -delete` in the build tree), so a report after
running a single test shows only what that test reached.

The script runs from the build directory and takes the compiler and the
source directory from its CMakeCache.txt.  Options:

```
--include PREFIX   count sources under this prefix instead of lib/ (repeatable)
--threshold PCT    list functions below this line coverage (default 50)
--limit N          list at most N functions (default: all)
--json             also write the totals and the function list to
                   coverage-summary.json in the build directory
```

`LWS_GCOV="llvm-cov gcov"` in the environment overrides the reader matched to
the compiler.

It only reports.  It exits 0 even when it cannot find a reader or read
some of the data files, and says so in the output.

## In Sai

The `coverage` configuration in `.sai.json` builds `distro_recommended`
instrumented on the `rocky9-ca/aarch64-a72a55-rk3588/clang` platform, with
fault injection, http stream compression (deflate and brotli) and ws
permessage-deflate forced on so their tests are in the run, then runs ctest
and prints the report into the job log; `build/coverage-summary.json` is
kept as an artifact.  A clang-built tree needs `llvm-cov` on the builder to
read the counters; without it the report says so and the job is not
affected.  The builder also needs the brotli development package.

`lws-api-test-http-compression` is the transfer check for the compression
paths: it serves a generated multi-megabyte text file named after its own
sha256 and fetches it back over h1 and h2c with each content-encoding,
decoding client-side and checking the digest against the name.
