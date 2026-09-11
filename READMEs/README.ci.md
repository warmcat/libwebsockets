## Need for CI

Generally if we're adding something that's supposed to work ongoing, the stuff
should be exercised in CI.

If there are few users for a particular feature, experience has shown that
refactors or other upheaval can easily break it into a state of uselessness
without anyone noticing until later.

Therefore here's a description of how to add something to the CI tests... this
is certainly a nonproductive PITA and I have never been thanked for the work
involved.  But if the promise of the various features working is going to
remain alive, it's necessary to include CI test where possible with new
nontrivial code.

## Integration points

### Sai

CI is run by Sai (https://libwebsockets.org/git/sai) across the builders in
`.sai.json`.  That file maps each platform / configuration to the CMake
options it needs, the build and test steps it runs, and the `ctest` invocation
that exercises the api-tests and minimal examples.

### ctest

The api-tests under `./minimal-examples-lowlevel/api-tests` and the
minimal example selftests are registered with `ctest` from their CMakeLists,
so a new test only needs to be wired into cmake there to be run on every Sai
builder that enables it.

### additional test scripts

`./scripts/h2spec.sh`, `./scripts/attack.sh` and friends are standalone
scripts that can be run from a build directory against an installed
build; they are not part of the default ctest run.
