# lws AGENTS.md

## Overview

Please err on the side of high quality, not lazy, implementation decisions, because the code
will have to be maintained for a long time.  And everybody, LLM or person, is able to work
better if we keep the code clean and to a high standard to start with.

Even if your instructions don't include specific admonishment about quality, it is always
necessary.

Our work should follow the existing usage of apis in the project as much as possible.

## Interacting

We will be working on the same sources, do not build into ./build since I will be using it; make
your own ./build-agy or whatever.

Use cmake .. --fresh in order to force the build dir to align with your options no matter what
was in there before.

While the idea is you should modify and test sources towards some goal, please do NOT modify the
git state unless directly asked.

Often although we are working on the same sources, they are being tested on devices you don't have
access to.  So you must ask for access to data state on those remote machines; looking at the local
machine you are running on for config or data state directly is of zero use in those circumstances.

## Completeness

If you are unable to complete something your coding partner expects from the interaction
with you, you must clearly explain to the user which parts are incomplete in this phase and need
further work.  DO NOT leave it silently incomplete and act like it is done without making the
situation crystal clear to your partner.

Often adding / modifying or removing features has a very strong expectation that you will
also take responsibility about certain side-effects.  For example, adding a switch to a
minimal example always means modifying the associated --help and the example's markdown
accordingly.  If we add significant new code, it must also bring with it api-test or other
example code to confirm it works properly.  These side-effects are expected to be taken
care of in the same phase of work, not "later", and even if not explicitly requested.

## Example code

The examples are not chaotic dumping grounds for trash.  They are supposed to show the user
the best way we know how to do things, that they can use in their own code reliably.  We
should make an extra effort to keep them clean and as quality exemplars.

## Coding

We are very concerned about security, architecturally and in the code.  We avoid using:

 - things like `scanf` for carefully parsing with code, eg with `lws_tokenize` or similar.

 - `FILE *` and use apis like open(), read().

 - casual linked-lists and use `lws_dll2_t`.

We consider using:

 - lwsac instead of discrete allocations, if the pattern of allocations will benefit from it.

 - lws_struct to convert between sqlite storage <-> structs <-> JSON

We are very concerned about portability and all builds occur with -Werror -Wall -Wextra.

## Appropriate locality

Sometimes we might work on things that are going to be more useful, or better suited for users,
if we adapt the code eg, to live in the library, or sometimes live outside the library.  If it
makes sense it's possible.

## Build dimensions

Lws is unusual in that

 - we address a lot of build options in CI, things like will it build and run with no logs at all,
   without client support, without server support and so on.  So code won't pass CI unless it
   takes care about its parts in common code protecting themselves with preprocessor options.

 - we support a lot of platforms in CI.  Code won't pass CI unless it takes care about the spread
   of platforms it will be tested on, eg, things that are platform-specific should go in lib/plat
   and for "not quite standard" platforms like POSIX on windows, we have to carefully use helpers
   like `LWS_POSIX_LENGTH_CAST()` as glue to fill the differences where needed.

## Security

Please bear in mind:

 - which parts of the system are secrets, and look after the security of them.
 - all external data is untrusted and should be assumed to be part of an attack until
   we have validated it to be within a range and type we expect and can safely consume.

 - all web pieces are served with a strict CSP.  That means ** no inline styles or scripts ** .
   You can usually find the web pieces (JS, HTML, css) in ./assets/

 - Before a vuln is found, you would have failed to take care about it.  Keep in mind
   common vuln patterns and avoid them in new code so nobody has to find your vuln.

## Build testing

If we are adding code to core lws library, if it's anything nontrivial we should think about adding an api test
or minimal example down ./minimal-example-lowlevel, or ./minimal-example if it's related to Secure Streams.

The api test or example should be executed from it's CMakeLists.txt with ctest.  It should be able to run
cross-platform, and not include shellscripts, instead use cmake / ctest commands that resolve to appropriate
commands for the platform.

minimal-examples-lowlevel/http-client/minimal-http-client-post/CMakeLists.txt shows how to use the fixtures
stuff to magic peers into being while being sensitive to parallel CI using a CMake unique socket allocator
function to make unique ports.

In the case you can build and run ctest meaningfully, please do confirm the build passes before completing
work on your goal.  Use parallel builds and eg, ctest -j8 to reduce the cost in realtime.
