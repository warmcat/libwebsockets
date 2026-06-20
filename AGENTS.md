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

If you are unable to complete something the user expects from the interaction with you, you
must clearly explain to the user which parts are incomplete and need further work.

## Coding

We are very concerned about security, architecturally and in the code.  We avoid using:

 - things like `scanf` for carefully parsing with code, eg with `lws_tokenize` or similar.

 - `FILE *` and use apis like open(), read().

 - casual linked-lists and use `lws_dll2_t`.

We consider using:

 - lwsac instead of discrete allocations, if the pattern of allocations will benefit from it.

 - lws_struct to convert between sqlite storage <-> structs <-> JSON

## Appropriate locality

Sometimes we might work on things that are going to be more useful, or better suited for users,
if we adapt the code eg, to live in the library, or sometimes live outside the library.  If it
makes sense it's possible.

## Security

Please bear in mind:

 - which parts of the system are secrets, and look after the security of them.
 - all external data is untrusted and should be assumed to be part of an attack until
   we have validated it to be within a range and type we expect and can safely consume.

 - all web pieces are served with a strict CSP.  That means ** no inline styles or scripts ** .
   You can usually find the web pieces (JS, HTML, css) in ./assets/

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
work on your goal.
