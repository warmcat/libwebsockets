# lws AGENTS.md

## Overview

Please make high quality, not lazy, implementation decisions, because the code will have to be
maintained for a long time.  And everybody, LLM or person, is able to work better if we keep
the code clean and to a high standard to start with.

Our work should follow the existing usage of apis in the project as much as possible.

## Coding

We avoid things like `scanf` for carefully parsing with code, eg with `lws_tokenize` or similar.

We avoid `FILE *` and use apis like open(), read().

We avoid casual linked-lists and use `lws_dll2_t`.

We consider using lwsac instead of discrete allocations, if the pattern of allocations will benefit from it.

We consider using lws_struct to convert between sqlite storage <-> structs <-> JSON

## Appropriate locality

Sometimes we might work on things that are going to be more useful, or better suited for users,
if we adapt the code eg, to live in the library, or sometimes live outside the library.  If it
makes sense it's possible.

## Security

Please bear in mind what parts of the system are secrets and look after the security of them.

In particular, all web pieces are made available on the internet with a strict CSP.  That means
no inline styles or scripts.  You can find the web pieces (JS, HTML, css) in ./assets/

## Build testing

If we are adding code to core lws library, if it's anything nontrivial we should think about adding an api test
or minimal example down ./minimal-example-lowlevel, or ./minimal-example if it's related to Secure Streams.

The api test or example should be executed from it's CMakeLists.txt with ctest.  It should be able to run
cross-platform, and not include shellscripts, instead use cmake / ctest commands that resolve to appropriate
commands for the platform.

minimal-examples-lowlevel/http-client/minimal-http-client-post/CMakeLists.txt shows how to use the fixtures
stuff to magic peers into being while being sensitive to parallel CI using `$ENV{SAI_INSTANCE_IDX}` to make
unique ports.
