Debugging problems
==================

Library is a component
----------------------

As a library, lws is just a component in a bigger application.

Many users are able to share their sources, but others decide not to, for
"commerical advantage" or whatever.

This makes answering questions like "what is wrong with my code I am not
going to show you?" very difficult.

Even if it's clear there is a problem somewhere, it cannot be understood or
reproduced by anyone else if it needs user code that isn't provided.

The biggest question is, "is this an lws problem actually"?


Use the test apps as sanity checks
----------------------------------

The test server and client are extremely useful for sanity checks and debugging
guidance.

 - test apps work on your platform, then either
   - your user code is broken, align it to how the test apps work, or,
   - something from your code is required to show an lws problem, provide a
     minimal patch on a test app so it can be reproduced
     
 - test apps break on your platform, but work on, eg, x86_64, either
   - toolchain or platform-specific (eg, OS) issue, or
   - lws platform support issue

 - test apps break everywhere
   - sounds like lws problem, info to reproduce and / or a patch is appreciated
