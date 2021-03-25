## lsquic WIP

 - Status is prealpha, obviously it is off by default in cmake.

 - Building it requires borningssl and lsquic built separately

 - Event loop is integrated to lws generic one (should work with event libs too)

 - Scheduler is integrated to `lws_sul`, including udp retries

 - DNS lookup action is not integrated with lws stateful one, it uses lsquic blocking one

 - Tx headers are partly wired up to client info struct

 - Rx headers (from server) are parsed by h1 parser on reconstituted qpack -> h1 headers,
   so these are actually wired up for the h1 header set anyway

 - minimal-http-client can do h3 GET from www.google.com/ over h3 with --lsq --server www.google.com

 - ss-h3 SS support is wired up (wire protocol "h3" in the policy), an SS minimal example
   is provided that can GET from www.google.com/ over h3 and control and consume it via
   a normal SS streamtype with normal states coming.


## Step 1: build boringssl

lsquic requires borningssl atm.

Boringssl is pretty ugly to work with.

1) It won't build on current Fedora without hacks
2) Fips pieces won't build even with hacks
3) It has CMake, but no install info provided, so no make install!
4) It completely conflicts with openssl on the same box, same libssl.so, libcrypto.so,
   same exports (more or less) same <openssl/xxx> include namespace

clone it from github

```
$ git clone https://github.com/google/boringssl.git
```

Apply hack needed to build on Fedora 34

```
$ diff --git a/CMakeLists.txt b/CMakeLists.txt
index f58e853cd..cd20c1012 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -117,7 +117,7 @@ endif()
 if(CMAKE_COMPILER_IS_GNUCXX OR CLANG)
   # Note clang-cl is odd and sets both CLANG and MSVC. We base our configuration
   # primarily on our normal Clang one.
-  set(C_CXX_FLAGS "-Werror -Wformat=2 -Wsign-compare -Wmissing-field-initializers -Wwrite-strings -Wvla")
+  set(C_CXX_FLAGS " -Wformat=2 -Wsign-compare -Wmissing-field-initializers -Wwrite-strings -Wvla")
   if(MSVC)
     # clang-cl sets different default warnings than clang. It also treats -Wall
     # as -Weverything, to match MSVC. Instead -W3 is the alias for -Wall.
@@ -517,7 +517,7 @@ if(USE_CUSTOM_LIBCXX)
   # CMAKE_CXX_FLAGS ends up in the linker flags as well, so use
   # add_compile_options. There does not appear to be a way to set
   # language-specific compile-only flags.
-  add_compile_options("-nostdinc++")
+  add_compile_options("-nostdinc++ -Wno-stringop-overflow")
   set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -nostdlib++")
   include_directories(
     SYSTEM
diff --git a/crypto/fipsmodule/bn/internal.h b/crypto/fipsmodule/bn/internal.h
index 623e0c6e7..3d368db06 100644
--- a/crypto/fipsmodule/bn/internal.h
+++ b/crypto/fipsmodule/bn/internal.h
@@ -297,7 +297,7 @@ void bn_mul_comba4(BN_ULONG r[8], const BN_ULONG a[4], const BN_ULONG b[4]);
 void bn_mul_comba8(BN_ULONG r[16], const BN_ULONG a[8], const BN_ULONG b[8]);
 
 // bn_sqr_comba8 sets |r| to |a|^2.
-void bn_sqr_comba8(BN_ULONG r[16], const BN_ULONG a[4]);
+void bn_sqr_comba8(BN_ULONG r[16], const BN_ULONG a[8]);
 
 // bn_sqr_comba4 sets |r| to |a|^2.
 void bn_sqr_comba4(BN_ULONG r[8], const BN_ULONG a[4]);
```

Build it

```
$ mkdir build ; cd build
$ cmake .. -DBUILD_SHARED_LIBS=1 -DFIPS=0 -DFIPS_SHARED=0
$ make -j12
```

There's no make install!  Have to bind from the build dir :-/

## Step 2: build lsquic

Quality seems pretty good, it has a couple of warnings on Fedora

```
$ git clone https://github.com/litespeedtech/lsquic.git
$ cs lsquic
$ git submodule init
$ git submodule update
$ mkdir build ; cd build
$ cmake .. -DLSQUIC_SHARED_LIB=1 -DBORINGSSL_INCLUDE=/projects/boringssl/include -DBORINGSSL_LIB='/projects/boringssl/build' -DZLIB_LIB=/usr/lib64/libz.so.1 -DLSQUIC_BIN=0 -DLSQUIC_TESTS=0
$ make -j 12 && sudo make install
```

## Step 3: build lws

```
$ cmake .. -DLWS_WITH_BORINGSSL=1 -DLWS_OPENSSL_INCLUDE_DIRS=/projects/boringssl/include '-DLWS_OPENSSL_LIBRARIES=/projects/boringssl/build/ssl/libssl.so;/projects/boringssl/build/crypto/libcrypto.so' -DLWS_WITH_MINIMAL_EXAMPLES=1 -DLWS_WITH_LSQUIC=1 -DLWS_WITH_SECURE_STREAMS=1
$ make -j12 && ./bin/lws-minimal-http-client --lsq --server www.google.com
$ ./bin/lws-minimal-secure-streams-h3 
``` 




