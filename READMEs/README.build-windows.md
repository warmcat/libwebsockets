# Some notes for the windows jungle

This was how I compiled libwebsockets in windows March 2020.

## OpenSSL

### Installing prebuilt libs

I used the 1.1.1d (the latest) libs from here, as recommended on the OpenSSL site

[overbyte.eu](https:..wiki.overbyte.eu/wiki/index.php/ICS_Download#Download_OpenSSL_Binaries_.28required_for_SSL-enabled_components.29)

I had to use procmon64 (windows' strace) to establish that these libraries are
looking for a cert bundle at "C:\Program Files\Common Files\SSL\cert.pem"... it's not
included in the zip file from the above, so...

### Installing a cert bundle

You can get a trusted cert bundle from here

[drwetter/testssl cert bundle](https://raw.githubusercontent.com/drwetter/testssl.sh/3.1dev/etc/Microsoft.pem)

Save it into `C:\Program Files\Common Files\SSL\cert.pem` where openssl will be able to see it.

### Installing cmake

CMake have a windows installer thing downloadable from here

[cmake](https://cmake.org/download/)

after that you can use `cmake` from the terminal OK.

### Installing git

Visit the canonical git site to download their windows installer thing

[git](https://git-scm.com/download/win)

after that `git` from the terminal is working.

### Install the free "community" visual studio

You can do this through "windows store" by searching for "visual studio"

I installed as little as possible, we just want the C "C++" tools.

It still wouldn't link without the "mt" helper tool from the
huge windows SDK, so you have to install GB of that as well.

### Building

Somehow windows cmake seems slightly broken, some of the plugins and
examples are conditional on `if (NOT WIN32)`, but it configures them
anyway.  For this reason (it seems "only", it worked when I commented the
cmake entries for the related plugins) `-DLWS_WITH_MINIMAL_EXAMPLES=1`

Instead I followed how appveyor builds the stuff in CI... clone libwebsockets then

```
> git clone https://libwebsockets.org/repo/libwebsockets
> cd libwebsockets
> mkdir build
> cd build
> cmake ..
> cmake --build . --config DEBUG
```

Installing requires admin privs, I opened a second cmd window as admin and did it
there.

```
> cmake --install . --config DEBUG
```

After that you can run the test apps OK.

## pthreads

It's amazing but after all these years windows doesn't offer pthreads compatibility
itself.  Just like the many other missing POSIX bits like fork().

I downloaded the latest (2012) zip release of pthreads-win32 from here

ftp://sourceware.org/pub/pthreads-win32

Then I created a dir "C:\Program Files (x86)\pthreads", and copied the `dll`,
`include` and `lib` subdirs from the `prebuilt` folder in the zip there.

The cmake incantation to build against pthreads set up like that is

```
 $ cmake .. -DLWS_EXT_PTHREAD_INCLUDE_DIR="C:\Program Files (x86)\pthreads\include" -DLWS_EXT_PTHREAD_LIBRARIES="C:\Program Files (x86)\pthreads\lib\x64\libpthreadGC2.a" -DLWS_WITH_MINIMAL_EXAMPLES=1
```

