Notes about building lws
========================


@section cm Introduction to CMake

CMake is a multi-platform build tool that can generate build files for many
different target platforms. See more info at http://www.cmake.org

CMake also allows/recommends you to do "out of source"-builds, that is,
the build files are separated from your sources, so there is no need to
create elaborate clean scripts to get a clean source tree, instead you
simply remove your build directory.

Libwebsockets has been tested to build successfully on the following platforms
with SSL support (for OpenSSL/wolfSSL/BoringSSL):

- Windows (Visual Studio)
- Windows (MinGW)
- Linux (x86 and ARM)
- OSX
- NetBSD


@section build1 Building the library and test apps

The project settings used by CMake to generate the platform specific build
files is called [CMakeLists.txt](CMakeLists.txt). CMake then uses one of its "Generators" to
output a Visual Studio project or Make file for instance. To see a list of
the available generators for your platform, simply run the "cmake" command.

Note that by default OpenSSL will be linked, if you don't want SSL support
see below on how to toggle compile options.


@section bu Building on Unix:

1. Install CMake 2.8 or greater: http://cmake.org/cmake/resources/software.html
   (Most Unix distributions comes with a packaged version also)

2. Install OpenSSL.

3. Generate the build files (default is Make files):
```
        $ cd /path/to/src
        $ mkdir build
        $ cd build
        $ cmake ..
```

4. Finally you can build using the generated Makefile:
```
	$ make && sudo make install
```
**NOTE**: The `build/`` directory can have any name and be located anywhere
 on your filesystem, and that the argument `..` given to cmake is simply
 the source directory of **libwebsockets** containing the [CMakeLists.txt](CMakeLists.txt)
 project file. All examples in this file assumes you use ".."

**NOTE2**:
A common option you may want to give is to set the install path, same
as --prefix= with autotools.  It defaults to /usr/local.
You can do this by, eg
```
	$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .
```

**NOTE3**:
On machines that want libraries in lib64, you can also add the
following to the cmake line
```
	-DLIB_SUFFIX=64
```

**NOTE4**:
If you are building against a non-distro OpenSSL (eg, in order to get
access to ALPN support only in newer OpenSSL versions) the nice way to
express that in one cmake command is eg,
```
	$ cmake .. -DOPENSSL_ROOT_DIR=/usr/local/ssl \
		 -DCMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE=/usr/local/ssl \
		 -DLWS_WITH_HTTP2=1
```

When you run the test apps using non-distro SSL, you have to force them
to use your libs, not the distro ones
```
	$ LD_LIBRARY_PATH=/usr/local/ssl/lib libwebsockets-test-server --ssl
```

To get it to build on latest openssl (2016-04-10) it needed this approach
```
	cmake .. -DLWS_WITH_HTTP2=1 -DLWS_OPENSSL_INCLUDE_DIRS=/usr/local/include/openssl -DLWS_OPENSSL_LIBRARIES="/usr/local/lib64/libssl.so;/usr/local/lib64/libcrypto.so"
```

Mac users have reported

```
 $ export OPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2k; cmake ..; make -j4
```

worked for them when using "homebrew" OpenSSL

**NOTE5**:
To build with debug info and _DEBUG for lower priority debug messages
compiled in, use
```
	$ cmake .. -DCMAKE_BUILD_TYPE=DEBUG
```

**NOTE6**
To build on Solaris the linker needs to be informed to use lib socket
and libnsl, and only builds in 64bit mode.

```bash
	$ cmake .. -DCMAKE_C_FLAGS=-m64 -DCMAKE_EXE_LINKER_FLAGS="-lsocket -lnsl"
```

4. Finally you can build using the generated Makefile:

```bash
	$ make
 ```

@section lcap Linux Capabilities

On Linux, lws now lets you retain selected root capabilities when dropping
privileges.  If libcap-dev or similar package is installed providing
sys/capabilities.h, and libcap or similar package is installed providing
libcap.so, CMake will enable the capability features.

The context creation info struct .caps[] and .count_caps members can then
be set by user code to enable selected root capabilities to survive the
transition to running under an unprivileged user.

@section cmq Quirk of cmake

When changing cmake options, for some reason the only way to get it to see the
changes sometimes is delete the contents of your build directory and do the
cmake from scratch.

deleting build/CMakeCache.txt may be enough.


@section cmw Building on Windows (Visual Studio)

1. Install CMake 2.6 or greater: http://cmake.org/cmake/resources/software.html

2. Install OpenSSL binaries. https://wiki.openssl.org/index.php/Binaries

   (**NOTE**: Preferably in the default location to make it easier for CMake to find them)

   **NOTE2**: 
   Be sure that OPENSSL_CONF environment variable is defined and points at 
   <OpenSSL install location>\bin\openssl.cfg
	 
3. Generate the Visual studio project by opening the Visual Studio cmd prompt:

```
	cd <path to src>
	md build
	cd build
	cmake -G "Visual Studio 10" ..
```

   (**NOTE**: There is also a cmake-gui available on Windows if you prefer that)
   
   **NOTE2**:
   See this link to find out the version number corresponding to your Visual Studio edition:
   http://superuser.com/a/194065

4. Now you should have a generated Visual Studio Solution in  your
   `<path to src>/build` directory, which can be used to build.

5. Some additional deps may be needed

 - iphlpapi.lib
 - psapi.lib
 - userenv.lib

6. If you're using libuv, you must make sure to compile libuv with the same multithread-dll / Mtd attributes as libwebsockets itself


@section cmwmgw Building on Windows (MinGW)

1. Install MinGW: http://sourceforge.net/projects/mingw/files

   (**NOTE**: Preferably in the default location C:\MinGW)

2. Fix up MinGW headers

   a) If still necessary, sdd the following lines to C:\MinGW\include\winsock2.h:
```
	#if(_WIN32_WINNT >= 0x0600)

	typedef struct pollfd {

		SOCKET  fd;
		SHORT   events;
		SHORT   revents;

	} WSAPOLLFD, *PWSAPOLLFD, FAR *LPWSAPOLLFD;

	WINSOCK_API_LINKAGE int WSAAPI WSAPoll(LPWSAPOLLFD fdArray, ULONG fds, INT timeout);

	#endif // (_WIN32_WINNT >= 0x0600)
```

       Update crtdefs.h line 47 to say:

```
	typedef __int64 ssize_t;
```

   b) Create C:\MinGW\include\mstcpip.h and copy and paste the content from following link into it:

   https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-headers/include/mstcpip.h

3. Install CMake 2.6 or greater: http://cmake.org/cmake/resources/software.html

4. Install OpenSSL binaries. https://wiki.openssl.org/index.php/Binaries

   (**NOTE**: Preferably in the default location to make it easier for CMake to find them)

   **NOTE2**: 
   Be sure that OPENSSL_CONF environment variable is defined and points at 
   <OpenSSL install location>\bin\openssl.cfg

5. Generate the build files (default is Make files) using MSYS shell:
```
	$ cd /drive/path/to/src
	$ mkdir build
	$ cd build
	$ cmake -G "MSYS Makefiles" -DCMAKE_INSTALL_PREFIX=C:/MinGW ..
```
   (**NOTE**: The `build/`` directory can have any name and be located anywhere
    on your filesystem, and that the argument `..` given to cmake is simply
    the source directory of **libwebsockets** containing the [CMakeLists.txt](CMakeLists.txt)
    project file. All examples in this file assumes you use "..")

   **NOTE2**:
   To generate build files allowing to create libwebsockets binaries with debug information
   set the CMAKE_BUILD_TYPE flag to DEBUG:
```
	$ cmake -G "MSYS Makefiles" -DCMAKE_INSTALL_PREFIX=C:/MinGW -DCMAKE_BUILD_TYPE=DEBUG ..
```
6. Finally you can build using the generated Makefile and get the results deployed into your MinGW installation:

```
	$ make
	$ make install
```

@section optee Building for OP-TEE

OP-TEE is a "Secure World" Trusted Execution Environment.

Although lws is only part of the necessary picture to have an https-enabled
TA, it does support OP-TEE as a platform and if you provide the other
pieces, does work very well.

Select it in cmake with `-DLWS_PLAT_OPTEE=1`


@section cmco Setting compile options

To set compile time flags you can either use one of the CMake gui applications
or do it via the command line.

@subsection cmcocl Command line

To list available options (omit the H if you don't want the help text):

	cmake -LH ..

Then to set an option and build (for example turn off SSL support):

	cmake -DLWS_WITH_SSL=0 ..
or
	cmake -DLWS_WITH_SSL:BOOL=OFF ..

@subsection cmcoug Unix GUI

If you have a curses-enabled build you simply type:
(not all packages include this, my debian install does not for example).

	ccmake

@subsection cmcowg Windows GUI

On windows CMake comes with a gui application:
	Start -> Programs -> CMake -> CMake (cmake-gui)


@section wolf wolfSSL/CyaSSL replacement for OpenSSL

wolfSSL/CyaSSL is a lightweight SSL library targeted at embedded systems:
https://www.wolfssl.com/wolfSSL/Products-wolfssl.html

It contains a OpenSSL compatibility layer which makes it possible to pretty
much link to it instead of OpenSSL, giving a much smaller footprint.

**NOTE**: wolfssl needs to be compiled using the `--enable-opensslextra` flag for
this to work.

@section wolf1 Compiling libwebsockets with wolfSSL

```
	cmake .. -DLWS_WITH_WOLFSSL=1 \
		 -DLWS_WOLFSSL_INCLUDE_DIRS=/path/to/wolfssl \
		 -DLWS_WOLFSSL_LIBRARIES=/path/to/wolfssl/wolfssl.a ..
```

**NOTE**: On windows use the .lib file extension for `LWS_WOLFSSL_LIBRARIES` instead.

@section cya Compiling libwebsockets with CyaSSL

```
	cmake .. -DLWS_WITH_CYASSL=1 \
		 -DLWS_CYASSL_INCLUDE_DIRS=/path/to/cyassl \
		 -DLWS_CYASSL_LIBRARIES=/path/to/wolfssl/cyassl.a ..
```

**NOTE**: On windows use the .lib file extension for `LWS_CYASSL_LIBRARIES` instead.

@section esp32 Building for ESP32

Step 1, get ESP-IDF with lws integrated as a component

```
    $ git clone --int --recursive https://github.com/lws-team/lws-esp-idf
```

Step 2: Get Application including the test plugins

```
    $ git clone https://github.com/lws-team/lws-esp32
```

Set your IDF_PATH to point to the esp-idf you downloaded in 1)

There's docs for how to build the lws-esp32 test app and reproduce it in the README.md here

https://github.com/lws-team/lws-esp32/blob/master/README.md


@section extplugins Building plugins outside of lws itself

The directory ./plugin-standalone/ shows how easy it is to create plugins
outside of lws itself.  First build lws itself with -DLWS_WITH_PLUGINS,
then use the same flow to build the standalone plugin
```
	cd ./plugin-standalone
	mkdir build
	cd build
	cmake ..
	make && sudo make install
```

if you changed the default plugin directory when you built lws, you must
also give the same arguments to cmake here (eg,
` -DCMAKE_INSTALL_PREFIX:PATH=/usr/something/else...` )

Otherwise if you run lwsws or libwebsockets-test-server-v2.0, it will now
find the additional plugin "libprotocol_example_standalone.so"
```
	lwsts[21257]:   Plugins:
	lwsts[21257]:    libprotocol_dumb_increment.so
	lwsts[21257]:    libprotocol_example_standalone.so
	lwsts[21257]:    libprotocol_lws_mirror.so
	lwsts[21257]:    libprotocol_lws_server_status.so
	lwsts[21257]:    libprotocol_lws_status.so
```
If you have multiple vhosts, you must enable plugins at the vhost
additionally, discovered plugins are not enabled automatically for security
reasons.  You do this using info->pvo or for lwsws, in the JSON config.


@section http2rp Reproducing HTTP/2 tests

Enable `-DLWS_WITH_HTTP2=1` in cmake to build with http/2 support enabled.

You must have built and be running lws against a version of openssl that has
ALPN.  At the time of writing, recent distros have started upgrading to OpenSSL
1.1+ that supports this already.  You'll know it's right by seeing

```
	lwsts[4752]:  Compiled with OpenSSL support
	lwsts[4752]:  Using SSL mode
	lwsts[4752]:  HTTP2 / ALPN enabled
```
at lws startup.

Recent Firefox and Chrome also support HTTP/2 by ALPN, so these should just work
with the test server running in -s / ssl mode.

For testing with nghttp client:

```
	$ nghttp -nvas https://localhost:7681/test.html
```

Testing with h2spec (https://github.com/summerwind/h2spec)

```
        $ h2spec  -h 127.0.0.1 -p 7681 -t -k -v -o 1
```

At the time of writing, http/2 support is not fully complete; however all the
h2spec tests pass.

```
145 tests, 144 passed, 1 skipped, 0 failed

```


@section cross Cross compiling

To enable cross-compiling **libwebsockets** using CMake you need to create
a "Toolchain file" that you supply to CMake when generating your build files.
CMake will then use the cross compilers and build paths specified in this file
to look for dependencies and such.

**Libwebsockets** includes an example toolchain file [cross-arm-linux-gnueabihf.cmake](cross-arm-linux-gnueabihf.cmake)
you can use as a starting point.

The commandline to configure for cross with this would look like
```
	$ cmake .. -DCMAKE_INSTALL_PREFIX:PATH=/usr/lib/my-cross-root \
		 -DCMAKE_TOOLCHAIN_FILE=../contrib/cross-arm-linux-gnueabihf.cmake \
		 -DLWS_WITHOUT_EXTENSIONS=1 -DLWS_WITH_SSL=0 \
		 -DLWS_WITH_ZIP_FOPS=0 -DLWS_WITH_ZLIB=0
```
The example shows how to build with no external cross lib dependencies, you
need to provide the cross libraries otherwise.

**NOTE**: start from an EMPTY build directory if you had a non-cross build in there
	before the settings will be cached and your changes ignored.
	Delete `build/CMakeCache.txt` at least before trying a new cmake config
	to ensure you are really building the options you think you are.

Additional information on cross compilation with CMake:
	http://www.vtk.org/Wiki/CMake_Cross_Compiling

@section cross_example Complex Cross compiling example

Here are step by step instructions for cross-building the external projects needed for lws with lwsws + mbedtls as an example.

In the example, my toolchain lives in `/projects/aist-tb/arm-tc` and is named `arm-linux-gnueabihf`.  So you will need to adapt those to where your toolchain lives and its name where you see them here.

Likewise I do all this in /tmp but it has no special meaning, you can adapt that to somewhere else.

All "foreign" cross-built binaries are sent into `/tmp/cross` so they cannot be confused for 'native' x86_64 stuff on your host machine in /usr/[local/]....

## Prepare the cmake toolchain file

1) `cd /tmp`

2) `wget -O mytoolchainfile https://raw.githubusercontent.com/warmcat/libwebsockets/master/contrib/cross-arm-linux-gnueabihf.cmake` 

3) Edit `/tmp/mytoolchainfile` adapting `CROSS_PATH`, `CMAKE_C_COMPILER` and `CMAKE_CXX_COMPILER` to reflect your toolchain install dir and path to your toolchain C and C++ compilers respectively.  For my case:

```
set(CROSS_PATH /projects/aist-tb/arm-tc/)
set(CMAKE_C_COMPILER "${CROSS_PATH}/bin/arm-linux-gnueabihf-gcc")
set(CMAKE_CXX_COMPILER "${CROSS_PATH}/bin/arm-linux-gnueabihf-g++")
```

## 1/4: Building libuv cross:

1) `export PATH=/projects/aist-tb/arm-tc/bin:$PATH`  Notice there is a **/bin** on the end of the toolchain path

2) `cd /tmp ; mkdir cross` we will put the cross-built libs in /tmp/cross

3) `git clone https://github.com/libuv/libuv.git` get libuv

4) `cd libuv`

5) `./autogen.sh`

```
+ libtoolize --copy
libtoolize: putting auxiliary files in '.'.
libtoolize: copying file './ltmain.sh'
libtoolize: putting macros in AC_CONFIG_MACRO_DIRS, 'm4'.
libtoolize: copying file 'm4/libtool.m4'
libtoolize: copying file 'm4/ltoptions.m4'
libtoolize: copying file 'm4/ltsugar.m4'
libtoolize: copying file 'm4/ltversion.m4'
libtoolize: copying file 'm4/lt~obsolete.m4'
+ aclocal -I m4
+ autoconf
+ automake --add-missing --copy
configure.ac:38: installing './ar-lib'
configure.ac:25: installing './compile'
configure.ac:22: installing './config.guess'
configure.ac:22: installing './config.sub'
configure.ac:21: installing './install-sh'
configure.ac:21: installing './missing'
Makefile.am: installing './depcomp'
```
If it has problems, you will need to install `automake`, `libtool` etc.

6) `./configure  --host=arm-linux-gnueabihf --prefix=/tmp/cross`

7) `make && make install` this will install to `/tmp/cross/...`

8) `file /tmp/cross/lib/libuv.so.1.0.0`  Check it's really built for ARM
```
/tmp/cross/lib/libuv.so.1.0.0: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, BuildID[sha1]=cdde0bc945e51db6001a9485349c035baaec2b46, with debug_info, not stripped
```

## 2/4: Building zlib cross

1) `cd /tmp`

2) `git clone https://github.com/madler/zlib.git`

3) `CC=arm-linux-gnueabihf-gcc ./configure --prefix=/tmp/cross`
```
Checking for shared library support...
Building shared library libz.so.1.2.11 with arm-linux-gnueabihf-gcc.
Checking for size_t... Yes.
Checking for off64_t... Yes.
Checking for fseeko... Yes.
Checking for strerror... Yes.
Checking for unistd.h... Yes.
Checking for stdarg.h... Yes.
Checking whether to use vs[n]printf() or s[n]printf()... using vs[n]printf().
Checking for vsnprintf() in stdio.h... Yes.
Checking for return value of vsnprintf()... Yes.
Checking for attribute(visibility) support... Yes.
```

4)  `make && make install`
```
arm-linux-gnueabihf-gcc -O3 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o example.o test/example.c
...
rm -f /tmp/cross/include/zlib.h /tmp/cross/include/zconf.h
cp zlib.h zconf.h /tmp/cross/include
chmod 644 /tmp/cross/include/zlib.h /tmp/cross/include/zconf.h
```

5) `file /tmp/cross/lib/libz.so.1.2.11`  This is just to confirm we built an ARM lib as expected
```
/tmp/cross/lib/libz.so.1.2.11: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, BuildID[sha1]=6f8ffef84389b1417d2fd1da1bd0c90f748f300d, with debug_info, not stripped
```

## 3/4: Building mbedtls cross

1) `cd /tmp`

2) `git clone https://github.com/ARMmbed/mbedtls.git`

3) `cd mbedtls ; mkdir build ; cd build`

3) `cmake .. -DCMAKE_TOOLCHAIN_FILE=/tmp/mytoolchainfile -DCMAKE_INSTALL_PREFIX:PATH=/tmp/cross -DUSE_SHARED_MBEDTLS_LIBRARY=1`  mbedtls also uses cmake, so you can simply reuse the toolchain file you used for libwebsockets.  That is why you shouldn't put project-specific options in the toolchain file, it should just describe the toolchain.

4) `make && make install`

5) `file /tmp/cross/lib/libmbedcrypto.so.2.6.0`
```
/tmp/cross/lib/libmbedcrypto.so.2.6.0: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, BuildID[sha1]=bcca195e78bd4fd2fb37f36ab7d72d477d609d87, with debug_info, not stripped
```

## 4/4: Building libwebsockets with everything

1) `cd /tmp`

2) `git clone ssh://git@github.com/warmcat/libwebsockets`

3) `cd libwebsockets ; mkdir build ; cd build`

4)  (this is all one line on the commandline)
```
cmake .. -DCMAKE_TOOLCHAIN_FILE=/tmp/mytoolchainfile \
-DCMAKE_INSTALL_PREFIX:PATH=/tmp/cross \
-DLWS_WITH_LWSWS=1 \
-DLWS_WITH_MBEDTLS=1 \
-DLWS_MBEDTLS_LIBRARIES="/tmp/cross/lib/libmbedcrypto.so;/tmp/cross/lib/libmbedtls.so;/tmp/cross/lib/libmbedx509.so" \
-DLWS_MBEDTLS_INCLUDE_DIRS=/tmp/cross/include \
-DLWS_LIBUV_LIBRARIES=/tmp/cross/lib/libuv.so \
-DLWS_LIBUV_INCLUDE_DIRS=/tmp/cross/include \
-DLWS_ZLIB_LIBRARIES=/tmp/cross/lib/libz.so \
-DLWS_ZLIB_INCLUDE_DIRS=/tmp/cross/include
```

3) `make && make install`

4) `file /tmp/cross/lib/libwebsockets.so.11`
```
/tmp/cross/lib/libwebsockets.so.11: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, BuildID[sha1]=81e59c6534f8e9629a9fc9065c6e955ce96ca690, with debug_info, not stripped
```

5) `arm-linux-gnueabihf-objdump -p /tmp/cross/lib/libwebsockets.so.11 | grep NEEDED`  Confirm that the lws library was linked against everything we expect (libm / libc are provided by your toolchain)
```
  NEEDED               libz.so.1
  NEEDED               libmbedcrypto.so.0
  NEEDED               libmbedtls.so.10
  NEEDED               libmbedx509.so.0
  NEEDED               libuv.so.1
  NEEDED               libm.so.6
  NEEDED               libc.so.6
```

You will also find the lws test apps in `/tmp/cross/bin`... to run lws on the target you will need to copy the related things from /tmp/cross... all the .so from /tmp/cross/lib and anything from /tmp/cross/bin you want.

@section mem Memory efficiency

Embedded server-only configuration without extensions (ie, no compression
on websocket connections), but with full v13 websocket features and http
server, built on ARM Cortex-A9:

Update at 8dac94d (2013-02-18)
```
	$ ./configure --without-client --without-extensions --disable-debug --without-daemonize

	Context Creation, 1024 fd limit[2]:   16720 (includes 12 bytes per fd)
	Per-connection [3]:                      72 bytes, +1328 during headers

	.text	.rodata	.data	.bss
	11512	2784	288	4
```
This shows the impact of the major configuration with/without options at
13ba5bbc633ea962d46d using Ubuntu ARM on a PandaBoard ES.

These are accounting for static allocations from the library elf, there are
additional dynamic allocations via malloc.  These are a bit old now but give
the right idea for relative "expense" of features.

Static allocations, ARM9

|                                | .text   | .rodata | .data | .bss |
|--------------------------------|---------|---------|-------|------|
| All (no without)               | 35024   | 9940    | 336   | 4104 |
| without client                 | 25684   | 7144    | 336   | 4104 |
| without client, exts           | 21652   | 6288    | 288   | 4104 |
| without client, exts, debug[1] | 19756   | 3768    | 288   | 4104 |
| without server                 | 30304   | 8160    | 336   | 4104 |
| without server, exts           | 25382   | 7204    | 288   | 4104 |
| without server, exts, debug[1] | 23712   | 4256    | 288   | 4104 |

[1] `--disable-debug` only removes messages below `lwsl_notice`.  Since that is
the default logging level the impact is not noticeable, error, warn and notice
logs are all still there.

[2] `1024` fd per process is the default limit (set by ulimit) in at least Fedora
and Ubuntu.  You can make significant savings tailoring this to actual expected
peak fds, ie, at a limit of `20`, context creation allocation reduces to `4432 +
240 = 4672`)

[3] known header content is freed after connection establishment
