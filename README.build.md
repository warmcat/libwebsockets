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

@section cmq Quirk of cmake

When changing cmake options, for some reason the only way to get it to see the
changes sometimes is delete the contents of your build directory and do the
cmake from scratch.


@section cmw Building on Windows (Visual Studio)

1. Install CMake 2.6 or greater: http://cmake.org/cmake/resources/software.html

2. Install OpenSSL binaries. http://www.openssl.org/related/binaries.html

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

   a) (32-bit) Add the following lines to C:\MinGW\include\winsock2.h:
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

       (64 bit)  Update crtdefs.h line 47 to say:

```
	typedef __int64 ssize_t;
```

   b) Create C:\MinGW\include\mstcpip.h and copy and paste the content from following link into it:
    
   (32-bit) http://wine-unstable.sourcearchive.com/documentation/1.1.32/mstcpip_8h-source.html
   (64-bit) https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-headers/include/mstcpip.h

3. Install CMake 2.6 or greater: http://cmake.org/cmake/resources/software.html

4. Install OpenSSL binaries. http://www.openssl.org/related/binaries.html

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
	cmake .. -DLWS_USE_WOLFSSL=1 \
		 -DLWS_WOLFSSL_INCLUDE_DIRS=/path/to/wolfssl \
		 -DLWS_WOLFSSL_LIBRARIES=/path/to/wolfssl/wolfssl.a ..
```

**NOTE**: On windows use the .lib file extension for `LWS_WOLFSSL_LIBRARIES` instead.

@section cya Compiling libwebsockets with CyaSSL

```
	cmake .. -DLWS_USE_CYASSL=1 \
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


@section http2rp Reproducing HTTP2.0 tests

You must have built and be running lws against a version of openssl that has
ALPN / NPN.  Most distros still have older versions.  You'll know it's right by
seeing
```
	lwsts[4752]:  Compiled with OpenSSL support
	lwsts[4752]:  Using SSL mode
	lwsts[4752]:  HTTP2 / ALPN enabled
```
at lws startup.

For non-SSL HTTP2.0 upgrade
```
	$ nghttp -nvasu http://localhost:7681/test.htm
```
For SSL / ALPN HTTP2.0 upgrade
```
	$ nghttp -nvas https://localhost:7681/test.html
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
	$ cmake .. -DCMAKE_INSTALL_PREFIX:PATH=/usr \
		 -DCMAKE_TOOLCHAIN_FILE=../cross-arm-linux-gnueabihf.cmake \
		 -DLWS_WITHOUT_EXTENSIONS=1 -DLWS_WITH_SSL=0
```
The example shows how to build with no external cross lib dependencies, you
need to provide the cross libraries otherwise.

**NOTE**: start from an EMPTY build directory if you had a non-cross build in there
	before the settings will be cached and your changes ignored.

Additional information on cross compilation with CMake:
	http://www.vtk.org/Wiki/CMake_Cross_Compiling

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
