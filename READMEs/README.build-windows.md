# Some notes for the windows jungle

This was how I compiled libwebsockets starting from a blank windows install
in June 2025.  Doing this on a linux distro is way simpler and quicker
than all this!

## Notes on vm installation

### Disk size

For building you'll need 40GB+ available for the guest storage.

### Required: Windows product key

Assuming like me the first thing you do with a new laptop is install Linux over
the windows it came with, you can recover your 'windows tax' windows product key
from your device typically using `sudo strings /sys/firmware/acpi/tables/MSDM`,
and use that for your VM install.

### Required: Spice guest

Note: I wasn't able to get this to work on Windows 11

To have shared clipboard, and for windows video driver to match your vm window
resolution, you must install spice guest tools inside the windows VM.  It also
installs some virtio pieces you will want.

https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe

### Blood-pressure reduction: Firefox

https://www.mozilla.org/en-US/exp/firefox/

When it's up, add-ons: ublock origin, privacy badger, noscript, disable search
bar prediction

### Blood-pressure reduction: Clink

Note: I wasn't able to get this to work on Windows 11.

This is a hack on cmd.exe that lets it understand Ctrl-R and fixup unix-style
slashes automagically.

https://github.com/mridgers/clink/releases/download/0.4.9/clink_0.4.9_setup.exe

If you're usually using *nix, you definitely need this to keep your sanity.

### Required: cmake

CMake have a windows installer thing downloadable from here

[cmake](https://cmake.org/download/)

after that you can use `cmake` from the terminal OK.

### Required: git

Visit the canonical git site to download their windows installer thing

[git](https://git-scm.com/download/win)

**Select the install option for "extra unix commands"** so you can get `ls -l`,
`cp`, `mv` and suchlike working in cmd.exe... that's awesome, thanks git!

Afterwards you can just use `git` as normal from cmd.exe as well.

### Required: Install the "free" "community" visual studio

You can do this through "windows store" by searching for "visual studio"

I installed as little as possible, we just want the C "C++" tools... 7GB :-)

It still wouldn't link without the "mt" helper tool from the
huge windows SDK, so you have to install GB of that as well.

They don't mention it during the install, but after 30 days this "free"
"community" edition demands you open a microsoft account or it stops working.
In the install they give you the option to add a microsoft account and the
alternative is, "not now, maybe later".  Compare and contrast to gcc or git or
the other FOSS projects.

### Required: OpenSSL

Since I last did this, vcpkg has essentially wrapped the complicated build process.

```
> git clone https://github.com/microsoft/vcpkg
> vcpkg integrate install
> vcpkg install openssl:x64-windows 
```

It took 30 minutes to build the thing apparently in the same way that was previously
described here manually.

### Powershell

CMake wants it and the version that comes with windows is too old to have pwsh.exe.

```
> sudo winget install --id Microsoft.PowerShell --source winget
```

#### Installing a cert bundle

You can get a trusted cert bundle from here

[drwetter/testssl cert bundle](https://raw.githubusercontent.com/drwetter/testssl.sh/3.1dev/etc/Microsoft.pem)

Save it into `C:\Program Files\Common Files\SSL\cert.pem` where openssl will be able to see it.

## Required: pthreads

It's amazing but after all these years windows doesn't offer pthreads compatibility
itself.  Just like the many other missing POSIX bits like fork().

I downloaded the latest (2012) zip release of pthreads-win32 from here

ftp://sourceware.org/pub/pthreads-win32

Then I created a dir "C:\Program Files (x86)\pthreads", and copied the `dll`,
`include` and `lib` subdirs from the `prebuilt` folder in the zip there.

## Building libwebsockets

We'll clone libwebsockets then use cmake to build via vs tools

```
> git clone https://libwebsockets.org/repo/libwebsockets
> cd libwebsockets
> mkdir build
> cd build
> cmake .. -DLWS_HAVE_PTHREAD_H=1 -DLWS_EXT_PTHREAD_INCLUDE_DIR="C:\Program Files (x86)\pthreads\include" -DLWS_EXT_PTHREAD_LIBRARIES="C:\Program Files (x86)\pthreads\lib\x64\libpthreadGC2.a" -DOPENSSL_ROOT_DIR="c:\Users\<user>\vcpkg\packages\openssl_x64-windows"
> cmake --build . -j 4 --config DEBUG
```

Installing:

```
> sudo cmake --install . --config DEBUG
```

### Hack the libs into view

The libs we built against aren't visible in the system, I don't know what
Real Windows Programmers are supposed to do about that, but I used sudo
prompt to copy them into C:\windows\system32

```
> sudo copy "C:\Program Files (x86)\pthreads\dll\x64\pthreadGC2.dll" C:\Windows\system32
> sudo copy "c:\Users\<user>\vcpkg\packages\openssl_x64-windows\bin\libcrypto-3.dll" C:\Windows\system32
> sudo copy "c:\Users\<user>\vcpkg\packages\openssl_x64-windows\bin\libssl-3.dll" C:\Windows\system32
```

After that you can run the test apps OK, eg

```
$ libwebsockets-test-server.exe -s
```

## Note about using paths with spaces in with cmake


