## Using CTest with lws

### Updating ancient cmake

You need a recent cmake to have the CTest tests work properly, if you're on an
older distro you need to update your cmake.  Luckily Kitware provide a repo for
common distros.  These instructions work for bionic and xenial.

First remove the old distro cmake and install the pieces needed to get the new repo keys

```
# apt purge --auto-remove cmake
# apt install gnupg wget apt-transport-https ca-certificates
# wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | sudo apt-key add -
# apt edit-sources
```

Add the line `deb https://apt.kitware.com/ubuntu/ bionic main` at the end
replacing `bionic` with `xenial` as needed, and save (:wq).  Then

```
# apt update
# apt install cmake
```

## Generating the tests

The main tests just need `-DLWS_WITH_MINIMAL_EXAMPLES=1`.  You can optionally set
`-DLWS_CTEST_INTERNET_AVAILABLE=0` to indicate you can't run the tests that need
internet connectivity.

## Preparing to run the tests

The tests have to spawn by script some "test buddies", for example the client
tests have to run a test server from the built lws image.  For that reason you
have to do a side-install into `./destdir` using `make install DESTDIR=../destdir`
from the build directory before all the tests will work properly.

## Running the tests

CMake puts the test action into a build-host type specific form, for unix type
platforms you just run `make test` or `CTEST_OUTPUT_ON_FAILURE=1 make test` to
see what happened to any broken tests.

On windows, it looks like `ctest . -C DEBUG` or RELEASE if that was the build
type.

## Considerations for creating tests

### Timeout

The default test timeout is 1500s, for that reason it's good practice to set
a more suitable `TIMEOUT` property on every test.

### Working Directory

Server-side test apps usually need to be run from their `./minimal-examples/...`
directory so they can access their assets like index.html etc.

However when building with `-DLWS_WITH_MBEDTLS=1` then even client-side apps
need to be run from their directory, since they need to get the trusted CA for
warmcat.com or libwebsockets.org additionally.

For that reason it's good practice to set the `WORKING_DIRECTORY` property to
the home dir of the example app in all cases.


