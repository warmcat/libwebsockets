#!/bin/bash

#
# Build libwebsockets static library for Android
#

# path to NDK
export NDK=/opt/ndk_r17/android-ndk-r17-beta2-linux-x86_64/android-ndk-r17-beta2
export ANDROID_NDK=${NDK}
export TOOLCHAIN=${NDK}/toolchain
export CORSS_SYSROOT=${NDK}/sysroot
export SYSROOT=${NDK}/platforms/android-22/arch-arm
set -e

# Download packages libz, libuv, mbedtls and libwebsockets
#zlib-1.2.8
#libuv-1.x
#mbedtls-2.11.0
#libwebsockets-3.0.0


# create a local android toolchain
API=${3:-24}

$NDK/build/tools/make-standalone-toolchain.sh \
 --toolchain=arm-linux-androideabi-4.9 \
 --arch=arm \
 --install-dir=`pwd`/android-toolchain-arm \
 --platform=android-$API \
 --stl=libc++ \
 --force \
 --verbose

# setup environment to use the gcc/ld from the android toolchain
export INSTALL_PATH=/opt/libwebsockets_android/android-toolchain-arm
export TOOLCHAIN_PATH=`pwd`/android-toolchain-arm
export TOOL=arm-linux-androideabi
export NDK_TOOLCHAIN_BASENAME=${TOOLCHAIN_PATH}/bin/${TOOL}
export PATH=`pwd`/android-toolchain-arm/bin:$PATH
export CC=$NDK_TOOLCHAIN_BASENAME-gcc
export CXX=$NDK_TOOLCHAIN_BASENAME-g++
export LINK=${CXX}
export LD=$NDK_TOOLCHAIN_BASENAME-ld
export AR=$NDK_TOOLCHAIN_BASENAME-ar
export RANLIB=$NDK_TOOLCHAIN_BASENAME-ranlib
export STRIP=$NDK_TOOLCHAIN_BASENAME-strip
export PLATFORM=android
export CFLAGS="D__ANDROID_API__=$API"

# configure and build libuv
[ ! -f ./android-toolchain-arm/lib/libuv.so ] && {
cd libuv
echo "=============================================>> build libuv"

PATH=$TOOLCHAIN_PATH:$PATH make clean
PATH=$TOOLCHAIN_PATH:$PATH make
PATH=$TOOLCHAIN_PATH:$PATH make install
echo "<<============================================= build libuv"
cd ..
}

# configure and build zlib
[ ! -f ./android-toolchain-arm/lib/libz.so ] && {
cd zlib-1.2.8
echo "=============================================>> build libz"

PATH=$TOOLCHAIN_PATH:$PATH make clean 
PATH=$TOOLCHAIN_PATH:$PATH make
PATH=$TOOLCHAIN_PATH:$PATH make install
echo "<<============================================= build libz"
cd ..
}

# configure and build mbedtls
[ ! -f ./android-toolchain-arm/lib/libmbedtls.so ] && {
echo "=============================================>> build mbedtls"
PREFIX=$TOOLCHAIN_PATH
cd mbedtls-2.11.0
[ ! -d build ] && mkdir build
cd build
export CFLAGS="$CFLAGS -fomit-frame-pointer"

PATH=$TOOLCHAIN_PATH:$PATH cmake .. -DCMAKE_TOOLCHAIN_FILE=`pwd`/../cross-arm-android-gnueabi.cmake \
  -DCMAKE_INSTALL_PREFIX:PATH=${INSTALL_PATH} \
  -DCMAKE_BUILD_TYPE=RELEASE -DUSE_SHARED_MBEDTLS_LIBRARY=On
  
PATH=$TOOLCHAIN_PATH:$PATH make clean
PATH=$TOOLCHAIN_PATH:$PATH make SHARED=1
PATH=$TOOLCHAIN_PATH:$PATH make install
echo "<<============================================= build mbedtls"
cd ../..
}

# configure and build libwebsockets
[ ! -f ./android-toolchain-arm/lib/libwebsockets.so ] && {
cd libwebsockets
[ ! -d build ] && mkdir build
cd build
echo "=============================================>> build libwebsockets"

PATH=$TOOLCHAIN_PATH:$PATH cmake .. -DCMAKE_TOOLCHAIN_FILE=`pwd`/../cross-arm-android-gnueabi.cmake \
  -DCMAKE_INSTALL_PREFIX:PATH=${INSTALL_PATH} \
  -DLWS_WITH_LWSWS=1 \
  -DLWS_WITH_MBEDTLS=1 \
  -DLWS_WITHOUT_TESTAPPS=1 \
  -DLWS_MBEDTLS_LIBRARIES="${INSTALL_PATH}/lib/libmbedcrypto.a;${INSTALL_PATH}/lib/libmbedtls.a;${INSTALL_PATH}/lib/libmbedx509.a" \
  -DLWS_MBEDTLS_INCLUDE_DIRS=${INSTALL_PATH}/include \
  -DLWS_LIBUV_LIBRARIES=${INSTALL_PATH}/lib/libuv.so \
  -DLWS_LIBUV_INCLUDE_DIRS=${INSTALL_PATH}/include \
  -DLWS_ZLIB_LIBRARIES=${INSTALL_PATH}/lib/libz.so \
  -DLWS_ZLIB_INCLUDE_DIRS=${INSTALL_PATH}/include 
PATH=$TOOLCHAIN_PATH:$PATH make
PATH=$TOOLCHAIN_PATH:$PATH make install
echo "<<============================================= build libwebsockets"
cd ../..
}
