#!/bin/bash

#
# Build libwebsockets static library for Android
#
# requires debian package xutils-dev for makedepend (openssl make depend)
#

# This is based on http://stackoverflow.com/questions/11929773/compiling-the-latest-openssl-for-android/
# via https://github.com/warmcat/libwebsockets/pull/502

# path to NDK
export NDK=/opt/Android/SDK/ndk-bundle

set -e

# Download packages libz, openssl and libwebsockets

[ ! -f zlib-1.2.8.tar.gz ] && {
wget http://prdownloads.sourceforge.net/libpng/zlib-1.2.8.tar.gz
}

[ ! -f openssl-1.0.2g.tar.gz ] && {
wget https://openssl.org/source/openssl-1.0.2g.tar.gz
}

[ ! -f libwebsockets.tar.gz ] && {
git clone https://github.com/warmcat/libwebsockets.git
tar caf libwebsockets.tar.gz libwebsockets
}

# Clean then Unzip

[ -d zlib-1.2.8 ] && rm -fr zlib-1.2.8
[ -d openssl-1.0.2g ] && rm -fr openssl-1.0.2g
[ -d libwebsockets ] && rm -fr libwebsockets
[ -d android-toolchain-arm ] && rm -fr android-toolchain-arm
tar xf zlib-1.2.8.tar.gz
tar xf openssl-1.0.2g.tar.gz
tar xf libwebsockets.tar.gz

# create a local android toolchain
$NDK/build/tools/make-standalone-toolchain.sh \
 --platform=android-9 \
 --toolchain=arm-linux-androideabi-4.9 \
 --install-dir=`pwd`/android-toolchain-arm

# setup environment to use the gcc/ld from the android toolchain
export TOOLCHAIN_PATH=`pwd`/android-toolchain-arm/bin
export TOOL=arm-linux-androideabi
export NDK_TOOLCHAIN_BASENAME=${TOOLCHAIN_PATH}/${TOOL}
export CC=$NDK_TOOLCHAIN_BASENAME-gcc
export CXX=$NDK_TOOLCHAIN_BASENAME-g++
export LINK=${CXX}
export LD=$NDK_TOOLCHAIN_BASENAME-ld
export AR=$NDK_TOOLCHAIN_BASENAME-ar
export RANLIB=$NDK_TOOLCHAIN_BASENAME-ranlib
export STRIP=$NDK_TOOLCHAIN_BASENAME-strip

# setup buildflags
export ARCH_FLAGS="-mthumb"
export ARCH_LINK=
export CPPFLAGS=" ${ARCH_FLAGS} -fpic -ffunction-sections -funwind-tables -fstack-protector -fno-strict-aliasing -finline-limit=64 "
export CXXFLAGS=" ${ARCH_FLAGS} -fpic -ffunction-sections -funwind-tables -fstack-protector -fno-strict-aliasing -finline-limit=64 -frtti -fexceptions "
export CFLAGS=" ${ARCH_FLAGS} -fpic -ffunction-sections -funwind-tables -fstack-protector -fno-strict-aliasing -finline-limit=64 "
export LDFLAGS=" ${ARCH_LINK} "

# configure and build zlib
[ ! -f ./android-toolchain-arm/lib/libz.a ] && {
cd zlib-1.2.8
PATH=$TOOLCHAIN_PATH:$PATH ./configure --static --prefix=$TOOLCHAIN_PATH/..
PATH=$TOOLCHAIN_PATH:$PATH make
PATH=$TOOLCHAIN_PATH:$PATH make install
cd ..
}

# configure and build openssl
[ ! -f ./android-toolchain-arm/lib/libssl.a ] && {
PREFIX=$TOOLCHAIN_PATH/..
cd openssl-1.0.2g
./Configure android --prefix=${PREFIX} no-shared no-idea no-mdc2 no-rc5 no-zlib no-zlib-dynamic enable-tlsext no-ssl2 no-ssl3 enable-ec enable-ecdh enable-ecp
PATH=$TOOLCHAIN_PATH:$PATH make depend
PATH=$TOOLCHAIN_PATH:$PATH make
PATH=$TOOLCHAIN_PATH:$PATH make install_sw
cd ..
}

# configure and build libwebsockets
[ ! -f ./android-toolchain-arm/lib/libwebsockets.a ] && {
cd libwebsockets
[ ! -d build ] && mkdir build
cd build
PATH=$TOOLCHAIN_PATH:$PATH cmake \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_AR=$AR \
  -DCMAKE_RANLIB=$RANLIB \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_INSTALL_PREFIX=$TOOLCHAIN_PATH/.. \
  -DLWS_WITH_SHARED=OFF \
  -DLWS_WITH_STATIC=ON \
  -DLWS_WITHOUT_DAEMONIZE=ON \
  -DLWS_WITHOUT_TESTAPPS=ON \
  -DLWS_IPV6=OFF \
  -DLWS_WITH_BUNDLED_ZLIB=OFF \
  -DLWS_WITH_SSL=ON  \
  -DLWS_WITH_HTTP2=ON \
  -DLWS_OPENSSL_LIBRARIES="$TOOLCHAIN_PATH/../lib/libssl.a;$TOOLCHAIN_PATH/../lib/libcrypto.a" \
  -DLWS_OPENSSL_INCLUDE_DIRS=$TOOLCHAIN_PATH/../include \
  -DCMAKE_BUILD_TYPE=Debug \
  ..
PATH=$TOOLCHAIN_PATH:$PATH make
PATH=$TOOLCHAIN_PATH:$PATH make install
cd ../..
}
