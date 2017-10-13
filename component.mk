COMPONENT_DEPENDS:=mbedtls openssl
COMPONENT_ADD_INCLUDEDIRS := ../../../../../../../../../../../../../../../../../../../../$(COMPONENT_BUILD_DIR)/include

COMPONENT_OWNBUILDTARGET:= 1

CROSS_PATH1:=$(shell which xtensa-esp32-elf-gcc )
CROSS_PATH:= $(shell dirname $(CROSS_PATH1) )/..

#-DLWS_WITH_BORINGSSL=1 \
#		-DOPENSSL_ROOT_DIR="${PWD}/../../boringssl" \
#		-DOPENSSL_LIBRARIES="${PWD}/../../boringssl/build/ssl/libssl.a;${PWD}/../../boringssl/build/crypto/libcrypto.a" \
#		-DOPENSSL_INCLUDE_DIRS="${PWD}/../../boringssl/include" \

# -DNDEBUG=1 after cflags
#		-DOPENSSL_LIBRARIES=x \
#		-DCOMPONENT_PATH=$(COMPONENT_PATH) \

.PHONY: build
build:
	cd $(COMPONENT_BUILD_DIR) ; \
	echo "doing lws cmake" ; \
	cmake $(COMPONENT_PATH)  -DLWS_C_FLAGS="$(CFLAGS) " \
		-DIDF_PATH=$(IDF_PATH) \
		-DCROSS_PATH=$(CROSS_PATH) \
		-DBUILD_DIR_BASE=$(BUILD_DIR_BASE) \
		-DCMAKE_TOOLCHAIN_FILE=$(COMPONENT_PATH)/contrib/cross-esp32.cmake \
		-DCMAKE_BUILD_TYPE=RELEASE \
		-DLWS_MBEDTLS_INCLUDE_DIRS="${IDF_PATH}/components/openssl/include;${IDF_PATH}/components/mbedtls/include;${IDF_PATH}/components/mbedtls/port/include" \
		-DLWS_WITH_STATS=0 \
		-DLWS_WITH_HTTP2=1 \
		-DZLIB_LIBRARY=$(BUILD_DIR_BASE)/zlib/libzlib.a \
		-DZLIB_INCLUDE_DIR=$(COMPONENT_PATH)/../zlib \
		-DLWS_WITH_ESP32=1 ;\
	make && \
	cp ${COMPONENT_BUILD_DIR}/lib/libwebsockets.a ${COMPONENT_BUILD_DIR}/liblibwebsockets.a

clean: myclean

myclean:
	rm -rf ./build

INCLUDES := $(INCLUDES) -I build/ 

