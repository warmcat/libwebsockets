COMPONENT_ADD_INCLUDEDIRS := ../../../../../../../../../$(COMPONENT_BUILD_DIR)/include

COMPONENT_OWNBUILDTARGET:= 1

CROSS_PATH1:=$(shell which xtensa-esp32-elf-gcc )
CROSS_PATH:= $(shell dirname $(CROSS_PATH1) )/..

#-DLWS_USE_BORINGSSL=1 \
#		-DOPENSSL_ROOT_DIR="${PWD}/../../boringssl" \
#		-DOPENSSL_LIBRARIES="${PWD}/../../boringssl/build/ssl/libssl.a;${PWD}/../../boringssl/build/crypto/libcrypto.a" \
#		-DOPENSSL_INCLUDE_DIRS="${PWD}/../../boringssl/include" \

.PHONY: build
build:
	cd $(COMPONENT_BUILD_DIR) ; \
	echo "doing lws cmake" ; \
	cmake $(COMPONENT_PATH)  -DLWS_C_FLAGS="$(CFLAGS) -DNDEBUG=1 " \
		-DIDF_PATH=$(IDF_PATH) \
		-DCROSS_PATH=$(CROSS_PATH) \
		-DCOMPONENT_PATH=$(COMPONENT_PATH) \
		-DBUILD_DIR_BASE=$(BUILD_DIR_BASE) \
		-DCMAKE_TOOLCHAIN_FILE=$(COMPONENT_PATH)/cross-esp32.cmake \
		-DCMAKE_BUILD_TYPE=RELEASE \
		-DOPENSSL_INCLUDE_DIR=${IDF_PATH}/components/openssl/include \
		-DOPENSSL_LIBRARIES=x \
		-DZLIB_LIBRARY=$(BUILD_DIR_BASE)/zlib/libzlib.a \
		-DZLIB_INCLUDE_DIR=$(COMPONENT_PATH)/../zlib \
		-DLWS_WITH_ESP32=1 ;\
	make && \
	cp ${COMPONENT_BUILD_DIR}/lib/libwebsockets.a ${COMPONENT_BUILD_DIR}/liblibwebsockets.a

clean: myclean

myclean:
	rm -rf ./build

INCLUDES := $(INCLUDES) -I build/ 

