COMPONENT_ADD_INCLUDEDIRS := ../../../../../../../../../$(COMPONENT_BUILD_DIR)/include-ext

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
	cmake $(COMPONENT_PATH)  -DLWS_C_FLAGS="$(CFLAGS)" \
		-DCROSS_PATH=$(CROSS_PATH) \
		-DCOMPONENT_PATH=$(COMPONENT_PATH) \
		-DCMAKE_TOOLCHAIN_FILE=$(COMPONENT_PATH)/cross-esp32.cmake \
		-DCMAKE_BUILD_TYPE=RELEASE \
		-DLWS_WITH_NO_LOGS=0 \
		-DLWS_WITH_ESP32=1 ;\
	mkdir -p $(COMPONENT_BUILD_DIR)/include-ext ; \
	cp $(COMPONENT_PATH)/lib/libwebsockets.h \
	   $(COMPONENT_BUILD_DIR)/lws_config.h \
	   $(COMPONENT_BUILD_DIR)/include-ext ; \
	make VERBOSE=1 && \
	cp ${COMPONENT_BUILD_DIR}/lib/libwebsockets.a ${COMPONENT_BUILD_DIR}/liblibwebsockets.a

clean: myclean

myclean:
	rm -rf ./build

INCLUDES := $(INCLUDES) -I build/ 

