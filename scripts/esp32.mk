#
# LWS-style images are composed like this
#
# [ OTA or Factory standard xpressif image ]
# [ 32-b LE len ] [ ROMFS ]
# [ 32-b LE len ] [ Image information JSON ]
#

SHELL=/bin/bash

ESPPORT ?= $(CONFIG_ESPTOOLPY_PORT)

LWS_BUILD_PATH=$(PROJECT_PATH)/build

jbi=$(LWS_BUILD_PATH)/json-buildinfo

FAC=$(CONFIG_LWS_IS_FACTORY_APPLICATION)
ifeq ($(FAC),)
	FAC=0
endif
export FAC
DIRNAME:=$(shell basename $$(pwd) | tr -d '\n')

$(LWS_BUILD_PATH)/pack.img: $(APP_BIN)
	GNUSTAT=stat ;\
	if [ `which gstat 2>/dev/null` ] ; then GNUSTAT=gstat ; fi ;\
	DIRNAME=$$(basename $$(pwd) | tr -d '\n') ;\
	genromfs -f $(LWS_BUILD_PATH)/romfs.img -d $(PROJECT_PATH)/romfs-files ; \
        RLEN=$$($$GNUSTAT -c %s $(LWS_BUILD_PATH)/romfs.img) ;\
        LEN=$$($$GNUSTAT -c %s $(LWS_BUILD_PATH)/$$DIRNAME.bin) ;\
        printf "             Original length: 0x%06x (%8d)\n" $$LEN $$LEN ; \
        printf %02x $$(( $$RLEN % 256 )) | xxd -r -p >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ;\
        printf %02x $$(( ( $$RLEN / 256 ) % 256 )) | xxd -r -p >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ;\
        printf %02x $$(( ( $$RLEN / 65536 ) % 256 )) | xxd -r -p >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ;\
        printf %02x $$(( ( $$RLEN / 16777216 ) % 256 )) | xxd -r -p >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ;\
        cat $(LWS_BUILD_PATH)/romfs.img >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ; \
        LEN=$$($$GNUSTAT -c %s $(LWS_BUILD_PATH)/$$DIRNAME.bin) ;\
	UNIXTIME=$$(date +%s | tr -d '\n') ; \
	echo -n -e "{\r\n \"schema\": \"lws1\",\r\n \"model\": \"$(CONFIG_LWS_MODEL_NAME)\",\r\n \"builder\": \"" > $(jbi) ;\
	hostname | tr -d '\n' >> $(jbi) ;\
	echo -n -e "\",\r\n \"app\": \"" >> $(jbi) ;\
	echo -n $$DIRNAME >> $(jbi) ;\
	echo -n -e "\",\r\n \"user\": \"" >> $(jbi) ;\
	whoami | tr -d '\n' >>$(jbi) ;\
	echo -n -e  "\",\r\n \"git\": \"" >> $(jbi) ;\
	git describe --dirty --always | tr -d '\n' >> $(jbi) ;\
	echo -n -e  "\",\r\n \"date\": \"" >> $(jbi) ;\
	date | tr -d '\n' >> $(jbi) ;\
	echo -n -e "\",\r\n \"unixtime\": \"" >> $(jbi) ;\
	echo -n $$UNIXTIME >> $(jbi) ;\
	echo -n -e "\",\r\n \"file\": \""$$DIRNAME-$$UNIXTIME.bin >> $(jbi) ;\
	echo -n -e "\",\r\n \"factory\": \"$(FAC)" >> $(jbi) ;\
	echo -n -e "\"\r\n}"  >> $(jbi) ;\
	JLEN=$$($$GNUSTAT -c %s $(jbi)) ;\
	printf %02x $$(( $$JLEN % 256 )) | xxd -r -p >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ;\
	printf %02x $$(( ( $$JLEN / 256 ) % 256 )) | xxd -r -p >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ;\
	printf %02x $$(( ( $$JLEN / 65536 ) % 256 )) | xxd -r -p >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ;\
	printf %02x $$(( ( $$JLEN / 16777216 ) % 256 )) | xxd -r -p >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ;\
	cat $(jbi) >> $(LWS_BUILD_PATH)/$$DIRNAME.bin ;\
	cp $(LWS_BUILD_PATH)/$$DIRNAME.bin $(LWS_BUILD_PATH)/pack.img ;\
        LEN=$$($$GNUSTAT -c %s $(LWS_BUILD_PATH)/$$DIRNAME.bin) ;\
	cp $(LWS_BUILD_PATH)/$$DIRNAME.bin $(LWS_BUILD_PATH)/$$DIRNAME-$$UNIXTIME.bin ;\
	printf "    After ROMFS + Build info: 0x%06x (%8d)\n" $$LEN $$LEN

.PHONY: manifest
manifest:
ifeq ($F,)
	echo "Usage make F=<factory app dir> A=<app dir> manifest"
	exit 1
endif
ifeq ($A,)
	echo "Usage make F=<factory app dir> A=<app dir> manifest"
	exit 1
endif
	echo -n -e "{\r\n\"app\": " > build/manifest.json
	cat $(A)/build/json-buildinfo >> build/manifest.json
	echo -n -e ", \"factory\": " >> build/manifest.json
	cat $(F)/build/json-buildinfo >> build/manifest.json
	echo -n -e "\r\n}\r\n" >> build/manifest.json

all: $(LWS_BUILD_PATH)/pack.img

flash: $(LWS_BUILD_PATH)/pack.img

flash_ota: $(LWS_BUILD_PATH)/pack.img
	DIRNAME=$$(basename $$(pwd) | tr -d '\n') ;\
	$(IDF_PATH)/components/esptool_py/esptool/esptool.py \
		--chip esp32 \
		--port $(ESPPORT) \
		--baud $(CONFIG_ESPTOOLPY_BAUD) \
		write_flash 0x110000 $(LWS_BUILD_PATH)/$$DIRNAME.bin

erase_ota:
	$(IDF_PATH)/components/esptool_py/esptool/esptool.py \
	        --chip esp32 \
	        --port $(ESPPORT) \
	        --baud $(CONFIG_ESPTOOLPY_BAUD) \
	        erase_region 0x110000 0x2f0000


export A
export F
.PHONY: upload
upload: manifest
ifeq ($F,)
	echo "Usage make F=<factory app dir> A=<app dir> manifest"
	exit 1
endif
ifeq ($A,)
	echo "Usage make F=<factory app dir> A=<app dir> manifest"
	exit 1
endif
	UPL=$(CONFIG_LWS_OTA_SERVER_UPLOAD_USER)@$(CONFIG_LWS_OTA_SERVER_FQDN):$(CONFIG_LWS_OTA_SERVER_UPLOAD_PATH)/$(CONFIG_LWS_OTA_SERVER_BASE_URL)/$(CONFIG_LWS_MODEL_NAME)/ ;\
	AFILE=$(A)/build/$$(cat $$A/build/json-buildinfo | grep -- \"file\"\: |cut -d' ' -f3 |cut -d'"' -f2) ;\
	echo "  Uploading $$AFILE to " $$UPL ;\
	scp $$AFILE $$UPL ;\
	FFILE=$(F)/build/$$(cat $$F/build/json-buildinfo | grep -- \"file\"\: |cut -d' ' -f3 |cut -d'"' -f2) ;\
	echo "  Uploading $$FFILE" ;\
	scp  $$FFILE $$UPL ;\
	echo "  Uploading manifest" ;\
	scp build/manifest.json $$UPL
