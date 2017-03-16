#
# LWS-style images are composed like this
#
# [ OTA or Factory standard xpressif image ]
# [ 32-b LE len ] [ ROMFS ]
# [ 32-b LE len ] [ Image information JSON ]
#

jbi=$(COMPONENT_PATH)/../build/json-buildinfo

.PHONY: romfs.img
pack.img:
	DIRNAME=$$(basename $$(pwd) | tr -d '\n') ;\
	cp $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin $(COMPONENT_PATH)/../build/$$DIRNAME.bin ; \
	genromfs -f $(COMPONENT_PATH)/../build/romfs.img -d $(COMPONENT_PATH)/../romfs-files ; \
        RLEN=$$(stat -c %s $(COMPONENT_PATH)/../build/romfs.img) ;\
        LEN=$$(stat -c %s $(COMPONENT_PATH)/../build/$$DIRNAME.bin) ;\
        printf "             Original length: 0x%06x (%8d)\n" $$LEN $$LEN ; \
        printf %02x $$(( $$RLEN % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$$DIRNAME.bin ;\
        printf %02x $$(( ( $$RLEN / 256 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$$DIRNAME.bin ;\
        printf %02x $$(( ( $$RLEN / 65536 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$$DIRNAME.bin ;\
        printf %02x $$(( ( $$RLEN / 16777216 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$$DIRNAME.bin ;\
        cat $(COMPONENT_PATH)/../build/romfs.img >>$(COMPONENT_PATH)/../build/$$DIRNAME.bin ; \
        LEN=$$(stat -c %s $(COMPONENT_PATH)/../build/$$DIRNAME.bin) ;\
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
	echo -n -e "\",\r\n \"factory\": \"$(LWS_IS_FACTORY_APPLICATION)" >> $(jbi) ;\
	echo -n -e "\"\r\n}"  >> $(jbi) ;\
	JLEN=$$(stat -c %s $(jbi)) ;\
	printf %02x $$(( $$JLEN % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$$DIRNAME.bin ;\
	printf %02x $$(( ( $$JLEN / 256 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$$DIRNAME.bin ;\
	printf %02x $$(( ( $$JLEN / 65536 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$$DIRNAME.bin ;\
	printf %02x $$(( ( $$JLEN / 16777216 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$$DIRNAME.bin ;\
	cat $(jbi) >> $(COMPONENT_PATH)/../build/$$DIRNAME.bin ;\
        LEN=$$(stat -c %s $(COMPONENT_PATH)/../build/$$DIRNAME.bin) ;\
	cp $(COMPONENT_PATH)/../build/$$DIRNAME.bin $(COMPONENT_PATH)/../build/$$DIRNAME-$$UNIXTIME.bin ;\
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

all: pack.img

flash_ota:
	DIRNAME=$$(basename $$(pwd) | tr -d '\n') ;\
	$(IDF_PATH)/components/esptool_py/esptool/esptool.py \
		--chip esp32 \
		--port $(CONFIG_ESPTOOLPY_PORT) \
		--baud $(CONFIG_ESPTOOLPY_BAUD) \
		write_flash 0x110000 $(COMPONENT_PATH)/../build/$$DIRNAME.bin

erase_ota:
	$(IDF_PATH)/components/esptool_py/esptool/esptool.py \
	        --chip esp32 \
	        --port $(CONFIG_ESPTOOLPY_PORT) \
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
