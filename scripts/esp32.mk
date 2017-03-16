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
	genromfs -f $(COMPONENT_PATH)/../build/romfs.img -d $(COMPONENT_PATH)/../romfs-files ; \
        RLEN=$$(stat -c %s $(COMPONENT_PATH)/../build/romfs.img) ;\
        LEN=$$(stat -c %s $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin) ;\
        printf "             Original length: 0x%06x (%8d)\n" $$LEN $$LEN ; \
        printf %02x $$(( $$RLEN % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ;\
        printf %02x $$(( ( $$RLEN / 256 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ;\
        printf %02x $$(( ( $$RLEN / 65536 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ;\
        printf %02x $$(( ( $$RLEN / 16777216 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ;\
        cat $(COMPONENT_PATH)/../build/romfs.img >>$(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ; \
        LEN=$$(stat -c %s $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin) ;\
        #
	echo -n -e "{\n \"schema\": \"lws1\",\n \"model\": \"$(CONFIG_LWS_MODEL_NAME)\",\n \"builder\": \"" > $(jbi)
	hostname | tr -d '\n' >> $(jbi)
	echo -n -e "\",\n \"app\": \"" >> $(jbi)
	basename $$(pwd) | tr -d '\n' >> $(jbi)
	echo -n -e "\",\n \"user\": \"" >> $(jbi)
	whoami | tr -d '\n' >>$(jbi)
	echo -n -e  "\",\n \"git\": \"" >> $(jbi)
	git describe --dirty --always | tr -d '\n' >> $(jbi)
	echo -n -e  "\",\n \"date\": \"" >> $(jbi)
	date  | tr -d '\n' >> $(jbi)
	echo -n -e "\",\n \"unixtime\": \"" >> $(jbi)
	date +%s | tr -d '\n' >> $(jbi)
	echo -n -e "\",\n \"factory\": \"$(LWS_IS_FACTORY_APPLICATION)" >> $(jbi)
	echo -n -e "\"\n}"  >> $(jbi)
	#
	JLEN=$$(stat -c %s $(jbi)) ;\
	printf %02x $$(( $$JLEN % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ;\
	printf %02x $$(( ( $$JLEN / 256 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ;\
	printf %02x $$(( ( $$JLEN / 65536 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ;\
	printf %02x $$(( ( $$JLEN / 16777216 ) % 256 )) | xxd -r -p >> $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ;\
	cat $(jbi) >> $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin ;\
        LEN=$$(stat -c %s $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin) ;\
	printf "    After ROMFS + Build info: 0x%06x (%8d)\n" $$LEN $$LEN

all: pack.img

flash_ota:
	$(IDF_PATH)/components/esptool_py/esptool/esptool.py \
		--chip esp32 \
		--port $(CONFIG_ESPTOOLPY_PORT) \
		--baud $(CONFIG_ESPTOOLPY_BAUD) \
		write_flash 0x110000 $(COMPONENT_PATH)/../build/$(PROJECT_NAME).bin

erase_ota:
	$(IDF_PATH)/components/esptool_py/esptool/esptool.py \
	        --chip esp32 \
	        --port $(CONFIG_ESPTOOLPY_PORT) \
	        --baud $(CONFIG_ESPTOOLPY_BAUD) \
	        erase_region 0x110000 0x2f0000


