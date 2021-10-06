################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include utilities/subdir.mk
-include usb/phy/subdir.mk
-include usb/device/source/lpcip3511/subdir.mk
-include usb/device/source/subdir.mk
-include usb/device/class/cdc/subdir.mk
-include usb/device/class/subdir.mk
-include startup/subdir.mk
-include source/sspc/subdir.mk
-include source/subdir.mk
-include flash_config/subdir.mk
-include drivers/subdir.mk
-include device/subdir.mk
-include component/uart/subdir.mk
-include component/osa/subdir.mk
-include component/lists/subdir.mk
-include board/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm.axf

# Tool invocations
evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm.axf: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: MCU Linker'
	arm-none-eabi-gcc -nostdlib -L"/home/agreen/Documents/MCUXpresso_11.4.1_6260/workspace/evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm/source" -Xlinker -Map="evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm.map" -Xlinker --gc-sections -Xlinker -print-memory-usage -Xlinker --sort-section=alignment -Xlinker --cref -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -T evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm_Debug.ld -o "evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm.axf" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '
	$(MAKE) --no-print-directory post-build

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm.axf
	-@echo ' '

post-build:
	-@echo 'Performing post-build steps'
	-arm-none-eabi-size "evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm.axf"; # arm-none-eabi-objcopy -v -O binary "evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm.axf" "evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm.bin" ; # checksum -p MIMXRT595S -d "evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm.bin";
	-@echo ' '

.PHONY: all clean dependents post-build

-include ../makefile.targets
