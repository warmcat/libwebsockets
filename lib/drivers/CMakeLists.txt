list(APPEND SOURCES
	drivers/display/lws-display.c
	drivers/display/ssd1306-i2c.c
	drivers/display/ili9341-spi.c
	drivers/display/gc9a01a-spi.c
	drivers/display/spd1656-spi.c
	drivers/display/uc8176-spi.c
	drivers/display/ssd1675b-spi.c
	drivers/display/epd-direct.c
	drivers/display/epd-direct-panels.c
	drivers/i2c/lws-i2c.c
	drivers/i2c/bitbang/lws-bb-i2c.c
	drivers/spi/lws-spi.c
	drivers/spi/bitbang/lws-bb-spi.c
	drivers/button/lws-button.c
	drivers/touch/lws-touch.c
	drivers/touch/cst816s-i2c.c
	drivers/touch/gt911-i2c.c
	drivers/led/led-gpio.c
	drivers/led/led-seq.c
	drivers/pwm/pwm.c
	drivers/settings/settings.c
)

if (LWS_WITH_NETWORK)
	list(APPEND SOURCES
		drivers/netdev/netdev.c
		drivers/netdev/wifi.c
		drivers/netdev/wifi-settings.c)

	if (LWS_WITH_SERVER AND LWS_WITH_SYS_SMD)
		list(APPEND SOURCES
			drivers/netdev/wifi-provision.c)
	endif()
endif()

if (LWS_ESP_PLATFORM)
	list(APPEND SOURCES
		plat/freertos/esp32/drivers/gpio-esp32.c
		plat/freertos/esp32/drivers/pwm-esp32.c
		)
endif()

exports_to_parent_scope()

