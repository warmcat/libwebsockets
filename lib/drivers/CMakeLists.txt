list(APPEND SOURCES
        drivers/display/lws-display.c
        drivers/display/ssd1306-i2c.c
        drivers/i2c/lws-i2c.c
        drivers/i2c/bitbang/lws-bb-i2c.c
	drivers/button/lws-button.c
	drivers/led/led-gpio.c
)

if (LWS_ESP_PLATFORM)
	list(APPEND SOURCES
		plat/freertos/esp32/drivers/gpio-esp32.c)
endif()

exports_to_parent_scope()

