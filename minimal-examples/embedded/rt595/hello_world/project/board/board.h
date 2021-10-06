/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _BOARD_H_
#define _BOARD_H_

#include "clock_config.h"
#include "fsl_common.h"
#include "fsl_reset.h"
#include "fsl_gpio.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*! @brief The board name */
#define BOARD_NAME      "EVK-MIMXRT595"
#define BOARD_I3C_CODEC (1)

/*! @brief The UART to use for debug messages. */
#define BOARD_DEBUG_UART_TYPE     kSerialPort_Uart
#define BOARD_DEBUG_UART_BASEADDR (uint32_t) USART0
#define BOARD_DEBUG_UART_INSTANCE 0U
#define BOARD_DEBUG_UART_CLK_FREQ CLOCK_GetFlexcommClkFreq(0)
#define BOARD_DEBUG_UART_FRG_CLK \
    (&(const clock_frg_clk_config_t){0U, kCLOCK_FrgPllDiv, 255U, 0U}) /*!< Select FRG0 mux as frg_pll */
#define BOARD_DEBUG_UART_CLK_ATTACH kFRG_to_FLEXCOMM0
#define BOARD_UART_IRQ_HANDLER      FLEXCOMM0_IRQHandler
#define BOARD_UART_IRQ              FLEXCOMM0_IRQn

#if BOARD_I3C_CODEC
#define BOARD_CODEC_I2C_BASEADDR   I3C0
#define BOARD_CODEC_I2C_INSTANCE   0
#define BOARD_CODEC_I2C_CLOCK_FREQ CLOCK_GetI3cClkFreq()
#else
#define BOARD_CODEC_I2C_BASEADDR   I2C4
#define BOARD_CODEC_I2C_INSTANCE   4
#define BOARD_CODEC_I2C_CLOCK_FREQ CLOCK_GetFlexcommClkFreq(4)
#endif

#define BOARD_FLEXSPI_PSRAM FLEXSPI1
#ifndef BOARD_ENABLE_PSRAM_CACHE
#define BOARD_ENABLE_PSRAM_CACHE 1
#endif

#ifndef BOARD_DEBUG_UART_BAUDRATE
#define BOARD_DEBUG_UART_BAUDRATE 115200
#endif /* BOARD_DEBUG_UART_BAUDRATE */

/* PCA9420 */
#define BOARD_PMIC_I2C_BASEADDR   I2C15
#define BOARD_PMIC_I2C_CLOCK_FREQ CLOCK_GetFlexcommClkFreq(15)

/* Accelerometer */
#define BOARD_ACCEL_I2C_BASEADDR   I2C4
#define BOARD_ACCEL_I2C_ADDR       0x1E
#define BOARD_ACCEL_I2C_CLOCK_FREQ CLOCK_GetFlexcommClkFreq(4)

/* Board led color mapping */
#define LOGIC_LED_ON  1U
#define LOGIC_LED_OFF 0U

#ifndef BOARD_LED_RED_GPIO
#define BOARD_LED_RED_GPIO GPIO
#endif
#define BOARD_LED_RED_GPIO_PORT 0U
#ifndef BOARD_LED_RED_GPIO_PIN
#define BOARD_LED_RED_GPIO_PIN 14U
#endif

#ifndef BOARD_LED_GREEN_GPIO
#define BOARD_LED_GREEN_GPIO GPIO
#endif
#define BOARD_LED_GREEN_GPIO_PORT 1U
#ifndef BOARD_LED_GREEN_GPIO_PIN
#define BOARD_LED_GREEN_GPIO_PIN 0U
#endif
#ifndef BOARD_LED_BLUE_GPIO
#define BOARD_LED_BLUE_GPIO GPIO
#endif
#define BOARD_LED_BLUE_GPIO_PORT 3U
#ifndef BOARD_LED_BLUE_GPIO_PIN
#define BOARD_LED_BLUE_GPIO_PIN 17U
#endif

#ifndef BOARD_FLASH_RESET_GPIO
#define BOARD_FLASH_RESET_GPIO GPIO
#endif
#ifndef BOARD_FLASH_RESET_GPIO_PORT
#define BOARD_FLASH_RESET_GPIO_PORT 4U
#endif
#ifndef BOARD_FLASH_RESET_GPIO_PIN
#define BOARD_FLASH_RESET_GPIO_PIN 5U
#endif

#define LED_RED_INIT(output)                                                          \
    GPIO_PinInit(BOARD_LED_RED_GPIO, BOARD_LED_RED_GPIO_PORT, BOARD_LED_RED_GPIO_PIN, \
                 &(gpio_pin_config_t){kGPIO_DigitalOutput, (output)}) /*!< Enable target LED_RED */
#define LED_RED_ON()                                          \
    GPIO_PortSet(BOARD_LED_RED_GPIO, BOARD_LED_RED_GPIO_PORT, \
                 1U << BOARD_LED_RED_GPIO_PIN) /*!< Turn on target LED_RED */
#define LED_RED_OFF()                                           \
    GPIO_PortClear(BOARD_LED_RED_GPIO, BOARD_LED_RED_GPIO_PORT, \
                   1U << BOARD_LED_RED_GPIO_PIN) /*!< Turn off target LED_RED */
#define LED_RED_TOGGLE()                                         \
    GPIO_PortToggle(BOARD_LED_RED_GPIO, BOARD_LED_RED_GPIO_PORT, \
                    1U << BOARD_LED_RED_GPIO_PIN) /*!< Toggle on target LED_RED */

#define LED_GREEN_INIT(output)                                                              \
    GPIO_PinInit(BOARD_LED_GREEN_GPIO, BOARD_LED_GREEN_GPIO_PORT, BOARD_LED_GREEN_GPIO_PIN, \
                 &(gpio_pin_config_t){kGPIO_DigitalOutput, (output)}) /*!< Enable target LED_GREEN */
#define LED_GREEN_ON()                                            \
    GPIO_PortSet(BOARD_LED_GREEN_GPIO, BOARD_LED_GREEN_GPIO_PORT, \
                 1U << BOARD_LED_GREEN_GPIO_PIN) /*!< Turn on target LED_GREEN */
#define LED_GREEN_OFF()                                             \
    GPIO_PortClear(BOARD_LED_GREEN_GPIO, BOARD_LED_GREEN_GPIO_PORT, \
                   1U << BOARD_LED_GREEN_GPIO_PIN) /*!< Turn off target LED_GREEN */
#define LED_GREEN_TOGGLE()                                           \
    GPIO_PortToggle(BOARD_LED_GREEN_GPIO, BOARD_LED_GREEN_GPIO_PORT, \
                    1U << BOARD_LED_GREEN_GPIO_PIN) /*!< Toggle on target LED_GREEN */

#define LED_BLUE_INIT(output)                                                            \
    GPIO_PinInit(BOARD_LED_BLUE_GPIO, BOARD_LED_BLUE_GPIO_PORT, BOARD_LED_BLUE_GPIO_PIN, \
                 &(gpio_pin_config_t){kGPIO_DigitalOutput, (output)}) /*!< Enable target LED_BLUE */
#define LED_BLUE_ON()                                           \
    GPIO_PortSet(BOARD_LED_BLUE_GPIO, BOARD_LED_BLUE_GPIO_PORT, \
                 1U << BOARD_LED_BLUE_GPIO_PIN) /*!< Turn on target LED_BLUE */
#define LED_BLUE_OFF()                                            \
    GPIO_PortClear(BOARD_LED_BLUE_GPIO, BOARD_LED_BLUE_GPIO_PORT, \
                   1U << BOARD_LED_BLUE_GPIO_PIN) /*!< Turn off target LED_BLUE */
#define LED_BLUE_TOGGLE()                                          \
    GPIO_PortToggle(BOARD_LED_BLUE_GPIO, BOARD_LED_BLUE_GPIO_PORT, \
                    1U << BOARD_LED_BLUE_GPIO_PIN) /*!< Toggle on target LED_BLUE */

/* Board SW PIN */
#ifndef BOARD_SW1_GPIO
#define BOARD_SW1_GPIO GPIO
#endif
#define BOARD_SW1_GPIO_PORT 0U
#ifndef BOARD_SW1_GPIO_PIN
#define BOARD_SW1_GPIO_PIN 25U
#endif

#ifndef BOARD_SW2_GPIO
#define BOARD_SW2_GPIO GPIO
#endif
#define BOARD_SW2_GPIO_PORT 0U
#ifndef BOARD_SW2_GPIO_PIN
#define BOARD_SW2_GPIO_PIN 10U
#endif

/* USB PHY condfiguration */
#define BOARD_USB_PHY_D_CAL     (0x0CU)
#define BOARD_USB_PHY_TXCAL45DP (0x06U)
#define BOARD_USB_PHY_TXCAL45DM (0x06U)

#define BOARD_FLASH_SIZE (0x4000000U)

/* SSD1963 (TFT_PROTO_5) panel. */
/* RST pin. */
#define BOARD_SSD1963_RST_PORT 5
#define BOARD_SSD1963_RST_PIN  0
/* CS pin. */
#define BOARD_SSD1963_CS_PORT 5
#define BOARD_SSD1963_CS_PIN  1
/* D/C pin, also named RS pin. */
#define BOARD_SSD1963_RS_PORT 4
#define BOARD_SSD1963_RS_PIN  31
/* Touch panel. */
#define BOARD_SSD1963_TOUCH_I2C_BASEADDR   I2C4
#define BOARD_SSD1963_TOUCH_I2C_CLOCK_FREQ CLOCK_GetFlexcommClkFreq(4)

/* MIPI panel. */
/* RST pin. */
#define BOARD_MIPI_RST_PORT 3
#define BOARD_MIPI_RST_PIN  21
/* POWER pin .*/
#define BOARD_MIPI_POWER_PORT 3
#define BOARD_MIPI_POWER_PIN  15
/* Backlight pin. */
#define BOARD_MIPI_BL_PORT 0
#define BOARD_MIPI_BL_PIN  12
/* TE pin. */
#define BOARD_MIPI_TE_PORT 3
#define BOARD_MIPI_TE_PIN  18

/* Touch panel. */
#define BOARD_MIPI_PANEL_TOUCH_I2C_BASEADDR   I2C4
#define BOARD_MIPI_PANEL_TOUCH_I2C_CLOCK_FREQ CLOCK_GetFlexcommClkFreq(4)
#define BOARD_MIPI_PANEL_TOUCH_RST_PORT       4
#define BOARD_MIPI_PANEL_TOUCH_RST_PIN        4
#define BOARD_MIPI_PANEL_TOUCH_INT_PORT       3
#define BOARD_MIPI_PANEL_TOUCH_INT_PIN        19

#define BOARD_BT_UART_INSTANCE 12
#define BOARD_BT_UART_BAUDRATE 3000000
#define BOARD_BT_UART_CLK_FREQ CLOCK_GetFlexcommClkFreq(12U)
#define BOARD_BT_UART_FRG_CLK \
    (&(const clock_frg_clk_config_t){12, kCLOCK_FrgMainClk, 255, 12}) /*!< Select FRG0 mux as frg_pll */
#define BOARD_BT_UART_CLK_ATTACH  kFRG_to_FLEXCOMM12
#define BOARD_BT_UART_RST         kFC12_RST_SHIFT_RSTn
#define BOARD_BT_UART_IRQ         FLEXCOMM12_IRQn
#define BOARD_BT_UART_IRQ_HANDLER FLEXCOMM12_IRQHandler
#define BOARD_BT_UART_CLKSRC      kCLOCK_Flexcomm12
#if defined(__cplusplus)
extern "C" {
#endif /* __cplusplus */

/*******************************************************************************
 * API
 ******************************************************************************/

void BOARD_InitDebugConsole(void);
status_t BOARD_InitPsRam(void);
void BOARD_FlexspiClockSafeConfig(void);
AT_QUICKACCESS_SECTION_CODE(void BOARD_SetFlexspiClock(FLEXSPI_Type *base, uint32_t src, uint32_t divider));
AT_QUICKACCESS_SECTION_CODE(void BOARD_DeinitFlash(FLEXSPI_Type *base));
AT_QUICKACCESS_SECTION_CODE(void BOARD_InitFlash(FLEXSPI_Type *base));
#if defined(SDK_I2C_BASED_COMPONENT_USED) && SDK_I2C_BASED_COMPONENT_USED
void BOARD_I2C_Init(I2C_Type *base, uint32_t clkSrc_Hz);
status_t BOARD_I2C_Send(I2C_Type *base,
                        uint8_t deviceAddress,
                        uint32_t subAddress,
                        uint8_t subaddressSize,
                        uint8_t *txBuff,
                        uint8_t txBuffSize);
status_t BOARD_I2C_Receive(I2C_Type *base,
                           uint8_t deviceAddress,
                           uint32_t subAddress,
                           uint8_t subaddressSize,
                           uint8_t *rxBuff,
                           uint8_t rxBuffSize);

void BOARD_PMIC_I2C_Init(void);
status_t BOARD_PMIC_I2C_Send(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, const uint8_t *txBuff, uint8_t txBuffSize);
status_t BOARD_PMIC_I2C_Receive(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, uint8_t *rxBuff, uint8_t rxBuffSize);

void BOARD_MIPIPanelTouch_I2C_Init(void);
status_t BOARD_MIPIPanelTouch_I2C_Send(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, const uint8_t *txBuff, uint8_t txBuffSize);
status_t BOARD_MIPIPanelTouch_I2C_Receive(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, uint8_t *rxBuff, uint8_t rxBuffSize);

void BOARD_Accel_I2C_Init(void);
status_t BOARD_Accel_I2C_Send(uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, uint32_t txBuff);
status_t BOARD_Accel_I2C_Receive(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, uint8_t *rxBuff, uint8_t rxBuffSize);
#endif /* SDK_I2C_BASED_COMPONENT_USED */

#if defined BOARD_USE_CODEC
void BOARD_I3C_Init(I3C_Type *base, uint32_t clkSrc_Hz);
status_t BOARD_I3C_Send(I3C_Type *base,
                        uint8_t deviceAddress,
                        uint32_t subAddress,
                        uint8_t subaddressSize,
                        uint8_t *txBuff,
                        uint8_t txBuffSize);
status_t BOARD_I3C_Receive(I3C_Type *base,
                           uint8_t deviceAddress,
                           uint32_t subAddress,
                           uint8_t subaddressSize,
                           uint8_t *rxBuff,
                           uint8_t rxBuffSize);
void BOARD_Codec_I2C_Init(void);
status_t BOARD_Codec_I2C_Send(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, const uint8_t *txBuff, uint8_t txBuffSize);
status_t BOARD_Codec_I2C_Receive(
    uint8_t deviceAddress, uint32_t subAddress, uint8_t subAddressSize, uint8_t *rxBuff, uint8_t rxBuffSize);
#endif

#if defined(__cplusplus)
}
#endif /* __cplusplus */

#endif /* _BOARD_H_ */
