/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2021, NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FSL_CLOCK_H_
#define _FSL_CLOCK_H_

#include "fsl_device_registers.h"
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "fsl_reset.h"
#include "fsl_common.h"

/*! @addtogroup clock */
/*! @{ */

/*! @file */

/*******************************************************************************
 * Definitions
 *****************************************************************************/

/*! @name Driver version */
/*@{*/
/*! @brief CLOCK driver version 2.6.1 */
#define FSL_CLOCK_DRIVER_VERSION (MAKE_VERSION(2, 6, 1))
/*@}*/

/* Definition for delay API in clock driver, users can redefine it to the real application. */
#ifndef SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY
#define SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY (198000000UL)
#endif

/*! @brief External XTAL (SYSOSC) clock frequency.
 *
 * The XTAL (YSOSC) clock frequency in Hz, when the clock is setup, use the
 * function CLOCK_SetXtalFreq to set the value in to clock driver. For example,
 * if XTAL is 16MHz,
 * @code
 * CLOCK_SetXtalFreq(160000000);
 * @endcode
 */
extern volatile uint32_t g_xtalFreq;

/*! @brief External CLK_IN pin clock frequency (clkin) clock frequency.
 *
 * The CLK_IN pin (clkin) clock frequency in Hz, when the clock is setup, use the
 * function CLOCK_SetClkinFreq to set the value in to clock driver. For example,
 * if CLK_IN is 16MHz,
 * @code
 * CLOCK_SetClkinFreq(160000000);
 * @endcode
 */
extern volatile uint32_t g_clkinFreq;

/*! @brief External MCLK IN clock frequency.
 *
 * The MCLK IN clock frequency in Hz, when the clock is setup, use the
 * function CLOCK_SetMclkFreq to set the value in to clock driver. For example,
 * if MCLK IN is 16MHz,
 * @code
 * CLOCK_SetMclkFreq(160000000);
 * @endcode
 */
extern volatile uint32_t g_mclkFreq;

/*! @brief Clock ip name array for MIPI DSI. */
#define MIPI_DSI_HOST_CLOCKS \
    {                        \
        kCLOCK_MipiDsiCtrl   \
    }

/*! @brief Clock ip name array for LCDIF. */
#define LCDIF_CLOCKS       \
    {                      \
        kCLOCK_DisplayCtrl \
    }

/*! @brief Clock ip name array for SCT. */
#define SCT_CLOCKS \
    {              \
        kCLOCK_Sct \
    }

/*! @brief Clock ip name array for USBD. */
#define USBD_CLOCKS        \
    {                      \
        kCLOCK_UsbhsDevice \
    }

/*! @brief Clock ip name array for FlexSPI */
#define FLEXSPI_CLOCKS                   \
    {                                    \
        kCLOCK_Flexspi0, kCLOCK_Flexspi1 \
    }

/*! @brief Clock ip name array for Cache64 */
#define CACHE64_CLOCKS                   \
    {                                    \
        kCLOCK_Flexspi0, kCLOCK_Flexspi1 \
    }

/*! @brief Clock ip name array for RNG */
#define TRNG_CLOCKS \
    {               \
        kCLOCK_Rng  \
    }

/*! @brief Clock ip name array for PUF */
#define PUF_CLOCKS \
    {              \
        kCLOCK_Puf \
    }

/*! @brief Clock ip name array for HashCrypt */
#define HASHCRYPT_CLOCKS \
    {                    \
        kCLOCK_Hashcrypt \
    }

/*! @brief Clock ip name array for Casper */
#define CASPER_CLOCKS \
    {                 \
        kCLOCK_Casper \
    }

/*! @brief Clock ip name array for Powerquad */
#define POWERQUAD_CLOCKS \
    {                    \
        kCLOCK_PowerQuad \
    }

/*! @brief Clock ip name array for ADC. */
#define LPADC_CLOCKS \
    {                \
        kCLOCK_Adc0  \
    }

/*! @brief Clock ip name array for ACMP. */
#define CMP_CLOCKS   \
    {                \
        kCLOCK_Acmp0 \
    }

/*! @brief Clock ip name array for uSDHC */
#define USDHC_CLOCKS               \
    {                              \
        kCLOCK_Sdio0, kCLOCK_Sdio1 \
    }

/*! @brief Clock ip name array for WWDT. */
#define WWDT_CLOCKS                \
    {                              \
        kCLOCK_Wwdt0, kCLOCK_Wwdt1 \
    }

/*! @brief Clock ip name array for UTICK. */
#define UTICK_CLOCKS  \
    {                 \
        kCLOCK_Utick0 \
    }

/*! @brief Clock ip name array for FlexIO. */
#define FLEXIO_CLOCKS \
    {                 \
        kCLOCK_Flexio \
    }

/*! @brief Clock ip name array for OSTimer */
#define OSTIMER_CLOCKS      \
    {                       \
        kCLOCK_OsEventTimer \
    }

/*! @brief Clock ip name array for FLEXCOMM. */
#define FLEXCOMM_CLOCKS                                                                                             \
    {                                                                                                               \
        kCLOCK_Flexcomm0, kCLOCK_Flexcomm1, kCLOCK_Flexcomm2, kCLOCK_Flexcomm3, kCLOCK_Flexcomm4, kCLOCK_Flexcomm5, \
            kCLOCK_Flexcomm6, kCLOCK_Flexcomm7, kCLOCK_Flexcomm8, kCLOCK_Flexcomm9, kCLOCK_Flexcomm10,              \
            kCLOCK_Flexcomm11, kCLOCK_Flexcomm12, kCLOCK_Flexcomm13, kCLOCK_Flexcomm14, kCLOCK_Flexcomm15,          \
            kCLOCK_Flexcomm16                                                                                       \
    }

/*! @brief Clock ip name array for LPUART. */
#define USART_CLOCKS                                                                                             \
    {                                                                                                            \
        kCLOCK_Usart0, kCLOCK_Usart1, kCLOCK_Usart2, kCLOCK_Usart3, kCLOCK_Usart4, kCLOCK_Usart5, kCLOCK_Usart6, \
            kCLOCK_Usart7, kCLOCK_Usart8, kCLOCK_Usart9, kCLOCK_Usart10, kCLOCK_Usart11, kCLOCK_Usart12,         \
            kCLOCK_Usart13                                                                                       \
    }

/*! @brief Clock ip name array for I2C. */
#define I2C_CLOCKS                                                                                              \
    {                                                                                                           \
        kCLOCK_I2c0, kCLOCK_I2c1, kCLOCK_I2c2, kCLOCK_I2c3, kCLOCK_I2c4, kCLOCK_I2c5, kCLOCK_I2c6, kCLOCK_I2c7, \
            kCLOCK_I2c8, kCLOCK_I2c9, kCLOCK_I2c10, kCLOCK_I2c11, kCLOCK_I2c12, kCLOCK_I2c13, kCLOCK_I2c15      \
    }

/*! @brief Clock ip name array for SPI. */
#define SPI_CLOCKS                                                                                              \
    {                                                                                                           \
        kCLOCK_Spi0, kCLOCK_Spi1, kCLOCK_Spi2, kCLOCK_Spi3, kCLOCK_Spi4, kCLOCK_Spi5, kCLOCK_Spi6, kCLOCK_Spi7, \
            kCLOCK_Spi8, kCLOCK_Spi9, kCLOCK_Spi10, kCLOCK_Spi11, kCLOCK_Spi12, kCLOCK_Spi13, kCLOCK_Spi14,     \
            kCLOCK_Spi16                                                                                        \
    }
/*! @brief Clock ip name array for FLEXI2S. */
#define I2S_CLOCKS                                                                                              \
    {                                                                                                           \
        kCLOCK_I2s0, kCLOCK_I2s1, kCLOCK_I2s2, kCLOCK_I2s3, kCLOCK_I2s4, kCLOCK_I2s5, kCLOCK_I2s6, kCLOCK_I2s7, \
            kCLOCK_I2s8, kCLOCK_I2s9, kCLOCK_I2s10, kCLOCK_I2s11, kCLOCK_I2s12, kCLOCK_I2s13                    \
    }

/*! @brief Clock ip name array for DMIC. */
#define DMIC_CLOCKS  \
    {                \
        kCLOCK_Dmic0 \
    }

/*! @brief Clock ip name array for SEMA */
#define SEMA42_CLOCKS \
    {                 \
        kCLOCK_Sema   \
    }

/*! @brief Clock ip name array for MUA */
#define MU_CLOCKS \
    {             \
        kCLOCK_Mu \
    }

/*! @brief Clock ip name array for DMA. */
#define DMA_CLOCKS                 \
    {                              \
        kCLOCK_Dmac0, kCLOCK_Dmac1 \
    }

/*! @brief Clock ip name array for CRC. */
#define CRC_CLOCKS \
    {              \
        kCLOCK_Crc \
    }

/*! @brief Clock ip name array for GPIO. */
#define GPIO_CLOCKS                                                                                     \
    {                                                                                                   \
        kCLOCK_HsGpio0, kCLOCK_HsGpio1, kCLOCK_HsGpio2, kCLOCK_HsGpio3, kCLOCK_HsGpio4, kCLOCK_HsGpio5, \
            kCLOCK_HsGpio6, kCLOCK_HsGpio7                                                              \
    }

/*! @brief Clock ip name array for PINT. */
#define PINT_CLOCKS       \
    {                     \
        kCLOCK_GpioIntCtl \
    }

/*! @brief Clock ip name array for I3C. */
#define I3C_CLOCKS               \
    {                            \
        kCLOCK_I3c0, kCLOCK_I3c1 \
    }

/*! @brief Clock ip name array for MRT. */
#define MRT_CLOCKS  \
    {               \
        kCLOCK_Mrt0 \
    }

/*! @brief Clock ip name array for RTC. */
#define RTC_CLOCKS \
    {              \
        kCLOCK_Rtc \
    }

/*! @brief Clock ip name array for CT32B. */
#define CTIMER_CLOCKS                                                             \
    {                                                                             \
        kCLOCK_Ct32b0, kCLOCK_Ct32b1, kCLOCK_Ct32b2, kCLOCK_Ct32b3, kCLOCK_Ct32b4 \
    }

/*! @brief Clock gate name used for CLOCK_EnableClock/CLOCK_DisableClock. */
/*------------------------------------------------------------------------------
 clock_ip_name_t definition:
------------------------------------------------------------------------------*/

#define CLK_GATE_REG_OFFSET_SHIFT 8U
#define CLK_GATE_REG_OFFSET_MASK  0xFF00U
#define CLK_GATE_BIT_SHIFT_SHIFT  0U
#define CLK_GATE_BIT_SHIFT_MASK   0x000000FFU

#define CLK_GATE_DEFINE(reg_offset, bit_shift)                                  \
    ((((reg_offset) << CLK_GATE_REG_OFFSET_SHIFT) & CLK_GATE_REG_OFFSET_MASK) | \
     (((bit_shift) << CLK_GATE_BIT_SHIFT_SHIFT) & CLK_GATE_BIT_SHIFT_MASK))

#define CLK_GATE_ABSTRACT_REG_OFFSET(x) (((uint32_t)(x)&CLK_GATE_REG_OFFSET_MASK) >> CLK_GATE_REG_OFFSET_SHIFT)
#define CLK_GATE_ABSTRACT_BITS_SHIFT(x) (((uint32_t)(x)&CLK_GATE_BIT_SHIFT_MASK) >> CLK_GATE_BIT_SHIFT_SHIFT)

#define CLK_CTL0_PSCCTL0 0
#define CLK_CTL0_PSCCTL1 1
#define CLK_CTL0_PSCCTL2 2
#define CLK_CTL1_PSCCTL0 3
#define CLK_CTL1_PSCCTL1 4
#define CLK_CTL1_PSCCTL2 5

/*! @brief Clock gate name used for CLOCK_EnableClock/CLOCK_DisableClock. */
typedef enum _clock_ip_name
{
    kCLOCK_IpInvalid   = 0U,                                    /*!< Invalid Ip Name. */
    kCLOCK_Dsp         = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 1),  /*!< Clock gate name: Dsp*/
    kCLOCK_RomCtrlr    = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 2),  /*!< Clock gate name: RomCtrlr*/
    kCLOCK_AxiSwitch   = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 3),  /*!< Clock gate name: AxiSwitch*/
    kCLOCK_AxiCtrl     = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 4),  /*!< Clock gate name: AxiCtrl*/
    kCLOCK_PowerQuad   = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 8),  /*!< Clock gate name: PowerQuad*/
    kCLOCK_Casper      = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 9),  /*!< Clock gate name: Casper*/
    kCLOCK_HashCrypt   = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 10), /*!< Clock gate name: HashCrypt*/
    kCLOCK_Puf         = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 11), /*!< Clock gate name: Puf*/
    kCLOCK_Rng         = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 12), /*!< Clock gate name: Rng*/
    kCLOCK_Flexspi0    = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 16), /*!< Clock gate name: Flexspi0*/
    kCLOCK_OtpCtrl     = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 17), /*!< Clock gate name: OtpCtrl*/
    kCLOCK_Flexspi1    = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 18), /*!< Clock gate name: Flexspi1*/
    kCLOCK_UsbhsPhy    = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 20), /*!< Clock gate name: UsbhsPhy*/
    kCLOCK_UsbhsDevice = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 21), /*!< Clock gate name: UsbhsDevice*/
    kCLOCK_UsbhsHost   = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 22), /*!< Clock gate name: UsbhsHost*/
    kCLOCK_UsbhsSram   = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 23), /*!< Clock gate name: UsbhsSram*/
    kCLOCK_Sct         = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 24), /*!< Clock gate name: Sct*/
    kCLOCK_Gpu         = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 26), /*!< Clock gate name: Gpu*/
    kCLOCK_DisplayCtrl = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 27), /*!< Clock gate name: DisplayCtrl*/
    kCLOCK_MipiDsiCtrl = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 28), /*!< Clock gate name: MipiDsiCtrl*/
    kCLOCK_Smartdma    = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL0, 30), /*!< Clock gate name: Smartdma*/

    kCLOCK_Sdio0    = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL1, 2),  /*!< Clock gate name: Sdio0*/
    kCLOCK_Sdio1    = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL1, 3),  /*!< Clock gate name: Sdio1*/
    kCLOCK_Acmp0    = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL1, 15), /*!< Clock gate name: Acmp0*/
    kCLOCK_Adc0     = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL1, 16), /*!< Clock gate name: Adc0*/
    kCLOCK_ShsGpio0 = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL1, 24), /*!< Clock gate name: ShsGpio0*/

    kCLOCK_Utick0 = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL2, 0),  /*!< Clock gate name: Utick0*/
    kCLOCK_Wwdt0  = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL2, 1),  /*!< Clock gate name: Wwdt0*/
    kCLOCK_Pmc    = CLK_GATE_DEFINE(CLK_CTL0_PSCCTL2, 29), /*!< Clock gate name: Pmc*/

    kCLOCK_Flexcomm0    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 8),  /*!< Clock gate name: Flexcomm0*/
    kCLOCK_Flexcomm1    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 9),  /*!< Clock gate name: Flexcomm1*/
    kCLOCK_Flexcomm2    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 10), /*!< Clock gate name: Flexcomm2*/
    kCLOCK_Flexcomm3    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 11), /*!< Clock gate name: Flexcomm3*/
    kCLOCK_Flexcomm4    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 12), /*!< Clock gate name: Flexcomm4*/
    kCLOCK_Flexcomm5    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 13), /*!< Clock gate name: Flexcomm5*/
    kCLOCK_Flexcomm6    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 14), /*!< Clock gate name: Flexcomm6*/
    kCLOCK_Flexcomm7    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 15), /*!< Clock gate name: Flexcomm7*/
    kCLOCK_Flexcomm8    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 16), /*!< Clock gate name: Flexcomm8*/
    kCLOCK_Flexcomm9    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 17), /*!< Clock gate name: Flexcomm9*/
    kCLOCK_Flexcomm10   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 18), /*!< Clock gate name: Flexcomm10*/
    kCLOCK_Flexcomm11   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 19), /*!< Clock gate name: Flexcomm11*/
    kCLOCK_Flexcomm12   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 20), /*!< Clock gate name: Flexcomm12*/
    kCLOCK_Flexcomm13   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 21), /*!< Clock gate name: Flexcomm13*/
    kCLOCK_Flexcomm14   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 22), /*!< Clock gate name: Flexcomm14*/
    kCLOCK_Flexcomm15   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 23), /*!< Clock gate name: Flexcomm15*/
    kCLOCK_Flexcomm16   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 25), /*!< Clock gate name: Flexcomm16*/
    kCLOCK_Usart0       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 8),  /*!< Clock gate name: Usart0*/
    kCLOCK_Usart1       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 9),  /*!< Clock gate name: Usart1*/
    kCLOCK_Usart2       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 10), /*!< Clock gate name: Usart2*/
    kCLOCK_Usart3       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 11), /*!< Clock gate name: Usart3*/
    kCLOCK_Usart4       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 12), /*!< Clock gate name: Usart4*/
    kCLOCK_Usart5       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 13), /*!< Clock gate name: Usart5*/
    kCLOCK_Usart6       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 14), /*!< Clock gate name: Usart6*/
    kCLOCK_Usart7       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 15), /*!< Clock gate name: Usart7*/
    kCLOCK_Usart8       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 16), /*!< Clock gate name: Usart8*/
    kCLOCK_Usart9       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 17), /*!< Clock gate name: Usart9*/
    kCLOCK_Usart10      = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 18), /*!< Clock gate name: Usart10*/
    kCLOCK_Usart11      = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 19), /*!< Clock gate name: Usart11*/
    kCLOCK_Usart12      = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 20), /*!< Clock gate name: Usart12*/
    kCLOCK_Usart13      = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 21), /*!< Clock gate name: Usart13*/
    kCLOCK_I2s0         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 8),  /*!< Clock gate name: I2s0*/
    kCLOCK_I2s1         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 9),  /*!< Clock gate name: I2s1*/
    kCLOCK_I2s2         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 10), /*!< Clock gate name: I2s2*/
    kCLOCK_I2s3         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 11), /*!< Clock gate name: I2s3*/
    kCLOCK_I2s4         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 12), /*!< Clock gate name: I2s4*/
    kCLOCK_I2s5         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 13), /*!< Clock gate name: I2s5*/
    kCLOCK_I2s6         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 14), /*!< Clock gate name: I2s6*/
    kCLOCK_I2s7         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 15), /*!< Clock gate name: I2s7*/
    kCLOCK_I2s8         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 16), /*!< Clock gate name: I2s8*/
    kCLOCK_I2s9         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 17), /*!< Clock gate name: I2s9*/
    kCLOCK_I2s10        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 18), /*!< Clock gate name: I2s10*/
    kCLOCK_I2s11        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 19), /*!< Clock gate name: I2s11*/
    kCLOCK_I2s12        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 20), /*!< Clock gate name: I2s12*/
    kCLOCK_I2s13        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 21), /*!< Clock gate name: I2s13*/
    kCLOCK_I2c0         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 8),  /*!< Clock gate name: I2c0*/
    kCLOCK_I2c1         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 9),  /*!< Clock gate name: I2c1*/
    kCLOCK_I2c2         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 10), /*!< Clock gate name: I2c2*/
    kCLOCK_I2c3         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 11), /*!< Clock gate name: I2c3*/
    kCLOCK_I2c4         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 12), /*!< Clock gate name: I2c4*/
    kCLOCK_I2c5         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 13), /*!< Clock gate name: I2c5*/
    kCLOCK_I2c6         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 14), /*!< Clock gate name: I2c6*/
    kCLOCK_I2c7         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 15), /*!< Clock gate name: I2c7*/
    kCLOCK_I2c8         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 16), /*!< Clock gate name: I2c8*/
    kCLOCK_I2c9         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 17), /*!< Clock gate name: I2c9*/
    kCLOCK_I2c10        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 18), /*!< Clock gate name: I2c10*/
    kCLOCK_I2c11        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 19), /*!< Clock gate name: I2c11*/
    kCLOCK_I2c12        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 20), /*!< Clock gate name: I2c12*/
    kCLOCK_I2c13        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 21), /*!< Clock gate name: I2c13*/
    kCLOCK_I2c15        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 23), /*!< Clock gate name: I2c15*/
    kCLOCK_Spi0         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 8),  /*!< Clock gate name: Spi0*/
    kCLOCK_Spi1         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 9),  /*!< Clock gate name: Spi1*/
    kCLOCK_Spi2         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 10), /*!< Clock gate name: Spi2*/
    kCLOCK_Spi3         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 11), /*!< Clock gate name: Spi3*/
    kCLOCK_Spi4         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 12), /*!< Clock gate name: Spi4*/
    kCLOCK_Spi5         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 13), /*!< Clock gate name: Spi5*/
    kCLOCK_Spi6         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 14), /*!< Clock gate name: Spi6*/
    kCLOCK_Spi7         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 15), /*!< Clock gate name: Spi7*/
    kCLOCK_Spi8         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 16), /*!< Clock gate name: Spi8*/
    kCLOCK_Spi9         = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 17), /*!< Clock gate name: Spi9*/
    kCLOCK_Spi10        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 18), /*!< Clock gate name: Spi10*/
    kCLOCK_Spi11        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 19), /*!< Clock gate name: Spi11*/
    kCLOCK_Spi12        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 20), /*!< Clock gate name: Spi12*/
    kCLOCK_Spi13        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 21), /*!< Clock gate name: Spi13*/
    kCLOCK_Spi14        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 22), /*!< Clock gate name: Spi14*/
    kCLOCK_Spi16        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 25), /*!< Clock gate name: Spi16*/
    kCLOCK_Dmic0        = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 24), /*!< Clock gate name: Dmic0*/
    kCLOCK_OsEventTimer = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 27), /*!< Clock gate name: OsEventTimer*/
    kCLOCK_Flexio       = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL0, 29), /*!< Clock gate name: Flexio*/

    kCLOCK_HsGpio0 = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 0),  /*!< Clock gate name: HsGpio0*/
    kCLOCK_HsGpio1 = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 1),  /*!< Clock gate name: HsGpio1*/
    kCLOCK_HsGpio2 = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 2),  /*!< Clock gate name: HsGpio2*/
    kCLOCK_HsGpio3 = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 3),  /*!< Clock gate name: HsGpio3*/
    kCLOCK_HsGpio4 = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 4),  /*!< Clock gate name: HsGpio4*/
    kCLOCK_HsGpio5 = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 5),  /*!< Clock gate name: HsGpio5*/
    kCLOCK_HsGpio6 = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 6),  /*!< Clock gate name: HsGpio6*/
    kCLOCK_HsGpio7 = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 7),  /*!< Clock gate name: HsGpio7*/
    kCLOCK_Crc     = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 16), /*!< Clock gate name: Crc*/
    kCLOCK_Dmac0   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 23), /*!< Clock gate name: Dmac0*/
    kCLOCK_Dmac1   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 24), /*!< Clock gate name: Dmac1*/
    kCLOCK_Mu      = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 28), /*!< Clock gate name: Mu*/
    kCLOCK_Sema    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 29), /*!< Clock gate name: Sema*/
    kCLOCK_Freqme  = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL1, 31), /*!< Clock gate name: Freqme*/

    kCLOCK_Ct32b0   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 0),  /*!< Clock gate name: Ct32b0*/
    kCLOCK_Ct32b1   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 1),  /*!< Clock gate name: Ct32b1*/
    kCLOCK_Ct32b2   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 2),  /*!< Clock gate name: Ct32b2*/
    kCLOCK_Ct32b3   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 3),  /*!< Clock gate name: Ct32b3*/
    kCLOCK_Ct32b4   = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 4),  /*!< Clock gate name: Ct32b4*/
    kCLOCK_Rtc      = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 7),  /*!< Clock gate name: Rtc*/
    kCLOCK_Mrt0     = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 8),  /*!< Clock gate name: Mrt0*/
    kCLOCK_Wwdt1    = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 10), /*!< Clock gate name: Wwdt1*/
    kCLOCK_I3c0     = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 16), /*!< Clock gate name: I3c0*/
    kCLOCK_I3c1     = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 17), /*!< Clock gate name: I3c1*/
    kCLOCK_Pint     = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 30), /*!< Clock gate name: Pint*/
    kCLOCK_InputMux = CLK_GATE_DEFINE(CLK_CTL1_PSCCTL2, 31)  /*!< Clock gate name: InputMux. */
} clock_ip_name_t;

/*! @brief Clock name used to get clock frequency. */
typedef enum _clock_name
{
    kCLOCK_CoreSysClk,       /*!< Core clock  (aka HCLK)                                 */
    kCLOCK_BusClk,           /*!< Bus clock (AHB/APB clock, aka HCLK)                    */
    kCLOCK_MclkClk,          /*!< MCLK, to MCLK pin                                      */
    kCLOCK_ClockOutClk,      /*!< CLOCKOUT                                               */
    kCLOCK_AdcClk,           /*!< ADC                                                    */
    kCLOCK_Flexspi0Clk,      /*!< FlexSpi0                                               */
    kCLOCK_Flexspi1Clk,      /*!< FlexSpi1                                               */
    kCLOCK_SctClk,           /*!< SCT                                                    */
    kCLOCK_Wdt0Clk,          /*!< Watchdog0                                              */
    kCLOCK_Wdt1Clk,          /*!< Watchdog1                                              */
    kCLOCK_SystickClk,       /*!< Systick                                                */
    kCLOCK_Sdio0Clk,         /*!< SDIO0                                                  */
    kCLOCK_Sdio1Clk,         /*!< SDIO1                                                  */
    kCLOCK_I3cClk,           /*!< I3C0 and I3C1                                          */
    kCLOCK_UsbClk,           /*!< USB0                                                   */
    kCLOCK_DmicClk,          /*!< Digital Mic clock                                      */
    kCLOCK_DspCpuClk,        /*!< DSP  clock                                             */
    kCLOCK_AcmpClk,          /*!< Acmp clock                                             */
    kCLOCK_Flexcomm0Clk,     /*!< Flexcomm0Clock                                         */
    kCLOCK_Flexcomm1Clk,     /*!< Flexcomm1Clock                                         */
    kCLOCK_Flexcomm2Clk,     /*!< Flexcomm2Clock                                         */
    kCLOCK_Flexcomm3Clk,     /*!< Flexcomm3Clock                                         */
    kCLOCK_Flexcomm4Clk,     /*!< Flexcomm4Clock                                         */
    kCLOCK_Flexcomm5Clk,     /*!< Flexcomm5Clock                                         */
    kCLOCK_Flexcomm6Clk,     /*!< Flexcomm6Clock                                         */
    kCLOCK_Flexcomm7Clk,     /*!< Flexcomm7Clock                                         */
    kCLOCK_Flexcomm8Clk,     /*!< Flexcomm8Clock                                         */
    kCLOCK_Flexcomm9Clk,     /*!< Flexcomm9Clock                                         */
    kCLOCK_Flexcomm10Clk,    /*!< Flexcomm10Clock                                        */
    kCLOCK_Flexcomm11Clk,    /*!< Flexcomm11Clock                                        */
    kCLOCK_Flexcomm12Clk,    /*!< Flexcomm12Clock                                        */
    kCLOCK_Flexcomm13Clk,    /*!< Flexcomm13Clock                                        */
    kCLOCK_Flexcomm14Clk,    /*!< Flexcomm14Clock                                        */
    kCLOCK_Flexcomm15Clk,    /*!< Flexcomm15Clock                                        */
    kCLOCK_Flexcomm16Clk,    /*!< Flexcomm16Clock                                        */
    kCLOCK_FlexioClk,        /*!< FlexIO                                                 */
    kCLOCK_GpuClk,           /*!< GPU Core                                               */
    kCLOCK_DcPixelClk,       /*!< DCNano Pixel Clock                                     */
    kCLOCK_MipiDphyClk,      /*!< MIPI D-PHY Bit Clock                                   */
    kCLOCK_MipiDphyEscRxClk, /*!< MIPI D-PHY RX Clock                                    */
    kCLOCK_MipiDphyEscTxClk, /*!< MIPI D-PHY TX Clock                                    */
} clock_name_t;

/**
 * @brief PLL PFD clock name
 */
typedef enum _clock_pfd
{
    kCLOCK_Pfd0 = 0U, /*!< PLL PFD0 */
    kCLOCK_Pfd1 = 1U, /*!< PLL PFD1 */
    kCLOCK_Pfd2 = 2U, /*!< PLL PFD2 */
    kCLOCK_Pfd3 = 3U, /*!< PLL PFD3 */
} clock_pfd_t;

/*! @brief Clock Mux Switches
 *  The encoding is as follows each connection identified is 32bits wide
 *  starting from LSB upwards
 *
 *  [    31             30              29:28        27:25         24:14        13:11          10:0    ]
 *  [CLKCTL index]:[FRODIVSEL onoff]:[FRODIVSEL]:[MUXB choice]:[MUXB offset]:[MUXA choice]:[MUXA offset]
 *  FRODIVSEL onoff '1' means need to set FRODIVSEL. MUX offset 0 means end of descriptor.
 */
/* CLKCTL0 SEL */
#define SYSPLL0CLKSEL_OFFSET    0x200
#define MAINCLKSELA_OFFSET      0x430
#define MAINCLKSELB_OFFSET      0x434
#define FLEXSPI0FCLKSEL_OFFSET  0x620
#define FLEXSPI1FCLKSEL_OFFSET  0x630
#define SCTFCLKSEL_OFFSET       0x640
#define USBHSFCLKSEL_OFFSET     0x660
#define SDIO0FCLKSEL_OFFSET     0x680
#define SDIO1FCLKSEL_OFFSET     0x690
#define ADC0FCLKSEL0_OFFSET     0x6D0
#define ADC0FCLKSEL1_OFFSET     0x6D4
#define UTICKFCLKSEL_OFFSET     0x700
#define WDT0FCLKSEL_OFFSET      0x720
#define A32KHZWAKECLKSEL_OFFSET 0x730
#define SYSTICKFCLKSEL_OFFSET   0x760
#define DPHYCLKSEL_OFFSET       0x770
#define DPHYESCCLKSEL_OFFSET    0x778
#define GPUCLKSEL_OFFSET        0x790
#define DCPIXELCLKSEL_OFFSET    0x7A0
/* CLKCTL1 SEL */
#define AUDIOPLL0CLKSEL_OFFSET     0x200
#define DSPCPUCLKSELA_OFFSET       0x430
#define DSPCPUCLKSELB_OFFSET       0x434
#define OSEVENTTFCLKSEL_OFFSET     0x480
#define FC0FCLKSEL_OFFSET          0x508
#define FC1FCLKSEL_OFFSET          0x528
#define FC2FCLKSEL_OFFSET          0x548
#define FC3FCLKSEL_OFFSET          0x568
#define FC4FCLKSEL_OFFSET          0x588
#define FC5FCLKSEL_OFFSET          0x5A8
#define FC6FCLKSEL_OFFSET          0x5C8
#define FC7FCLKSEL_OFFSET          0x5E8
#define FC8FCLKSEL_OFFSET          0x608
#define FC9FCLKSEL_OFFSET          0x628
#define FC10FCLKSEL_OFFSET         0x648
#define FC11FCLKSEL_OFFSET         0x668
#define FC12FCLKSEL_OFFSET         0x688
#define FC13FCLKSEL_OFFSET         0x6A8
#define FC14FCLKSEL_OFFSET         0x6C8
#define FC15FCLKSEL_OFFSET         0x6E8
#define FC16FCLKSEL_OFFSET         0x708
#define FLEXIOCLKSEL_OFFSET        0x728
#define DMIC0FCLKSEL_OFFSET        0x780
#define CT32BIT0FCLKSEL_OFFSET     0x7A0
#define CT32BIT1FCLKSEL_OFFSET     0x7A4
#define CT32BIT2FCLKSEL_OFFSET     0x7A8
#define CT32BIT3FCLKSEL_OFFSET     0x7AC
#define CT32BIT4FCLKSEL_OFFSET     0x7B0
#define AUDIOMCLKSEL_OFFSET        0x7C0
#define CLKOUTSEL0_OFFSET          0x7E0
#define CLKOUTSEL1_OFFSET          0x7E4
#define I3C01FCLKSEL_OFFSET        0x800
#define I3C01FCLKSTCSEL_OFFSET     0x804
#define I3C01FCLKSTSTCLKSEL_OFFSET 0x814
#define WDT1FCLKSEL_OFFSET         0x820
#define ACMP0FCLKSEL_OFFSET        0x830
/* CLKCTL0 DIV */
#define LOWFREQCLKDIV_OFFSET    0x130
#define MAINPLLCLKDIV_OFFSET    0x240
#define DSPPLLCLKDIV_OFFSET     0x244
#define AUX0PLLCLKDIV_OFFSET    0x248
#define AUX1PLLCLKDIV_OFFSET    0x24C
#define SYSCPUAHBCLKDIV_OFFSET  0x400
#define PFC0CLKDIV_OFFSET       0x500
#define PFC1CLKDIV_OFFSET       0x504
#define FLEXSPI0FCLKDIV_OFFSET  0x624
#define FLEXSPI1FCLKDIV_OFFSET  0x634
#define SCTFCLKDIV_OFFSET       0x644
#define USBHSFCLKDIV_OFFSET     0x664
#define SDIO0FCLKDIV_OFFSET     0x684
#define SDIO1FCLKDIV_OFFSET     0x694
#define ADC0FCLKDIV_OFFSET      0x6D8
#define A32KHZWAKECLKDIV_OFFSET 0x734
#define SYSTICKFCLKDIV_OFFSET   0x764
#define DPHYCLKDIV_OFFSET       0x774
#define DPHYESCRXCLKDIV_OFFSET  0x77C
#define DPHYESCTXCLKDIV_OFFSET  0x780
#define GPUCLKDIV_OFFSET        0x794
#define DCPIXELCLKDIV_OFFSET    0x7A4
/* CLKCTL1 DIV */
#define AUDIOPLLCLKDIV_OFFSET  0x240
#define DSPCPUCLKDIV_OFFSET    0x400
#define FLEXIOCLKDIV_OFFSET    0x740
#define FRGPLLCLKDIV_OFFSET    0x760
#define DMIC0FCLKDIV_OFFSET    0x784
#define AUDIOMCLKDIV_OFFSET    0x7C4
#define CLKOUTFCLKDIV_OFFSET   0x7E8
#define I3C01FCLKSTCDIV_OFFSET 0x808
#define I3C01FCLKSDIV_OFFSET   0x80C
#define I3C01FCLKDIV_OFFSET    0x810
#define ACMP0FCLKDIV_OFFSET    0x834

#define CLKCTL0_TUPLE_MUXA(reg, choice) ((((reg) >> 2U) & 0x7FFU) | (((choice)&0x7U) << 11U))
#define CLKCTL0_TUPLE_MUXB(reg, choice) (((((reg) >> 2U) & 0x7FFU) << 14U) | (((choice)&0x7U) << 25U))
#define CLKCTL1_TUPLE_MUXA(reg, choice) (0x80000000U | ((((reg) >> 2U) & 0x7FFU) | (((choice)&0x7U) << 11U)))
#define CLKCTL1_TUPLE_MUXB(reg, choice) (0x80000000U | (((((reg) >> 2U) & 0x7FFU) << 14U) | (((choice)&0x7U) << 25U)))
#define CLKCTL_TUPLE_FRODIVSEL(choice)  (0x40000000U | (((choice)&0x7U) << 28U))
#define CLKCTL_TUPLE_REG(base, tuple)   ((volatile uint32_t *)(((uint32_t)(base)) + (((uint32_t)(tuple)&0x7FFU) << 2U)))
#define CLKCTL_TUPLE_SEL(tuple)         (((uint32_t)(tuple) >> 11U) & 0x7U)

/*!
 * @brief The enumerator of clock attach Id.
 */
typedef enum _clock_attach_id
{
    kFRO_DIV8_to_SYS_PLL = CLKCTL0_TUPLE_MUXA(SYSPLL0CLKSEL_OFFSET, 0), /*!< Attach FRO_DIV8 to SYS_PLL. */
    kOSC_CLK_to_SYS_PLL  = CLKCTL0_TUPLE_MUXA(SYSPLL0CLKSEL_OFFSET, 1), /*!< Attach OSC_CLK to SYS_PLL. */
    kNONE_to_SYS_PLL     = CLKCTL0_TUPLE_MUXA(SYSPLL0CLKSEL_OFFSET, 7), /*!< Attach NONE to SYS_PLL. */

    kFRO_DIV8_to_AUDIO_PLL = CLKCTL1_TUPLE_MUXA(AUDIOPLL0CLKSEL_OFFSET, 0), /*!< Attach FRO_DIV8 to AUDIO_PLL. */
    kOSC_CLK_to_AUDIO_PLL  = CLKCTL1_TUPLE_MUXA(AUDIOPLL0CLKSEL_OFFSET, 1), /*!< Attach OSC_CLK to AUDIO_PLL. */
    kNONE_to_AUDIO_PLL     = CLKCTL1_TUPLE_MUXA(AUDIOPLL0CLKSEL_OFFSET, 7), /*!< Attach NONE to AUDIO_PLL. */

    kLPOSC_to_MAIN_CLK = CLKCTL0_TUPLE_MUXA(MAINCLKSELA_OFFSET, 0) |
                         CLKCTL0_TUPLE_MUXB(MAINCLKSELB_OFFSET, 0), /*!< Attach LPOSC to MAIN_CLK. */
    kFRO_DIV2_to_MAIN_CLK = CLKCTL_TUPLE_FRODIVSEL(0) | CLKCTL0_TUPLE_MUXA(MAINCLKSELA_OFFSET, 1) |
                            CLKCTL0_TUPLE_MUXB(MAINCLKSELB_OFFSET, 0), /*!< Attach Fro_DIV2 to MAIN_CLK. */
    kFRO_DIV4_to_MAIN_CLK = CLKCTL_TUPLE_FRODIVSEL(1) | CLKCTL0_TUPLE_MUXA(MAINCLKSELA_OFFSET, 1) |
                            CLKCTL0_TUPLE_MUXB(MAINCLKSELB_OFFSET, 0), /*!< Attach Fro_DIV4 to MAIN_CLK. */
    kFRO_DIV8_to_MAIN_CLK = CLKCTL_TUPLE_FRODIVSEL(2) | CLKCTL0_TUPLE_MUXA(MAINCLKSELA_OFFSET, 1) |
                            CLKCTL0_TUPLE_MUXB(MAINCLKSELB_OFFSET, 0), /*!< Attach Fro_DIV8 to MAIN_CLK. */
    kFRO_DIV16_to_MAIN_CLK = CLKCTL_TUPLE_FRODIVSEL(3) | CLKCTL0_TUPLE_MUXA(MAINCLKSELA_OFFSET, 1) |
                             CLKCTL0_TUPLE_MUXB(MAINCLKSELB_OFFSET, 0), /*!< Attach Fro_DIV16 to MAIN_CLK. */
    kOSC_CLK_to_MAIN_CLK = CLKCTL0_TUPLE_MUXA(MAINCLKSELA_OFFSET, 2) |
                           CLKCTL0_TUPLE_MUXB(MAINCLKSELB_OFFSET, 0), /*!< Attach OSC_CLK to MAIN_CLK. */
    kFRO_DIV1_to_MAIN_CLK = CLKCTL0_TUPLE_MUXA(MAINCLKSELA_OFFSET, 3) |
                            CLKCTL0_TUPLE_MUXB(MAINCLKSELB_OFFSET, 0), /*!< Attach FRO_DIV1 to MAIN_CLK. */
    kMAIN_PLL_to_MAIN_CLK = CLKCTL0_TUPLE_MUXA(MAINCLKSELB_OFFSET, 1), /*!< Attach MAIN_PLL to MAIN_CLK. */
    kOSC32K_to_MAIN_CLK   = CLKCTL0_TUPLE_MUXA(MAINCLKSELB_OFFSET, 2), /*!< Attach OSC32K to MAIN_CLK. */

    kFRO_DIV1_to_DSP_MAIN_CLK = CLKCTL1_TUPLE_MUXA(DSPCPUCLKSELA_OFFSET, 0) |
                                CLKCTL1_TUPLE_MUXB(DSPCPUCLKSELB_OFFSET, 0), /*!< Attach Fro_DIV1 to DSP_MAIN_CLK. */
    kOSC_CLK_to_DSP_MAIN_CLK = CLKCTL1_TUPLE_MUXA(DSPCPUCLKSELA_OFFSET, 1) |
                               CLKCTL1_TUPLE_MUXB(DSPCPUCLKSELB_OFFSET, 0), /*!< Attach OSC_CLK to DSP_MAIN_CLK. */
    kLPOSC_to_DSP_MAIN_CLK = CLKCTL1_TUPLE_MUXA(DSPCPUCLKSELA_OFFSET, 2) |
                             CLKCTL1_TUPLE_MUXB(DSPCPUCLKSELB_OFFSET, 0),    /*!< Attach LPOSC to DSP_MAIN_CLK. */
    kMAIN_PLL_to_DSP_MAIN_CLK = CLKCTL1_TUPLE_MUXA(DSPCPUCLKSELB_OFFSET, 1), /*!< Attach MAIN_PLL to DSP_MAIN_CLK. */
    kDSP_PLL_to_DSP_MAIN_CLK  = CLKCTL1_TUPLE_MUXA(DSPCPUCLKSELB_OFFSET, 2), /*!< Attach DSP_PLL to DSP_MAIN_CLK. */
    kOSC32K_to_DSP_MAIN_CLK   = CLKCTL1_TUPLE_MUXA(DSPCPUCLKSELB_OFFSET, 3), /*!< Attach OSC32K to DSP_MAIN_CLK. */

    kLPOSC_to_UTICK_CLK = CLKCTL0_TUPLE_MUXA(UTICKFCLKSEL_OFFSET, 0), /*!< Attach LPOSC to UTICK_CLK. */
    kNONE_to_UTICK_CLK  = CLKCTL0_TUPLE_MUXA(UTICKFCLKSEL_OFFSET, 7), /*!< Attach NONE to UTICK_CLK. */

    kLPOSC_to_WDT0_CLK = CLKCTL0_TUPLE_MUXA(WDT0FCLKSEL_OFFSET, 0), /*!< Attach LPOSC to WDT0_CLK. */
    kNONE_to_WDT0_CLK  = CLKCTL0_TUPLE_MUXA(WDT0FCLKSEL_OFFSET, 7), /*!< Attach NONE to WDT0_CLK. */

    kLPOSC_to_WDT1_CLK = CLKCTL1_TUPLE_MUXA(WDT1FCLKSEL_OFFSET, 0), /*!< Attach LPOSC to WDT1_CLK. */
    kNONE_to_WDT1_CLK  = CLKCTL1_TUPLE_MUXA(WDT1FCLKSEL_OFFSET, 7), /*!< Attach NONE to WDT1_CLK. */

    kOSC32K_to_32KHZWAKE_CLK = CLKCTL0_TUPLE_MUXA(A32KHZWAKECLKSEL_OFFSET, 0), /*!< Attach OSC32K to 32KHZWAKE_CLK. */
    kLPOSC_DIV32_to_32KHZWAKE_CLK = CLKCTL0_TUPLE_MUXA(A32KHZWAKECLKSEL_OFFSET, 1), /*!< Attach LPOSC_DIV32
                                                                                    to 32KHZWAKE_CLK. */
    kNONE_to_32KHZWAKE_CLK = CLKCTL0_TUPLE_MUXA(A32KHZWAKECLKSEL_OFFSET, 7), /*!< Attach NONE to 32KHZWAKE_CLK. */

    kMAIN_CLK_DIV_to_SYSTICK_CLK = CLKCTL0_TUPLE_MUXA(SYSTICKFCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK_DIV
                                                                                    to SYSTICK_CLK. */
    kLPOSC_to_SYSTICK_CLK  = CLKCTL0_TUPLE_MUXA(SYSTICKFCLKSEL_OFFSET, 1),       /*!< Attach LPOSC to SYSTICK_CLK. */
    kOSC32K_to_SYSTICK_CLK = CLKCTL0_TUPLE_MUXA(SYSTICKFCLKSEL_OFFSET, 2),       /*!< Attach OSC32K to SYSTICK_CLK. */
    kNONE_to_SYSTICK_CLK   = CLKCTL0_TUPLE_MUXA(SYSTICKFCLKSEL_OFFSET, 7),       /*!< Attach NONE to SYSTICK_CLK. */

    kMAIN_CLK_to_SDIO0_CLK = CLKCTL0_TUPLE_MUXA(SDIO0FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to SDIO0_CLK. */
    kMAIN_PLL_to_SDIO0_CLK = CLKCTL0_TUPLE_MUXA(SDIO0FCLKSEL_OFFSET, 1), /*!< Attach MAIN_PLL to SDIO0_CLK. */
    kAUX0_PLL_to_SDIO0_CLK = CLKCTL0_TUPLE_MUXA(SDIO0FCLKSEL_OFFSET, 2), /*!< Attach AUX0_PLL to SDIO0_CLK. */
    kFRO_DIV2_to_SDIO0_CLK = CLKCTL0_TUPLE_MUXA(SDIO0FCLKSEL_OFFSET, 3), /*!< Attach FRO_DIV2 to SDIO0_CLK. */
    kAUX1_PLL_to_SDIO0_CLK = CLKCTL0_TUPLE_MUXA(SDIO0FCLKSEL_OFFSET, 4), /*!< Attach AUX1_PLL to SDIO0_CLK. */
    kNONE_to_SDIO0_CLK     = CLKCTL0_TUPLE_MUXA(SDIO0FCLKSEL_OFFSET, 7), /*!< Attach NONE to SDIO0_CLK. */

    kMAIN_CLK_to_SDIO1_CLK = CLKCTL0_TUPLE_MUXA(SDIO1FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to SDIO1_CLK. */
    kMAIN_PLL_to_SDIO1_CLK = CLKCTL0_TUPLE_MUXA(SDIO1FCLKSEL_OFFSET, 1), /*!< Attach MAIN_PLL to SDIO1_CLK. */
    kAUX0_PLL_to_SDIO1_CLK = CLKCTL0_TUPLE_MUXA(SDIO1FCLKSEL_OFFSET, 2), /*!< Attach AUX0_PLL to SDIO1_CLK. */
    kFRO_DIV2_to_SDIO1_CLK = CLKCTL0_TUPLE_MUXA(SDIO1FCLKSEL_OFFSET, 3), /*!< Attach FRO_DIV2 to SDIO1_CLK. */
    kAUX1_PLL_to_SDIO1_CLK = CLKCTL0_TUPLE_MUXA(SDIO1FCLKSEL_OFFSET, 4), /*!< Attach AUX1_PLL to SDIO1_CLK. */
    kNONE_to_SDIO1_CLK     = CLKCTL0_TUPLE_MUXA(SDIO1FCLKSEL_OFFSET, 7), /*!< Attach NONE to SDIO1_CLK. */

    kMAIN_CLK_to_CTIMER0     = CLKCTL1_TUPLE_MUXA(CT32BIT0FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to CTIMER0. */
    kFRO_DIV1_to_CTIMER0     = CLKCTL1_TUPLE_MUXA(CT32BIT0FCLKSEL_OFFSET, 1), /*!< Attach FRO_DIV1 to CTIMER0. */
    kAUDIO_PLL_to_CTIMER0    = CLKCTL1_TUPLE_MUXA(CT32BIT0FCLKSEL_OFFSET, 2), /*!< Attach AUDIO_PLL to CTIMER0. */
    kMASTER_CLK_to_CTIMER0   = CLKCTL1_TUPLE_MUXA(CT32BIT0FCLKSEL_OFFSET, 3), /*!< Attach MASTER_CLK to CTIMER0. */
    k32K_WAKE_CLK_to_CTIMER0 = CLKCTL1_TUPLE_MUXA(CT32BIT0FCLKSEL_OFFSET, 4), /*!< Attach 32K_WAKE_CLK to CTIMER0. */
    kNONE_to_CTIMER0         = CLKCTL1_TUPLE_MUXA(CT32BIT0FCLKSEL_OFFSET, 7), /*!< Attach NONE to CTIMER0. */

    kMAIN_CLK_to_CTIMER1     = CLKCTL1_TUPLE_MUXA(CT32BIT1FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to CTIMER1. */
    kFRO_DIV1_to_CTIMER1     = CLKCTL1_TUPLE_MUXA(CT32BIT1FCLKSEL_OFFSET, 1), /*!< Attach FRO_DIV1 to CTIMER1. */
    kAUDIO_PLL_to_CTIMER1    = CLKCTL1_TUPLE_MUXA(CT32BIT1FCLKSEL_OFFSET, 2), /*!< Attach AUDIO_PLL to CTIMER1. */
    kMASTER_CLK_to_CTIMER1   = CLKCTL1_TUPLE_MUXA(CT32BIT1FCLKSEL_OFFSET, 3), /*!< Attach MASTER_CLK to CTIMER1. */
    k32K_WAKE_CLK_to_CTIMER1 = CLKCTL1_TUPLE_MUXA(CT32BIT1FCLKSEL_OFFSET, 4), /*!< Attach 32K_WAKE_CLK to CTIMER1. */
    kNONE_to_CTIMER1         = CLKCTL1_TUPLE_MUXA(CT32BIT1FCLKSEL_OFFSET, 7), /*!< Attach NONE to CTIMER1. */

    kMAIN_CLK_to_CTIMER2     = CLKCTL1_TUPLE_MUXA(CT32BIT2FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to CTIMER2. */
    kFRO_DIV1_to_CTIMER2     = CLKCTL1_TUPLE_MUXA(CT32BIT2FCLKSEL_OFFSET, 1), /*!< Attach FRO_DIV1 to CTIMER2. */
    kAUDIO_PLL_to_CTIMER2    = CLKCTL1_TUPLE_MUXA(CT32BIT2FCLKSEL_OFFSET, 2), /*!< Attach AUDIO_PLL to CTIMER2. */
    kMASTER_CLK_to_CTIMER2   = CLKCTL1_TUPLE_MUXA(CT32BIT2FCLKSEL_OFFSET, 3), /*!< Attach MASTER_CLK to CTIMER2. */
    k32K_WAKE_CLK_to_CTIMER2 = CLKCTL1_TUPLE_MUXA(CT32BIT2FCLKSEL_OFFSET, 4), /*!< Attach 32K_WAKE_CLK to CTIMER2. */
    kNONE_to_CTIMER2         = CLKCTL1_TUPLE_MUXA(CT32BIT2FCLKSEL_OFFSET, 7), /*!< Attach NONE to CTIMER2. */

    kMAIN_CLK_to_CTIMER3     = CLKCTL1_TUPLE_MUXA(CT32BIT3FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to CTIMER3. */
    kFRO_DIV1_to_CTIMER3     = CLKCTL1_TUPLE_MUXA(CT32BIT3FCLKSEL_OFFSET, 1), /*!< Attach FRO_DIV1 to CTIMER3. */
    kAUDIO_PLL_to_CTIMER3    = CLKCTL1_TUPLE_MUXA(CT32BIT3FCLKSEL_OFFSET, 2), /*!< Attach AUDIO_PLL to CTIMER3. */
    kMASTER_CLK_to_CTIMER3   = CLKCTL1_TUPLE_MUXA(CT32BIT3FCLKSEL_OFFSET, 3), /*!< Attach MASTER_CLK to CTIMER3. */
    k32K_WAKE_CLK_to_CTIMER3 = CLKCTL1_TUPLE_MUXA(CT32BIT3FCLKSEL_OFFSET, 4), /*!< Attach 32K_WAKE_CLK to CTIMER3. */
    kNONE_to_CTIMER3         = CLKCTL1_TUPLE_MUXA(CT32BIT3FCLKSEL_OFFSET, 7), /*!< Attach NONE to CTIMER3. */

    kMAIN_CLK_to_CTIMER4     = CLKCTL1_TUPLE_MUXA(CT32BIT4FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to CTIMER4. */
    kFRO_DIV1_to_CTIMER4     = CLKCTL1_TUPLE_MUXA(CT32BIT4FCLKSEL_OFFSET, 1), /*!< Attach FRO_DIV1 to CTIMER4. */
    kAUDIO_PLL_to_CTIMER4    = CLKCTL1_TUPLE_MUXA(CT32BIT4FCLKSEL_OFFSET, 2), /*!< Attach AUDIO_PLL to CTIMER4. */
    kMASTER_CLK_to_CTIMER4   = CLKCTL1_TUPLE_MUXA(CT32BIT4FCLKSEL_OFFSET, 3), /*!< Attach MASTER_CLK to CTIMER4. */
    k32K_WAKE_CLK_to_CTIMER4 = CLKCTL1_TUPLE_MUXA(CT32BIT4FCLKSEL_OFFSET, 4), /*!< Attach 32K_WAKE_CLK to CTIMER4. */
    kNONE_to_CTIMER4         = CLKCTL1_TUPLE_MUXA(CT32BIT4FCLKSEL_OFFSET, 7), /*!< Attach NONE to CTIMER4. */

    kMAIN_CLK_to_FLEXSPI0_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI0FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to FLEXSPI0_CLK. */
    kMAIN_PLL_to_FLEXSPI0_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI0FCLKSEL_OFFSET, 1), /*!< Attach MAIN_PLL to FLEXSPI0_CLK. */
    kAUX0_PLL_to_FLEXSPI0_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI0FCLKSEL_OFFSET, 2), /*!< Attach AUX0_PLL to FLEXSPI0_CLK. */
    kFRO_DIV1_to_FLEXSPI0_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI0FCLKSEL_OFFSET, 3), /*!< Attach FRO_DIV1 to FLEXSPI0_CLK. */
    kAUX1_PLL_to_FLEXSPI0_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI0FCLKSEL_OFFSET, 4), /*!< Attach AUX1_PLL to FLEXSPI0_CLK. */
    kFRO_DIV4_to_FLEXSPI0_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI0FCLKSEL_OFFSET, 5), /*!< Attach FRO_DIV4 to FLEXSPI0_CLK. */
    kFRO_DIV8_to_FLEXSPI0_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI0FCLKSEL_OFFSET, 6), /*!< Attach FRO_DIV8 to FLEXSPI0_CLK. */
    kNONE_to_FLEXSPI0_CLK     = CLKCTL0_TUPLE_MUXA(FLEXSPI0FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXSPI0_CLK. */

    kMAIN_CLK_to_FLEXSPI1_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI1FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to FLEXSPI1_CLK. */
    kMAIN_PLL_to_FLEXSPI1_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI1FCLKSEL_OFFSET, 1), /*!< Attach MAIN_PLL to FLEXSPI1_CLK. */
    kAUX0_PLL_to_FLEXSPI1_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI1FCLKSEL_OFFSET, 2), /*!< Attach AUX0_PLL to FLEXSPI1_CLK. */
    kFRO_DIV1_to_FLEXSPI1_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI1FCLKSEL_OFFSET, 3), /*!< Attach FRO_DIV1 to FLEXSPI1_CLK. */
    kAUX1_PLL_to_FLEXSPI1_CLK = CLKCTL0_TUPLE_MUXA(FLEXSPI1FCLKSEL_OFFSET, 4), /*!< Attach AUX1_PLL to FLEXSPI1_CLK. */
    kNONE_to_FLEXSPI1_CLK     = CLKCTL0_TUPLE_MUXA(FLEXSPI1FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXSPI1_CLK. */

    kOSC_CLK_to_USB_CLK  = CLKCTL0_TUPLE_MUXA(USBHSFCLKSEL_OFFSET, 0), /*!< Attach OSC_CLK to USB_CLK. */
    kMAIN_CLK_to_USB_CLK = CLKCTL0_TUPLE_MUXA(USBHSFCLKSEL_OFFSET, 1), /*!< Attach MAIN_CLK to USB_CLK. */
    kAUX0_PLL_to_USB_CLK = CLKCTL0_TUPLE_MUXA(USBHSFCLKSEL_OFFSET, 3), /*!< Attach AUX0_PLL to USB_CLK. */
    kNONE_to_USB_CLK     = CLKCTL0_TUPLE_MUXA(USBHSFCLKSEL_OFFSET, 7), /*!< Attach NONE to USB_CLK. */

    kMAIN_CLK_to_SCT_CLK  = CLKCTL0_TUPLE_MUXA(SCTFCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to SCT_CLK. */
    kMAIN_PLL_to_SCT_CLK  = CLKCTL0_TUPLE_MUXA(SCTFCLKSEL_OFFSET, 1), /*!< Attach MAIN_PLL to SCT_CLK. */
    kAUX0_PLL_to_SCT_CLK  = CLKCTL0_TUPLE_MUXA(SCTFCLKSEL_OFFSET, 2), /*!< Attach AUX0_PLL to SCT_CLK. */
    kFRO_DIV1_to_SCT_CLK  = CLKCTL0_TUPLE_MUXA(SCTFCLKSEL_OFFSET, 3), /*!< Attach FRO_DIV1 to SCT_CLK. */
    kAUX1_PLL_to_SCT_CLK  = CLKCTL0_TUPLE_MUXA(SCTFCLKSEL_OFFSET, 4), /*!< Attach AUX1_PLL to SCT_CLK. */
    kAUDIO_PLL_to_SCT_CLK = CLKCTL0_TUPLE_MUXA(SCTFCLKSEL_OFFSET, 5), /*!< Attach AUDIO_PLL to SCT_CLK. */
    kNONE_to_SCT_CLK      = CLKCTL0_TUPLE_MUXA(SCTFCLKSEL_OFFSET, 7), /*!< Attach NONE to SCT_CLK. */

    kLPOSC_to_OSTIMER_CLK  = CLKCTL1_TUPLE_MUXA(OSEVENTTFCLKSEL_OFFSET, 0), /*!< Attach LPOSC to OSTIMER_CLK. */
    kOSC32K_to_OSTIMER_CLK = CLKCTL1_TUPLE_MUXA(OSEVENTTFCLKSEL_OFFSET, 1), /*!< Attach OSC32K to OSTIMER_CLK. */
    kHCLK_to_OSTIMER_CLK   = CLKCTL1_TUPLE_MUXA(OSEVENTTFCLKSEL_OFFSET, 2), /*!< Attach HCLK to OSTIMER_CLK. */
    kNONE_to_OSTIMER_CLK   = CLKCTL1_TUPLE_MUXA(OSEVENTTFCLKSEL_OFFSET, 7), /*!< Attach NONE to OSTIMER_CLK. */

    kFRO_DIV8_to_MCLK_CLK  = CLKCTL1_TUPLE_MUXA(AUDIOMCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV8 to MCLK_CLK. */
    kAUDIO_PLL_to_MCLK_CLK = CLKCTL1_TUPLE_MUXA(AUDIOMCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to MCLK_CLK. */
    kNONE_to_MCLK_CLK      = CLKCTL1_TUPLE_MUXA(AUDIOMCLKSEL_OFFSET, 7), /*!< Attach NONE to MCLK_CLK. */

    kFRO_DIV4_to_DMIC     = CLKCTL1_TUPLE_MUXA(DMIC0FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to DMIC. */
    kAUDIO_PLL_to_DMIC    = CLKCTL1_TUPLE_MUXA(DMIC0FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to DMIC. */
    kMASTER_CLK_to_DMIC   = CLKCTL1_TUPLE_MUXA(DMIC0FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to DMIC. */
    kLPOSC_to_DMIC        = CLKCTL1_TUPLE_MUXA(DMIC0FCLKSEL_OFFSET, 3), /*!< Attach LPOSC to DMIC. */
    k32K_WAKE_CLK_to_DMIC = CLKCTL1_TUPLE_MUXA(DMIC0FCLKSEL_OFFSET, 4), /*!< Attach 32K_WAKE_CLK to DMIC. */
    kNONE_to_DMIC         = CLKCTL1_TUPLE_MUXA(DMIC0FCLKSEL_OFFSET, 7), /*!< Attach NONE to DMIC. */

    kFRO_DIV4_to_FLEXCOMM0   = CLKCTL1_TUPLE_MUXA(FC0FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM0. */
    kAUDIO_PLL_to_FLEXCOMM0  = CLKCTL1_TUPLE_MUXA(FC0FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM0. */
    kMASTER_CLK_to_FLEXCOMM0 = CLKCTL1_TUPLE_MUXA(FC0FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM0. */
    kFRG_to_FLEXCOMM0        = CLKCTL1_TUPLE_MUXA(FC0FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM0. */
    kNONE_to_FLEXCOMM0       = CLKCTL1_TUPLE_MUXA(FC0FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM0. */

    kFRO_DIV4_to_FLEXCOMM1   = CLKCTL1_TUPLE_MUXA(FC1FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM1. */
    kAUDIO_PLL_to_FLEXCOMM1  = CLKCTL1_TUPLE_MUXA(FC1FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM1. */
    kMASTER_CLK_to_FLEXCOMM1 = CLKCTL1_TUPLE_MUXA(FC1FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM1. */
    kFRG_to_FLEXCOMM1        = CLKCTL1_TUPLE_MUXA(FC1FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM1. */
    kNONE_to_FLEXCOMM1       = CLKCTL1_TUPLE_MUXA(FC1FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM1. */

    kFRO_DIV4_to_FLEXCOMM2   = CLKCTL1_TUPLE_MUXA(FC2FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM2. */
    kAUDIO_PLL_to_FLEXCOMM2  = CLKCTL1_TUPLE_MUXA(FC2FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM2. */
    kMASTER_CLK_to_FLEXCOMM2 = CLKCTL1_TUPLE_MUXA(FC2FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM2. */
    kFRG_to_FLEXCOMM2        = CLKCTL1_TUPLE_MUXA(FC2FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM2. */
    kNONE_to_FLEXCOMM2       = CLKCTL1_TUPLE_MUXA(FC2FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM2. */

    kFRO_DIV4_to_FLEXCOMM3   = CLKCTL1_TUPLE_MUXA(FC3FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM3. */
    kAUDIO_PLL_to_FLEXCOMM3  = CLKCTL1_TUPLE_MUXA(FC3FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM3. */
    kMASTER_CLK_to_FLEXCOMM3 = CLKCTL1_TUPLE_MUXA(FC3FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM3. */
    kFRG_to_FLEXCOMM3        = CLKCTL1_TUPLE_MUXA(FC3FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM3. */
    kNONE_to_FLEXCOMM3       = CLKCTL1_TUPLE_MUXA(FC3FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM3. */

    kFRO_DIV4_to_FLEXCOMM4   = CLKCTL1_TUPLE_MUXA(FC4FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM4. */
    kAUDIO_PLL_to_FLEXCOMM4  = CLKCTL1_TUPLE_MUXA(FC4FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM4. */
    kMASTER_CLK_to_FLEXCOMM4 = CLKCTL1_TUPLE_MUXA(FC4FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM4. */
    kFRG_to_FLEXCOMM4        = CLKCTL1_TUPLE_MUXA(FC4FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM4. */
    kNONE_to_FLEXCOMM4       = CLKCTL1_TUPLE_MUXA(FC4FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM4. */

    kFRO_DIV4_to_FLEXCOMM5   = CLKCTL1_TUPLE_MUXA(FC5FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM5. */
    kAUDIO_PLL_to_FLEXCOMM5  = CLKCTL1_TUPLE_MUXA(FC5FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM5. */
    kMASTER_CLK_to_FLEXCOMM5 = CLKCTL1_TUPLE_MUXA(FC5FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM5. */
    kFRG_to_FLEXCOMM5        = CLKCTL1_TUPLE_MUXA(FC5FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM5. */
    kNONE_to_FLEXCOMM5       = CLKCTL1_TUPLE_MUXA(FC5FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM5. */

    kFRO_DIV4_to_FLEXCOMM6   = CLKCTL1_TUPLE_MUXA(FC6FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM6. */
    kAUDIO_PLL_to_FLEXCOMM6  = CLKCTL1_TUPLE_MUXA(FC6FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM6. */
    kMASTER_CLK_to_FLEXCOMM6 = CLKCTL1_TUPLE_MUXA(FC6FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM6. */
    kFRG_to_FLEXCOMM6        = CLKCTL1_TUPLE_MUXA(FC6FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM6. */
    kNONE_to_FLEXCOMM6       = CLKCTL1_TUPLE_MUXA(FC6FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM6. */

    kFRO_DIV4_to_FLEXCOMM7   = CLKCTL1_TUPLE_MUXA(FC7FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM7. */
    kAUDIO_PLL_to_FLEXCOMM7  = CLKCTL1_TUPLE_MUXA(FC7FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM7. */
    kMASTER_CLK_to_FLEXCOMM7 = CLKCTL1_TUPLE_MUXA(FC7FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM7. */
    kFRG_to_FLEXCOMM7        = CLKCTL1_TUPLE_MUXA(FC7FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM7. */
    kNONE_to_FLEXCOMM7       = CLKCTL1_TUPLE_MUXA(FC7FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM7. */

    kFRO_DIV4_to_FLEXCOMM8   = CLKCTL1_TUPLE_MUXA(FC8FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM8. */
    kAUDIO_PLL_to_FLEXCOMM8  = CLKCTL1_TUPLE_MUXA(FC8FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM8. */
    kMASTER_CLK_to_FLEXCOMM8 = CLKCTL1_TUPLE_MUXA(FC8FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM8. */
    kFRG_to_FLEXCOMM8        = CLKCTL1_TUPLE_MUXA(FC8FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM8. */
    kNONE_to_FLEXCOMM8       = CLKCTL1_TUPLE_MUXA(FC8FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM8. */

    kFRO_DIV4_to_FLEXCOMM9   = CLKCTL1_TUPLE_MUXA(FC9FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM9. */
    kAUDIO_PLL_to_FLEXCOMM9  = CLKCTL1_TUPLE_MUXA(FC9FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM9. */
    kMASTER_CLK_to_FLEXCOMM9 = CLKCTL1_TUPLE_MUXA(FC9FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM9. */
    kFRG_to_FLEXCOMM9        = CLKCTL1_TUPLE_MUXA(FC9FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM9. */
    kNONE_to_FLEXCOMM9       = CLKCTL1_TUPLE_MUXA(FC9FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM9. */

    kFRO_DIV4_to_FLEXCOMM10   = CLKCTL1_TUPLE_MUXA(FC10FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM10. */
    kAUDIO_PLL_to_FLEXCOMM10  = CLKCTL1_TUPLE_MUXA(FC10FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM10. */
    kMASTER_CLK_to_FLEXCOMM10 = CLKCTL1_TUPLE_MUXA(FC10FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM10. */
    kFRG_to_FLEXCOMM10        = CLKCTL1_TUPLE_MUXA(FC10FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM10. */
    kNONE_to_FLEXCOMM10       = CLKCTL1_TUPLE_MUXA(FC10FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM10. */

    kFRO_DIV4_to_FLEXCOMM11   = CLKCTL1_TUPLE_MUXA(FC11FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM11. */
    kAUDIO_PLL_to_FLEXCOMM11  = CLKCTL1_TUPLE_MUXA(FC11FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM11. */
    kMASTER_CLK_to_FLEXCOMM11 = CLKCTL1_TUPLE_MUXA(FC11FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM11. */
    kFRG_to_FLEXCOMM11        = CLKCTL1_TUPLE_MUXA(FC11FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM11. */
    kNONE_to_FLEXCOMM11       = CLKCTL1_TUPLE_MUXA(FC11FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM11. */

    kFRO_DIV4_to_FLEXCOMM12   = CLKCTL1_TUPLE_MUXA(FC12FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM12. */
    kAUDIO_PLL_to_FLEXCOMM12  = CLKCTL1_TUPLE_MUXA(FC12FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM12. */
    kMASTER_CLK_to_FLEXCOMM12 = CLKCTL1_TUPLE_MUXA(FC12FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM12. */
    kFRG_to_FLEXCOMM12        = CLKCTL1_TUPLE_MUXA(FC12FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM12. */
    kNONE_to_FLEXCOMM12       = CLKCTL1_TUPLE_MUXA(FC12FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM12. */

    kFRO_DIV4_to_FLEXCOMM13   = CLKCTL1_TUPLE_MUXA(FC13FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM13. */
    kAUDIO_PLL_to_FLEXCOMM13  = CLKCTL1_TUPLE_MUXA(FC13FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM13. */
    kMASTER_CLK_to_FLEXCOMM13 = CLKCTL1_TUPLE_MUXA(FC13FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM13. */
    kFRG_to_FLEXCOMM13        = CLKCTL1_TUPLE_MUXA(FC13FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM13. */
    kNONE_to_FLEXCOMM13       = CLKCTL1_TUPLE_MUXA(FC13FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM13. */

    kFRO_DIV4_to_FLEXCOMM14   = CLKCTL1_TUPLE_MUXA(FC14FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM14. */
    kAUDIO_PLL_to_FLEXCOMM14  = CLKCTL1_TUPLE_MUXA(FC14FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM14. */
    kMASTER_CLK_to_FLEXCOMM14 = CLKCTL1_TUPLE_MUXA(FC14FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM14. */
    kFRG_to_FLEXCOMM14        = CLKCTL1_TUPLE_MUXA(FC14FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM14. */
    kNONE_to_FLEXCOMM14       = CLKCTL1_TUPLE_MUXA(FC14FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM14. */

    kFRO_DIV4_to_FLEXCOMM15   = CLKCTL1_TUPLE_MUXA(FC15FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM15. */
    kAUDIO_PLL_to_FLEXCOMM15  = CLKCTL1_TUPLE_MUXA(FC15FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM15. */
    kMASTER_CLK_to_FLEXCOMM15 = CLKCTL1_TUPLE_MUXA(FC15FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM15. */
    kFRG_to_FLEXCOMM15        = CLKCTL1_TUPLE_MUXA(FC15FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM15. */
    kNONE_to_FLEXCOMM15       = CLKCTL1_TUPLE_MUXA(FC15FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM15. */

    kFRO_DIV4_to_FLEXCOMM16   = CLKCTL1_TUPLE_MUXA(FC16FCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV4 to FLEXCOMM16. */
    kAUDIO_PLL_to_FLEXCOMM16  = CLKCTL1_TUPLE_MUXA(FC16FCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXCOMM16. */
    kMASTER_CLK_to_FLEXCOMM16 = CLKCTL1_TUPLE_MUXA(FC16FCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXCOMM16. */
    kFRG_to_FLEXCOMM16        = CLKCTL1_TUPLE_MUXA(FC16FCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXCOMM16. */
    kNONE_to_FLEXCOMM16       = CLKCTL1_TUPLE_MUXA(FC16FCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXCOMM16. */

    kFRO_DIV2_to_FLEXIO   = CLKCTL1_TUPLE_MUXA(FLEXIOCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV2 to FLEXIO. */
    kAUDIO_PLL_to_FLEXIO  = CLKCTL1_TUPLE_MUXA(FLEXIOCLKSEL_OFFSET, 1), /*!< Attach AUDIO_PLL to FLEXIO. */
    kMASTER_CLK_to_FLEXIO = CLKCTL1_TUPLE_MUXA(FLEXIOCLKSEL_OFFSET, 2), /*!< Attach MASTER_CLK to FLEXIO. */
    kFRG_to_FLEXIO        = CLKCTL1_TUPLE_MUXA(FLEXIOCLKSEL_OFFSET, 3), /*!< Attach FRG to FLEXIO. */
    kNONE_to_FLEXIO       = CLKCTL1_TUPLE_MUXA(FLEXIOCLKSEL_OFFSET, 7), /*!< Attach NONE to FLEXIO. */

    kMAIN_CLK_to_I3C_CLK = CLKCTL1_TUPLE_MUXA(I3C01FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to I3C_CLK. */
    kFRO_DIV8_to_I3C_CLK = CLKCTL1_TUPLE_MUXA(I3C01FCLKSEL_OFFSET, 1), /*!< Attach FRO_DIV8 to I3C_CLK. */
    kNONE_to_I3C_CLK     = CLKCTL1_TUPLE_MUXA(I3C01FCLKSEL_OFFSET, 7), /*!< Attach NONE to I3C_CLK. */

    kI3C_CLK_to_I3C_TC_CLK = CLKCTL1_TUPLE_MUXA(I3C01FCLKSTCSEL_OFFSET, 0), /*!< Attach I3C_CLK to I3C_TC_CLK. */
    kLPOSC_to_I3C_TC_CLK   = CLKCTL1_TUPLE_MUXA(I3C01FCLKSTCSEL_OFFSET, 1), /*!< Attach LPOSC to I3C_TC_CLK. */
    kNONE_to_I3C_TC_CLK    = CLKCTL1_TUPLE_MUXA(I3C01FCLKSTCSEL_OFFSET, 7), /*!< Attach NONE to I3C_TC_CLK. */

    kMAIN_CLK_to_ACMP_CLK = CLKCTL1_TUPLE_MUXA(ACMP0FCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to ACMP_CLK. */
    kFRO_DIV4_to_ACMP_CLK = CLKCTL1_TUPLE_MUXA(ACMP0FCLKSEL_OFFSET, 1), /*!< Attach FRO_DIV4 to ACMP_CLK. */
    kAUX0_PLL_to_ACMP_CLK = CLKCTL1_TUPLE_MUXA(ACMP0FCLKSEL_OFFSET, 2), /*!< Attach AUX0_PLL to ACMP_CLK. */
    kAUX1_PLL_to_ACMP_CLK = CLKCTL1_TUPLE_MUXA(ACMP0FCLKSEL_OFFSET, 3), /*!< Attach AUX1_PLL to ACMP_CLK. */
    kNONE_to_ACMP_CLK     = CLKCTL1_TUPLE_MUXA(ACMP0FCLKSEL_OFFSET, 7), /*!< Attach NONE to ACMP_CLK. */

    kOSC_CLK_to_ADC_CLK = CLKCTL0_TUPLE_MUXA(ADC0FCLKSEL0_OFFSET, 0) |
                          CLKCTL0_TUPLE_MUXB(ADC0FCLKSEL1_OFFSET, 0), /*!< Attach OSC_CLK to ADC_CLK. */
    kLPOSC_to_ADC_CLK = CLKCTL0_TUPLE_MUXA(ADC0FCLKSEL0_OFFSET, 1) |
                        CLKCTL0_TUPLE_MUXB(ADC0FCLKSEL1_OFFSET, 0), /*!< Attach LPOSC to ADC_CLK. */
    kFRO_DIV4_to_ADC_CLK = CLKCTL0_TUPLE_MUXA(ADC0FCLKSEL0_OFFSET, 2) |
                           CLKCTL0_TUPLE_MUXB(ADC0FCLKSEL1_OFFSET, 0), /*!< Attach FRO_DIV4 to ADC_CLK. */
    kMAIN_PLL_to_ADC_CLK = CLKCTL0_TUPLE_MUXA(ADC0FCLKSEL1_OFFSET, 1), /*!< Attach MAIN_PLL to ADC_CLK. */
    kAUX0_PLL_to_ADC_CLK = CLKCTL0_TUPLE_MUXA(ADC0FCLKSEL1_OFFSET, 2), /*!< Attach AUX0_PLL to ADC_CLK. */
    kAUX1_PLL_to_ADC_CLK = CLKCTL0_TUPLE_MUXA(ADC0FCLKSEL1_OFFSET, 3), /*!< Attach AUX1_PLL to ADC_CLK. */

    kOSC_CLK_to_CLKOUT = CLKCTL1_TUPLE_MUXA(CLKOUTSEL0_OFFSET, 0) |
                         CLKCTL1_TUPLE_MUXB(CLKOUTSEL1_OFFSET, 0), /*!< Attach OSC_CLK to CLKOUT. */
    kLPOSC_to_CLKOUT = CLKCTL1_TUPLE_MUXA(CLKOUTSEL0_OFFSET, 1) |
                       CLKCTL1_TUPLE_MUXB(CLKOUTSEL1_OFFSET, 0), /*!< Attach LPOSC to CLKOUT. */
    kFRO_DIV2_to_CLKOUT = CLKCTL1_TUPLE_MUXA(CLKOUTSEL0_OFFSET, 2) |
                          CLKCTL1_TUPLE_MUXB(CLKOUTSEL1_OFFSET, 0), /*!< Attach FRO_DIV2 to CLKOUT. */
    kMAIN_CLK_to_CLKOUT = CLKCTL1_TUPLE_MUXA(CLKOUTSEL0_OFFSET, 3) |
                          CLKCTL1_TUPLE_MUXB(CLKOUTSEL1_OFFSET, 0), /*!< Attach MAIN_CLK to CLKOUT. */
    kDSP_MAIN_to_CLKOUT = CLKCTL1_TUPLE_MUXA(CLKOUTSEL0_OFFSET, 4) |
                          CLKCTL1_TUPLE_MUXB(CLKOUTSEL1_OFFSET, 0),  /*!< Attach DSP_MAIN to CLKOUT. */
    kMAIN_PLL_to_CLKOUT  = CLKCTL1_TUPLE_MUXA(CLKOUTSEL1_OFFSET, 1), /*!< Attach MAIN_PLL to CLKOUT. */
    kAUX0_PLL_to_CLKOUT  = CLKCTL1_TUPLE_MUXA(CLKOUTSEL1_OFFSET, 2), /*!< Attach AUX0_PLL to CLKOUT. */
    kDSP_PLL_to_CLKOUT   = CLKCTL1_TUPLE_MUXA(CLKOUTSEL1_OFFSET, 3), /*!< Attach DSP_PLL to CLKOUT. */
    kAUX1_PLL_to_CLKOUT  = CLKCTL1_TUPLE_MUXA(CLKOUTSEL1_OFFSET, 4), /*!< Attach AUX1_PLL to CLKOUT. */
    kAUDIO_PLL_to_CLKOUT = CLKCTL1_TUPLE_MUXA(CLKOUTSEL1_OFFSET, 5), /*!< Attach AUDIO_PLL to CLKOUT. */
    kOSC32K_to_CLKOUT    = CLKCTL1_TUPLE_MUXA(CLKOUTSEL1_OFFSET, 6), /*!< Attach OSC32K to CLKOUT. */
    kNONE_to_CLKOUT      = CLKCTL1_TUPLE_MUXA(CLKOUTSEL1_OFFSET, 7), /*!< Attach NONE to CLKOUT. */

    kMAIN_CLK_to_GPU_CLK = CLKCTL0_TUPLE_MUXA(GPUCLKSEL_OFFSET, 0), /*!< Attach MAIN_CLK to GPU_CLK. */
    kFRO_DIV1_to_GPU_CLK = CLKCTL0_TUPLE_MUXA(GPUCLKSEL_OFFSET, 1), /*!< Attach FRO_DIV1 to GPU_CLK. */
    kMAIN_PLL_to_GPU_CLK = CLKCTL0_TUPLE_MUXA(GPUCLKSEL_OFFSET, 2), /*!< Attach MAIN_PLL to GPU_CLK. */
    kAUX0_PLL_to_GPU_CLK = CLKCTL0_TUPLE_MUXA(GPUCLKSEL_OFFSET, 3), /*!< Attach AUX0_PLL to GPU_CLK. */
    kAUX1_PLL_to_GPU_CLK = CLKCTL0_TUPLE_MUXA(GPUCLKSEL_OFFSET, 4), /*!< Attach AUX1_PLL to GPU_CLK. */
    kNONE_to_GPU_CLK     = CLKCTL0_TUPLE_MUXA(GPUCLKSEL_OFFSET, 7), /*!< Attach NONE to GPU_CLK. */

    kFRO_DIV1_to_MIPI_DPHY_CLK = CLKCTL0_TUPLE_MUXA(DPHYCLKSEL_OFFSET, 0), /*!< Attach FRO_DIV1 to MIPI_DPHY_CLK. */
    kMAIN_PLL_to_MIPI_DPHY_CLK = CLKCTL0_TUPLE_MUXA(DPHYCLKSEL_OFFSET, 1), /*!< Attach MAIN_PLL to MIPI_DPHY_CLK. */
    kAUX0_PLL_to_MIPI_DPHY_CLK = CLKCTL0_TUPLE_MUXA(DPHYCLKSEL_OFFSET, 2), /*!< Attach AUX0_PLL to MIPI_DPHY_CLK. */
    kAUX1_PLL_to_MIPI_DPHY_CLK = CLKCTL0_TUPLE_MUXA(DPHYCLKSEL_OFFSET, 3), /*!< Attach AUX1_PLL to MIPI_DPHY_CLK. */
    kNONE_to_MIPI_DPHY_CLK     = CLKCTL0_TUPLE_MUXA(DPHYCLKSEL_OFFSET, 7), /*!< Attach NONE to MIPI_DPHY_CLK. */

    kFRO_DIV1_to_MIPI_DPHYESC_CLK = CLKCTL0_TUPLE_MUXA(DPHYESCCLKSEL_OFFSET, 0),  /*!< Attach FRO_DIV1
                                                                                         to MIPI_DPHYESC_CLK. */
    kFRO_DIV16_to_MIPI_DPHYESC_CLK = CLKCTL0_TUPLE_MUXA(DPHYESCCLKSEL_OFFSET, 1), /*!< Attach FRO_DIV16
                                                                                    to MIPI_DPHYESC_CLK. */
    kAUX0_PLL_to_MIPI_DPHYESC_CLK = CLKCTL0_TUPLE_MUXA(DPHYESCCLKSEL_OFFSET, 2),  /*!< Attach AUX0_PLL
                                                                                     to MIPI_DPHYESC_CLK. */
    kAUX1_PLL_to_MIPI_DPHYESC_CLK = CLKCTL0_TUPLE_MUXA(DPHYESCCLKSEL_OFFSET, 3),  /*!< Attach AUX1_PLL
                                                                                     to MIPI_DPHYESC_CLK. */

    kMIPI_DPHY_CLK_to_DCPIXEL_CLK = CLKCTL0_TUPLE_MUXA(DCPIXELCLKSEL_OFFSET, 0), /*!< Attach MIPI_DPHY_CLK
                                                                                    to DCPIXEL_CLK. */
    kMAIN_CLK_to_DCPIXEL_CLK = CLKCTL0_TUPLE_MUXA(DCPIXELCLKSEL_OFFSET, 1),      /*!< Attach MAIN_CLK to DCPIXEL_CLK. */
    kFRO_DIV1_to_DCPIXEL_CLK = CLKCTL0_TUPLE_MUXA(DCPIXELCLKSEL_OFFSET, 2),      /*!< Attach FRO_DIV1 to DCPIXEL_CLK. */
    kMAIN_PLL_to_DCPIXEL_CLK = CLKCTL0_TUPLE_MUXA(DCPIXELCLKSEL_OFFSET, 3),      /*!< Attach MAIN_PLL to DCPIXEL_CLK. */
    kAUX0_PLL_to_DCPIXEL_CLK = CLKCTL0_TUPLE_MUXA(DCPIXELCLKSEL_OFFSET, 4),      /*!< Attach AUX0_PLL to DCPIXEL_CLK. */
    kAUX1_PLL_to_DCPIXEL_CLK = CLKCTL0_TUPLE_MUXA(DCPIXELCLKSEL_OFFSET, 5),      /*!< Attach AUX1_PLL to DCPIXEL_CLK. */
    kNONE_to_DCPIXEL_CLK     = CLKCTL0_TUPLE_MUXA(DCPIXELCLKSEL_OFFSET, 7),      /*!< Attach NONE to DCPIXEL_CLK. */
} clock_attach_id_t;

/*! @brief Clock dividers */
typedef enum _clock_div_name
{
    kCLOCK_DivAudioPllClk  = CLKCTL1_TUPLE_MUXA(AUDIOPLLCLKDIV_OFFSET, 0),   /*!< Audio Pll Clk Divider. */
    kCLOCK_DivMainPllClk   = CLKCTL0_TUPLE_MUXA(MAINPLLCLKDIV_OFFSET, 0),    /*!< Main Pll Clk Divider. */
    kCLOCK_DivDspPllClk    = CLKCTL0_TUPLE_MUXA(DSPPLLCLKDIV_OFFSET, 0),     /*!< Dsp Pll Clk Divider. */
    kCLOCK_DivAux0PllClk   = CLKCTL0_TUPLE_MUXA(AUX0PLLCLKDIV_OFFSET, 0),    /*!< Aux0 Pll Clk Divider. */
    kCLOCK_DivAux1PllClk   = CLKCTL0_TUPLE_MUXA(AUX1PLLCLKDIV_OFFSET, 0),    /*!< Aux1 Pll Clk Divider. */
    kCLOCK_DivPfc0Clk      = CLKCTL0_TUPLE_MUXA(PFC0CLKDIV_OFFSET, 0),       /*!< Pfc0 Clk Divider. */
    kCLOCK_DivPfc1Clk      = CLKCTL0_TUPLE_MUXA(PFC1CLKDIV_OFFSET, 0),       /*!< Pfc1 Clk Divider. */
    kCLOCK_DivSysCpuAhbClk = CLKCTL0_TUPLE_MUXA(SYSCPUAHBCLKDIV_OFFSET, 0),  /*!< Sys Cpu Ahb Clk Divider. */
    kCLOCK_Div32KhzWakeClk = CLKCTL0_TUPLE_MUXA(A32KHZWAKECLKDIV_OFFSET, 0), /*!< Khz Wake Clk Divider. */
    kCLOCK_DivSystickClk   = CLKCTL0_TUPLE_MUXA(SYSTICKFCLKDIV_OFFSET, 0),   /*!< Systick Clk Divider. */
    kCLOCK_DivSdio0Clk     = CLKCTL0_TUPLE_MUXA(SDIO0FCLKDIV_OFFSET, 0),     /*!< Sdio0 Clk Divider. */
    kCLOCK_DivSdio1Clk     = CLKCTL0_TUPLE_MUXA(SDIO1FCLKDIV_OFFSET, 0),     /*!< Sdio1 Clk Divider. */
    kCLOCK_DivFlexspi0Clk  = CLKCTL0_TUPLE_MUXA(FLEXSPI0FCLKDIV_OFFSET, 0),  /*!< Flexspi0 Clk Divider. */
    kCLOCK_DivFlexspi1Clk  = CLKCTL0_TUPLE_MUXA(FLEXSPI1FCLKDIV_OFFSET, 0),  /*!< Flexspi1 Clk Divider. */
    kCLOCK_DivUsbHsFclk    = CLKCTL0_TUPLE_MUXA(USBHSFCLKDIV_OFFSET, 0),     /*!< Usb Hs Fclk Divider. */
    kCLOCK_DivSctClk       = CLKCTL0_TUPLE_MUXA(SCTFCLKDIV_OFFSET, 0),       /*!< Sct Clk Divider. */
    kCLOCK_DivMclkClk      = CLKCTL1_TUPLE_MUXA(AUDIOMCLKDIV_OFFSET, 0),     /*!< Mclk Clk Divider. */
    kCLOCK_DivDmicClk      = CLKCTL1_TUPLE_MUXA(DMIC0FCLKDIV_OFFSET, 0),     /*!< Dmic Clk Divider. */
    kCLOCK_DivPLLFRGClk    = CLKCTL1_TUPLE_MUXA(FRGPLLCLKDIV_OFFSET, 0),     /*!< P L L F R G Clk Divider. */
    kCLOCK_DivFlexioClk    = CLKCTL1_TUPLE_MUXA(FLEXIOCLKDIV_OFFSET, 0),     /*!< Flexio Clk Divider. */
    kCLOCK_DivI3cClk       = CLKCTL1_TUPLE_MUXA(I3C01FCLKDIV_OFFSET, 0),     /*!< I3c Clk Divider. */
    kCLOCK_DivI3cTcClk     = CLKCTL1_TUPLE_MUXA(I3C01FCLKSTCDIV_OFFSET, 0),  /*!< I3c Tc Clk Divider. */
    kCLOCK_DivI3cSlowClk   = CLKCTL1_TUPLE_MUXA(I3C01FCLKSDIV_OFFSET, 0),    /*!< I3c Slow Clk Divider. */
    kCLOCK_DivDspCpuClk    = CLKCTL1_TUPLE_MUXA(DSPCPUCLKDIV_OFFSET, 0),     /*!< Dsp Cpu Clk Divider. */
    kCLOCK_DivAcmpClk      = CLKCTL1_TUPLE_MUXA(ACMP0FCLKDIV_OFFSET, 0),     /*!< Acmp Clk Divider. */
    kCLOCK_DivAdcClk       = CLKCTL0_TUPLE_MUXA(ADC0FCLKDIV_OFFSET, 0),      /*!< Adc Clk Divider. */
    kCLOCK_DivLowFreqClk   = CLKCTL0_TUPLE_MUXA(LOWFREQCLKDIV_OFFSET, 0),    /*!< Low Freq Clk Divider. */
    kCLOCK_DivClockOut     = CLKCTL1_TUPLE_MUXA(CLKOUTFCLKDIV_OFFSET, 0),    /*!< Clock Out Divider. */
    kCLOCK_DivGpuClk       = CLKCTL0_TUPLE_MUXA(GPUCLKDIV_OFFSET, 0),        /*!< Gpu Clk Divider. */
    kCLOCK_DivDcPixelClk   = CLKCTL0_TUPLE_MUXA(DCPIXELCLKDIV_OFFSET, 0),    /*!< Dc Pixel Clk Divider. */
    kCLOCK_DivDphyClk      = CLKCTL0_TUPLE_MUXA(DPHYCLKDIV_OFFSET, 0),       /*!< Dphy Clk Divider. */
    kCLOCK_DivDphyEscRxClk = CLKCTL0_TUPLE_MUXA(DPHYESCRXCLKDIV_OFFSET, 0),  /*!< Dphy Esc Rx Clk Divider. */
    kCLOCK_DivDphyEscTxClk = CLKCTL0_TUPLE_MUXA(DPHYESCTXCLKDIV_OFFSET, 0),  /*!< Dphy Esc Tx Clk Divider. */
} clock_div_name_t;

/*! @brief SysPLL Reference Input Clock Source */
typedef enum _sys_pll_src
{
    kCLOCK_SysPllFroDiv8Clk = 0, /*!< FRO_DIV8 clock */
    kCLOCK_SysPllXtalIn     = 1, /*!< OSC clock */
    kCLOCK_SysPllNone       = 7  /*!< Gated to reduce power */
} sys_pll_src_t;

/*! @brief SysPLL Multiplication Factor */
typedef enum _sys_pll_mult
{
    kCLOCK_SysPllMult16 = 0, /*!< Divide by 16 */
    kCLOCK_SysPllMult17,     /*!< Divide by 17 */
    kCLOCK_SysPllMult18,     /*!< Divide by 18 */
    kCLOCK_SysPllMult19,     /*!< Divide by 19 */
    kCLOCK_SysPllMult20,     /*!< Divide by 20 */
    kCLOCK_SysPllMult21,     /*!< Divide by 21 */
    kCLOCK_SysPllMult22,     /*!< Divide by 22 */
} sys_pll_mult_t;

/*! @brief PLL configuration for SYSPLL */
typedef struct _clock_sys_pll_config
{
    sys_pll_src_t sys_pll_src;   /*!< Reference Input Clock Source */
    uint32_t numerator;          /*!< 30 bit numerator of fractional loop divider. */
    uint32_t denominator;        /*!< 30 bit numerator of fractional loop divider. */
    sys_pll_mult_t sys_pll_mult; /*!< Multiplication Factor */
} clock_sys_pll_config_t;

/*! @brief AudioPll Reference Input Clock Source */
typedef enum _audio_pll_src
{
    kCLOCK_AudioPllFroDiv8Clk = 0, /*!< FRO_DIV8 clock */
    kCLOCK_AudioPllXtalIn     = 1, /*!< OSC clock */
    kCLOCK_AudioPllNone       = 7  /*!< Gated to reduce power */
} audio_pll_src_t;

/*! @brief AudioPll Multiplication Factor */
typedef enum _audio_pll_mult
{
    kCLOCK_AudioPllMult16 = 0, /*!< Divide by 16 */
    kCLOCK_AudioPllMult17,     /*!< Divide by 17 */
    kCLOCK_AudioPllMult18,     /*!< Divide by 18 */
    kCLOCK_AudioPllMult19,     /*!< Divide by 19 */
    kCLOCK_AudioPllMult20,     /*!< Divide by 20 */
    kCLOCK_AudioPllMult21,     /*!< Divide by 21 */
    kCLOCK_AudioPllMult22,     /*!< Divide by 22 */
} audio_pll_mult_t;

/*! @brief PLL configuration for SYSPLL */
typedef struct _clock_audio_pll_config
{
    audio_pll_src_t audio_pll_src;   /*!< Reference Input Clock Source */
    uint32_t numerator;              /*!< 30 bit numerator of fractional loop divider. */
    uint32_t denominator;            /*!< 30 bit numerator of fractional loop divider. */
    audio_pll_mult_t audio_pll_mult; /*!< Multiplication Factor */
} clock_audio_pll_config_t;

/*! @brief PLL configuration for FRG */
typedef struct _clock_frg_clk_config
{
    uint8_t num; /*!< FRG clock, [0 - 16]: Flexcomm, [17]: Flexio */
    enum
    {
        kCLOCK_FrgMainClk = 0, /*!< Main System clock */
        kCLOCK_FrgPllDiv,      /*!< Main pll clock divider*/
        kCLOCK_FrgFroDiv4,     /*!< FRO_DIV4 */
    } sfg_clock_src;
    uint8_t divider; /*!< Denominator of the fractional divider. */
    uint8_t mult;    /*!< Numerator of the fractional divider. */
} clock_frg_clk_config_t;

/*! @brief FRO output enable */
typedef enum _clock_fro_output_en
{
    kCLOCK_FroDiv1OutEn  = CLKCTL0_FRODIVOEN_FRO_DIV1_O_EN_MASK,  /*!< Enable Fro Div1 output. */
    kCLOCK_FroDiv2OutEn  = CLKCTL0_FRODIVOEN_FRO_DIV2_O_EN_MASK,  /*!< Enable Fro Div2 output. */
    kCLOCK_FroDiv4OutEn  = CLKCTL0_FRODIVOEN_FRO_DIV4_O_EN_MASK,  /*!< Enable Fro Div4 output. */
    kCLOCK_FroDiv8OutEn  = CLKCTL0_FRODIVOEN_FRO_DIV8_O_EN_MASK,  /*!< Enable Fro Div8 output. */
    kCLOCK_FroDiv16OutEn = CLKCTL0_FRODIVOEN_FRO_DIV16_O_EN_MASK, /*!< Enable Fro Div16 output. */
    kCLOCK_FroAllOutEn   = CLKCTL0_FRODIVOEN_FRO_DIV1_O_EN_MASK | CLKCTL0_FRODIVOEN_FRO_DIV2_O_EN_MASK |
                         CLKCTL0_FRODIVOEN_FRO_DIV4_O_EN_MASK | CLKCTL0_FRODIVOEN_FRO_DIV8_O_EN_MASK |
                         CLKCTL0_FRODIVOEN_FRO_DIV16_O_EN_MASK
} clock_fro_output_en_t;

/*! @brief FRO frequence configuration */
typedef enum _clock_fro_freq
{
    kCLOCK_Fro192M, /*!< 192MHz FRO clock. */
    kCLOCK_Fro96M,  /*!< 96MHz FRO clock. */
} clock_fro_freq_t;

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif /* __cplusplus */

static inline void CLOCK_EnableClock(clock_ip_name_t clk)
{
    uint32_t index = CLK_GATE_ABSTRACT_REG_OFFSET(clk);

    switch (index)
    {
        case CLK_CTL0_PSCCTL0:
            CLKCTL0->PSCCTL0_SET = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL0_PSCCTL1:
            CLKCTL0->PSCCTL1_SET = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL0_PSCCTL2:
            CLKCTL0->PSCCTL2_SET = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL1_PSCCTL0:
            CLKCTL1->PSCCTL0_SET = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL1_PSCCTL1:
            CLKCTL1->PSCCTL1_SET = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL1_PSCCTL2:
            CLKCTL1->PSCCTL2_SET = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        default:
            assert(false);
            break;
    }
}

static inline void CLOCK_DisableClock(clock_ip_name_t clk)
{
    uint32_t index = CLK_GATE_ABSTRACT_REG_OFFSET(clk);
    switch (index)
    {
        case CLK_CTL0_PSCCTL0:
            CLKCTL0->PSCCTL0_CLR = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL0_PSCCTL1:
            CLKCTL0->PSCCTL1_CLR = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL0_PSCCTL2:
            CLKCTL0->PSCCTL2_CLR = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL1_PSCCTL0:
            CLKCTL1->PSCCTL0_CLR = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL1_PSCCTL1:
            CLKCTL1->PSCCTL1_CLR = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        case CLK_CTL1_PSCCTL2:
            CLKCTL1->PSCCTL2_CLR = (1UL << CLK_GATE_ABSTRACT_BITS_SHIFT(clk));
            break;
        default:
            assert(false);
            break;
    }
}

/**
 * @brief   Configure the clock selection muxes.
 * @param   connection  : Clock to be configured.
 * @return  Nothing
 */
void CLOCK_AttachClk(clock_attach_id_t connection);

/**
 * @brief   Setup peripheral clock dividers.
 * @param   div_name    : Clock divider name
 * @param   divider     : Value to be divided. Divided clock frequency = Undivided clock frequency / divider.
 * @return  Nothing
 */
void CLOCK_SetClkDiv(clock_div_name_t div_name, uint32_t divider);

/*! @brief  Return Frequency of selected clock
 *  @return Frequency of selected clock
 */
uint32_t CLOCK_GetFreq(clock_name_t clockName);

/*! @brief  Return Input frequency for the Fractional baud rate generator
 *  @return Input Frequency for FRG
 */
uint32_t CLOCK_GetFRGClock(uint32_t id);

/*! @brief  Set output of the Fractional baud rate generator
 * @param   config    : Configuration to set to FRGn clock.
 */
void CLOCK_SetFRGClock(const clock_frg_clk_config_t *config);

/*! @brief  Return Frequency of SYSPLL
 *  @return Frequency of SYSPLL
 */
uint32_t CLOCK_GetSysPllFreq(void);

/*! @brief  Get current output frequency of specific System PLL PFD.
 *  @param   pfd    : pfd name to get frequency.
 *  @return  Frequency of SYSPLL PFD.
 */
uint32_t CLOCK_GetSysPfdFreq(clock_pfd_t pfd);

/*! @brief  Return Frequency of AUDIO PLL
 *  @return Frequency of AUDIO PLL
 */
uint32_t CLOCK_GetAudioPllFreq(void);

/*! @brief  Get current output frequency of specific Audio PLL PFD.
 *  @param   pfd    : pfd name to get frequency.
 *  @return  Frequency of AUDIO PLL PFD.
 */
uint32_t CLOCK_GetAudioPfdFreq(clock_pfd_t pfd);

/*! @brief  Return Frequency of main clk
 *  @return Frequency of main clk
 */
uint32_t CLOCK_GetMainClkFreq(void);

/*! @brief  Return Frequency of DSP main clk
 *  @return Frequency of DSP main clk
 */
uint32_t CLOCK_GetDspMainClkFreq(void);

/*! @brief  Return Frequency of ACMP clk
 *  @return Frequency of ACMP clk
 */
uint32_t CLOCK_GetAcmpClkFreq(void);

/*! @brief  Return Frequency of DMIC clk
 *  @return Frequency of DMIC clk
 */
uint32_t CLOCK_GetDmicClkFreq(void);

/*! @brief  Return Frequency of USB clk
 *  @return Frequency of USB clk
 */
uint32_t CLOCK_GetUsbClkFreq(void);

/*! @brief  Return Frequency of SDIO clk
 *  @param  id : SDIO index to get frequency.
 *  @return Frequency of SDIO clk
 */
uint32_t CLOCK_GetSdioClkFreq(uint32_t id);

/*! @brief  Return Frequency of I3C clk
 *  @return Frequency of I3C clk
 */
uint32_t CLOCK_GetI3cClkFreq(void);

/*! @brief  Return Frequency of systick clk
 *  @return Frequency of systick clk
 */
uint32_t CLOCK_GetSystickClkFreq(void);

/*! @brief  Return Frequency of WDT clk
 *  @param  id : WDT index to get frequency.
 *  @return Frequency of WDT clk
 */
uint32_t CLOCK_GetWdtClkFreq(uint32_t id);

/*! @brief  Return output Frequency of mclk
 *  @return Frequency of mclk output clk
 */
uint32_t CLOCK_GetMclkClkFreq(void);

/*! @brief  Return Frequency of sct
 *  @return Frequency of sct clk
 */
uint32_t CLOCK_GetSctClkFreq(void);

/*! @brief  Enable/Disable sys osc clock from external crystal clock.
 *  @param  enable : true to enable system osc clock, false to bypass system osc.
 *  @param  enableLowPower : true to enable low power mode, false to enable high gain mode.
 *  @param  delay_us : Delay time after OSC power up.
 */
void CLOCK_EnableSysOscClk(bool enable, bool enableLowPower, uint32_t delay_us);

/*! @brief  Enable/Disable FRO clock output.
 *  @param  divOutEnable : Or'ed value of clock_fro_output_en_t to enable certain clock freq output.
 */
void CLOCK_EnableFroClk(uint32_t divOutEnable);

#ifndef __XCC__
/*! @brief  Enable/Disable FRO192M or FRO96M clock output.
 *  @param  froFreq : target fro frequency.
 *  @param  divOutEnable : Or'ed value of clock_fro_output_en_t to enable certain clock freq output.
 */
void CLOCK_EnableFroClkRange(clock_fro_freq_t froFreq, uint32_t divOutEnable);
#endif /* __XCC__ */

/*! @brief  Enable LPOSC 1MHz clock.
 */
void CLOCK_EnableLpOscClk(void);

/*! @brief  Return Frequency of sys osc Clock
 *  @return Frequency of sys osc Clock. Or CLK_IN pin frequency.
 */
static inline uint32_t CLOCK_GetXtalInClkFreq(void)
{
    return (CLKCTL0->SYSOSCBYPASS == 0U) ? g_xtalFreq : ((CLKCTL0->SYSOSCBYPASS == 1U) ? g_clkinFreq : 0U);
}

/*! @brief  Return Frequency of MCLK Input Clock
 *  @return Frequency of MCLK input Clock.
 */
static inline uint32_t CLOCK_GetMclkInClkFreq(void)
{
    return g_mclkFreq;
}

/*! @brief  Return Frequency of Lower power osc
 *  @return Frequency of LPOSC
 */
static inline uint32_t CLOCK_GetLpOscFreq(void)
{
    return CLK_LPOSC_1MHZ;
}

/*! @brief  Return Frequency of 32kHz osc
 *  @return Frequency of 32kHz osc
 */
static inline uint32_t CLOCK_GetOsc32KFreq(void)
{
    return ((CLKCTL0->OSC32KHZCTL0 & CLKCTL0_OSC32KHZCTL0_ENA32KHZ_MASK) != 0UL) ? CLK_RTC_32K_CLK : 0U;
}

/*! @brief  Enables and disables 32kHz osc
 *  @param  enable : true to enable 32k osc clock, false to disable clock
 */
static inline void CLOCK_EnableOsc32K(bool enable)
{
    if (enable)
    {
        CLKCTL0->OSC32KHZCTL0 |= CLKCTL0_OSC32KHZCTL0_ENA32KHZ_MASK;
    }
    else
    {
        CLKCTL0->OSC32KHZCTL0 &= ~CLKCTL0_OSC32KHZCTL0_ENA32KHZ_MASK;
    }
}

/*! @brief  Return Frequency of 32khz wake clk
 *  @return Frequency of 32kHz wake clk
 */
static inline uint32_t CLOCK_GetWakeClk32KFreq(void)
{
    return ((CLKCTL0->A32KHZWAKECLKSEL & CLKCTL0_A32KHZWAKECLKSEL_SEL_MASK) != 0U) ?
               CLOCK_GetLpOscFreq() / ((CLKCTL0->A32KHZWAKECLKDIV & CLKCTL0_A32KHZWAKECLKDIV_DIV_MASK) + 1U) :
               CLOCK_GetOsc32KFreq();
}

/*!
 * @brief Set the XTALIN (system OSC) frequency based on board setting.
 *
 * @param freq : The XTAL input clock frequency in Hz.
 */
static inline void CLOCK_SetXtalFreq(uint32_t freq)
{
    g_xtalFreq = freq;
}

/*!
 * @brief Set the CLKIN (CLKIN pin) frequency based on board setting.
 *
 * @param freq : The CLK_IN pin input clock frequency in Hz.
 */
static inline void CLOCK_SetClkinFreq(uint32_t freq)
{
    g_clkinFreq = freq;
}

/*!
 * @brief Set the MCLK IN frequency based on board setting.
 *
 * @param freq : The MCLK input clock frequency in Hz.
 */
static inline void CLOCK_SetMclkFreq(uint32_t freq)
{
    g_mclkFreq = freq;
}

/*! @brief  Return Frequency of Flexcomm functional Clock
 *  @param  id : flexcomm index to get frequency.
 *  @return Frequency of Flexcomm functional Clock
 */
uint32_t CLOCK_GetFlexcommClkFreq(uint32_t id);

/*! @brief  Return Frequency of Flexio functional Clock
 *  @return Frequency of Flexcomm functional Clock
 */
uint32_t CLOCK_GetFlexioClkFreq(void);

/*! @brief  Return Frequency of Ctimer Clock
 *  @param  id : ctimer index to get frequency.
 *  @return Frequency of Ctimer Clock
 */
uint32_t CLOCK_GetCtimerClkFreq(uint32_t id);
/*! @brief  Return Frequency of ClockOut
 *  @return Frequency of ClockOut
 */
uint32_t CLOCK_GetClockOutClkFreq(void);
/*! @brief  Return Frequency of Adc Clock
 *  @return Frequency of Adc Clock.
 */
uint32_t CLOCK_GetAdcClkFreq(void);
/*! @brief  Return Frequency of FLEXSPI Clock
 *  @param  id : flexspi index to get frequency.
 *  @return Frequency of Flexspi.
 */
uint32_t CLOCK_GetFlexspiClkFreq(uint32_t id);

/*! @brief  Return Frequency of GPU functional Clock
 *  @return Frequency of GPU functional Clock
 */
uint32_t CLOCK_GetGpuClkFreq(void);

/*! @brief  Return Frequency of DCNano Pixel functional Clock
 *  @return Frequency of DCNano pixel functional Clock
 */
uint32_t CLOCK_GetDcPixelClkFreq(void);

/*! @brief  Return Frequency of MIPI DPHY functional Clock
 *  @return Frequency of MIPI DPHY functional Clock
 */
uint32_t CLOCK_GetMipiDphyClkFreq(void);

/*! @brief  Return Frequency of MIPI DPHY Esc RX functional Clock
 *  @return Frequency of MIPI DPHY Esc RX functional Clock
 */
uint32_t CLOCK_GetMipiDphyEscRxClkFreq(void);

/*! @brief  Return Frequency of MIPI DPHY Esc Tx functional Clock
 *  @return Frequency of MIPI DPHY Esc Tx functional Clock
 */
uint32_t CLOCK_GetMipiDphyEscTxClkFreq(void);

/*! @brief  Initialize the System PLL.
 *  @param  config    : Configuration to set to PLL.
 */
void CLOCK_InitSysPll(const clock_sys_pll_config_t *config);

/*! brief  Deinit the System PLL.
 *  param  none.
 */
static inline void CLOCK_DeinitSysPll(void)
{
    /* Set System PLL Reset & HOLDRINGOFF_ENA */
    CLKCTL0->SYSPLL0CTL0 |= CLKCTL0_SYSPLL0CTL0_HOLDRINGOFF_ENA_MASK | CLKCTL0_SYSPLL0CTL0_RESET_MASK;
    /* Power down System PLL*/
    SYSCTL0->PDRUNCFG0_SET = SYSCTL0_PDRUNCFG0_SYSPLLLDO_PD_MASK | SYSCTL0_PDRUNCFG0_SYSPLLANA_PD_MASK;
}

/*! @brief Initialize the System PLL PFD.
 *  @param pfd    : Which PFD clock to enable.
 *  @param divider    : The PFD divider value.
 *  @note It is recommended that PFD settings are kept between 12-35.
 */
void CLOCK_InitSysPfd(clock_pfd_t pfd, uint8_t divider);

/*! brief Disable the audio PLL PFD.
 *  param pfd    : Which PFD clock to disable.
 */
static inline void CLOCK_DeinitSysPfd(clock_pfd_t pfd)
{
    CLKCTL0->SYSPLL0PFD |= ((uint32_t)CLKCTL0_SYSPLL0PFD_PFD0_CLKGATE_MASK << (8U * (uint32_t)pfd));
}

/*! @brief  Initialize the audio PLL.
 *  @param  config    : Configuration to set to PLL.
 */
void CLOCK_InitAudioPll(const clock_audio_pll_config_t *config);

/*! brief  Deinit the Audio PLL.
 *  param  none.
 */
static inline void CLOCK_DeinitAudioPll(void)
{
    /* Set Audio PLL Reset & HOLDRINGOFF_ENA */
    CLKCTL1->AUDIOPLL0CTL0 |= CLKCTL1_AUDIOPLL0CTL0_HOLDRINGOFF_ENA_MASK | CLKCTL1_AUDIOPLL0CTL0_RESET_MASK;
    /* Power down Audio PLL */
    SYSCTL0->PDRUNCFG0_SET = SYSCTL0_PDRUNCFG0_AUDPLLLDO_PD_MASK | SYSCTL0_PDRUNCFG0_AUDPLLANA_PD_MASK;
}

/*! @brief Initialize the audio PLL PFD.
 *  @param pfd    : Which PFD clock to enable.
 *  @param divider    : The PFD divider value.
 *  @note It is recommended that PFD settings are kept between 12-35.
 */
void CLOCK_InitAudioPfd(clock_pfd_t pfd, uint8_t divider);

/*! brief Disable the audio PLL PFD.
 *  param pfd    : Which PFD clock to disable.
 */
static inline void CLOCK_DeinitAudioPfd(uint32_t pfd)
{
    CLKCTL1->AUDIOPLL0PFD |= ((uint32_t)CLKCTL1_AUDIOPLL0PFD_PFD0_CLKGATE_MASK << (8U * pfd));
}

/*! @brief  Enable/Disable FRO tuning.
 *   On enable, the function will wait until FRO is close to the target frequency.
 */
void CLOCK_EnableFroTuning(bool enable);

/*! @brief Enable USB HS device clock.
 *
 * This function enables USB HS device clock.
 */
void CLOCK_EnableUsbHs0DeviceClock(clock_attach_id_t src, uint8_t divider);

/*! @brief Disable USB HS device clock.
 *
 * This function disables USB HS device clock.
 */
void CLOCK_DisableUsbHs0DeviceClock(void);

/*! @brief Enable USB HS host clock.
 *
 * This function enables USB HS host clock.
 */
void CLOCK_EnableUsbHs0HostClock(clock_attach_id_t src, uint8_t divider);

/*! @brief Disable USB HS host clock.
 *
 * This function disables USB HS host clock.
 */
void CLOCK_DisableUsbHs0HostClock(void);

/*! brief Enable USB hs0PhyPll clock.
 *
 * param src  USB HS clock source.
 * param freq The frequency specified by src.
 * retval true The clock is set successfully.
 * retval false The clock source is invalid to get proper USB HS clock.
 */
bool CLOCK_EnableUsbHs0PhyPllClock(clock_attach_id_t src, uint32_t freq);

/*! @brief Disable USB hs0PhyPll clock.
 *
 * This function disables USB hs0PhyPll clock.
 */
void CLOCK_DisableUsbHs0PhyPllClock(void);

#if defined(__cplusplus)
}
#endif /* __cplusplus */

/*! @} */

#endif /* _FSL_CLOCK_H_ */
