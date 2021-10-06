/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2020, NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FSL_RESET_H_
#define _FSL_RESET_H_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "fsl_device_registers.h"

/*!
 * @addtogroup reset
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @name Driver version */
/*@{*/
/*! @brief reset driver version 2.0.1. */
#define FSL_RESET_DRIVER_VERSION (MAKE_VERSION(2, 0, 1))
/*@}*/

/*!
 * @brief Reset control registers index
 */
#define RST_CTL0_PSCCTL0 0
#define RST_CTL0_PSCCTL1 1
#define RST_CTL0_PSCCTL2 2
#define RST_CTL1_PSCCTL0 3
#define RST_CTL1_PSCCTL1 4
#define RST_CTL1_PSCCTL2 5
/*!
 * @brief Enumeration for peripheral reset control bits
 *
 * Defines the enumeration for peripheral reset control bits in RSTCLTx registers
 */
typedef enum _RSTCTL_RSTn
{
    kDSP_RST_SHIFT_RSTn           = (RST_CTL0_PSCCTL0 << 8) | 1U,  /**< DSP reset control */
    kAXI_SWITCH_RST_SHIFT_RSTn    = (RST_CTL0_PSCCTL0 << 8) | 3U,  /**< AXI Switch reset control */
    kPOWERQUAD_RST_SHIFT_RSTn     = (RST_CTL0_PSCCTL0 << 8) | 8U,  /**< POWERQUAD reset control */
    kCASPER_RST_SHIFT_RSTn        = (RST_CTL0_PSCCTL0 << 8) | 9U,  /**< CASPER reset control */
    kHASHCRYPT_RST_SHIFT_RSTn     = (RST_CTL0_PSCCTL0 << 8) | 10U, /**< HASHCRYPT reset control */
    kPUF_RST_SHIFT_RSTn           = (RST_CTL0_PSCCTL0 << 8) | 11U, /**< Physical unclonable function reset control */
    kRNG_RST_SHIFT_RSTn           = (RST_CTL0_PSCCTL0 << 8) | 12U, /**< Random number generator (RNG) reset control */
    kFLEXSPI0_RST_SHIFT_RSTn      = (RST_CTL0_PSCCTL0 << 8) | 16U, /**< FLEXSPI0/OTFAD reset control */
    kFLEXSPI1_RST_SHIFT_RSTn      = (RST_CTL0_PSCCTL0 << 8) | 18U, /**< FLEXSPI1 reset control */
    kUSBHS_PHY_RST_SHIFT_RSTn     = (RST_CTL0_PSCCTL0 << 8) | 20U, /**< High speed USB PHY reset control */
    kUSBHS_DEVICE_RST_SHIFT_RSTn  = (RST_CTL0_PSCCTL0 << 8) | 21U, /**< High speed USB Device reset control */
    kUSBHS_HOST_RST_SHIFT_RSTn    = (RST_CTL0_PSCCTL0 << 8) | 22U, /**< High speed USB Host reset control */
    kUSBHS_SRAM_RST_SHIFT_RSTn    = (RST_CTL0_PSCCTL0 << 8) | 23U, /**< High speed USB SRAM reset control */
    kSCT_RST_SHIFT_RSTn           = (RST_CTL0_PSCCTL0 << 8) | 24U, /**< Standard ctimers reset control */
    kGPU_RST_SHIFT_RSTn           = (RST_CTL0_PSCCTL0 << 8) | 26U, /**< GPU reset control */
    kDISP_CTRL_RST_SHIFT_RSTn     = (RST_CTL0_PSCCTL0 << 8) | 27U, /**< Display controller reset control */
    kMIPI_DSI_CTRL_RST_SHIFT_RSTn = (RST_CTL0_PSCCTL0 << 8) | 28U, /**< MIPI DSI controller reset control */
    kMIPI_DSI_PHY_RST_SHIFT_RSTn  = (RST_CTL0_PSCCTL0 << 8) | 29U, /**< MIPI DSI PHY reset control */
    kSMART_DMA_RST_SHIFT_RSTn     = (RST_CTL0_PSCCTL0 << 8) | 30U, /**< Smart DMA reset control */

    kSDIO0_RST_SHIFT_RSTn    = (RST_CTL0_PSCCTL1 << 8) | 2U,  /**< SDIO0 reset control */
    kSDIO1_RST_SHIFT_RSTn    = (RST_CTL0_PSCCTL1 << 8) | 3U,  /**< SDIO1 reset control */
    kACMP0_RST_SHIFT_RSTn    = (RST_CTL0_PSCCTL1 << 8) | 15U, /**< Grouped interrupt (PINT) reset control. */
    kADC0_RST_SHIFT_RSTn     = (RST_CTL0_PSCCTL1 << 8) | 16U, /**< ADC0 reset control */
    kSHSGPIO0_RST_SHIFT_RSTn = (RST_CTL0_PSCCTL1 << 8) | 24U, /**< Security HSGPIO 0 reset control */

    kUTICK0_RST_SHIFT_RSTn = (RST_CTL0_PSCCTL2 << 8) | 0U, /**< Micro-tick timer reset control */
    kWWDT0_RST_SHIFT_RSTn  = (RST_CTL0_PSCCTL2 << 8) | 1U, /**< Windowed Watchdog timer 0 reset control */

    kFC0_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 8U,  /**< Flexcomm Interface 0 reset control */
    kFC1_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 9U,  /**< Flexcomm Interface 1 reset control */
    kFC2_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 10U, /**< Flexcomm Interface 2 reset control */
    kFC3_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 11U, /**< Flexcomm Interface 3 reset control */
    kFC4_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 12U, /**< Flexcomm Interface 4 reset control */
    kFC5_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 13U, /**< Flexcomm Interface 5 reset control */
    kFC6_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 14U, /**< Flexcomm Interface 6 reset control */
    kFC7_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 15U, /**< Flexcomm Interface 7 reset control */
    kFC8_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 16U, /**< Flexcomm Interface 8 reset control */
    kFC9_RST_SHIFT_RSTn           = (RST_CTL1_PSCCTL0 << 8) | 17U, /**< Flexcomm Interface 9 reset control */
    kFC10_RST_SHIFT_RSTn          = (RST_CTL1_PSCCTL0 << 8) | 18U, /**< Flexcomm Interface 10 reset control */
    kFC11_RST_SHIFT_RSTn          = (RST_CTL1_PSCCTL0 << 8) | 19U, /**< Flexcomm Interface 11 reset control */
    kFC12_RST_SHIFT_RSTn          = (RST_CTL1_PSCCTL0 << 8) | 20U, /**< Flexcomm Interface 12 reset control */
    kFC13_RST_SHIFT_RSTn          = (RST_CTL1_PSCCTL0 << 8) | 21U, /**< Flexcomm Interface 13 reset control */
    kFC14_RST_SHIFT_RSTn          = (RST_CTL1_PSCCTL0 << 8) | 22U, /**< Flexcomm Interface 14 reset control */
    kFC15_RST_SHIFT_RSTn          = (RST_CTL1_PSCCTL0 << 8) | 23U, /**< Flexcomm Interface 15 reset control */
    kDMIC_RST_SHIFT_RSTn          = (RST_CTL1_PSCCTL0 << 8) | 24U, /**< Digital microphone interface reset control */
    kFC16_RST_SHIFT_RSTn          = (RST_CTL1_PSCCTL0 << 8) | 25U, /**< Flexcomm Interface 16 reset control */
    kOSEVENT_TIMER_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL0 << 8) | 27U, /**< Osevent Timer reset control */
    kFLEXIO_RST_SHIFT_RSTn        = (RST_CTL1_PSCCTL0 << 8) | 29U, /**< FlexIO reset control */

    kHSGPIO0_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL1 << 8) | 0U,  /**< HSGPIO 0 reset control */
    kHSGPIO1_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL1 << 8) | 1U,  /**< HSGPIO 1 reset control */
    kHSGPIO2_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL1 << 8) | 2U,  /**< HSGPIO 2 reset control */
    kHSGPIO3_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL1 << 8) | 3U,  /**< HSGPIO 3 reset control */
    kHSGPIO4_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL1 << 8) | 4U,  /**< HSGPIO 4 reset control */
    kHSGPIO5_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL1 << 8) | 5U,  /**< HSGPIO 5 reset control */
    kHSGPIO6_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL1 << 8) | 6U,  /**< HSGPIO 6 reset control */
    kHSGPIO7_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL1 << 8) | 7U,  /**< HSGPIO 7 reset control */
    kCRC_RST_SHIFT_RSTn     = (RST_CTL1_PSCCTL1 << 8) | 16U, /**< CRC reset control */
    kDMAC0_RST_SHIFT_RSTn   = (RST_CTL1_PSCCTL1 << 8) | 23U, /**< DMA Controller 0 reset control */
    kDMAC1_RST_SHIFT_RSTn   = (RST_CTL1_PSCCTL1 << 8) | 24U, /**< DMA Controller 1  reset control */
    kMU_RST_SHIFT_RSTn      = (RST_CTL1_PSCCTL1 << 8) | 28U, /**< Message Unit reset control */
    kSEMA_RST_SHIFT_RSTn    = (RST_CTL1_PSCCTL1 << 8) | 29U, /**< Semaphore reset control */
    kFREQME_RST_SHIFT_RSTn  = (RST_CTL1_PSCCTL1 << 8) | 31U, /**< Frequency Measure reset control */

    kCT32B0_RST_SHIFT_RSTn   = (RST_CTL1_PSCCTL2 << 8) | 0U,  /**< CT32B0 reset control */
    kCT32B1_RST_SHIFT_RSTn   = (RST_CTL1_PSCCTL2 << 8) | 1U,  /**< CT32B1 reset control */
    kCT32B2_RST_SHIFT_RSTn   = (RST_CTL1_PSCCTL2 << 8) | 2U,  /**< CT32B3 reset control */
    kCT32B3_RST_SHIFT_RSTn   = (RST_CTL1_PSCCTL2 << 8) | 3U,  /**< CT32B4 reset control */
    kCT32B4_RST_SHIFT_RSTn   = (RST_CTL1_PSCCTL2 << 8) | 4U,  /**< CT32B4 reset control */
    kMRT0_RST_SHIFT_RSTn     = (RST_CTL1_PSCCTL2 << 8) | 8U,  /**< Multi-rate timer (MRT) reset control */
    kWWDT1_RST_SHIFT_RSTn    = (RST_CTL1_PSCCTL2 << 8) | 10U, /**< Windowed Watchdog timer 1 reset control */
    kI3C0_RST_SHIFT_RSTn     = (RST_CTL1_PSCCTL2 << 8) | 16U, /**< I3C0 reset control */
    kI3C1_RST_SHIFT_RSTn     = (RST_CTL1_PSCCTL2 << 8) | 17U, /**< I3C1 reset control */
    kPINT_RST_SHIFT_RSTn     = (RST_CTL1_PSCCTL2 << 8) | 30U, /**< GPIO Pin interrupt reset control */
    kINPUTMUX_RST_SHIFT_RSTn = (RST_CTL1_PSCCTL2 << 8) | 31U, /**< Peripheral input muxes reset control */
} RSTCTL_RSTn_t;

/** Array initializers with peripheral reset bits **/
#define ADC_RSTS             \
    {                        \
        kADC0_RST_SHIFT_RSTn \
    } /* Reset bits for ADC peripheral */
#define CASPER_RSTS            \
    {                          \
        kCASPER_RST_SHIFT_RSTn \
    } /* Reset bits for Casper peripheral */
#define CRC_RSTS            \
    {                       \
        kCRC_RST_SHIFT_RSTn \
    } /* Reset bits for CRC peripheral */
#define CTIMER_RSTS                                                                                     \
    {                                                                                                   \
        kCT32B0_RST_SHIFT_RSTn, kCT32B1_RST_SHIFT_RSTn, kCT32B2_RST_SHIFT_RSTn, kCT32B3_RST_SHIFT_RSTn, \
            kCT32B4_RST_SHIFT_RSTn                                                                      \
    } /* Reset bits for TIMER peripheral */
#define DCNANO_RSTS               \
    {                             \
        kDISP_CTRL_RST_SHIFT_RSTn \
    } /* Reset bits for CRC peripheral */
#define MIPI_DSI_RSTS                 \
    {                                 \
        kMIPI_DSI_CTRL_RST_SHIFT_RSTn \
    } /* Reset bits for CRC peripheral */
#define DMA_RSTS_N                                   \
    {                                                \
        kDMAC0_RST_SHIFT_RSTn, kDMAC1_RST_SHIFT_RSTn \
    } /* Reset bits for DMA peripheral */
#define DMIC_RSTS            \
    {                        \
        kDMIC_RST_SHIFT_RSTn \
    } /* Reset bits for ADC peripheral */
#define FLEXCOMM_RSTS                                                                                                \
    {                                                                                                                \
        kFC0_RST_SHIFT_RSTn, kFC1_RST_SHIFT_RSTn, kFC2_RST_SHIFT_RSTn, kFC3_RST_SHIFT_RSTn, kFC4_RST_SHIFT_RSTn,     \
            kFC5_RST_SHIFT_RSTn, kFC6_RST_SHIFT_RSTn, kFC7_RST_SHIFT_RSTn, kFC8_RST_SHIFT_RSTn, kFC9_RST_SHIFT_RSTn, \
            kFC10_RST_SHIFT_RSTn, kFC11_RST_SHIFT_RSTn, kFC12_RST_SHIFT_RSTn, kFC13_RST_SHIFT_RSTn,                  \
            kFC14_RST_SHIFT_RSTn, kFC15_RST_SHIFT_RSTn, kFC16_RST_SHIFT_RSTn                                         \
    } /* Reset bits for FLEXCOMM peripheral */
#define FLEXIO_RSTS            \
    {                          \
        kFLEXIO_RST_SHIFT_RSTn \
    } /* Resets bits for FLEXIO peripheral */
#define FLEXSPI_RSTS                                       \
    {                                                      \
        kFLEXSPI0_RST_SHIFT_RSTn, kFLEXSPI1_RST_SHIFT_RSTn \
    } /* Resets bits for FLEXSPI peripheral */
#define GPIO_RSTS_N                                                                                            \
    {                                                                                                          \
        kHSGPIO0_RST_SHIFT_RSTn, kHSGPIO1_RST_SHIFT_RSTn, kHSGPIO2_RST_SHIFT_RSTn, kHSGPIO3_RST_SHIFT_RSTn,    \
            kHSGPIO4_RST_SHIFT_RSTn, kHSGPIO5_RST_SHIFT_RSTn, kHSGPIO6_RST_SHIFT_RSTn, kHSGPIO7_RST_SHIFT_RSTn \
    } /* Reset bits for GPIO peripheral */
#define HASHCRYPT_RSTS            \
    {                             \
        kHASHCRYPT_RST_SHIFT_RSTn \
    } /* Reset bits for Hashcrypt peripheral */
#define I3C_RSTS                                   \
    {                                              \
        kI3C0_RST_SHIFT_RSTn, kI3C1_RST_SHIFT_RSTn \
    } /* Reset bits for I3C peripheral */
#define INPUTMUX_RSTS            \
    {                            \
        kINPUTMUX_RST_SHIFT_RSTn \
    } /* Reset bits for INPUTMUX peripheral */
#define MRT_RSTS             \
    {                        \
        kMRT0_RST_SHIFT_RSTn \
    } /* Reset bits for MRT peripheral */
#define MU_RSTS            \
    {                      \
        kMU_RST_SHIFT_RSTn \
    } /* Reset bits for MU peripheral */
#define OSTIMER_RSTS                  \
    {                                 \
        kOSEVENT_TIMER_RST_SHIFT_RSTn \
    } /* Reset bits for OSTIMER peripheral */
#define PINT_RSTS            \
    {                        \
        kPINT_RST_SHIFT_RSTn \
    } /* Reset bits for PINT peripheral */
#define POWERQUAD_RSTS            \
    {                             \
        kPOWERQUAD_RST_SHIFT_RSTn \
    } /* Reset bits for Powerquad peripheral */
#define PUF_RSTS            \
    {                       \
        kPUF_RST_SHIFT_RSTn \
    } /* Reset bits for PUF peripheral */
#define SCT_RSTS            \
    {                       \
        kSCT_RST_SHIFT_RSTn \
    } /* Reset bits for SCT peripheral */
#define SEMA42_RSTS          \
    {                        \
        kSEMA_RST_SHIFT_RSTn \
    } /* Reset bits for SEMA42 peripheral */
#define TRNG_RSTS           \
    {                       \
        kRNG_RST_SHIFT_RSTn \
    } /* Reset bits for TRNG peripheral */
#define USDHC_RSTS                                   \
    {                                                \
        kSDIO0_RST_SHIFT_RSTn, kSDIO1_RST_SHIFT_RSTn \
    } /* Reset bits for USDHC peripheral */
#define UTICK_RSTS             \
    {                          \
        kUTICK0_RST_SHIFT_RSTn \
    } /* Reset bits for UTICK peripheral */
#define WWDT_RSTS                                    \
    {                                                \
        kWWDT0_RST_SHIFT_RSTn, kWWDT1_RST_SHIFT_RSTn \
    } /* Reset bits for WWDT peripheral */

/*!
 * @brief IP reset handle
 */
typedef RSTCTL_RSTn_t reset_ip_name_t;

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief Assert reset to peripheral.
 *
 * Asserts reset signal to specified peripheral module.
 *
 * @param peripheral Assert reset to this peripheral. The enum argument contains encoding of reset register
 *                   and reset bit position in the reset register.
 */
void RESET_SetPeripheralReset(reset_ip_name_t peripheral);

/*!
 * @brief Clear reset to peripheral.
 *
 * Clears reset signal to specified peripheral module, allows it to operate.
 *
 * @param peripheral Clear reset to this peripheral. The enum argument contains encoding of reset register
 *                   and reset bit position in the reset register.
 */
void RESET_ClearPeripheralReset(reset_ip_name_t peripheral);

/*!
 * @brief Reset peripheral module.
 *
 * Reset peripheral module.
 *
 * @param peripheral Peripheral to reset. The enum argument contains encoding of reset register
 *                   and reset bit position in the reset register.
 */
void RESET_PeripheralReset(reset_ip_name_t peripheral);

#if defined(__cplusplus)
}
#endif

/*! @} */

#endif /* _FSL_RESET_H_ */
