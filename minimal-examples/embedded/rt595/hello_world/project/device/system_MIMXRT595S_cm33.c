/*
** ###################################################################
**     Processors:          MIMXRT595SFAWC_cm33
**                          MIMXRT595SFFOC_cm33
**
**     Compilers:           GNU C Compiler
**                          IAR ANSI C/C++ Compiler for ARM
**                          Keil ARM C/C++ Compiler
**                          MCUXpresso Compiler
**
**     Reference manual:    RT500 Reference Manual. Rev.C, 8/2020
**     Version:             rev. 5.0, 2020-08-27
**     Build:               b201016
**
**     Abstract:
**         Provides a system configuration function and a global variable that
**         contains the system frequency. It configures the device and initializes
**         the oscillator (PLL) that is part of the microcontroller device.
**
**     Copyright 2016 Freescale Semiconductor, Inc.
**     Copyright 2016-2020 NXP
**     All rights reserved.
**
**     SPDX-License-Identifier: BSD-3-Clause
**
**     http:                 www.nxp.com
**     mail:                 support@nxp.com
**
**     Revisions:
**     - rev. 1.0 (2019-04-19)
**         Initial version.
**     - rev. 2.0 (2019-07-22)
**         Base on rev 0.7 RM.
**     - rev. 3.0 (2020-03-16)
**         Base on Rev.A RM.
**     - rev. 4.0 (2020-05-18)
**         Base on Rev.B RM.
**     - rev. 5.0 (2020-08-27)
**         Base on Rev.C RM.
**
** ###################################################################
*/

/*!
 * @file MIMXRT595S_cm33
 * @version 5.0
 * @date 2020-08-27
 * @brief Device specific configuration file for MIMXRT595S_cm33 (implementation
 *        file)
 *
 * Provides a system configuration function and a global variable that contains
 * the system frequency. It configures the device and initializes the oscillator
 * (PLL) that is part of the microcontroller device.
 */

#include <stdint.h>
#include "fsl_device_registers.h"

#define SYSTEM_IS_XIP_FLEXSPI()                                                                               \
    ((((uint32_t)SystemCoreClockUpdate >= 0x08000000U) && ((uint32_t)SystemCoreClockUpdate < 0x10000000U)) || \
     (((uint32_t)SystemCoreClockUpdate >= 0x18000000U) && ((uint32_t)SystemCoreClockUpdate < 0x20000000U)))

/* Get OSC clock from SYSOSCBYPASS */
static uint32_t getOscClk(void)
{
    return (CLKCTL0->SYSOSCBYPASS == 0U) ? CLK_XTAL_OSC_CLK : ((CLKCTL0->SYSOSCBYPASS == 1U) ? CLK_EXT_CLKIN : 0U);
}

/* Get FRO DIV clock from FRODIVSEL */
static uint32_t getFroDivClk(void)
{
    uint32_t freq = 0U;

    switch ((CLKCTL0->FRODIVSEL) & CLKCTL0_FRODIVSEL_SEL_MASK)
    {
        case CLKCTL0_FRODIVSEL_SEL(0):
            freq = CLK_FRO_DIV2_CLK;
            break;
        case CLKCTL0_FRODIVSEL_SEL(1):
            freq = CLK_FRO_DIV4_CLK;
            break;
        case CLKCTL0_FRODIVSEL_SEL(2):
            freq = CLK_FRO_DIV8_CLK;
            break;
        case CLKCTL0_FRODIVSEL_SEL(3):
            freq = CLK_FRO_DIV16_CLK;
            break;
        default:
            freq = 0U;
            break;
    }

    return freq;
}

/* ----------------------------------------------------------------------------
   -- Core clock
   ---------------------------------------------------------------------------- */

uint32_t SystemCoreClock = DEFAULT_SYSTEM_CLOCK;

/* ----------------------------------------------------------------------------
   -- SystemInit()
   ---------------------------------------------------------------------------- */

__attribute__((weak)) void SystemInit(void)
{
#if ((__FPU_PRESENT == 1) && (__FPU_USED == 1))
    SCB->CPACR |= ((3UL << 10 * 2) | (3UL << 11 * 2)); /* set CP10, CP11 Full Access in Secure mode */
#if defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
    SCB_NS->CPACR |= ((3UL << 10 * 2) | (3UL << 11 * 2)); /* set CP10, CP11 Full Access in Non-secure mode */
#endif                                                    /* (__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U) */
#endif                                                    /* ((__FPU_PRESENT == 1) && (__FPU_USED == 1)) */

    SCB->CPACR |= ((3UL << 0 * 2) | (3UL << 1 * 2)); /* set CP0, CP1 Full Access in Secure mode (enable PowerQuad) */

#if defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
    SCB_NS->CPACR |=
        ((3UL << 0 * 2) | (3UL << 1 * 2)); /* set CP0, CP1 Full Access in Non-secure mode (enable PowerQuad) */
#endif                                     /* (__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U) */

    SCB->NSACR |= ((3UL << 0) | (3UL << 10)); /* enable CP0, CP1, CP10, CP11 Non-secure Access */

    SYSCTL0->DSPSTALL = SYSCTL0_DSPSTALL_DSPSTALL_MASK;
    
    PMC->CTRL |= PMC_CTRL_CLKDIVEN_MASK; /* enable the internal clock divider for power saving */

    if (SYSTEM_IS_XIP_FLEXSPI() && (CACHE64_POLSEL0->POLSEL == 0U)) /* set CAHCHE64 if not configured */
    {
        /* set command to invalidate all ways and write GO bit to initiate command */
        CACHE64_CTRL0->CCR = CACHE64_CTRL_CCR_INVW1_MASK | CACHE64_CTRL_CCR_INVW0_MASK;
        CACHE64_CTRL0->CCR |= CACHE64_CTRL_CCR_GO_MASK;
        /* Wait until the command completes */
        while ((CACHE64_CTRL0->CCR & CACHE64_CTRL_CCR_GO_MASK) != 0U)
        {
        }
        /* Enable cache, enable write buffer */
        CACHE64_CTRL0->CCR = (CACHE64_CTRL_CCR_ENWRBUF_MASK | CACHE64_CTRL_CCR_ENCACHE_MASK);

        /* Set whole FlexSPI0 space to write through. */
        CACHE64_POLSEL0->REG0_TOP = 0x07FFFC00U;
        CACHE64_POLSEL0->REG1_TOP = 0x0U;
        CACHE64_POLSEL0->POLSEL   = 0x1U;

        __ISB();
        __DSB();
    }

    SystemInitHook();
}

/* ----------------------------------------------------------------------------
   -- SystemCoreClockUpdate()
   ---------------------------------------------------------------------------- */

void SystemCoreClockUpdate(void)
{
    /* iMXRT5xx systemCoreClockUpdate */
    uint32_t freq    = 0U;
    uint64_t freqTmp = 0U;

    switch ((CLKCTL0->MAINCLKSELB) & CLKCTL0_MAINCLKSELB_SEL_MASK)
    {
        case CLKCTL0_MAINCLKSELB_SEL(0): /* MAINCLKSELA clock */
            switch ((CLKCTL0->MAINCLKSELA) & CLKCTL0_MAINCLKSELA_SEL_MASK)
            {
                case CLKCTL0_MAINCLKSELA_SEL(0): /* Low Power Oscillator Clock (1m_lposc) */
                    freq = CLK_LPOSC_1MHZ;
                    break;
                case CLKCTL0_MAINCLKSELA_SEL(1): /* FRO DIV clock */
                    freq = getFroDivClk();
                    break;
                case CLKCTL0_MAINCLKSELA_SEL(2): /* OSC clock */
                    freq = getOscClk();
                    break;
                case CLKCTL0_MAINCLKSELA_SEL(3): /* FRO clock */
                    freq = CLK_FRO_CLK;
                    break;
                default:
                    freq = 0U;
                    break;
            }
            break;

        case CLKCTL0_MAINCLKSELB_SEL(1): /* Main System PLL clock */
            switch ((CLKCTL0->SYSPLL0CLKSEL) & CLKCTL0_SYSPLL0CLKSEL_SEL_MASK)
            {
                case CLKCTL0_SYSPLL0CLKSEL_SEL(0): /* FRO_DIV8 clock */
                    freq = CLK_FRO_DIV8_CLK;
                    break;
                case CLKCTL0_SYSPLL0CLKSEL_SEL(1): /* OSC clock */
                    freq = getOscClk();
                    break;
                default:
                    freq = 0U;
                    break;
            }

            if (((CLKCTL0->SYSPLL0CTL0) & CLKCTL0_SYSPLL0CTL0_BYPASS_MASK) == 0U)
            {
                /* PLL output frequency = Fref * (DIV_SELECT + NUM/DENOM). */
                freqTmp = ((uint64_t)freq * ((uint64_t)(CLKCTL0->SYSPLL0NUM))) / ((uint64_t)(CLKCTL0->SYSPLL0DENOM));
                freq *= ((CLKCTL0->SYSPLL0CTL0) & CLKCTL0_SYSPLL0CTL0_MULT_MASK) >> CLKCTL0_SYSPLL0CTL0_MULT_SHIFT;
                freq += (uint32_t)freqTmp;
                freq =
                    (uint32_t)((uint64_t)freq * 18U /
                               ((CLKCTL0->SYSPLL0PFD & CLKCTL0_SYSPLL0PFD_PFD0_MASK) >> CLKCTL0_SYSPLL0PFD_PFD0_SHIFT));
            }

            freq = freq / ((CLKCTL0->MAINPLLCLKDIV & CLKCTL0_MAINPLLCLKDIV_DIV_MASK) + 1U);
            break;

        case CLKCTL0_MAINCLKSELB_SEL(2): /* RTC 32KHz clock */
            freq = CLK_RTC_32K_CLK;
            break;

        default:
            freq = 0U;
            break;
    }

    SystemCoreClock = freq / ((CLKCTL0->SYSCPUAHBCLKDIV & CLKCTL0_SYSCPUAHBCLKDIV_DIV_MASK) + 1U);
}

/* ----------------------------------------------------------------------------
   -- SystemInitHook()
   ---------------------------------------------------------------------------- */

__attribute__((weak)) void SystemInitHook(void)
{
    /* Void implementation of the weak function. */
}
