/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2021, NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_clock.h"
#include "fsl_common.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* Component ID definition, used by tools. */
#ifndef FSL_COMPONENT_ID
#define FSL_COMPONENT_ID "platform.drivers.clock"
#endif

#define OTP_INIT_API      ((void (*)(uint32_t src_clk_freq))0x13007FFF)
#define OTP_DEINIT_API    ((void (*)(void))0x1300804D)
#define OTP_FUSE_READ_API ((void (*)(uint32_t addr, uint32_t * data))0x1300805D)
/* OTP fuse index. */
#define FRO_192MHZ_SC_TRIM 0x2C
#define FRO_192MHZ_RD_TRIM 0x2B
#define FRO_96MHZ_SC_TRIM  0x2E
#define FRO_96MHZ_RD_TRIM  0x2D

/*******************************************************************************
 * Variables
 ******************************************************************************/

/* External XTAL (OSC) clock frequency. */
volatile uint32_t g_xtalFreq = 0U;
/* External CLK_IN pin clock frequency. */
volatile uint32_t g_clkinFreq = 0U;
/* External MCLK IN clock frequency. */
volatile uint32_t g_mclkFreq = 0U;

/*******************************************************************************
 * Code
 ******************************************************************************/

/* Clock Selection for IP */
/**
 * brief   Configure the clock selection muxes.
 * param   connection : Clock to be configured.
 * return  Nothing
 */
void CLOCK_AttachClk(clock_attach_id_t connection)
{
    bool final_descriptor = false;
    uint32_t i;
    uint32_t tuple;
    volatile uint32_t *pClkSel;

    for (i = 0U; (i < 2U) && (!final_descriptor); i++)
    {
        tuple = ((uint32_t)connection) >> (i * 14U); /*!<  pick up next descriptor */
        if ((((uint32_t)connection) & 0x80000000U) != 0UL)
        {
            pClkSel = CLKCTL_TUPLE_REG(CLKCTL1, tuple);
        }
        else
        {
            pClkSel = CLKCTL_TUPLE_REG(CLKCTL0, tuple);
        }
        if ((tuple & 0x7FFU) != 0U)
        {
            *pClkSel = CLKCTL_TUPLE_SEL(tuple);
        }
        else
        {
            final_descriptor = true;
        }
    }

    if ((((uint32_t)connection) & 0x40000000U) != 0U)
    {
        CLKCTL0->FRODIVSEL = (((uint32_t)connection) >> 28U) & 0x3U;
    }
}

/* Set IP Clock divider */
/**
 * brief   Setup peripheral clock dividers.
 * param   div_name    : Clock divider name
 * param   divider     : Value to be divided. Divided clock frequency = Undivided clock frequency / divider.
 * return  Nothing
 */
void CLOCK_SetClkDiv(clock_div_name_t div_name, uint32_t divider)
{
    volatile uint32_t *pClkDiv;

    if ((((uint32_t)div_name) & 0x80000000U) != 0U)
    {
        pClkDiv = CLKCTL_TUPLE_REG(CLKCTL1, div_name);
    }
    else
    {
        pClkDiv = CLKCTL_TUPLE_REG(CLKCTL0, div_name);
    }
    /* Reset the divider counter */
    *pClkDiv |= 1UL << 29U;

    if (divider == 0U) /*!<  halt */
    {
        *pClkDiv |= 1UL << 30U;
    }
    else
    {
        *pClkDiv = divider - 1U;

        while (((*pClkDiv) & 0x80000000U) != 0U)
        {
        }
    }
}

/* Get SYSTEM PLL Clk */
/*! brief  Return Frequency of SYSPLL
 *  return Frequency of SYSPLL
 */
uint32_t CLOCK_GetSysPllFreq(void)
{
    uint32_t freq = 0U;
    uint64_t freqTmp;

    switch ((CLKCTL0->SYSPLL0CLKSEL) & CLKCTL0_SYSPLL0CLKSEL_SEL_MASK)
    {
        case CLKCTL0_SYSPLL0CLKSEL_SEL(0):
            freq = CLK_FRO_DIV8_CLK;
            break;
        case CLKCTL0_SYSPLL0CLKSEL_SEL(1):
            freq = CLOCK_GetXtalInClkFreq();
            break;
        default:
            assert(false);
            break;
    }

    if (((CLKCTL0->SYSPLL0CTL0) & CLKCTL0_SYSPLL0CTL0_BYPASS_MASK) == 0U)
    {
        /* PLL output frequency = Fref * (DIV_SELECT + NUM/DENOM). */
        freqTmp = ((uint64_t)freq * ((uint64_t)(CLKCTL0->SYSPLL0NUM))) / ((uint64_t)(CLKCTL0->SYSPLL0DENOM));
        freq *= ((CLKCTL0->SYSPLL0CTL0) & CLKCTL0_SYSPLL0CTL0_MULT_MASK) >> CLKCTL0_SYSPLL0CTL0_MULT_SHIFT;
        freq += (uint32_t)freqTmp;
    }

    return freq;
}

/* Get SYSTEM PLL PFDn Clk */
/*! brief  Get current output frequency of specific System PLL PFD.
 *  param   pfd    : pfd name to get frequency.
 *  return  Frequency of SYSPLL PFD.
 */
uint32_t CLOCK_GetSysPfdFreq(clock_pfd_t pfd)
{
    uint32_t freq = CLOCK_GetSysPllFreq();

    if (((CLKCTL0->SYSPLL0CTL0) & CLKCTL0_SYSPLL0CTL0_BYPASS_MASK) == 0U)
    {
        switch (pfd)
        {
            case kCLOCK_Pfd0:
                freq =
                    (uint32_t)((uint64_t)freq * 18U /
                               ((CLKCTL0->SYSPLL0PFD & CLKCTL0_SYSPLL0PFD_PFD0_MASK) >> CLKCTL0_SYSPLL0PFD_PFD0_SHIFT));
                break;

            case kCLOCK_Pfd1:
                freq =
                    (uint32_t)((uint64_t)freq * 18U /
                               ((CLKCTL0->SYSPLL0PFD & CLKCTL0_SYSPLL0PFD_PFD1_MASK) >> CLKCTL0_SYSPLL0PFD_PFD1_SHIFT));
                break;

            case kCLOCK_Pfd2:
                freq =
                    (uint32_t)((uint64_t)freq * 18U /
                               ((CLKCTL0->SYSPLL0PFD & CLKCTL0_SYSPLL0PFD_PFD2_MASK) >> CLKCTL0_SYSPLL0PFD_PFD2_SHIFT));
                break;

            case kCLOCK_Pfd3:
                freq =
                    (uint32_t)((uint64_t)freq * 18U /
                               ((CLKCTL0->SYSPLL0PFD & CLKCTL0_SYSPLL0PFD_PFD3_MASK) >> CLKCTL0_SYSPLL0PFD_PFD3_SHIFT));
                break;

            default:
                freq = 0U;
                break;
        }
    }

    return freq;
}

static uint32_t CLOCK_GetMainPllClkFreq(void)
{
    return CLOCK_GetSysPfdFreq(kCLOCK_Pfd0) / ((CLKCTL0->MAINPLLCLKDIV & CLKCTL0_MAINPLLCLKDIV_DIV_MASK) + 1U);
}
static uint32_t CLOCK_GetDspPllClkFreq(void)
{
    return CLOCK_GetSysPfdFreq(kCLOCK_Pfd1) / ((CLKCTL0->DSPPLLCLKDIV & CLKCTL0_DSPPLLCLKDIV_DIV_MASK) + 1U);
}
static uint32_t CLOCK_GetAux0PllClkFreq(void)
{
    return CLOCK_GetSysPfdFreq(kCLOCK_Pfd2) / ((CLKCTL0->AUX0PLLCLKDIV & CLKCTL0_AUX0PLLCLKDIV_DIV_MASK) + 1U);
}
static uint32_t CLOCK_GetAux1PllClkFreq(void)
{
    return CLOCK_GetSysPfdFreq(kCLOCK_Pfd3) / ((CLKCTL0->AUX1PLLCLKDIV & CLKCTL0_AUX1PLLCLKDIV_DIV_MASK) + 1U);
}

/* Get AUDIO PLL Clk */
/*! brief  Return Frequency of AUDIO PLL
 *  return Frequency of AUDIO PLL
 */
uint32_t CLOCK_GetAudioPllFreq(void)
{
    uint32_t freq = 0U;
    uint64_t freqTmp;

    switch ((CLKCTL1->AUDIOPLL0CLKSEL) & CLKCTL1_AUDIOPLL0CLKSEL_SEL_MASK)
    {
        case CLKCTL1_AUDIOPLL0CLKSEL_SEL(0):
            freq = CLK_FRO_DIV8_CLK;
            break;
        case CLKCTL1_AUDIOPLL0CLKSEL_SEL(1):
            freq = CLOCK_GetXtalInClkFreq();
            break;
        default:
            freq = 0U;
            break;
    }

    if (((CLKCTL1->AUDIOPLL0CTL0) & CLKCTL1_AUDIOPLL0CTL0_BYPASS_MASK) == 0U)
    {
        /* PLL output frequency = Fref * (DIV_SELECT + NUM/DENOM). */
        freqTmp = ((uint64_t)freq * ((uint64_t)(CLKCTL1->AUDIOPLL0NUM))) / ((uint64_t)(CLKCTL1->AUDIOPLL0DENOM));
        freq *= ((CLKCTL1->AUDIOPLL0CTL0) & CLKCTL1_AUDIOPLL0CTL0_MULT_MASK) >> CLKCTL1_AUDIOPLL0CTL0_MULT_SHIFT;
        freq += (uint32_t)freqTmp;
    }

    return freq;
}

/* Get AUDIO PLL PFDn Clk */
/*! brief  Get current output frequency of specific Audio PLL PFD.
 *  param   pfd    : pfd name to get frequency.
 *  return  Frequency of AUDIO PLL PFD.
 */
uint32_t CLOCK_GetAudioPfdFreq(clock_pfd_t pfd)
{
    uint32_t freq = CLOCK_GetAudioPllFreq();

    if (((CLKCTL1->AUDIOPLL0CTL0) & CLKCTL1_AUDIOPLL0CTL0_BYPASS_MASK) == 0U)
    {
        switch (pfd)
        {
            case kCLOCK_Pfd0:
                freq = (uint32_t)(
                    (uint64_t)freq * 18U /
                    ((CLKCTL1->AUDIOPLL0PFD & CLKCTL1_AUDIOPLL0PFD_PFD0_MASK) >> CLKCTL1_AUDIOPLL0PFD_PFD0_SHIFT));
                break;

            case kCLOCK_Pfd1:
                freq = (uint32_t)(
                    (uint64_t)freq * 18U /
                    ((CLKCTL1->AUDIOPLL0PFD & CLKCTL1_AUDIOPLL0PFD_PFD1_MASK) >> CLKCTL1_AUDIOPLL0PFD_PFD1_SHIFT));
                break;

            case kCLOCK_Pfd2:
                freq = (uint32_t)(
                    (uint64_t)freq * 18U /
                    ((CLKCTL1->AUDIOPLL0PFD & CLKCTL1_AUDIOPLL0PFD_PFD2_MASK) >> CLKCTL1_AUDIOPLL0PFD_PFD2_SHIFT));
                break;

            case kCLOCK_Pfd3:
                freq = (uint32_t)(
                    (uint64_t)freq * 18U /
                    ((CLKCTL1->AUDIOPLL0PFD & CLKCTL1_AUDIOPLL0PFD_PFD3_MASK) >> CLKCTL1_AUDIOPLL0PFD_PFD3_SHIFT));
                break;

            default:
                freq = 0U;
                break;
        }
    }

    return freq;
}

static uint32_t CLOCK_GetAudioPllClkFreq(void)
{
    return CLOCK_GetAudioPfdFreq(kCLOCK_Pfd0) / ((CLKCTL1->AUDIOPLLCLKDIV & CLKCTL1_AUDIOPLLCLKDIV_DIV_MASK) + 1U);
}

static uint32_t CLOCK_GetFroDivFreq(void)
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

/* Get MAIN Clk */
/*! brief  Return Frequency of main clk
 *  return Frequency of main clk
 */
uint32_t CLOCK_GetMainClkFreq(void)
{
    uint32_t freq = 0U;

    switch ((CLKCTL0->MAINCLKSELB) & CLKCTL0_MAINCLKSELB_SEL_MASK)
    {
        case CLKCTL0_MAINCLKSELB_SEL(0):
            switch ((CLKCTL0->MAINCLKSELA) & CLKCTL0_MAINCLKSELA_SEL_MASK)
            {
                case CLKCTL0_MAINCLKSELA_SEL(0):
                    freq = CLOCK_GetLpOscFreq();
                    break;
                case CLKCTL0_MAINCLKSELA_SEL(1):
                    freq = CLOCK_GetFroDivFreq();
                    break;
                case CLKCTL0_MAINCLKSELA_SEL(2):
                    freq = CLOCK_GetXtalInClkFreq();
                    break;
                case CLKCTL0_MAINCLKSELA_SEL(3):
                    freq = CLK_FRO_CLK;
                    break;
                default:
                    freq = 0U;
                    break;
            }
            break;

        case CLKCTL0_MAINCLKSELB_SEL(1):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL0_MAINCLKSELB_SEL(2):
            freq = CLOCK_GetOsc32KFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq;
}

/* Get DSP MAIN Clk */
/*! brief  Return Frequency of DSP main clk
 *  return Frequency of DSP main clk
 */
uint32_t CLOCK_GetDspMainClkFreq(void)
{
    uint32_t freq = 0U;

    switch ((CLKCTL1->DSPCPUCLKSELB) & CLKCTL1_DSPCPUCLKSELB_SEL_MASK)
    {
        case CLKCTL1_DSPCPUCLKSELB_SEL(0):
            switch ((CLKCTL1->DSPCPUCLKSELA) & CLKCTL1_DSPCPUCLKSELA_SEL_MASK)
            {
                case CLKCTL1_DSPCPUCLKSELA_SEL(0):
                    freq = CLK_FRO_CLK;
                    break;
                case CLKCTL1_DSPCPUCLKSELA_SEL(1):
                    freq = CLOCK_GetXtalInClkFreq();
                    break;
                case CLKCTL1_DSPCPUCLKSELA_SEL(2):
                    freq = CLOCK_GetLpOscFreq();
                    break;
                default:
                    freq = 0U;
                    break;
            }
            break;

        case CLKCTL1_DSPCPUCLKSELB_SEL(1):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL1_DSPCPUCLKSELB_SEL(2):
            freq = CLOCK_GetDspPllClkFreq();
            break;

        case CLKCTL1_DSPCPUCLKSELB_SEL(3):
            freq = CLOCK_GetOsc32KFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq;
}

/* Get ADC Clk */
/*! brief  Return Frequency of Adc Clock
 *  return Frequency of Adc Clock.
 */
uint32_t CLOCK_GetAdcClkFreq(void)
{
    uint32_t freq = 0U;

    switch ((CLKCTL0->ADC0FCLKSEL1) & CLKCTL0_ADC0FCLKSEL1_SEL_MASK)
    {
        case CLKCTL0_ADC0FCLKSEL1_SEL(0):
            switch ((CLKCTL0->ADC0FCLKSEL0) & CLKCTL0_ADC0FCLKSEL0_SEL_MASK)
            {
                case CLKCTL0_ADC0FCLKSEL0_SEL(0):
                    freq = CLOCK_GetXtalInClkFreq();
                    break;
                case CLKCTL0_ADC0FCLKSEL0_SEL(1):
                    freq = CLOCK_GetLpOscFreq();
                    break;
                case CLKCTL0_ADC0FCLKSEL0_SEL(2):
                    freq = CLK_FRO_DIV4_CLK;
                    break;
                default:
                    freq = 0U;
                    break;
            }
            break;

        case CLKCTL0_ADC0FCLKSEL1_SEL(1):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL0_ADC0FCLKSEL1_SEL(2):
            freq = CLOCK_GetAux0PllClkFreq();
            break;

        case CLKCTL0_ADC0FCLKSEL1_SEL(3):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL0->ADC0FCLKDIV & CLKCTL0_ADC0FCLKDIV_DIV_MASK) + 1U);
}

/* Get CLOCK OUT Clk */
/*! brief  Return Frequency of ClockOut
 *  return Frequency of ClockOut
 */
uint32_t CLOCK_GetClockOutClkFreq(void)
{
    uint32_t freq = 0U;

    switch ((CLKCTL1->CLKOUTSEL1) & CLKCTL1_CLKOUTSEL1_SEL_MASK)
    {
        case CLKCTL1_CLKOUTSEL1_SEL(0):
            switch ((CLKCTL1->CLKOUTSEL0) & CLKCTL1_CLKOUTSEL0_SEL_MASK)
            {
                case CLKCTL1_CLKOUTSEL0_SEL(0):
                    freq = CLOCK_GetXtalInClkFreq();
                    break;
                case CLKCTL1_CLKOUTSEL0_SEL(1):
                    freq = CLOCK_GetLpOscFreq();
                    break;
                case CLKCTL1_CLKOUTSEL0_SEL(2):
                    freq = CLK_FRO_DIV2_CLK;
                    break;
                case CLKCTL1_CLKOUTSEL0_SEL(3):
                    freq = CLOCK_GetMainClkFreq();
                    break;
                case CLKCTL1_CLKOUTSEL0_SEL(4):
                    freq = CLOCK_GetDspMainClkFreq();
                    break;
                default:
                    freq = 0U;
                    break;
            }
            break;

        case CLKCTL1_CLKOUTSEL1_SEL(1):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL1_CLKOUTSEL1_SEL(2):
            freq = CLOCK_GetAux0PllClkFreq();
            break;

        case CLKCTL1_CLKOUTSEL1_SEL(3):
            freq = CLOCK_GetDspPllClkFreq();
            break;

        case CLKCTL1_CLKOUTSEL1_SEL(4):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        case CLKCTL1_CLKOUTSEL1_SEL(5):
            freq = CLOCK_GetAudioPllClkFreq();
            break;

        case CLKCTL1_CLKOUTSEL1_SEL(6):
            freq = CLOCK_GetOsc32KFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL1->CLKOUTFCLKDIV & CLKCTL1_CLKOUTFCLKDIV_DIV_MASK) + 1U);
}

/* Get FRG Clk */
/*! brief  Return Input frequency for the Fractional baud rate generator
 *  return Input Frequency for FRG
 */
uint32_t CLOCK_GetFRGClock(uint32_t id)
{
    uint32_t freq      = 0U;
    uint32_t frgPllDiv = 1U;
    uint32_t clkSel    = 0U;
    uint32_t frgDiv    = 0U;
    uint32_t frgMul    = 0U;

    assert(id <= 17U);

    if (id == 17U)
    {
        clkSel = CLKCTL1->FRG17CLKSEL & CLKCTL1_FRG17CLKSEL_SEL_MASK;
        frgMul = (CLKCTL1->FRG17CTL & CLKCTL1_FRG17CTL_MULT_MASK) >> CLKCTL1_FRG17CTL_MULT_SHIFT;
        frgDiv = (CLKCTL1->FRG17CTL & CLKCTL1_FRG17CTL_DIV_MASK) >> CLKCTL1_FRG17CTL_DIV_SHIFT;
    }
    else
    {
        clkSel = CLKCTL1->FLEXCOMM[id].FRGCLKSEL & CLKCTL1_FRGCLKSEL_SEL_MASK;
        frgMul = (CLKCTL1->FLEXCOMM[id].FRGCTL & CLKCTL1_FRGCTL_MULT_MASK) >> CLKCTL1_FRGCTL_MULT_SHIFT;
        frgDiv = (CLKCTL1->FLEXCOMM[id].FRGCTL & CLKCTL1_FRGCTL_DIV_MASK) >> CLKCTL1_FRGCTL_DIV_SHIFT;
    }

    switch (clkSel)
    {
        case CLKCTL1_FRGCLKSEL_SEL(0):
            freq = CLOCK_GetMainClkFreq();
            break;

        case CLKCTL1_FRGCLKSEL_SEL(1):
            frgPllDiv = (CLKCTL1->FRGPLLCLKDIV & CLKCTL1_FRGPLLCLKDIV_DIV_MASK) + 1U;
            freq      = CLOCK_GetMainPllClkFreq() / frgPllDiv;
            break;

        case CLKCTL1_FRGCLKSEL_SEL(2):
            freq = CLK_FRO_DIV4_CLK;
            break;

        default:
            freq = 0U;
            break;
    }

    return (uint32_t)(((uint64_t)freq * ((uint64_t)frgDiv + 1ULL)) / (frgMul + frgDiv + 1UL));
}

/* Get FLEXCOMM Clk */
/*! brief  Return Frequency of Flexcomm functional Clock
 *  param   id    : flexcomm index to get frequency.
 *  return Frequency of Flexcomm functional Clock
 */
uint32_t CLOCK_GetFlexcommClkFreq(uint32_t id)
{
    uint32_t freq   = 0U;
    uint32_t clkSel = 0U;

    assert(id <= 16U);

    clkSel = CLKCTL1->FLEXCOMM[id].FCFCLKSEL;

    switch (clkSel & CLKCTL1_FCFCLKSEL_SEL_MASK)
    {
        case CLKCTL1_FCFCLKSEL_SEL(0):
            freq = CLK_FRO_DIV4_CLK;
            break;

        case CLKCTL1_FCFCLKSEL_SEL(1):
            freq = CLOCK_GetAudioPllClkFreq();
            break;

        case CLKCTL1_FCFCLKSEL_SEL(2):
            freq = g_mclkFreq;
            break;

        case CLKCTL1_FCFCLKSEL_SEL(3):
            freq = CLOCK_GetFRGClock(id);
            break;

        default:
            freq = 0U;
            break;
    }

    return freq;
}

/*! @brief  Return Frequency of Flexio functional Clock
 *  @return Frequency of Flexcomm functional Clock
 */
uint32_t CLOCK_GetFlexioClkFreq(void)
{
    uint32_t freq = 0U;

    switch (CLKCTL1->FLEXIOCLKSEL & CLKCTL1_FLEXIOCLKSEL_SEL_MASK)
    {
        case CLKCTL1_FLEXIOCLKSEL_SEL(0):
            freq = CLK_FRO_DIV2_CLK;
            break;

        case CLKCTL1_FLEXIOCLKSEL_SEL(1):
            freq = CLOCK_GetAudioPllClkFreq();
            break;

        case CLKCTL1_FLEXIOCLKSEL_SEL(2):
            freq = CLOCK_GetMclkInClkFreq();
            break;

        case CLKCTL1_FLEXIOCLKSEL_SEL(3):
            freq = CLOCK_GetFRGClock(17);
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL1->FLEXIOCLKDIV & CLKCTL1_FLEXIOCLKDIV_DIV_MASK) + 1U);
}

/* Get CTIMER Clk */
/*! brief  Return Frequency of Ctimer Clock
 *  param   id    : ctimer index to get frequency.
 *  return Frequency of Ctimer Clock
 */
uint32_t CLOCK_GetCtimerClkFreq(uint32_t id)
{
    uint32_t freq = 0U;

    switch ((CLKCTL1->CT32BITFCLKSEL[id]) & CLKCTL1_CT32BITFCLKSEL_SEL_MASK)
    {
        case CLKCTL1_CT32BITFCLKSEL_SEL(0):
            freq = CLOCK_GetMainClkFreq();
            break;

        case CLKCTL1_CT32BITFCLKSEL_SEL(1):
            freq = CLK_FRO_CLK;
            break;

        case CLKCTL1_CT32BITFCLKSEL_SEL(2):
            freq = CLOCK_GetAudioPllClkFreq();
            break;

        case CLKCTL1_CT32BITFCLKSEL_SEL(3):
            freq = CLOCK_GetMclkInClkFreq();
            break;

        case CLKCTL1_CT32BITFCLKSEL_SEL(4):
            freq = CLOCK_GetWakeClk32KFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq;
}

/*! @brief  Return Frequency of FLEXSPI Clock
 *  @param  id : flexspi index to get frequency.
 *  @return Frequency of Flexspi.
 */
uint32_t CLOCK_GetFlexspiClkFreq(uint32_t id)
{
    uint32_t freq = 0U;
    uint32_t clkSel;
    uint32_t clkDiv;

    assert(id <= 1U);

    if (id == 0U)
    {
        clkSel = CLKCTL0->FLEXSPI0FCLKSEL & CLKCTL0_FLEXSPI0FCLKSEL_SEL_MASK;
        clkDiv = CLKCTL0->FLEXSPI0FCLKDIV & CLKCTL0_FLEXSPI0FCLKDIV_DIV_MASK;
    }
    else
    {
        clkSel = CLKCTL0->FLEXSPI1FCLKSEL & CLKCTL0_FLEXSPI1FCLKSEL_SEL_MASK;
        clkDiv = CLKCTL0->FLEXSPI1FCLKDIV & CLKCTL0_FLEXSPI1FCLKDIV_DIV_MASK;
    }

    switch (clkSel)
    {
        case CLKCTL0_FLEXSPI0FCLKSEL_SEL(0):
            freq = CLOCK_GetMainClkFreq();
            break;

        case CLKCTL0_FLEXSPI0FCLKSEL_SEL(1):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL0_FLEXSPI0FCLKSEL_SEL(2):
            freq = CLOCK_GetAux0PllClkFreq();
            break;

        case CLKCTL0_FLEXSPI0FCLKSEL_SEL(3):
            freq = CLK_FRO_CLK;
            break;

        case CLKCTL0_FLEXSPI0FCLKSEL_SEL(4):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / (clkDiv + 1U);
}

/* Get SCT Clk */
/*! brief  Return Frequency of sct
 *  return Frequency of sct clk
 */
uint32_t CLOCK_GetSctClkFreq(void)
{
    uint32_t freq = 0U;

    switch ((CLKCTL0->SCTFCLKSEL) & CLKCTL0_SCTFCLKSEL_SEL_MASK)
    {
        case CLKCTL0_SCTFCLKSEL_SEL(0):
            freq = CLOCK_GetMainClkFreq();
            break;

        case CLKCTL0_SCTFCLKSEL_SEL(1):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL0_SCTFCLKSEL_SEL(2):
            freq = CLOCK_GetAux0PllClkFreq();
            break;

        case CLKCTL0_SCTFCLKSEL_SEL(3):
            freq = CLK_FRO_CLK;
            break;

        case CLKCTL0_SCTFCLKSEL_SEL(4):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        case CLKCTL0_SCTFCLKSEL_SEL(5):
            freq = CLOCK_GetAudioPllClkFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL0->SCTIN7CLKDIV & CLKCTL0_SCTIN7CLKDIV_DIV_MASK) + 1U);
}

/*! brief  Return Frequency of mclk
 *  return Frequency of mclk clk
 */
uint32_t CLOCK_GetMclkClkFreq(void)
{
    uint32_t freq = 0U;

    if ((CLKCTL1->AUDIOMCLKSEL & CLKCTL1_AUDIOMCLKSEL_SEL_MASK) == CLKCTL1_AUDIOMCLKSEL_SEL(0))
    {
        freq = CLK_FRO_DIV8_CLK;
    }
    else if ((CLKCTL1->AUDIOMCLKSEL & CLKCTL1_AUDIOMCLKSEL_SEL_MASK) == CLKCTL1_AUDIOMCLKSEL_SEL(1))
    {
        freq = CLOCK_GetAudioPllClkFreq();
    }
    else
    {
        freq = 0U;
    }

    return freq / ((CLKCTL1->AUDIOMCLKDIV & CLKCTL1_AUDIOMCLKDIV_DIV_MASK) + 1U);
}

/*! @brief  Return Frequency of WDT clk
 *  @param  id : WDT index to get frequency.
 *  @return Frequency of WDT clk
 */
uint32_t CLOCK_GetWdtClkFreq(uint32_t id)
{
    uint32_t freq = 0U;

    assert(id <= 1U);

    if (id == 0U)
    {
        if ((CLKCTL0->WDT0FCLKSEL & CLKCTL0_WDT0FCLKSEL_SEL_MASK) == CLKCTL0_WDT0FCLKSEL_SEL(0))
        {
            freq = CLOCK_GetLpOscFreq();
        }
        else
        {
            freq = 0U;
        }
    }
    else
    {
        if ((CLKCTL1->WDT1FCLKSEL & CLKCTL1_WDT1FCLKSEL_SEL_MASK) == CLKCTL1_WDT1FCLKSEL_SEL(0))
        {
            freq = CLOCK_GetLpOscFreq();
        }
        else
        {
            freq = 0U;
        }
    }

    return freq;
}

/*! brief  Return Frequency of systick clk
 *  return Frequency of systick clk
 */
uint32_t CLOCK_GetSystickClkFreq(void)
{
    uint32_t freq = 0U;

    switch (CLKCTL0->SYSTICKFCLKSEL & CLKCTL0_SYSTICKFCLKSEL_SEL_MASK)
    {
        case CLKCTL0_SYSTICKFCLKSEL_SEL(0):
            freq = CLOCK_GetMainClkFreq() / ((CLKCTL0->SYSTICKFCLKDIV & CLKCTL0_SYSTICKFCLKDIV_DIV_MASK) + 1U);
            break;

        case CLKCTL0_SYSTICKFCLKSEL_SEL(1):
            freq = CLOCK_GetLpOscFreq();
            break;

        case CLKCTL0_SYSTICKFCLKSEL_SEL(2):
            freq = CLOCK_GetOsc32KFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq;
}

/*! brief  Return Frequency of SDIO clk
 *  param id : SDIO index to get frequency.
 *  return Frequency of SDIO clk
 */
uint32_t CLOCK_GetSdioClkFreq(uint32_t id)
{
    uint32_t freq = 0U;
    volatile uint32_t *pClkSel;
    volatile uint32_t *pClkDiv;

    assert(id <= 1U);

    if (id == 0U)
    {
        pClkSel = &CLKCTL0->SDIO0FCLKSEL;
        pClkDiv = &CLKCTL0->SDIO0FCLKDIV;
    }
    else
    {
        pClkSel = &CLKCTL0->SDIO1FCLKSEL;
        pClkDiv = &CLKCTL0->SDIO1FCLKDIV;
    }

    switch ((*pClkSel) & CLKCTL0_SDIO0FCLKSEL_SEL_MASK)
    {
        case CLKCTL0_SDIO0FCLKSEL_SEL(0):
            freq = CLOCK_GetMainClkFreq();
            break;

        case CLKCTL0_SDIO0FCLKSEL_SEL(1):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL0_SDIO0FCLKSEL_SEL(2):
            freq = CLOCK_GetAux0PllClkFreq();
            break;

        case CLKCTL0_SDIO0FCLKSEL_SEL(3):
            freq = CLK_FRO_DIV2_CLK;
            break;

        case CLKCTL0_SDIO0FCLKSEL_SEL(4):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / (((*pClkDiv) & CLKCTL0_SDIO0FCLKDIV_DIV_MASK) + 1U);
}

/*! @brief  Return Frequency of I3C clk
 *  @return Frequency of I3C clk
 */
uint32_t CLOCK_GetI3cClkFreq(void)
{
    uint32_t freq = 0U;

    switch (CLKCTL1->I3C01FCLKSEL & CLKCTL1_I3C01FCLKSEL_SEL_MASK)
    {
        case CLKCTL1_I3C01FCLKSEL_SEL(0):
            freq = CLOCK_GetMainClkFreq();
            break;

        case CLKCTL1_I3C01FCLKSEL_SEL(1):
            freq = CLK_FRO_DIV8_CLK;
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL1->I3C01FCLKDIV & CLKCTL1_I3C01FCLKDIV_DIV_MASK) + 1U);
}

/*! brief  Return Frequency of USB clk
 *  return Frequency of USB clk
 */
uint32_t CLOCK_GetUsbClkFreq(void)
{
    uint32_t freq = 0U;

    switch (CLKCTL0->USBHSFCLKSEL & CLKCTL0_USBHSFCLKSEL_SEL_MASK)
    {
        case CLKCTL0_USBHSFCLKSEL_SEL(0):
            freq = CLOCK_GetXtalInClkFreq();
            break;
        case CLKCTL0_USBHSFCLKSEL_SEL(1):
            freq = CLOCK_GetMainClkFreq();
            break;
        case CLKCTL0_USBHSFCLKSEL_SEL(2):
            freq = CLK_FRO_DIV8_CLK;
            break;
        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL0->USBHSFCLKDIV & CLKCTL0_USBHSFCLKDIV_DIV_MASK) + 1U);
}

/*! brief  Return Frequency of DMIC clk
 *  return Frequency of DMIC clk
 */
uint32_t CLOCK_GetDmicClkFreq(void)
{
    uint32_t freq = 0U;

    switch ((CLKCTL1->DMIC0FCLKSEL) & CLKCTL1_DMIC0FCLKSEL_SEL_MASK)
    {
        case CLKCTL1_DMIC0FCLKSEL_SEL(0):
            freq = CLK_FRO_DIV4_CLK;
            break;

        case CLKCTL1_DMIC0FCLKSEL_SEL(1):
            freq = CLOCK_GetAudioPllClkFreq();
            break;

        case CLKCTL1_DMIC0FCLKSEL_SEL(2):
            freq = CLOCK_GetMclkInClkFreq();
            break;

        case CLKCTL1_DMIC0FCLKSEL_SEL(3):
            freq = CLOCK_GetLpOscFreq();
            break;

        case CLKCTL1_DMIC0FCLKSEL_SEL(4):
            freq = CLOCK_GetWakeClk32KFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL1->DMIC0FCLKDIV & CLKCTL1_DMIC0FCLKDIV_DIV_MASK) + 1U);
}

/*! brief  Return Frequency of ACMP clk
 *  return Frequency of ACMP clk
 */
uint32_t CLOCK_GetAcmpClkFreq(void)
{
    uint32_t freq = 0U;

    switch ((CLKCTL1->ACMP0FCLKSEL) & CLKCTL1_ACMP0FCLKSEL_SEL_MASK)
    {
        case CLKCTL1_ACMP0FCLKSEL_SEL(0):
            freq = CLOCK_GetMainClkFreq();
            break;

        case CLKCTL1_ACMP0FCLKSEL_SEL(1):
            freq = CLK_FRO_DIV4_CLK;
            break;

        case CLKCTL1_ACMP0FCLKSEL_SEL(2):
            freq = CLOCK_GetAux0PllClkFreq();
            break;

        case CLKCTL1_ACMP0FCLKSEL_SEL(3):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL1->ACMP0FCLKDIV & CLKCTL1_ACMP0FCLKDIV_DIV_MASK) + 1U);
}

/*! @brief  Return Frequency of GPU functional Clock
 *  @return Frequency of GPU functional Clock
 */
uint32_t CLOCK_GetGpuClkFreq(void)
{
    uint32_t freq = 0U;

    switch (CLKCTL0->GPUCLKSEL & CLKCTL0_GPUCLKSEL_SEL_MASK)
    {
        case CLKCTL0_GPUCLKSEL_SEL(0):
            freq = CLOCK_GetMainClkFreq();
            break;

        case CLKCTL0_GPUCLKSEL_SEL(1):
            freq = CLK_FRO_CLK;
            break;

        case CLKCTL0_GPUCLKSEL_SEL(2):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL0_GPUCLKSEL_SEL(3):
            freq = CLOCK_GetAux0PllClkFreq();
            break;

        case CLKCTL0_GPUCLKSEL_SEL(4):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL0->GPUCLKDIV & CLKCTL0_GPUCLKDIV_DIV_MASK) + 1U);
}

/*! @brief  Return Frequency of DCNano Pixel functional Clock
 *  @return Frequency of DCNano pixel functional Clock
 */
uint32_t CLOCK_GetDcPixelClkFreq(void)
{
    uint32_t freq = 0U;

    switch (CLKCTL0->DCPIXELCLKSEL & CLKCTL0_DCPIXELCLKSEL_SEL_MASK)
    {
        case CLKCTL0_DCPIXELCLKSEL_SEL(0):
            freq = CLOCK_GetMipiDphyClkFreq();
            break;
        case CLKCTL0_DCPIXELCLKSEL_SEL(1):
            freq = CLOCK_GetMainClkFreq();
            break;

        case CLKCTL0_DCPIXELCLKSEL_SEL(2):
            freq = CLK_FRO_CLK;
            break;

        case CLKCTL0_DCPIXELCLKSEL_SEL(3):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL0_DCPIXELCLKSEL_SEL(4):
            freq = CLOCK_GetAux0PllClkFreq();
            break;

        case CLKCTL0_DCPIXELCLKSEL_SEL(5):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL0->DCPIXELCLKDIV & CLKCTL0_DCPIXELCLKDIV_DIV_MASK) + 1U);
}

/*! @brief  Return Frequency of MIPI DPHY functional Clock
 *  @return Frequency of MIPI DPHY functional Clock
 */
uint32_t CLOCK_GetMipiDphyClkFreq(void)
{
    uint32_t freq = 0U;

    switch (CLKCTL0->DPHYCLKSEL & CLKCTL0_DPHYCLKSEL_SEL_MASK)
    {
        case CLKCTL0_DPHYCLKSEL_SEL(0):
            freq = CLK_FRO_CLK;
            break;
        case CLKCTL0_DPHYCLKSEL_SEL(1):
            freq = CLOCK_GetMainPllClkFreq();
            break;

        case CLKCTL0_DPHYCLKSEL_SEL(2):
            freq = CLOCK_GetAux0PllClkFreq();
            break;

        case CLKCTL0_DPHYCLKSEL_SEL(3):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL0->DPHYCLKDIV & CLKCTL0_DPHYCLKDIV_DIV_MASK) + 1U);
}

/*! @brief  Return Frequency of MIPI DPHY Esc RX functional Clock
 *  @return Frequency of MIPI DPHY Esc RX functional Clock
 */
uint32_t CLOCK_GetMipiDphyEscRxClkFreq(void)
{
    uint32_t freq = 0U;

    switch (CLKCTL0->DPHYESCCLKSEL & CLKCTL0_DPHYESCCLKSEL_SEL_MASK)
    {
        case CLKCTL0_DPHYESCCLKSEL_SEL(0):
            freq = CLK_FRO_CLK;
            break;
        case CLKCTL0_DPHYESCCLKSEL_SEL(1):
            freq = CLK_FRO_DIV16_CLK;
            break;
        case CLKCTL0_DPHYESCCLKSEL_SEL(2):
            freq = CLOCK_GetAux0PllClkFreq();
            break;
        case CLKCTL0_DPHYESCCLKSEL_SEL(3):
            freq = CLOCK_GetAux1PllClkFreq();
            break;

        default:
            freq = 0U;
            break;
    }

    return freq / ((CLKCTL0->DPHYESCRXCLKDIV & CLKCTL0_DPHYESCRXCLKDIV_DIV_MASK) + 1U);
}

/*! @brief  Return Frequency of MIPI DPHY Esc Tx functional Clock
 *  @return Frequency of MIPI DPHY Esc Tx functional Clock
 */
uint32_t CLOCK_GetMipiDphyEscTxClkFreq(void)
{
    return CLOCK_GetMipiDphyEscRxClkFreq() / ((CLKCTL0->DPHYESCTXCLKDIV & CLKCTL0_DPHYESCTXCLKDIV_DIV_MASK) + 1U);
}

/* Get IP Clk */
/*! brief  Return Frequency of selected clock
 *  return Frequency of selected clock
 */
uint32_t CLOCK_GetFreq(clock_name_t clockName)
{
    uint32_t freq = 0U;

    switch (clockName)
    {
        case kCLOCK_CoreSysClk:
        case kCLOCK_BusClk:
            freq = CLOCK_GetMainClkFreq() / ((CLKCTL0->SYSCPUAHBCLKDIV & CLKCTL0_SYSCPUAHBCLKDIV_DIV_MASK) + 1U);
            break;
        case kCLOCK_MclkClk:
            freq = CLOCK_GetMclkClkFreq();
            break;
        case kCLOCK_ClockOutClk:
            freq = CLOCK_GetClockOutClkFreq();
            break;
        case kCLOCK_AdcClk:
            freq = CLOCK_GetAdcClkFreq();
            break;
        case kCLOCK_Flexspi0Clk:
            freq = CLOCK_GetFlexspiClkFreq(0U);
            break;
        case kCLOCK_Flexspi1Clk:
            freq = CLOCK_GetFlexspiClkFreq(1U);
            break;
        case kCLOCK_SctClk:
            freq = CLOCK_GetSctClkFreq();
            break;
        case kCLOCK_Wdt0Clk:
            freq = CLOCK_GetWdtClkFreq(0U);
            break;
        case kCLOCK_Wdt1Clk:
            freq = CLOCK_GetWdtClkFreq(1U);
            break;
        case kCLOCK_SystickClk:
            freq = CLOCK_GetSystickClkFreq();
            break;
        case kCLOCK_Sdio0Clk:
            freq = CLOCK_GetSdioClkFreq(0U);
            break;
        case kCLOCK_Sdio1Clk:
            freq = CLOCK_GetSdioClkFreq(1U);
            break;
        case kCLOCK_I3cClk:
            freq = CLOCK_GetI3cClkFreq();
            break;
        case kCLOCK_UsbClk:
            freq = CLOCK_GetUsbClkFreq();
            break;
        case kCLOCK_DmicClk:
            freq = CLOCK_GetDmicClkFreq();
            break;
        case kCLOCK_DspCpuClk:
            freq = CLOCK_GetDspMainClkFreq() / ((CLKCTL1->DSPCPUCLKDIV & CLKCTL1_DSPCPUCLKDIV_DIV_MASK) + 1U);
            break;
        case kCLOCK_AcmpClk:
            freq = CLOCK_GetAcmpClkFreq();
            break;
        case kCLOCK_Flexcomm0Clk:
            freq = CLOCK_GetFlexcommClkFreq(0U);
            break;
        case kCLOCK_Flexcomm1Clk:
            freq = CLOCK_GetFlexcommClkFreq(1U);
            break;
        case kCLOCK_Flexcomm2Clk:
            freq = CLOCK_GetFlexcommClkFreq(2U);
            break;
        case kCLOCK_Flexcomm3Clk:
            freq = CLOCK_GetFlexcommClkFreq(3U);
            break;
        case kCLOCK_Flexcomm4Clk:
            freq = CLOCK_GetFlexcommClkFreq(4U);
            break;
        case kCLOCK_Flexcomm5Clk:
            freq = CLOCK_GetFlexcommClkFreq(5U);
            break;
        case kCLOCK_Flexcomm6Clk:
            freq = CLOCK_GetFlexcommClkFreq(6U);
            break;
        case kCLOCK_Flexcomm7Clk:
            freq = CLOCK_GetFlexcommClkFreq(7U);
            break;
        case kCLOCK_Flexcomm8Clk:
            freq = CLOCK_GetFlexcommClkFreq(8U);
            break;
        case kCLOCK_Flexcomm9Clk:
            freq = CLOCK_GetFlexcommClkFreq(9U);
            break;
        case kCLOCK_Flexcomm10Clk:
            freq = CLOCK_GetFlexcommClkFreq(10U);
            break;
        case kCLOCK_Flexcomm11Clk:
            freq = CLOCK_GetFlexcommClkFreq(11U);
            break;
        case kCLOCK_Flexcomm12Clk:
            freq = CLOCK_GetFlexcommClkFreq(12U);
            break;
        case kCLOCK_Flexcomm13Clk:
            freq = CLOCK_GetFlexcommClkFreq(13U);
            break;
        case kCLOCK_Flexcomm14Clk:
            freq = CLOCK_GetFlexcommClkFreq(14U);
            break;
        case kCLOCK_Flexcomm15Clk:
            freq = CLOCK_GetFlexcommClkFreq(15U);
            break;
        case kCLOCK_Flexcomm16Clk:
            freq = CLOCK_GetFlexcommClkFreq(16U);
            break;
        case kCLOCK_FlexioClk:
            freq = CLOCK_GetFlexioClkFreq();
            break;
        case kCLOCK_GpuClk:
            freq = CLOCK_GetGpuClkFreq();
            break;
        case kCLOCK_DcPixelClk:
            freq = CLOCK_GetDcPixelClkFreq();
            break;
        case kCLOCK_MipiDphyClk:
            freq = CLOCK_GetMipiDphyClkFreq();
            break;
        case kCLOCK_MipiDphyEscRxClk:
            freq = CLOCK_GetMipiDphyEscRxClkFreq();
            break;
        case kCLOCK_MipiDphyEscTxClk:
            freq = CLOCK_GetMipiDphyEscTxClkFreq();
            break;
        default:
            freq = 0U;
            break;
    }

    return freq;
}

/* Set FRG Clk */
/*! brief  Set output of the Fractional baud rate generator
 * param   config    : Configuration to set to FRGn clock.
 */
void CLOCK_SetFRGClock(const clock_frg_clk_config_t *config)
{
    uint32_t i = config->num;

    assert(i <= 17U);
    assert(config->divider == 255U); /* Always set to 0xFF to use with the fractional baudrate generator.*/

    if (i == 17U)
    {
        CLKCTL1->FRG17CLKSEL = (uint32_t)config->sfg_clock_src;
        CLKCTL1->FRG17CTL    = (CLKCTL1_FRG17CTL_MULT(config->mult) | CLKCTL1_FRG17CTL_DIV(config->divider));
    }
    else
    {
        CLKCTL1->FLEXCOMM[i].FRGCLKSEL = (uint32_t)config->sfg_clock_src;
        CLKCTL1->FLEXCOMM[i].FRGCTL    = (CLKCTL1_FRGCTL_MULT(config->mult) | CLKCTL1_FRGCTL_DIV(config->divider));
    }
}

/* Initialize the SYSTEM PLL Clk */
/*! brief  Initialize the System PLL.
 *  param  config    : Configuration to set to PLL.
 */
void CLOCK_InitSysPll(const clock_sys_pll_config_t *config)
{
    /* Power down SYSPLL before change fractional settings */
    SYSCTL0->PDRUNCFG0_SET = SYSCTL0_PDRUNCFG0_SYSPLLLDO_PD_MASK | SYSCTL0_PDRUNCFG0_SYSPLLANA_PD_MASK;

    CLKCTL0->SYSPLL0CLKSEL = (uint32_t)config->sys_pll_src;
    CLKCTL0->SYSPLL0NUM    = config->numerator;
    CLKCTL0->SYSPLL0DENOM  = config->denominator;
    switch (config->sys_pll_mult)
    {
        case kCLOCK_SysPllMult16:
            CLKCTL0->SYSPLL0CTL0 =
                (CLKCTL0->SYSPLL0CTL0 & ~CLKCTL0_SYSPLL0CTL0_MULT_MASK) | CLKCTL0_SYSPLL0CTL0_MULT(16);
            break;
        case kCLOCK_SysPllMult17:
            CLKCTL0->SYSPLL0CTL0 =
                (CLKCTL0->SYSPLL0CTL0 & ~CLKCTL0_SYSPLL0CTL0_MULT_MASK) | CLKCTL0_SYSPLL0CTL0_MULT(17);
            break;
        case kCLOCK_SysPllMult18:
            CLKCTL0->SYSPLL0CTL0 =
                (CLKCTL0->SYSPLL0CTL0 & ~CLKCTL0_SYSPLL0CTL0_MULT_MASK) | CLKCTL0_SYSPLL0CTL0_MULT(18);
            break;
        case kCLOCK_SysPllMult19:
            CLKCTL0->SYSPLL0CTL0 =
                (CLKCTL0->SYSPLL0CTL0 & ~CLKCTL0_SYSPLL0CTL0_MULT_MASK) | CLKCTL0_SYSPLL0CTL0_MULT(19);
            break;
        case kCLOCK_SysPllMult20:
            CLKCTL0->SYSPLL0CTL0 =
                (CLKCTL0->SYSPLL0CTL0 & ~CLKCTL0_SYSPLL0CTL0_MULT_MASK) | CLKCTL0_SYSPLL0CTL0_MULT(20);
            break;
        case kCLOCK_SysPllMult21:
            CLKCTL0->SYSPLL0CTL0 =
                (CLKCTL0->SYSPLL0CTL0 & ~CLKCTL0_SYSPLL0CTL0_MULT_MASK) | CLKCTL0_SYSPLL0CTL0_MULT(21);
            break;
        case kCLOCK_SysPllMult22:
            CLKCTL0->SYSPLL0CTL0 =
                (CLKCTL0->SYSPLL0CTL0 & ~CLKCTL0_SYSPLL0CTL0_MULT_MASK) | CLKCTL0_SYSPLL0CTL0_MULT(22);
            break;
        default:
            assert(false);
            break;
    }
    /* Clear System PLL reset*/
    CLKCTL0->SYSPLL0CTL0 &= ~CLKCTL0_SYSPLL0CTL0_RESET_MASK;
    /* Power up SYSPLL*/
    SYSCTL0->PDRUNCFG0_CLR = SYSCTL0_PDRUNCFG0_SYSPLLLDO_PD_MASK | SYSCTL0_PDRUNCFG0_SYSPLLANA_PD_MASK;
    SDK_DelayAtLeastUs((CLKCTL0->SYSPLL0LOCKTIMEDIV2 & CLKCTL0_SYSPLL0LOCKTIMEDIV2_LOCKTIMEDIV2_MASK) / 2U,
                       SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY);
    /* Set System PLL HOLDRINGOFF_ENA */
    CLKCTL0->SYSPLL0CTL0 |= CLKCTL0_SYSPLL0CTL0_HOLDRINGOFF_ENA_MASK;
    SDK_DelayAtLeastUs((CLKCTL0->SYSPLL0LOCKTIMEDIV2 & CLKCTL0_SYSPLL0LOCKTIMEDIV2_LOCKTIMEDIV2_MASK) / 6U,
                       SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY);
    /* Clear System PLL HOLDRINGOFF_ENA*/
    CLKCTL0->SYSPLL0CTL0 &= ~CLKCTL0_SYSPLL0CTL0_HOLDRINGOFF_ENA_MASK;
    SDK_DelayAtLeastUs((CLKCTL0->SYSPLL0LOCKTIMEDIV2 & CLKCTL0_SYSPLL0LOCKTIMEDIV2_LOCKTIMEDIV2_MASK) / 3U,
                       SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY);
}

/* Initialize the System PLL PFD */
/*! brief Initialize the System PLL PFD.
 *  param pfd    : Which PFD clock to enable.
 *  param divider    : The PFD divider value.
 *  note It is recommended that PFD settings are kept between 12-35.
 */
void CLOCK_InitSysPfd(clock_pfd_t pfd, uint8_t divider)
{
    uint32_t pfdIndex = (uint32_t)pfd;
    uint32_t syspfd;

    syspfd = CLKCTL0->SYSPLL0PFD &
             ~(((uint32_t)CLKCTL0_SYSPLL0PFD_PFD0_CLKGATE_MASK | (uint32_t)CLKCTL0_SYSPLL0PFD_PFD0_MASK)
               << (8UL * pfdIndex));

    /* Disable the clock output first. */
    CLKCTL0->SYSPLL0PFD = syspfd | ((uint32_t)CLKCTL0_SYSPLL0PFD_PFD0_CLKGATE_MASK << (8UL * pfdIndex));

    /* Set the new value and enable output. */
    CLKCTL0->SYSPLL0PFD = syspfd | ((uint32_t)CLKCTL0_SYSPLL0PFD_PFD0(divider) << (8UL * pfdIndex));
    /* Wait for output becomes stable. */
    while ((CLKCTL0->SYSPLL0PFD & ((uint32_t)CLKCTL0_SYSPLL0PFD_PFD0_CLKRDY_MASK << (8UL * pfdIndex))) == 0UL)
    {
    }
    /* Clear ready status flag. */
    CLKCTL0->SYSPLL0PFD |= ((uint32_t)CLKCTL0_SYSPLL0PFD_PFD0_CLKRDY_MASK << (8UL * pfdIndex));
}

/* Initialize the Audio PLL Clk */
/*! brief  Initialize the audio PLL.
 *  param  config    : Configuration to set to PLL.
 */
void CLOCK_InitAudioPll(const clock_audio_pll_config_t *config)
{
    /* Power down Audio PLL before change fractional settings */
    SYSCTL0->PDRUNCFG0_SET = SYSCTL0_PDRUNCFG0_AUDPLLLDO_PD_MASK | SYSCTL0_PDRUNCFG0_AUDPLLANA_PD_MASK;

    CLKCTL1->AUDIOPLL0CLKSEL = (uint32_t)config->audio_pll_src;
    CLKCTL1->AUDIOPLL0NUM    = config->numerator;
    CLKCTL1->AUDIOPLL0DENOM  = config->denominator;

    switch (config->audio_pll_mult)
    {
        case kCLOCK_AudioPllMult16:
            CLKCTL1->AUDIOPLL0CTL0 =
                (CLKCTL1->AUDIOPLL0CTL0 & ~CLKCTL1_AUDIOPLL0CTL0_MULT_MASK) | CLKCTL1_AUDIOPLL0CTL0_MULT(16);
            break;
        case kCLOCK_AudioPllMult17:
            CLKCTL1->AUDIOPLL0CTL0 =
                (CLKCTL1->AUDIOPLL0CTL0 & ~CLKCTL1_AUDIOPLL0CTL0_MULT_MASK) | CLKCTL1_AUDIOPLL0CTL0_MULT(17);
            break;
        case kCLOCK_AudioPllMult18:
            CLKCTL1->AUDIOPLL0CTL0 =
                (CLKCTL1->AUDIOPLL0CTL0 & ~CLKCTL1_AUDIOPLL0CTL0_MULT_MASK) | CLKCTL1_AUDIOPLL0CTL0_MULT(18);
            break;
        case kCLOCK_AudioPllMult19:
            CLKCTL1->AUDIOPLL0CTL0 =
                (CLKCTL1->AUDIOPLL0CTL0 & ~CLKCTL1_AUDIOPLL0CTL0_MULT_MASK) | CLKCTL1_AUDIOPLL0CTL0_MULT(19);
            break;
        case kCLOCK_AudioPllMult20:
            CLKCTL1->AUDIOPLL0CTL0 =
                (CLKCTL1->AUDIOPLL0CTL0 & ~CLKCTL1_AUDIOPLL0CTL0_MULT_MASK) | CLKCTL1_AUDIOPLL0CTL0_MULT(20);
            break;
        case kCLOCK_AudioPllMult21:
            CLKCTL1->AUDIOPLL0CTL0 =
                (CLKCTL1->AUDIOPLL0CTL0 & ~CLKCTL1_AUDIOPLL0CTL0_MULT_MASK) | CLKCTL1_AUDIOPLL0CTL0_MULT(21);
            break;
        case kCLOCK_AudioPllMult22:
            CLKCTL1->AUDIOPLL0CTL0 =
                (CLKCTL1->AUDIOPLL0CTL0 & ~CLKCTL1_AUDIOPLL0CTL0_MULT_MASK) | CLKCTL1_AUDIOPLL0CTL0_MULT(22);
            break;
        default:
            assert(false);
            break;
    }
    /* Clear Audio PLL reset*/
    CLKCTL1->AUDIOPLL0CTL0 &= ~CLKCTL1_AUDIOPLL0CTL0_RESET_MASK;
    /* Power up Audio PLL*/
    SYSCTL0->PDRUNCFG0_CLR = SYSCTL0_PDRUNCFG0_AUDPLLLDO_PD_MASK | SYSCTL0_PDRUNCFG0_AUDPLLANA_PD_MASK;
    SDK_DelayAtLeastUs((CLKCTL1->AUDIOPLL0LOCKTIMEDIV2 & CLKCTL1_AUDIOPLL0LOCKTIMEDIV2_LOCKTIMEDIV2_MASK) / 2U,
                       SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY);
    /* Set Audio PLL HOLDRINGOFF_ENA */
    CLKCTL1->AUDIOPLL0CTL0 |= CLKCTL1_AUDIOPLL0CTL0_HOLDRINGOFF_ENA_MASK;
    SDK_DelayAtLeastUs((CLKCTL1->AUDIOPLL0LOCKTIMEDIV2 & CLKCTL1_AUDIOPLL0LOCKTIMEDIV2_LOCKTIMEDIV2_MASK) / 6U,
                       SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY);
    /* Clear Audio PLL HOLDRINGOFF_ENA*/
    CLKCTL1->AUDIOPLL0CTL0 &= ~CLKCTL1_AUDIOPLL0CTL0_HOLDRINGOFF_ENA_MASK;
    SDK_DelayAtLeastUs((CLKCTL1->AUDIOPLL0LOCKTIMEDIV2 & CLKCTL1_AUDIOPLL0LOCKTIMEDIV2_LOCKTIMEDIV2_MASK) / 3U,
                       SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY);
}

/* Initialize the Audio PLL PFD */
/*! brief Initialize the audio PLL PFD.
 *  param pfd    : Which PFD clock to enable.
 *  param divider    : The PFD divider value.
 *  note It is recommended that PFD settings are kept between 12-35.
 */
void CLOCK_InitAudioPfd(clock_pfd_t pfd, uint8_t divider)
{
    uint32_t pfdIndex = (uint32_t)pfd;
    uint32_t syspfd;

    syspfd = CLKCTL1->AUDIOPLL0PFD &
             ~(((uint32_t)CLKCTL1_AUDIOPLL0PFD_PFD0_CLKGATE_MASK | (uint32_t)CLKCTL1_AUDIOPLL0PFD_PFD0_MASK)
               << (8UL * pfdIndex));

    /* Disable the clock output first. */
    CLKCTL1->AUDIOPLL0PFD = syspfd | ((uint32_t)CLKCTL1_AUDIOPLL0PFD_PFD0_CLKGATE_MASK << (8UL * pfdIndex));

    /* Set the new value and enable output. */
    CLKCTL1->AUDIOPLL0PFD = syspfd | ((uint32_t)CLKCTL1_AUDIOPLL0PFD_PFD0(divider) << (8UL * pfdIndex));
    /* Wait for output becomes stable. */
    while ((CLKCTL1->AUDIOPLL0PFD & ((uint32_t)CLKCTL1_AUDIOPLL0PFD_PFD0_CLKRDY_MASK << (8UL * pfdIndex))) == 0UL)
    {
    }
    /* Clear ready status flag. */
    CLKCTL1->AUDIOPLL0PFD |= ((uint32_t)CLKCTL1_AUDIOPLL0PFD_PFD0_CLKRDY_MASK << (8UL * pfdIndex));
}

/*! @brief  Enable/Disable sys osc clock from external crystal clock.
 *  @param  enable : true to enable system osc clock, false to bypass system osc.
 *  @param  enableLowPower : true to enable low power mode, false to enable high gain mode.
 *  @param  delay_us : Delay time after OSC power up.
 */
void CLOCK_EnableSysOscClk(bool enable, bool enableLowPower, uint32_t delay_us)
{
    uint32_t ctrl = enableLowPower ? CLKCTL0_SYSOSCCTL0_LP_ENABLE_MASK : 0U;

    if (enable)
    {
        CLKCTL0->SYSOSCCTL0   = ctrl;
        CLKCTL0->SYSOSCBYPASS = 0U;
        SDK_DelayAtLeastUs(delay_us, SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY);
    }
    else
    {
        CLKCTL0->SYSOSCCTL0 = ctrl | CLKCTL0_SYSOSCCTL0_BYPASS_ENABLE_MASK;
    }
}

/*! @brief  Enable/Disable FRO clock output.
 *  @param  divOutEnable : Or'ed value of clock_fro_output_en_t to enable certain clock freq output.
 */
void CLOCK_EnableFroClk(uint32_t divOutEnable)
{
    if (divOutEnable != 0U)
    {
        /* Some FRO frequency need to be outputed. Wait FRO stable first in case FRO just get powered on. */
        while ((CLKCTL0->FROCLKSTATUS & CLKCTL0_FROCLKSTATUS_CLK_OK_MASK) == 0U)
        {
        }
    }
    else
    {
        /* Do nothing */
    }
    CLKCTL0->FRODIVOEN = divOutEnable & (uint32_t)kCLOCK_FroAllOutEn;
}

#ifndef __XCC__
/*! @brief  Enable/Disable FRO192M or FRO96M clock output.
 *  @param  froFreq : target fro frequency.
 *  @param  divOutEnable : Or'ed value of clock_fro_output_en_t to enable certain clock freq output.
 */
void CLOCK_EnableFroClkRange(clock_fro_freq_t froFreq, uint32_t divOutEnable)
{
    uint32_t scTrim, rdTrim;

    OTP_INIT_API(CLOCK_GetFreq(kCLOCK_BusClk));
    if (froFreq == kCLOCK_Fro192M)
    {
        /* Read 192M FRO clock Trim settings from fuse. */
        OTP_FUSE_READ_API(FRO_192MHZ_SC_TRIM, &scTrim);
        OTP_FUSE_READ_API(FRO_192MHZ_RD_TRIM, &rdTrim);
    }
    else
    {
        /* Read 96M FRO clock Trim settings from fuse. */
        OTP_FUSE_READ_API(FRO_96MHZ_SC_TRIM, &scTrim);
        OTP_FUSE_READ_API(FRO_96MHZ_RD_TRIM, &rdTrim);
    }
    OTP_DEINIT_API();

    CLKCTL0->FRO_SCTRIM = CLKCTL0_FRO_SCTRIM_TRIM(scTrim);
    CLKCTL0->FRO_RDTRIM = CLKCTL0_FRO_RDTRIM_TRIM(rdTrim);
    CLOCK_EnableFroClk(divOutEnable);
}
#endif /* __XCC__ */

/*! @brief  Enable LPOSC 1MHz clock.
 */
void CLOCK_EnableLpOscClk(void)
{
    /* No LPOSC enable/disable control in CLKCTL. Just wait LPOSC stable in case LPOSC just get powered on. */
    while ((CLKCTL0->LPOSCCTL0 & CLKCTL0_LPOSCCTL0_CLKRDY_MASK) == 0U)
    {
    }
}

void CLOCK_EnableFroTuning(bool enable)
{
    uint32_t xtalFreq    = CLOCK_GetXtalInClkFreq();
    uint32_t froDiv4Freq = CLK_FRO_DIV4_CLK;
    uint64_t targetFreq  = (uint64_t)froDiv4Freq;
    uint32_t expected, up, low;
    uint32_t captured, trim;

    assert(xtalFreq);
    assert(targetFreq > xtalFreq);

    if (enable)
    {
        expected = (uint32_t)((targetFreq * (2047U * 2U + 1U) / xtalFreq + 6U) / 2U);
        up       = (uint32_t)(targetFreq * 2047U * 100085U / xtalFreq / 100000U + 2U);
        low      = (uint32_t)((targetFreq * 2048U * 99915U + (uint64_t)xtalFreq * 100000U) / xtalFreq / 100000U + 3U);

        /* Start tuning */
        CLKCTL0->FRO_CONTROL = CLKCTL0_FRO_CONTROL_EXP_COUNT(expected) |
                               CLKCTL0_FRO_CONTROL_THRESH_RANGE_UP(up - expected) |
                               CLKCTL0_FRO_CONTROL_THRESH_RANGE_LOW(expected - low) | CLKCTL0_FRO_CONTROL_ENA_TUNE_MASK;

        while (true)
        {
            while ((CLKCTL0->FRO_CAPVAL & CLKCTL0_FRO_CAPVAL_DATA_VALID_MASK) == 0U)
            {
            }

            captured = CLKCTL0->FRO_CAPVAL & CLKCTL0_FRO_CAPVAL_CAPVAL_MASK;
            trim     = CLKCTL0->FRO_RDTRIM;
            /* Clear FRO_CAPVAL VALID flag */
            CLKCTL0->FRO_RDTRIM = trim;
            /* Reach the frequency range, then return. */
            if ((captured <= up) && (captured >= low))
            {
                break;
            }
        }
    }
    else
    {
        CLKCTL0->FRO_CONTROL &= ~CLKCTL0_FRO_CONTROL_ENA_TUNE_MASK;
    }
}

/*! @brief Enable USB HS device clock.
 *
 * This function enables USB HS device clock.
 */
void CLOCK_EnableUsbHs0DeviceClock(clock_attach_id_t src, uint8_t divider)
{
    CLOCK_AttachClk(src);
    /* frequency division for usb ip clock */
    CLOCK_SetClkDiv(kCLOCK_DivUsbHsFclk, divider);
    /* Enable usbhs device clock */
    CLOCK_EnableClock(kCLOCK_UsbhsDevice);
}

/*! @brief Disable USB HS device clock.
 *
 * This function disables USB HS device clock.
 */
void CLOCK_DisableUsbHs0DeviceClock(void)
{
    /* Disable usbhs device clock */
    CLOCK_DisableClock(kCLOCK_UsbhsDevice);
}

/*! @brief Enable USB HS host clock.
 *
 * This function enables USB HS host clock.
 */
void CLOCK_EnableUsbHs0HostClock(clock_attach_id_t src, uint8_t divider)
{
    CLOCK_AttachClk(src);
    /* frequency division for usb ip clock */
    CLOCK_SetClkDiv(kCLOCK_DivUsbHsFclk, divider);
    /* Enable usbhs host clock */
    CLOCK_EnableClock(kCLOCK_UsbhsHost);
}

/*! @brief Disable USB HS host clock.
 *
 * This function disables USB HS host clock.
 */
void CLOCK_DisableUsbHs0HostClock(void)
{
    /* Disable usbhs host clock */
    CLOCK_DisableClock(kCLOCK_UsbhsHost);
}

/*! brief Enable USB hs0PhyPll clock.
 *
 * param src  USB HS clock source.
 * param freq The frequency specified by src.
 * retval true The clock is set successfully.
 * retval false The clock source is invalid to get proper USB HS clock.
 */
bool CLOCK_EnableUsbHs0PhyPllClock(clock_attach_id_t src, uint32_t freq)
{
    uint32_t phyPllDiv  = 0U;
    uint16_t multiplier = 0U;
    bool retVal         = true;

    if (((uint32_t)(CLKCTL0->USBHSFCLKSEL & CLKCTL0_USBHSFCLKSEL_SEL_MASK)) != CLKCTL0_USBHSFCLKSEL_SEL(src))
    {
        retVal = false;
    }

    if ((480000000U % freq) != 0U)
    {
        retVal = false;
    }

    multiplier = (uint16_t)(480000000U / freq);

    switch (multiplier)
    {
        case 13U:
        {
            phyPllDiv = USBPHY_PLL_SIC_PLL_DIV_SEL(0U);
            break;
        }
        case 15U:
        {
            phyPllDiv = USBPHY_PLL_SIC_PLL_DIV_SEL(1U);
            break;
        }
        case 16U:
        {
            phyPllDiv = USBPHY_PLL_SIC_PLL_DIV_SEL(2U);
            break;
        }
        case 20U:
        {
            phyPllDiv = USBPHY_PLL_SIC_PLL_DIV_SEL(3U);
            break;
        }
        case 22U:
        {
            phyPllDiv = USBPHY_PLL_SIC_PLL_DIV_SEL(4U);
            break;
        }
        case 25U:
        {
            phyPllDiv = USBPHY_PLL_SIC_PLL_DIV_SEL(5U);
            break;
        }
        case 30U:
        {
            phyPllDiv = USBPHY_PLL_SIC_PLL_DIV_SEL(6U);
            break;
        }
        case 240U:
        {
            phyPllDiv = USBPHY_PLL_SIC_PLL_DIV_SEL(7U);
            break;
        }
        default:
        {
            retVal = false;
            break;
        }
    }

    if (retVal)
    {
        /* enable usb phy clock */
        CLOCK_EnableClock(kCLOCK_UsbhsPhy);
        USBPHY->CTRL_CLR = USBPHY_CTRL_SFTRST_MASK;
        USBPHY->CTRL_CLR = USBPHY_CTRL_CLR_CLKGATE_MASK;

        /* This field controls the USB PLL regulator, set to enable the regulator. SW
        must set this bit 15 us before setting PLL_POWER to avoid glitches on PLL
        output clock. */
        USBPHY->PLL_SIC_SET = USBPHY_PLL_SIC_PLL_REG_ENABLE_MASK;
        uint32_t i          = 5000U;
        while ((i--) != 0U)
        {
            __NOP();
        }

        USBPHY->PLL_SIC_SET = USBPHY_PLL_SIC_PLL_POWER(1);
        while ((USBPHY->PLL_SIC & USBPHY_PLL_SIC_PLL_POWER_MASK) == 0U)
        {
            USBPHY->PLL_SIC_SET = USBPHY_PLL_SIC_PLL_POWER(1);
        }

        while ((USBPHY->PLL_SIC & USBPHY_PLL_SIC_PLL_LOCK_MASK) == 0U)
        {
        }

        USBPHY->PLL_SIC     = (USBPHY->PLL_SIC & ~(USBPHY_PLL_SIC_PLL_DIV_SEL_MASK)) | phyPllDiv;
        USBPHY->PLL_SIC_CLR = USBPHY_PLL_SIC_PLL_BYPASS_MASK;
        while ((USBPHY->PLL_SIC & USBPHY_PLL_SIC_PLL_BYPASS_MASK) != 0U)
        {
            USBPHY->PLL_SIC_CLR = USBPHY_PLL_SIC_PLL_BYPASS_MASK;
        }

        USBPHY->PLL_SIC_SET = USBPHY_PLL_SIC_PLL_ENABLE(1);
        USBPHY->PLL_SIC_SET = USBPHY_PLL_SIC_SET_PLL_EN_USB_CLKS(1);
        while ((USBPHY->PLL_SIC & (USBPHY_PLL_SIC_PLL_ENABLE(1) | USBPHY_PLL_SIC_SET_PLL_EN_USB_CLKS(1))) !=
               (USBPHY_PLL_SIC_PLL_ENABLE(1) | USBPHY_PLL_SIC_SET_PLL_EN_USB_CLKS(1)))
        {
            USBPHY->PLL_SIC_SET = USBPHY_PLL_SIC_PLL_ENABLE(1) | USBPHY_PLL_SIC_SET_PLL_EN_USB_CLKS(1);
        }

        USBPHY->PWD = 0x0;
    }

    return retVal;
}

/*! @brief Disable USB hs0PhyPll clock.
 *
 * This function disables USB hs0PhyPll clock.
 */
void CLOCK_DisableUsbHs0PhyPllClock(void)
{
    USBPHY->CTRL |= USBPHY_CTRL_CLKGATE_MASK;          /* Set to 1U to gate clocks */
    USBPHY->PLL_SIC &= ~USBPHY_PLL_SIC_PLL_POWER_MASK; /* Power down PLL */
}
