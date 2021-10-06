/*
** ###################################################################
**     Version:             rev. 4.0, 2020-05-18
**     Build:               b210526
**
**     Abstract:
**         Chip specific module features.
**
**     Copyright 2016 Freescale Semiconductor, Inc.
**     Copyright 2016-2021 NXP
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
**
** ###################################################################
*/

#ifndef _MIMXRT595S_cm33_FEATURES_H_
#define _MIMXRT595S_cm33_FEATURES_H_

/* SOC module features */

/* @brief ACMP availability on the SoC. */
#define FSL_FEATURE_SOC_ACMP_COUNT (1)
/* @brief AIPS availability on the SoC. */
#define FSL_FEATURE_SOC_AIPS_COUNT (2)
/* @brief CACHE64_CTRL availability on the SoC. */
#define FSL_FEATURE_SOC_CACHE64_CTRL_COUNT (2)
/* @brief CACHE64_POLSEL availability on the SoC. */
#define FSL_FEATURE_SOC_CACHE64_POLSEL_COUNT (2)
/* @brief CASPER availability on the SoC. */
#define FSL_FEATURE_SOC_CASPER_COUNT (1)
/* @brief CLKCTL0 availability on the SoC. */
#define FSL_FEATURE_SOC_CLKCTL0_COUNT (1)
/* @brief CLKCTL1 availability on the SoC. */
#define FSL_FEATURE_SOC_CLKCTL1_COUNT (1)
/* @brief CRC availability on the SoC. */
#define FSL_FEATURE_SOC_CRC_COUNT (1)
/* @brief CTIMER availability on the SoC. */
#define FSL_FEATURE_SOC_CTIMER_COUNT (5)
/* @brief DMA availability on the SoC. */
#define FSL_FEATURE_SOC_DMA_COUNT (2)
/* @brief DMIC availability on the SoC. */
#define FSL_FEATURE_SOC_DMIC_COUNT (1)
/* @brief FLEXCOMM availability on the SoC. */
#define FSL_FEATURE_SOC_FLEXCOMM_COUNT (17)
/* @brief FLEXIO availability on the SoC. */
#define FSL_FEATURE_SOC_FLEXIO_COUNT (1)
/* @brief FLEXSPI availability on the SoC. */
#define FSL_FEATURE_SOC_FLEXSPI_COUNT (2)
/* @brief FREQME availability on the SoC. */
#define FSL_FEATURE_SOC_FREQME_COUNT (1)
/* @brief GPIO availability on the SoC. */
#define FSL_FEATURE_SOC_GPIO_COUNT (1)
/* @brief SECGPIO availability on the SoC. */
#define FSL_FEATURE_SOC_SECGPIO_COUNT (1)
/* @brief HASHCRYPT availability on the SoC. */
#define FSL_FEATURE_SOC_HASHCRYPT_COUNT (1)
/* @brief I2C availability on the SoC. */
#define FSL_FEATURE_SOC_I2C_COUNT (15)
/* @brief I3C availability on the SoC. */
#define FSL_FEATURE_SOC_I3C_COUNT (2)
/* @brief I2S availability on the SoC. */
#define FSL_FEATURE_SOC_I2S_COUNT (14)
/* @brief INPUTMUX availability on the SoC. */
#define FSL_FEATURE_SOC_INPUTMUX_COUNT (1)
/* @brief IOPCTL availability on the SoC. */
#define FSL_FEATURE_SOC_IOPCTL_COUNT (1)
/* @brief LCDIF availability on the SoC. */
#define FSL_FEATURE_SOC_LCDIF_COUNT (1)
/* @brief LPADC availability on the SoC. */
#define FSL_FEATURE_SOC_LPADC_COUNT (1)
/* @brief MIPI_DSI_HOST availability on the SoC. */
#define FSL_FEATURE_SOC_MIPI_DSI_HOST_COUNT (1)
/* @brief MRT availability on the SoC. */
#define FSL_FEATURE_SOC_MRT_COUNT (1)
/* @brief MU availability on the SoC. */
#define FSL_FEATURE_SOC_MU_COUNT (1)
/* @brief OCOTP availability on the SoC. */
#define FSL_FEATURE_SOC_OCOTP_COUNT (1)
/* @brief OSTIMER availability on the SoC. */
#define FSL_FEATURE_SOC_OSTIMER_COUNT (1)
/* @brief OTFAD availability on the SoC. */
#define FSL_FEATURE_SOC_OTFAD_COUNT (1)
/* @brief PINT availability on the SoC. */
#define FSL_FEATURE_SOC_PINT_COUNT (1)
/* @brief PMC availability on the SoC. */
#define FSL_FEATURE_SOC_PMC_COUNT (1)
/* @brief POWERQUAD availability on the SoC. */
#define FSL_FEATURE_SOC_POWERQUAD_COUNT (1)
/* @brief PUF availability on the SoC. */
#define FSL_FEATURE_SOC_PUF_COUNT (1)
/* @brief RSTCTL0 availability on the SoC. */
#define FSL_FEATURE_SOC_RSTCTL0_COUNT (1)
/* @brief RSTCTL1 availability on the SoC. */
#define FSL_FEATURE_SOC_RSTCTL1_COUNT (1)
/* @brief RTC availability on the SoC. */
#define FSL_FEATURE_SOC_RTC_COUNT (1)
/* @brief SCT availability on the SoC. */
#define FSL_FEATURE_SOC_SCT_COUNT (1)
/* @brief SEMA42 availability on the SoC. */
#define FSL_FEATURE_SOC_SEMA42_COUNT (1)
/* @brief SMARTDMA availability on the SoC. */
#define FSL_FEATURE_SOC_SMARTDMA_COUNT (1)
/* @brief SPI availability on the SoC. */
#define FSL_FEATURE_SOC_SPI_COUNT (16)
/* @brief SYSCTL0 availability on the SoC. */
#define FSL_FEATURE_SOC_SYSCTL0_COUNT (1)
/* @brief SYSCTL1 availability on the SoC. */
#define FSL_FEATURE_SOC_SYSCTL1_COUNT (1)
/* @brief TRNG availability on the SoC. */
#define FSL_FEATURE_SOC_TRNG_COUNT (1)
/* @brief USART availability on the SoC. */
#define FSL_FEATURE_SOC_USART_COUNT (14)
/* @brief USBHSD availability on the SoC. */
#define FSL_FEATURE_SOC_USBHSD_COUNT (1)
/* @brief USBHSDCD availability on the SoC. */
#define FSL_FEATURE_SOC_USBHSDCD_COUNT (1)
/* @brief USBHSH availability on the SoC. */
#define FSL_FEATURE_SOC_USBHSH_COUNT (1)
/* @brief USBPHY availability on the SoC. */
#define FSL_FEATURE_SOC_USBPHY_COUNT (1)
/* @brief USDHC availability on the SoC. */
#define FSL_FEATURE_SOC_USDHC_COUNT (2)
/* @brief UTICK availability on the SoC. */
#define FSL_FEATURE_SOC_UTICK_COUNT (1)
/* @brief WWDT availability on the SoC. */
#define FSL_FEATURE_SOC_WWDT_COUNT (2)

/* ACMP module features */

/* @brief Has CMP_C3. */
#define FSL_FEATURE_ACMP_HAS_C3_REG (1)
/* @brief Has C0 LINKEN Bit */
#define FSL_FEATURE_ACMP_HAS_C0_LINKEN_BIT (1)
/* @brief Has C0 OFFSET Bit */
#define FSL_FEATURE_ACMP_HAS_C0_OFFSET_BIT (0)
/* @brief Has C1 INPSEL Bit */
#define FSL_FEATURE_ACMP_HAS_C1_INPSEL_BIT (0)
/* @brief Has C1 INNSEL Bit */
#define FSL_FEATURE_ACMP_HAS_C1_INNSEL_BIT (0)
/* @brief Has C1 DACOE Bit */
#define FSL_FEATURE_ACMP_HAS_C1_DACOE_BIT (0)
/* @brief Has C1 DMODE Bit */
#define FSL_FEATURE_ACMP_HAS_C1_DMODE_BIT (1)
/* @brief Has C2 RRE Bit */
#define FSL_FEATURE_ACMP_HAS_C2_RRE_BIT (0)

/* LPADC module features */

/* @brief FIFO availability on the SoC. */
#define FSL_FEATURE_LPADC_FIFO_COUNT (2)
/* @brief Does not support two simultanious single ended conversions (bitfield TCTRL[FIFO_SEL_B]). */
#define FSL_FEATURE_LPADC_HAS_NO_TCTRL_FIFO_SEL_B (1)
/* @brief Has subsequent trigger priority (bitfield CFG[TPRICTRL]). */
#define FSL_FEATURE_LPADC_HAS_CFG_SUBSEQUENT_PRIORITY (1)
/* @brief Has differential mode (bitfield CMDLn[DIFF]). */
#define FSL_FEATURE_LPADC_HAS_CMDL_DIFF (1)
/* @brief Has channel scale (bitfield CMDLn[CSCALE]). */
#define FSL_FEATURE_LPADC_HAS_CMDL_CSCALE (1)
/* @brief Has conversion type select (bitfield CMDLn[CTYPE]). */
#define FSL_FEATURE_LPADC_HAS_CMDL_CTYPE (0)
/* @brief Has conversion resolution select  (bitfield CMDLn[MODE]). */
#define FSL_FEATURE_LPADC_HAS_CMDL_MODE (0)
/* @brief Has Wait for trigger assertion before execution (bitfield CMDHn[WAIT_TRIG]). */
#define FSL_FEATURE_LPADC_HAS_CMDH_WAIT_TRIG (1)
/* @brief Has offset calibration (bitfield CTRL[CALOFS]). */
#define FSL_FEATURE_LPADC_HAS_CTRL_CALOFS (0)
/* @brief Has gain calibration (bitfield CTRL[CAL_REQ]). */
#define FSL_FEATURE_LPADC_HAS_CTRL_CAL_REQ (0)
/* @brief Has calibration average (bitfield CTRL[CAL_AVGS]). */
#define FSL_FEATURE_LPADC_HAS_CTRL_CAL_AVGS (0)
/* @brief Has internal clock (bitfield CFG[ADCKEN]). */
#define FSL_FEATURE_LPADC_HAS_CFG_ADCKEN (0)
/* @brief Enable support for low voltage reference on option 1 reference (bitfield CFG[VREF1RNG]). */
#define FSL_FEATURE_LPADC_HAS_CFG_VREF1RNG (0)
/* @brief Has calibration (bitfield CFG[CALOFS]). */
#define FSL_FEATURE_LPADC_HAS_CFG_CALOFS (0)
/* @brief Has offset trim (register OFSTRIM). */
#define FSL_FEATURE_LPADC_HAS_OFSTRIM (0)

/* CACHE64_CTRL module features */

/* @brief Cache Line size in byte. */
#define FSL_FEATURE_CACHE64_CTRL_LINESIZE_BYTE (32)

/* CACHE64_POLSEL module features */

/* No feature definitions */

/* CASPER module features */

/* @brief Base address of the CASPER dedicated RAM. */
#define FSL_FEATURE_CASPER_RAM_BASE_ADDRESS (0x40202000u)

/* CRC module features */

/* @brief Has data register with name CRC */
#define FSL_FEATURE_CRC_HAS_CRC_REG (0)

/* DMA module features */

/* @brief Number of channels */
#define FSL_FEATURE_DMA_NUMBER_OF_CHANNELSn(x) (37)
/* @brief Number of all DMA channels */
#define FSL_FEATURE_DMA_ALL_CHANNELS (74)
/* @brief Max Number of DMA channels */
#define FSL_FEATURE_DMA_MAX_CHANNELS (37)
/* @brief Align size of DMA descriptor */
#define FSL_FEATURE_DMA_DESCRIPTOR_ALIGN_SIZE (1024)
/* @brief DMA head link descriptor table align size */
#define FSL_FEATURE_DMA_LINK_DESCRIPTOR_ALIGN_SIZE (16U)

/* DMIC module features */

/* @brief Number of channels */
#define FSL_FEATURE_DMIC_CHANNEL_NUM (8)
/* @brief DMIC channel support stereo data */
#define FSL_FEATURE_DMIC_IO_HAS_STEREO_2_4_6 (1)
/* @brief DMIC does not support bypass channel clock */
#define FSL_FEATURE_DMIC_IO_HAS_NO_BYPASS (1)
/* @brief DMIC channel FIFO register support sign extended */
#define FSL_FEATURE_DMIC_CHANNEL_HAS_SIGNEXTEND (1)
/* @brief DMIC has no IOCFG register */
#define FSL_FEATURE_DMIC_HAS_NO_IOCFG (1)
/* @brief DMIC has decimator reset function */
#define FSL_FEATURE_DMIC_HAS_DECIMATOR_RESET_FUNC (1)
/* @brief DMIC has global channel synchronization function */
#define FSL_FEATURE_DMIC_HAS_GLOBAL_SYNC_FUNC (1)

/* FLEXCOMM module features */

/* @brief FLEXCOMM0 USART INDEX 0 */
#define FSL_FEATURE_FLEXCOMM0_USART_INDEX  (0)
/* @brief FLEXCOMM0 SPI INDEX 0 */
#define FSL_FEATURE_FLEXCOMM0_SPI_INDEX  (0)
/* @brief FLEXCOMM0 I2C INDEX 0 */
#define FSL_FEATURE_FLEXCOMM0_I2C_INDEX  (0)
/* @brief FLEXCOMM0 I2S INDEX 0 */
#define FSL_FEATURE_FLEXCOMM0_I2S_INDEX  (0)
/* @brief FLEXCOMM1 USART INDEX 1 */
#define FSL_FEATURE_FLEXCOMM1_USART_INDEX  (1)
/* @brief FLEXCOMM1 SPI INDEX 1 */
#define FSL_FEATURE_FLEXCOMM1_SPI_INDEX  (1)
/* @brief FLEXCOMM1 I2C INDEX 1 */
#define FSL_FEATURE_FLEXCOMM1_I2C_INDEX  (1)
/* @brief FLEXCOMM1 I2S INDEX 1 */
#define FSL_FEATURE_FLEXCOMM1_I2S_INDEX  (1)
/* @brief FLEXCOMM2 USART INDEX 2 */
#define FSL_FEATURE_FLEXCOMM2_USART_INDEX  (2)
/* @brief FLEXCOMM2 SPI INDEX 2 */
#define FSL_FEATURE_FLEXCOMM2_SPI_INDEX  (2)
/* @brief FLEXCOMM2 I2C INDEX 2 */
#define FSL_FEATURE_FLEXCOMM2_I2C_INDEX  (2)
/* @brief FLEXCOMM2 I2S INDEX 2 */
#define FSL_FEATURE_FLEXCOMM2_I2S_INDEX  (2)
/* @brief FLEXCOMM3 USART INDEX 3 */
#define FSL_FEATURE_FLEXCOMM3_USART_INDEX  (3)
/* @brief FLEXCOMM3 SPI INDEX 3 */
#define FSL_FEATURE_FLEXCOMM3_SPI_INDEX  (3)
/* @brief FLEXCOMM3 I2C INDEX 3 */
#define FSL_FEATURE_FLEXCOMM3_I2C_INDEX  (3)
/* @brief FLEXCOMM3 I2S INDEX 3 */
#define FSL_FEATURE_FLEXCOMM3_I2S_INDEX  (3)
/* @brief FLEXCOMM4 USART INDEX 4 */
#define FSL_FEATURE_FLEXCOMM4_USART_INDEX  (4)
/* @brief FLEXCOMM4 SPI INDEX 4 */
#define FSL_FEATURE_FLEXCOMM4_SPI_INDEX  (4)
/* @brief FLEXCOMM4 I2C INDEX 4 */
#define FSL_FEATURE_FLEXCOMM4_I2C_INDEX  (4)
/* @brief FLEXCOMM4 I2S INDEX 4 */
#define FSL_FEATURE_FLEXCOMM4_I2S_INDEX  (4)
/* @brief FLEXCOMM5 USART INDEX 5 */
#define FSL_FEATURE_FLEXCOMM5_USART_INDEX  (5)
/* @brief FLEXCOMM5 SPI INDEX 5 */
#define FSL_FEATURE_FLEXCOMM5_SPI_INDEX  (5)
/* @brief FLEXCOMM5 I2C INDEX 5 */
#define FSL_FEATURE_FLEXCOMM5_I2C_INDEX  (5)
/* @brief FLEXCOMM5 I2S INDEX 5 */
#define FSL_FEATURE_FLEXCOMM5_I2S_INDEX  (5)
/* @brief FLEXCOMM6 USART INDEX 6 */
#define FSL_FEATURE_FLEXCOMM6_USART_INDEX  (6)
/* @brief FLEXCOMM6 SPI INDEX 6 */
#define FSL_FEATURE_FLEXCOMM6_SPI_INDEX  (6)
/* @brief FLEXCOMM6 I2C INDEX 6 */
#define FSL_FEATURE_FLEXCOMM6_I2C_INDEX  (6)
/* @brief FLEXCOMM6 I2S INDEX 6 */
#define FSL_FEATURE_FLEXCOMM6_I2S_INDEX  (6)
/* @brief FLEXCOMM7 USART INDEX 7 */
#define FSL_FEATURE_FLEXCOMM7_USART_INDEX  (7)
/* @brief FLEXCOMM7 SPI INDEX 7 */
#define FSL_FEATURE_FLEXCOMM7_SPI_INDEX  (7)
/* @brief FLEXCOMM7 I2C INDEX 7 */
#define FSL_FEATURE_FLEXCOMM7_I2C_INDEX  (7)
/* @brief FLEXCOMM7 I2S INDEX 7 */
#define FSL_FEATURE_FLEXCOMM7_I2S_INDEX  (7)
/* @brief I2S has DMIC interconnection */
#define FSL_FEATURE_FLEXCOMM_INSTANCE_I2S_HAS_DMIC_INTERCONNECTIONn(x) \
    (((x) == FLEXCOMM0) ? (1) : \
    (((x) == FLEXCOMM1) ? (0) : \
    (((x) == FLEXCOMM2) ? (0) : \
    (((x) == FLEXCOMM3) ? (0) : \
    (((x) == FLEXCOMM4) ? (0) : \
    (((x) == FLEXCOMM5) ? (0) : \
    (((x) == FLEXCOMM6) ? (0) : \
    (((x) == FLEXCOMM7) ? (0) : \
    (((x) == FLEXCOMM14) ? (0) : \
    (((x) == FLEXCOMM15) ? (0) : \
    (((x) == FLEXCOMM16) ? (0) : \
    (((x) == FLEXCOMM8) ? (0) : \
    (((x) == FLEXCOMM9) ? (0) : \
    (((x) == FLEXCOMM10) ? (0) : \
    (((x) == FLEXCOMM11) ? (0) : \
    (((x) == FLEXCOMM12) ? (0) : \
    (((x) == FLEXCOMM13) ? (0) : (-1))))))))))))))))))
/* @brief FLEXCOMM14 SPI(HS_SPI) INDEX 14 */
#define FSL_FEATURE_FLEXCOMM14_SPI_INDEX  (14)
/* @brief FLEXCOMM15 I2C INDEX 15 */
#define FSL_FEATURE_FLEXCOMM15_I2C_INDEX  (15)
/* @brief FLEXCOMM16 SPI(HS_SPI) INDEX 16 */
#define FSL_FEATURE_FLEXCOMM16_SPI_INDEX  (16)
/* @brief FLEXCOMM8 USART INDEX 8 */
#define FSL_FEATURE_FLEXCOMM8_USART_INDEX  (8)
/* @brief FLEXCOMM9 USART INDEX 9 */
#define FSL_FEATURE_FLEXCOMM9_USART_INDEX  (9)
/* @brief FLEXCOMM10 USART INDEX 10 */
#define FSL_FEATURE_FLEXCOMM10_USART_INDEX  (10)
/* @brief FLEXCOMM11 USART INDEX 11 */
#define FSL_FEATURE_FLEXCOMM11_USART_INDEX  (11)
/* @brief FLEXCOMM12 USART INDEX 12 */
#define FSL_FEATURE_FLEXCOMM12_USART_INDEX  (12)
/* @brief FLEXCOMM13 USART INDEX 13 */
#define FSL_FEATURE_FLEXCOMM13_USART_INDEX  (13)
/* @brief FLEXCOMM8 SPI INDEX 8 */
#define FSL_FEATURE_FLEXCOMM8_SPI_INDEX  (8)
/* @brief FLEXCOMM9 SPI INDEX 9 */
#define FSL_FEATURE_FLEXCOMM9_SPI_INDEX  (9)
/* @brief FLEXCOMM10 SPI INDEX 10 */
#define FSL_FEATURE_FLEXCOMM10_SPI_INDEX  (10)
/* @brief FLEXCOMM11 SPI INDEX 11 */
#define FSL_FEATURE_FLEXCOMM11_SPI_INDEX  (11)
/* @brief FLEXCOMM12 SPI INDEX 12 */
#define FSL_FEATURE_FLEXCOMM12_SPI_INDEX  (12)
/* @brief FLEXCOMM13 SPI INDEX 13 */
#define FSL_FEATURE_FLEXCOMM13_SPI_INDEX  (13)
/* @brief FLEXCOMM8 I2C INDEX 8 */
#define FSL_FEATURE_FLEXCOMM8_I2C_INDEX  (8)
/* @brief FLEXCOMM9 I2C INDEX 9 */
#define FSL_FEATURE_FLEXCOMM9_I2C_INDEX  (9)
/* @brief FLEXCOMM10 I2C INDEX 10 */
#define FSL_FEATURE_FLEXCOMM10_I2C_INDEX  (10)
/* @brief FLEXCOMM11 I2C INDEX 11 */
#define FSL_FEATURE_FLEXCOMM11_I2C_INDEX  (11)
/* @brief FLEXCOMM12 I2C INDEX 12 */
#define FSL_FEATURE_FLEXCOMM12_I2C_INDEX  (12)
/* @brief FLEXCOMM13 I2C INDEX 13 */
#define FSL_FEATURE_FLEXCOMM13_I2C_INDEX  (13)
/* @brief FLEXCOMM8 I2S INDEX 8 */
#define FSL_FEATURE_FLEXCOMM8_I2S_INDEX  (8)
/* @brief FLEXCOMM9 I2S INDEX 9 */
#define FSL_FEATURE_FLEXCOMM9_I2S_INDEX  (9)
/* @brief FLEXCOMM10 I2S INDEX 10 */
#define FSL_FEATURE_FLEXCOMM10_I2S_INDEX  (10)
/* @brief FLEXCOMM11 I2S INDEX 11 */
#define FSL_FEATURE_FLEXCOMM11_I2S_INDEX  (11)
/* @brief FLEXCOMM12 I2S INDEX 12 */
#define FSL_FEATURE_FLEXCOMM12_I2S_INDEX  (12)
/* @brief FLEXCOMM13 I2S INDEX 13 */
#define FSL_FEATURE_FLEXCOMM13_I2S_INDEX  (13)

/* FLEXIO module features */

/* @brief FLEXIO support reset from RSTCTL */
#define FSL_FEATURE_FLEXIO_HAS_RESET (1)
/* @brief Has Shifter Status Register (FLEXIO_SHIFTSTAT) */
#define FSL_FEATURE_FLEXIO_HAS_SHIFTER_STATUS (1)
/* @brief Has Pin Data Input Register (FLEXIO_PIN) */
#define FSL_FEATURE_FLEXIO_HAS_PIN_STATUS (1)
/* @brief Has Shifter Buffer N Nibble Byte Swapped Register (FLEXIO_SHIFTBUFNBSn) */
#define FSL_FEATURE_FLEXIO_HAS_SHFT_BUFFER_NIBBLE_BYTE_SWAP (1)
/* @brief Has Shifter Buffer N Half Word Swapped Register (FLEXIO_SHIFTBUFHWSn) */
#define FSL_FEATURE_FLEXIO_HAS_SHFT_BUFFER_HALF_WORD_SWAP (1)
/* @brief Has Shifter Buffer N Nibble Swapped Register (FLEXIO_SHIFTBUFNISn) */
#define FSL_FEATURE_FLEXIO_HAS_SHFT_BUFFER_NIBBLE_SWAP (1)
/* @brief Supports Shifter State Mode (FLEXIO_SHIFTCTLn[SMOD]) */
#define FSL_FEATURE_FLEXIO_HAS_STATE_MODE (1)
/* @brief Supports Shifter Logic Mode (FLEXIO_SHIFTCTLn[SMOD]) */
#define FSL_FEATURE_FLEXIO_HAS_LOGIC_MODE (1)
/* @brief Supports paralle width (FLEXIO_SHIFTCFGn[PWIDTH]) */
#define FSL_FEATURE_FLEXIO_HAS_PARALLEL_WIDTH (1)
/* @brief Reset value of the FLEXIO_VERID register */
#define FSL_FEATURE_FLEXIO_VERID_RESET_VALUE (0x2010003)
/* @brief Reset value of the FLEXIO_PARAM register */
#define FSL_FEATURE_FLEXIO_PARAM_RESET_VALUE (0x10100808)

/* FLEXSPI module features */

/* @brief FlexSPI AHB buffer count */
#define FSL_FEATURE_FLEXSPI_AHB_BUFFER_COUNTn(x) (8)
/* @brief FlexSPI0 and FlexSPI1 have shared IRQ */
#define FSL_FEATURE_FLEXSPI_HAS_SHARED_IRQ0_IRQ1 (1)
/* @brief FlexSPI has no MCR0 ARDFEN bit */
#define FSL_FEATURE_FLEXSPI_HAS_NO_MCR0_ARDFEN (1)
/* @brief FlexSPI has no MCR0 ATDFEN bit */
#define FSL_FEATURE_FLEXSPI_HAS_NO_MCR0_ATDFEN (1)
/* @brief FlexSPI DMA needs multiple DES to transfer */
#define FSL_FEATURE_FLEXSPI_DMA_MULTIPLE_DES (1)
/* @brief FlexSPI uses min DQS delay */
#define FSL_FEATURE_FLEXSPI_DQS_DELAY_MIN (1)
/* @brief FlexSPI has no MCR0 COMBINATIONEN bit */
#define FSL_FEATURE_FLEXSPI_HAS_NO_MCR0_COMBINATIONEN (1)

/* GPIO module features */

/* @brief GPIO has interrupts */
#define FSL_FEATURE_GPIO_HAS_INTERRUPT (1)

/* HASHCRYPT module features */

/* @brief hashcrypt has reload feature */
#define FSL_FEATURE_HASHCRYPT_HAS_RELOAD_FEATURE (1)

/* I2S module features */

/* @brief I2S support dual channel transfer. */
#define FSL_FEATURE_I2S_SUPPORT_SECONDARY_CHANNEL (1)
/* @brief I2S has DMIC interconnection. */
#define FSL_FEATURE_FLEXCOMM_I2S_HAS_DMIC_INTERCONNECTION  (1)

/* INPUTMUX module features */

/* @brief Number of channels */
#define FSL_FEATURE_INPUTMUX_HAS_SIGNAL_ENA (1)
/* @brief Inputmux has channel mux control */
#define FSL_FEATURE_INPUTMUX_HAS_CHANNEL_MUX (1)

/* MIPI_DSI_HOST module features */

/* @brief Does not have DPHY PLL */
#define FSL_FEATURE_MIPI_DSI_HOST_NO_DPHY_PLL (1)
/* @brief Support TX ULPS */
#define FSL_FEATURE_MIPI_DSI_HOST_HAS_ULPS (0)
/* @brief Has control register to enable or disable TX ULPS */
#define FSL_FEATURE_MIPI_DSI_HOST_HAS_ULPS_CTRL (0)
/* @brief Has pixel-link to DPI remap */
#define FSL_FEATURE_MIPI_DSI_HOST_HAS_PXL2DPI (0)

/* MRT module features */

/* @brief number of channels. */
#define FSL_FEATURE_MRT_NUMBER_OF_CHANNELS  (4)

/* MU module features */

/* @brief MU side for current core */
#define FSL_FEATURE_MU_SIDE_A (1)
/* @brief MU Has register CCR */
#define FSL_FEATURE_MU_HAS_CCR (0)
/* @brief MU Has register SR[RS], BSR[ARS] */
#define FSL_FEATURE_MU_HAS_SR_RS (1)
/* @brief MU Has register CR[RDIE], CR[RAIE], SR[RDIP], SR[RAIP] */
#define FSL_FEATURE_MU_HAS_RESET_INT (1)
/* @brief MU Has register SR[MURIP] */
#define FSL_FEATURE_MU_HAS_SR_MURIP (0)
/* @brief brief MU Has register SR[HRIP] */
#define FSL_FEATURE_MU_HAS_SR_HRIP (0)
/* @brief brief MU does not support enable clock of the other core, CR[CLKE] or CCR[CLKE]. */
#define FSL_FEATURE_MU_NO_CLKE (1)
/* @brief brief MU does not support NMI, CR[NMI]. */
#define FSL_FEATURE_MU_NO_NMI (1)
/* @brief brief MU does not support hold the other core reset. CR[RSTH] or CCR[RSTH]. */
#define FSL_FEATURE_MU_NO_RSTH (1)
/* @brief brief MU does not supports MU reset, CR[MUR]. */
#define FSL_FEATURE_MU_NO_MUR (0)
/* @brief brief MU does not supports hardware reset, CR[HR] or CCR[HR]. */
#define FSL_FEATURE_MU_NO_HR (1)
/* @brief brief MU supports mask the hardware reset. CR[HRM] or CCR[HRM]. */
#define FSL_FEATURE_MU_HAS_HRM (0)

/* OTFAD module features */

/* @brief OTFAD has Security Violation Mode (SVM) */
#define FSL_FEATURE_OTFAD_HAS_SVM_MODE (0)
/* @brief OTFAD has Key Blob Processing */
#define FSL_FEATURE_OTFAD_HAS_KEYBLOB_PROCESSING (0)
/* @brief OTFAD has interrupt request enable */
#define FSL_FEATURE_OTFAD_HAS_HAS_IRQ_ENABLE (0)
/* @brief OTFAD has Force Error */
#define FSL_FEATURE_OTFAD_HAS_FORCE_ERR (0)

/* PINT module features */

/* @brief Number of connected outputs */
#define FSL_FEATURE_PINT_NUMBER_OF_CONNECTED_OUTPUTS (8)

/* PMC module features */

/* @brief Has no OS Timer control register in PMC. */
#define FSL_FEATURE_PMC_HAS_NO_OSTIMER_REG (1)

/* PUF module features */

/* @brief PUF need to setup SRAM manually */
#define FSL_FEATURE_PUF_PWR_HAS_MANUAL_SLEEP_CONTROL (1)
/* @brief PUF has SHIFT_STATUS register. */
#define FSL_FEATURE_PUF_HAS_SHIFT_STATUS (0)
/* @brief PUF has IDXBLK_SHIFT register. */
#define FSL_FEATURE_PUF_HAS_IDXBLK_SHIFT (0)

/* RTC module features */

/* @brief RTC does not support reset from RSTCTL. */
#define FSL_FEATURE_RTC_HAS_NO_RESET (1)

/* SCT module features */

/* @brief Number of events */
#define FSL_FEATURE_SCT_NUMBER_OF_EVENTS (16)
/* @brief Number of states */
#define FSL_FEATURE_SCT_NUMBER_OF_STATES (32)
/* @brief Number of match capture */
#define FSL_FEATURE_SCT_NUMBER_OF_MATCH_CAPTURE (16)
/* @brief Number of outputs */
#define FSL_FEATURE_SCT_NUMBER_OF_OUTPUTS (10)

/* SECGPIO module features */

/* @brief GPIO has interrupts */
#define FSL_FEATURE_SECGPIO_HAS_INTERRUPT (1)

/* SEMA42 module features */

/* @brief Gate counts */
#define FSL_FEATURE_SEMA42_GATE_COUNT (16)

/* TRNG module features */

/* @brief Need configure default frequency minimum value */
#define FSL_FEATURE_TRNG_FORCE_USER_CONFIG_DEFAULT_FREQUENCY_MINIMUM (1)
/* @brief The user configured frequency minimum value */
#define FSL_FEATURE_TRNG_USER_CONFIG_DEFAULT_FREQUENCY_MINIMUM_VALUE (0)

/* USBHSD module features */

/* @brief Size of the USB dedicated RAM */
#define FSL_FEATURE_USBHSD_USB_RAM (0x00004000)
/* @brief Base address of the USB dedicated RAM */
#define FSL_FEATURE_USBHSD_USB_RAM_BASE_ADDRESS (0x40140000)
/* @brief USBHSD version */
#define FSL_FEATURE_USBHSD_VERSION (300)
/* @brief Number of the endpoint in USB HS */
#define FSL_FEATURE_USBHSD_EP_NUM (6)
/* @brief The controller doesn't exit HS mode automatically after vbus becomes invalid */
#define FSL_FEATURE_USBHSD_HAS_EXIT_HS_ISSUE (1)

/* USBHSH module features */

/* @brief Size of the USB dedicated RAM */
#define FSL_FEATURE_USBHSH_USB_RAM (0x00004000)
/* @brief Base address of the USB dedicated RAM */
#define FSL_FEATURE_USBHSH_USB_RAM_BASE_ADDRESS (0x40140000)
/* @brief USBHSH version */
#define FSL_FEATURE_USBHSH_VERSION (300)
/* @brief USBHSH has packet turnaround time-out register */
#define FSL_FEATURE_USBHSH_HAS_TURNAROUND_TIMEOUT (0)

/* USBPHY module features */

/* @brief USBPHY contain DCD analog module */
#define FSL_FEATURE_USBPHY_HAS_DCD_ANALOG (1)
/* @brief USBPHY has register TRIM_OVERRIDE_EN */
#define FSL_FEATURE_USBPHY_HAS_TRIM_OVERRIDE_EN (1)
/* @brief USBPHY is 28FDSOI */
#define FSL_FEATURE_USBPHY_28FDSOI (0)

/* USDHC module features */

/* @brief Has external DMA support (VEND_SPEC[EXT_DMA_EN]) */
#define FSL_FEATURE_USDHC_HAS_EXT_DMA (0)
/* @brief Has HS400 mode (MIX_CTRL[HS400_MODE]) */
#define FSL_FEATURE_USDHC_HAS_HS400_MODE (1)
/* @brief Has SDR50 support (HOST_CTRL_CAP[SDR50_SUPPORT]) */
#define FSL_FEATURE_USDHC_HAS_SDR50_MODE (1)
/* @brief Has SDR104 support (HOST_CTRL_CAP[SDR104_SUPPORT]) */
#define FSL_FEATURE_USDHC_HAS_SDR104_MODE (1)
/* @brief USDHC has reset control */
#define FSL_FEATURE_USDHC_HAS_RESET (1)
/* @brief USDHC has no bitfield WTMK_LVL[WR_BRST_LEN] and WTMK_LVL[RD_BRST_LEN] */
#define FSL_FEATURE_USDHC_HAS_NO_RW_BURST_LEN (0)
/* @brief If USDHC instance support 8 bit width */
#define FSL_FEATURE_USDHC_INSTANCE_SUPPORT_8_BIT_WIDTHn(x) (1)
/* @brief If USDHC instance support HS400 mode */
#define FSL_FEATURE_USDHC_INSTANCE_SUPPORT_HS400_MODEn(x) \
    (((x) == USDHC0) ? (1) : \
    (((x) == USDHC1) ? (0) : (-1)))
/* @brief If USDHC instance support 1v8 signal */
#define FSL_FEATURE_USDHC_INSTANCE_SUPPORT_1V8_SIGNALn(x) (1)
/* @brief Has no retuning time counter (HOST_CTRL_CAP[TIME_COUNT_RETURNING]) */
#define FSL_FEATURE_USDHC_REGISTER_HOST_CTRL_CAP_HAS_NO_RETUNING_TIME_COUNTER (0)

/* UTICK module features */

/* @brief UTICK does not support power down configure. */
#define FSL_FEATURE_UTICK_HAS_NO_PDCFG (1)

/* WWDT module features */

/* @brief WWDT does not support oscillator lock. */
#define FSL_FEATURE_WWDT_HAS_NO_OSCILLATOR_LOCK (0)
/* @brief WWDT does not support power down configure. */
#define FSL_FEATURE_WWDT_HAS_NO_PDCFG (1)

#endif /* _MIMXRT595S_cm33_FEATURES_H_ */

