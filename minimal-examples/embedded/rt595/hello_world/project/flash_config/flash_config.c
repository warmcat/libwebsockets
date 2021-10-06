/*
 * Copyright 2018-2019 NXP
 * All rights reserved.
 *
 * SPDXLicense-Identifier: BSD-3-Clause
 */
#include "flash_config.h"
#include "board.h"

/* Component ID definition, used by tools. */
#ifndef FSL_COMPONENT_ID
#define FSL_COMPONENT_ID "platform.drivers.flash_config"
#endif

/*******************************************************************************
 * Code
 ******************************************************************************/
#if defined(BOOT_HEADER_ENABLE) && (BOOT_HEADER_ENABLE == 1)
#if defined(__ARMCC_VERSION) || defined(__GNUC__)
__attribute__((section(".flash_conf"), used))
#elif defined(__ICCARM__)
#pragma location = ".flash_conf"
#endif

const flexspi_nor_config_t flash_config = {
    .memConfig =
        {
            .tag                 = FLEXSPI_CFG_BLK_TAG,
            .version             = FLEXSPI_CFG_BLK_VERSION,
            .readSampleClkSrc    = kFlexSPIReadSampleClk_ExternalInputFromDqsPad,
            .csHoldTime          = 3,
            .csSetupTime         = 3,
            .deviceModeCfgEnable = 1,
            .deviceModeType      = kDeviceConfigCmdType_Spi2Xpi,
            .waitTimeCfgCommands = 1,
            .deviceModeSeq =
                {
                    .seqNum   = 1,
                    .seqId    = 6, /* See Lookup table for more details */
                    .reserved = 0,
                },
            .deviceModeArg = 2, /* Enable OPI DDR mode */
            .controllerMiscOption =
                (1u << kFlexSpiMiscOffset_SafeConfigFreqEnable) | (1u << kFlexSpiMiscOffset_DdrModeEnable),
            .deviceType    = kFlexSpiDeviceType_SerialNOR,
            .sflashPadType = kSerialFlash_8Pads,
            .serialClkFreq = kFlexSpiSerialClk_80MHz,
            .sflashA1Size  = 64ul * 1024u * 1024u,
            .dataValidTime =
                {
                    [0] = {.time_100ps = 16},
                },
            .busyOffset      = 0u,
            .busyBitPolarity = 0u,
            .lookupTable =
                {
                    /* Read */
                    [0] = FLEXSPI_LUT_SEQ(CMD_DDR, FLEXSPI_8PAD, 0xEE, CMD_DDR, FLEXSPI_8PAD, 0x11),
                    [1] = FLEXSPI_LUT_SEQ(RADDR_DDR, FLEXSPI_8PAD, 0x20, DUMMY_DDR, FLEXSPI_8PAD, 0x04),
                    [2] = FLEXSPI_LUT_SEQ(READ_DDR, FLEXSPI_8PAD, 0x04, STOP_EXE, FLEXSPI_1PAD, 0x00),

                    /* Read Status */
                    [4 * 1 + 0] = FLEXSPI_LUT_SEQ(CMD_SDR, FLEXSPI_1PAD, 0x05, READ_SDR, FLEXSPI_1PAD, 0x04),

                    /* Write Enable */
                    [4 * 3 + 0] = FLEXSPI_LUT_SEQ(CMD_SDR, FLEXSPI_1PAD, 0x06, STOP_EXE, FLEXSPI_1PAD, 0x00),

                    /* Enable OPI DDR mode */
                    [4 * 6 + 0] = FLEXSPI_LUT_SEQ(CMD_SDR, FLEXSPI_1PAD, 0x72, CMD_SDR, FLEXSPI_1PAD, 0x00),
                    [4 * 6 + 1] = FLEXSPI_LUT_SEQ(CMD_SDR, FLEXSPI_1PAD, 0x00, CMD_SDR, FLEXSPI_1PAD, 0x00),
                    [4 * 6 + 2] = FLEXSPI_LUT_SEQ(CMD_SDR, FLEXSPI_1PAD, 0x00, WRITE_SDR, FLEXSPI_1PAD, 0x01),
                },
        },
    .pageSize      = 256u,
    .sectorSize    = 4u * 1024u,
    .blockSize     = 64u * 1024u,
    .flashStateCtx = 0x07008200u,
};
#endif /* BOOT_HEADER_ENABLE */
