/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __FSL_IAP_H_
#define __FSL_IAP_H_

#include "fsl_common.h"
/*!
 * @addtogroup IAP_driver
 * @{
 */

/*! @file */

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*! @name Driver version */
/*@{*/
/*! @brief IAP driver version 2.1.2. */
#define FSL_IAP_DRIVER_VERSION (MAKE_VERSION(2, 1, 2))
/*@}*/

/*!
 * @addtogroup iap_flexspi_driver
 * @{
 */

/*! @brief FlexSPI LUT command */

#define NOR_CMD_INDEX_READ        0 /*!< 0 */
#define NOR_CMD_INDEX_READSTATUS  1 /*!< 1 */
#define NOR_CMD_INDEX_WRITEENABLE 2 /*!< 2 */
#define NOR_CMD_INDEX_ERASESECTOR 3 /*!< 3 */
#define NOR_CMD_INDEX_PAGEPROGRAM 4 /*!< 4 */
#define NOR_CMD_INDEX_CHIPERASE   5 /*!< 5 */
#define NOR_CMD_INDEX_DUMMY       6 /*!< 6 */
#define NOR_CMD_INDEX_ERASEBLOCK  7 /*!< 7 */

#define NOR_CMD_LUT_SEQ_IDX_READ       0 /*!< 0  READ LUT sequence id in lookupTable stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_READSTATUS 1 /*!< 1  Read Status LUT sequence id in lookupTable stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_READSTATUS_XPI \
    2 /*!< 2  Read status DPI/QPI/OPI sequence id in lookupTable stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_WRITEENABLE 3 /*!< 3  Write Enable sequence id in lookupTable stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_WRITEENABLE_XPI \
    4 /*!< 4  Write Enable DPI/QPI/OPI sequence id in lookupTable stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_ERASESECTOR 5  /*!< 5  Erase Sector sequence id in lookupTable stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_ERASEBLOCK  8  /*!< 8 Erase Block sequence id in lookupTable stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_PAGEPROGRAM 9  /*!< 9  Program sequence id in lookupTable stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_CHIPERASE   11 /*!< 11 Chip Erase sequence in lookupTable id stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_READ_SFDP   13 /*!< 13 Read SFDP sequence in lookupTable id stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_RESTORE_NOCMD \
    14 /*!< 14 Restore 0-4-4/0-8-8 mode sequence id in lookupTable stored in config block */
#define NOR_CMD_LUT_SEQ_IDX_EXIT_NOCMD \
    15 /*!< 15 Exit 0-4-4/0-8-8 mode sequence id in lookupTable stored in config blobk */

/*!
 * @name FlexSPI status.
 * @{
 */
/*! @brief FlexSPI Driver status group. */
enum
{
    kStatusGroup_FlexSPI    = 60,
    kStatusGroup_FlexSPINOR = 201,
};

/*! @brief FlexSPI Driver status. */
enum _flexspi_status
{
    kStatus_FLEXSPI_Success         = MAKE_STATUS(kStatusGroup_Generic, 0), /*!< API is executed successfully*/
    kStatus_FLEXSPI_Fail            = MAKE_STATUS(kStatusGroup_Generic, 1), /*!< API is executed fails*/
    kStatus_FLEXSPI_InvalidArgument = MAKE_STATUS(kStatusGroup_Generic, 4), /*!< Invalid argument*/
    kStatus_FLEXSPI_SequenceExecutionTimeout =
        MAKE_STATUS(kStatusGroup_FlexSPI, 0), /*!< The FlexSPI Sequence Execution timeout*/
    kStatus_FLEXSPI_InvalidSequence = MAKE_STATUS(kStatusGroup_FlexSPI, 1), /*!< The FlexSPI LUT sequence invalid*/
    kStatus_FLEXSPI_DeviceTimeout   = MAKE_STATUS(kStatusGroup_FlexSPI, 2), /*!< The FlexSPI device timeout*/
    kStatus_FLEXSPINOR_ProgramFail =
        MAKE_STATUS(kStatusGroup_FlexSPINOR, 0), /*!< Status for Page programming failure */
    kStatus_FLEXSPINOR_EraseSectorFail =
        MAKE_STATUS(kStatusGroup_FlexSPINOR, 1),                               /*!< Status for Sector Erase failure */
    kStatus_FLEXSPINOR_EraseAllFail = MAKE_STATUS(kStatusGroup_FlexSPINOR, 2), /*!< Status for Chip Erase failure */
    kStatus_FLEXSPINOR_WaitTimeout  = MAKE_STATUS(kStatusGroup_FlexSPINOR, 3), /*!< Status for timeout */
    kStatus_FLEXSPINOR_NotSupported = MAKE_STATUS(kStatusGroup_FlexSPINOR, 4), /*  Status for PageSize overflow */
    kStatus_FLEXSPINOR_WriteAlignmentError =
        MAKE_STATUS(kStatusGroup_FlexSPINOR, 5), /*!< Status for Alignement error */
    kStatus_FLEXSPINOR_CommandFailure =
        MAKE_STATUS(kStatusGroup_FlexSPINOR, 6), /*!< Status for Erase/Program Verify Error */
    kStatus_FLEXSPINOR_SFDP_NotFound = MAKE_STATUS(kStatusGroup_FlexSPINOR, 7), /*!< Status for SFDP read failure */
    kStatus_FLEXSPINOR_Unsupported_SFDP_Version =
        MAKE_STATUS(kStatusGroup_FlexSPINOR, 8), /*!< Status for Unrecognized SFDP version */
    kStatus_FLEXSPINOR_Flash_NotFound =
        MAKE_STATUS(kStatusGroup_FlexSPINOR, 9), /*!< Status for Flash detection failure */
    kStatus_FLEXSPINOR_DTRRead_DummyProbeFailed =
        MAKE_STATUS(kStatusGroup_FlexSPINOR, 10), /*!< Status for DDR Read dummy probe failure */
};
/*! @} */

/*! @brief Flash Configuration Option0 device_type. */
enum
{
    kSerialNorCfgOption_Tag                         = 0x0c,
    kSerialNorCfgOption_DeviceType_ReadSFDP_SDR     = 0,
    kSerialNorCfgOption_DeviceType_ReadSFDP_DDR     = 1,
    kSerialNorCfgOption_DeviceType_HyperFLASH1V8    = 2,
    kSerialNorCfgOption_DeviceType_HyperFLASH3V0    = 3,
    kSerialNorCfgOption_DeviceType_MacronixOctalDDR = 4,
    kSerialNorCfgOption_DeviceType_MacronixOctalSDR = 5, /* For RT600 devcies only. */
    kSerialNorCfgOption_DeviceType_MicronOctalDDR   = 6,
    kSerialNorCfgOption_DeviceType_MicronOctalSDR   = 7, /* For RT600 devcies only. */
    kSerialNorCfgOption_DeviceType_AdestoOctalDDR   = 8,
    kSerialNorCfgOption_DeviceType_AdestoOctalSDR   = 9, /* For RT600 devcies only. */
};

/*! @brief Flash Configuration Option0 quad_mode_setting. */
enum
{
    kSerialNorQuadMode_NotConfig            = 0,
    kSerialNorQuadMode_StatusReg1_Bit6      = 1,
    kSerialNorQuadMode_StatusReg2_Bit1      = 2,
    kSerialNorQuadMode_StatusReg2_Bit7      = 3,
    kSerialNorQuadMode_StatusReg2_Bit1_0x31 = 4,
};

/*! @brief Flash Configuration Option0 misc_mode. */
enum
{
    kSerialNorEnhanceMode_Disabled         = 0,
    kSerialNorEnhanceMode_0_4_4_Mode       = 1,
    kSerialNorEnhanceMode_0_8_8_Mode       = 2,
    kSerialNorEnhanceMode_DataOrderSwapped = 3,
    kSerialNorEnhanceMode_2ndPinMux        = 4,
};

/*! @brief FLEXSPI_RESET_PIN boot configurations in OTP */
enum
{
    kFlashResetLogic_Disabled     = 0,
    kFlashResetLogic_ResetPin     = 1,
    kFlashResetLogic_JedecHwReset = 2,
};

/*! @brief Flash Configuration Option1 flash_connection. */
enum
{
    kSerialNorConnection_SinglePortA,
    kSerialNorConnection_Parallel,
    kSerialNorConnection_SinglePortB,
    kSerialNorConnection_BothPorts
};

/*! @brief Serial NOR Configuration Option */
typedef struct _serial_nor_config_option
{
    union
    {
        struct
        {
            uint32_t max_freq : 4;          /*!< Maximum supported Frequency */
            uint32_t misc_mode : 4;         /*!< miscellaneous mode */
            uint32_t quad_mode_setting : 4; /*!< Quad mode setting */
            uint32_t cmd_pads : 4;          /*!< Command pads */
            uint32_t query_pads : 4;        /*!< SFDP read pads */
            uint32_t device_type : 4;       /*!< Device type */
            uint32_t option_size : 4;       /*!< Option size, in terms of uint32_t, size = (option_size + 1) * 4 */
            uint32_t tag : 4;               /*!< Tag, must be 0x0E */
        } B;
        uint32_t U;
    } option0;

    union
    {
        struct
        {
            uint32_t dummy_cycles : 8;     /*!< Dummy cycles before read */
            uint32_t status_override : 8;  /*!< Override status register value during device mode configuration */
            uint32_t pinmux_group : 4;     /*!< The pinmux group selection */
            uint32_t dqs_pinmux_group : 4; /*!< The DQS Pinmux Group Selection */
            uint32_t drive_strength : 4;   /*!< The Drive Strength of FlexSPI Pads */
            uint32_t flash_connection : 4; /*!< Flash connection option: 0 - Single Flash connected to port A, 1 - */
            /*! Parallel mode, 2 - Single Flash connected to Port B */
        } B;
        uint32_t U;
    } option1;

} serial_nor_config_option_t;

/*! @brief Flash Run Context */
typedef union
{
    struct
    {
        uint8_t por_mode;
        uint8_t current_mode;
        uint8_t exit_no_cmd_sequence;
        uint8_t restore_sequence;
    } B;
    uint32_t U;
} flash_run_context_t;

/*!@brief Flash Device Mode Configuration Sequence */
enum
{
    kRestoreSequence_None           = 0,
    kRestoreSequence_HW_Reset       = 1,
    kRestoreSequence_4QPI_FF        = 2,
    kRestoreSequence_5QPI_FF        = 3,
    kRestoreSequence_8QPI_FF        = 4,
    kRestoreSequence_Send_F0        = 5,
    kRestoreSequence_Send_66_99     = 6,
    kRestoreSequence_Send_6699_9966 = 7,
    kRestoreSequence_Send_06_FF     = 8, /*  Adesto EcoXIP */
};

/*!@brief Flash Config Mode Definition */
enum
{
    kFlashInstMode_ExtendedSpi = 0x00,
    kFlashInstMode_0_4_4_SDR   = 0x01,
    kFlashInstMode_0_4_4_DDR   = 0x02,
    kFlashInstMode_QPI_SDR     = 0x41,
    kFlashInstMode_QPI_DDR     = 0x42,
    kFlashInstMode_OPI_SDR     = 0x81, /* For RT600 devices only. */
    kFlashInstMode_OPI_DDR     = 0x82,
};

/*!@brief Flash Device Type Definition */
enum
{
    kFlexSpiDeviceType_SerialNOR    = 1,    /*!< Flash devices are Serial NOR */
    kFlexSpiDeviceType_SerialNAND   = 2,    /*!< Flash devices are Serial NAND */
    kFlexSpiDeviceType_SerialRAM    = 3,    /*!< Flash devices are Serial RAM/HyperFLASH */
    kFlexSpiDeviceType_MCP_NOR_NAND = 0x12, /*!< Flash device is MCP device, A1 is Serial NOR, A2 is Serial NAND */
    kFlexSpiDeviceType_MCP_NOR_RAM  = 0x13, /*!< Flash deivce is MCP device, A1 is Serial NOR, A2 is Serial RAMs */
};

/*!@brief Flash Pad Definitions */
enum
{
    kSerialFlash_1Pad  = 1,
    kSerialFlash_2Pads = 2,
    kSerialFlash_4Pads = 4,
    kSerialFlash_8Pads = 8,
};

/*!@brief FlexSPI LUT Sequence structure */
typedef struct _lut_sequence
{
    uint8_t seqNum; /*!< Sequence Number, valid number: 1-16 */
    uint8_t seqId;  /*!< Sequence Index, valid number: 0-15 */
    uint16_t reserved;
} flexspi_lut_seq_t;

/*!@brief Flash Configuration Command Type */
enum
{
    kDeviceConfigCmdType_Generic,    /*!< Generic command, for example: configure dummy cycles, drive strength, etc */
    kDeviceConfigCmdType_QuadEnable, /*!< Quad Enable command */
    kDeviceConfigCmdType_Spi2Xpi,    /*!< Switch from SPI to DPI/QPI/OPI mode */
    kDeviceConfigCmdType_Xpi2Spi,    /*!< Switch from DPI/QPI/OPI to SPI mode */
    kDeviceConfigCmdType_Spi2NoCmd,  /*!< Switch to 0-4-4/0-8-8 mode */
    kDeviceConfigCmdType_Reset,      /*!< Reset device command */
};

/*!@brief FlexSPI Dll Time Block */
typedef struct
{
    uint8_t time_100ps;  /* Data valid time, in terms of 100ps */
    uint8_t delay_cells; /* Data valid time, in terms of delay cells */
} flexspi_dll_time_t;

/*!@brief FlexSPI Memory Configuration Block */
typedef struct _FlexSPIConfig
{
    uint32_t tag;       /*!< [0x000-0x003] Tag, fixed value 0x42464346UL */
    uint32_t version;   /*!< [0x004-0x007] Version,[31:24] -'V', [23:16] - Major, [15:8] - Minor, [7:0] - bugfix */
    uint32_t reserved0; /*!< [0x008-0x00b] Reserved for future use */
    uint8_t readSampleClkSrc;   /*!< [0x00c-0x00c] Read Sample Clock Source, valid value: 0/1/3 */
    uint8_t csHoldTime;         /*!< [0x00d-0x00d] CS hold time, default value: 3 */
    uint8_t csSetupTime;        /*!< [0x00e-0x00e] CS setup time, default value: 3 */
    uint8_t columnAddressWidth; /*!< [0x00f-0x00f] Column Address with, for HyperBus protocol, it is fixed to 3, For */
    /*! Serial NAND, need to refer to datasheet */
    uint8_t deviceModeCfgEnable; /*!< [0x010-0x010] Device Mode Configure enable flag, 1 - Enable, 0 - Disable */
    uint8_t
        deviceModeType; /*!< [0x011-0x011] Specify the configuration command type:Quad Enable, DPI/QPI/OPI switch, */
    /*! Generic configuration, etc. */
    uint16_t waitTimeCfgCommands; /*!< [0x012-0x013] Wait time for all configuration commands, unit: 100us, Used for */
    /*! DPI/QPI/OPI switch or reset command */
    flexspi_lut_seq_t
        deviceModeSeq; /*!< [0x014-0x017] Device mode sequence info, [7:0] - LUT sequence id, [15:8] - LUt */
    /*! sequence number, [31:16] Reserved */
    uint32_t deviceModeArg;    /*!< [0x018-0x01b] Argument/Parameter for device configuration */
    uint8_t configCmdEnable;   /*!< [0x01c-0x01c] Configure command Enable Flag, 1 - Enable, 0 - Disable */
    uint8_t configModeType[3]; /*!< [0x01d-0x01f] Configure Mode Type, similar as deviceModeTpe */
    flexspi_lut_seq_t
        configCmdSeqs[3]; /*!< [0x020-0x02b] Sequence info for Device Configuration command, similar as deviceModeSeq */
    uint32_t reserved1;   /*!< [0x02c-0x02f] Reserved for future use */
    uint32_t configCmdArgs[3]; /*!< [0x030-0x03b] Arguments/Parameters for device Configuration commands */
    uint32_t reserved2;        /*!< [0x03c-0x03f] Reserved for future use */
    uint32_t
        controllerMiscOption; /*!< [0x040-0x043] Controller Misc Options, see Misc feature bit definitions for more */
    /*! details */
    uint8_t deviceType;    /*!< [0x044-0x044] Device Type:  See Flash Type Definition for more details */
    uint8_t sflashPadType; /*!< [0x045-0x045] Serial Flash Pad Type: 1 - Single, 2 - Dual, 4 - Quad, 8 - Octal */
    uint8_t serialClkFreq; /*!< [0x046-0x046] Serial Flash Frequencey, device specific definitions, See System Boot */
    /*! Chapter for more details */
    uint8_t
        lutCustomSeqEnable; /*!< [0x047-0x047] LUT customization Enable, it is required if the program/erase cannot */
    /*! be done using 1 LUT sequence, currently, only applicable to HyperFLASH */
    uint32_t reserved3[2];               /*!< [0x048-0x04f] Reserved for future use */
    uint32_t sflashA1Size;               /*!< [0x050-0x053] Size of Flash connected to A1 */
    uint32_t sflashA2Size;               /*!< [0x054-0x057] Size of Flash connected to A2 */
    uint32_t sflashB1Size;               /*!< [0x058-0x05b] Size of Flash connected to B1 */
    uint32_t sflashB2Size;               /*!< [0x05c-0x05f] Size of Flash connected to B2 */
    uint32_t csPadSettingOverride;       /*!< [0x060-0x063] CS pad setting override value */
    uint32_t sclkPadSettingOverride;     /*!< [0x064-0x067] SCK pad setting override value */
    uint32_t dataPadSettingOverride;     /*!< [0x068-0x06b] data pad setting override value */
    uint32_t dqsPadSettingOverride;      /*!< [0x06c-0x06f] DQS pad setting override value */
    uint32_t timeoutInMs;                /*!< [0x070-0x073] Timeout threshold for read status command */
    uint32_t commandInterval;            /*!< [0x074-0x077] CS deselect interval between two commands */
    flexspi_dll_time_t dataValidTime[2]; /*!< [0x078-0x07b] CLK edge to data valid time for PORT A and PORT B */
    uint16_t busyOffset;                 /*!< [0x07c-0x07d] Busy offset, valid value: 0-31 */
    uint16_t
        busyBitPolarity; /*!< [0x07e-0x07f] Busy flag polarity, 0 - busy flag is 1 when flash device is busy, 1 - */
    /*! busy flag is 0 when flash device is busy */
    uint32_t lookupTable[64];           /*!< [0x080-0x17f] Lookup table holds Flash command sequences */
    flexspi_lut_seq_t lutCustomSeq[12]; /*!< [0x180-0x1af] Customizable LUT Sequences */
    uint32_t reserved4[4];              /*!< [0x1b0-0x1bf] Reserved for future use */
} flexspi_mem_config_block_t;

/*!@brief FlexSPI Operation Type */
typedef enum _FlexSPIOperationType
{
    kFlexSpiOperation_Command = 0, /*!< FlexSPI operation: Only command, both TX and */
    /*! RX buffer are ignored. */
    kFlexSpiOperation_Config = 1, /*!< FlexSPI operation: Configure device mode, the */
    /*! TX FIFO size is fixed in LUT. */
    kFlexSpiOperation_Write = 2, /*!< FlexSPI operation: Write,  only TX buffer is */
    /*! effective */
    kFlexSpiOperation_Read = 3, /*!< FlexSPI operation: Read, only Rx Buffer is */
    /*! effective. */
    kFlexSpiOperation_End = kFlexSpiOperation_Read,
} flexspi_operation_t;

/*!@brief FlexSPI Transfer Context */
typedef struct _FlexSpiXfer
{
    flexspi_operation_t operation; /*!< FlexSPI operation */
    uint32_t baseAddress;          /*!< FlexSPI operation base address */
    uint32_t seqId;                /*!< Sequence Id */
    uint32_t seqNum;               /*!< Sequence Number */
    bool isParallelModeEnable;     /*!< Is a parallel transfer */
    uint32_t *txBuffer;            /*!< Tx buffer */
    uint32_t txSize;               /*!< Tx size in bytes */
    uint32_t *rxBuffer;            /*!< Rx buffer */
    uint32_t rxSize;               /*!< Rx size in bytes */
} flexspi_xfer_t;

/*!@brief Serial NOR configuration block */
typedef struct _flexspi_nor_config
{
    flexspi_mem_config_block_t memConfig; /*!< Common memory configuration info via FlexSPI */
    uint32_t pageSize;                    /*!< Page size of Serial NOR */
    uint32_t sectorSize;                  /*!< Sector size of Serial NOR */
    uint8_t ipcmdSerialClkFreq;           /*!< Clock frequency for IP command */
    uint8_t isUniformBlockSize;           /*!< Sector/Block size is the same */
    uint8_t isDataOrderSwapped;           /*!< Data order (D0, D1, D2, D3) is swapped (D1,D0, D3, D2) */
    uint8_t reserved0[1];                 /*!< Reserved for future use */
    uint8_t serialNorType;                /*!< Serial NOR Flash type: 0/1/2/3 */
    uint8_t needExitNoCmdMode;            /*!< Need to exit NoCmd mode before other IP command */
    uint8_t halfClkForNonReadCmd;         /*!< Half the Serial Clock for non-read command: true/false */
    uint8_t needRestoreNoCmdMode;         /*!< Need to Restore NoCmd mode after IP commmand execution */
    uint32_t blockSize;                   /*!< Block size */
    uint32_t flashStateCtx;               /*!< Flash State Context */
    uint32_t reserve2[10];                /*!< Reserved for future use */
} flexspi_nor_config_t;
/*! @} */

/*!
 * @addtogroup iap_otp_driver
 * @{
 */

/*! @brief OTP Status Group */
enum
{
    kStatusGroup_OtpGroup = 0x210,
};

/*! @brief OTP Error Status definitions */
enum
{
    kStatus_OTP_InvalidAddress = MAKE_STATUS(kStatusGroup_OtpGroup, 1), /*!< Invalid OTP address */
    kStatus_OTP_ProgramFail    = MAKE_STATUS(kStatusGroup_OtpGroup, 2), /*!< Program Fail */
    kStatus_OTP_CrcFail        = MAKE_STATUS(kStatusGroup_OtpGroup, 3), /*!< CrcCheck Fail */
    kStatus_OTP_Error          = MAKE_STATUS(kStatusGroup_OtpGroup, 4), /*!< Errors happened during OTP operation */
    kStatus_OTP_EccCheckFail   = MAKE_STATUS(kStatusGroup_OtpGroup, 5), /*!< Ecc Check failed during OTP operation */
    kStatus_OTP_Locked         = MAKE_STATUS(kStatusGroup_OtpGroup, 6), /*!< OTP Fuse field has been locked */
    kStatus_OTP_Timeout        = MAKE_STATUS(kStatusGroup_OtpGroup, 7), /*!< OTP operation time out */
    kStatus_OTP_CrcCheckPass   = MAKE_STATUS(kStatusGroup_OtpGroup, 8), /*!< OTP CRC Check Pass */
};
/*! @} */

/*!
 * @addtogroup iap_boot_driver
 * @{
 */

/*! @brief IAP boot option. */
typedef struct _iap_boot_option
{
    union
    {
        struct
        {
            uint32_t reserved : 8;       /*! reserved field. */
            uint32_t bootImageIndex : 4; /*! FlexSPI boot image index for FlexSPI NOR flash. */
            uint32_t instance : 4;       /*! Only used when boot interface is FlexSPI/SD/MMC. */
            uint32_t bootInterface : 4;  /*! RT500: 0: USART 2: SPI 3: USB HID 4:FlexSPI 6:SD 7:MMC.
                                             RT600: 0: USART 1: I2C 2: SPI 3: USB HID 4:FlexSPI 7:SD 8:MMC*/
            uint32_t mode : 4;           /* boot mode, 0: Master boot mode; 1: ISP boot */
            uint32_t tag : 8;            /*! tag, should always be "0xEB". */
        } B;
        uint32_t U;
    } option;
} iap_boot_option_t;

/*! IAP boot option tag */
#define IAP_BOOT_OPTION_TAG (0xEBU)
/*! IAP boot option mode */
#define IAP_BOOT_OPTION_MODE_MASTER (0U)
#define IAP_BOOT_OPTION_MODE_ISP    (1U)

/*! @} */

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @addtogroup iap_boot_driver
 * @{
 */

/*!
 * @brief Invoke into ROM with specified boot parameters.
 *
 * @param option Boot parameters. Refer to #iap_boot_option_t.
 */
void IAP_RunBootLoader(iap_boot_option_t *option);
/*! @} */

/*!
 * @addtogroup iap_flexspi_driver
 * @{
 */

/*!
 * @brief Initialize Serial NOR devices via FlexSPI.
 *
 * This function configures the FlexSPI controller with the arguments pointed by param config.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param config The Flash configuration block. Refer to #flexspi_nor_config_t.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
#if defined(DOXYGEN_OUTPUT) && DOXYGEN_OUTPUT
status_t IAP_FlexspiNorInit(uint32_t instance, flexspi_nor_config_t *config);
#else
AT_QUICKACCESS_SECTION_CODE(status_t IAP_FlexspiNorInit(uint32_t instance, flexspi_nor_config_t *config));
#endif

/*!
 * @brief Program data to Serial NOR via FlexSPI.
 *
 * This function Program data to specified destination address.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param config The Flash configuration block. Refer to #flexspi_nor_config_t.
 * @param dstAddr The destination address to be programmed.
 * @param src Points to the buffer which hold the data to be programmed.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiNorPageProgram(uint32_t instance,
                                   flexspi_nor_config_t *config,
                                   uint32_t dstAddr,
                                   const uint32_t *src);

/*!
 * @brief Erase all the Serial NOR devices connected on FlexSPI.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param config The Flash configuration block. Refer to #flexspi_nor_config_t.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiNorEraseAll(uint32_t instance, flexspi_nor_config_t *config);

/*!
 * @brief Erase Flash Region specified by address and length.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param config The Flash configuration block. Refer to #flexspi_nor_config_t.
 * @param start The start address to be erased.
 * @param length The length to be erased.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiNorErase(uint32_t instance, flexspi_nor_config_t *config, uint32_t start, uint32_t length);

/*!
 * @brief Erase one sector specified by address.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param config The Flash configuration block. Refer to #flexspi_nor_config_t.
 * @param address The address of the sector to be erased.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiNorEraseSector(uint32_t instance, flexspi_nor_config_t *config, uint32_t address);

/*!
 * @brief Erase one block specified by address.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param config The Flash configuration block. Refer to #flexspi_nor_config_t.
 * @param address The address of the block to be erased.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiNorEraseBlock(uint32_t instance, flexspi_nor_config_t *config, uint32_t address);

/*!
 * @brief Get FlexSPI NOR Configuration Block based on specified option.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param config The Flash configuration block. Refer to #flexspi_nor_config_t.
 * @param option The Flash Configuration Option block. Refer to #serial_nor_config_option_t.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiNorGetConfig(uint32_t instance, flexspi_nor_config_t *config, serial_nor_config_option_t *option);

/*!
 * @brief Read data from Flexspi NOR Flash.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param config The Flash configuration block. Refer to #flexspi_nor_config_t.
 * @param dst Buffer address used to store the read data.
 * @param start The Read address.
 * @param bytes The Read size
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiNorRead(
    uint32_t instance, flexspi_nor_config_t *config, uint32_t *dst, uint32_t start, uint32_t bytes);

/*!
 * @brief Get FlexSPI Xfer data.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param xfer The FlexSPI Transfer Context block. Refer to #flexspi_xfer_t.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiXfer(uint32_t instance, flexspi_xfer_t *xfer);

/*!
 * @brief Update FlexSPI Lookup table.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param seqIndex The index of FlexSPI LUT to be updated.
 * @param lutBase Points to the buffer which hold the LUT data to be programmed.
 * @param numberOfSeq The number of LUT seq that need to be updated.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiUpdateLut(uint32_t instance, uint32_t seqIndex, const uint32_t *lutBase, uint32_t numberOfSeq);

/*!
 * @brief Set the clock source for FlexSPI.
 *
 * @param clockSrc Clock source for flexspi interface.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
status_t IAP_FlexspiSetClockSource(uint32_t clockSrc);

/*!
 * @brief Configure the flexspi interface clock frequency and data sample mode.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param freqOption FlexSPI interface clock frequency selection.
 * @param sampleClkMode FlexSPI controller data sample mode.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
void IAP_FlexspiConfigClock(uint32_t instance, uint32_t freqOption, uint32_t sampleClkMode);

/*!
 * @brief Configure flexspi nor automatically.
 *
 * @param instance FlexSPI controller instance, only support 0.
 * @param config The Flash configuration block. Refer to #flexspi_nor_config_t.
 * @param option The Flash Configuration Option block. Refer to #serial_nor_config_option_t.
 * @return The status flags. This is a member of the
 *         enumeration ::_flexspi_status
 */
#if defined(DOXYGEN_OUTPUT) && DOXYGEN_OUTPUT
status_t IAP_FlexspiNorAutoConfig(uint32_t instance, flexspi_nor_config_t *config, serial_nor_config_option_t *option);
#else
AT_QUICKACCESS_SECTION_CODE(status_t IAP_FlexspiNorAutoConfig(uint32_t instance,
                                                              flexspi_nor_config_t *config,
                                                              serial_nor_config_option_t *option));
#endif
/*! @} */

/*!
 * @addtogroup iap_otp_driver
 * @{
 */

/*!
 * @brief Initialize OTP controller
 *
 * This function enables OTP Controller clock.
 *
 * @param src_clk_freq The Frequency of the source clock of OTP controller
 * @return kStatus_Success
 */
status_t IAP_OtpInit(uint32_t src_clk_freq);

/*!
 * @brief De-Initialize OTP controller
 *
 * This functin disables OTP Controller Clock.
 * @return kStatus_Success
 */
status_t IAP_OtpDeinit(void);

/*!
 * @brief Read Fuse value from OTP Fuse Block
 *
 * This function read fuse data from OTP Fuse block to specified data buffer.
 *
 * @param addr Fuse address
 * @param data Buffer to hold the data read from OTP Fuse block
 * @return kStatus_Success - Data read from OTP Fuse block successfully
 *         kStatus_InvalidArgument - data pointer is invalid
 *         kStatus_OTP_EccCheckFail - Ecc Check Failed
 *         kStatus_OTP_Error - Other Errors
 */
status_t IAP_OtpFuseRead(uint32_t addr, uint32_t *data);

/*!
 * @brief Program value to OTP Fuse block
 *
 * This function program data to specified OTP Fuse address.
 *
 * @param addr Fuse address
 * @param data data to be programmed into OTP Fuse block
 * @param lock lock the fuse field or not
 * @return kStatus_Success - Data has been programmed into OTP Fuse block successfully
 *         kStatus_OTP_ProgramFail - Fuse programming failed
 *         kStatus_OTP_Locked - The address to be programmed into is locked
 *         kStatus_OTP_Error - Other Errors
 */
status_t IAP_OtpFuseProgram(uint32_t addr, uint32_t data, bool lock);

/*!
 * @brief Reload all shadow registers from OTP fuse block
 *
 * This function reloads all the shadow registers from OTP Fuse block
 *
 * @return kStatus_Success - Shadow registers' reloadding succeeded.
 *         kStatus_OTP_EccCheckFail - Ecc Check Failed
 *         kStatus_OTP_Error - Other Errors
 */
status_t IAP_OtpShadowRegisterReload(void);

/*!
 * @brief Do CRC Check via OTP controller
 *
 * This function checks whether data in specified fuse address ranges match the crc value in the specified CRC address
 *  and return the actual crc value as needed.
 *
 * @param start_addr Start address of selected Fuse address range
 * @param end_addr   End address of selected Fuse address range
 * @param crc_addr   Address that hold CRC data
 *
 * @return kStatus_Success CRC check succeeded, CRC value matched.
 *         kStatus_InvalidArgument - Invalid Argument
 *         kStatus_OTP_EccCheckFail Ecc Check Failed
 *         kStatus_OTP_CrcFail CRC Check Failed
 */
status_t IAP_OtpCrcCheck(uint32_t start_addr, uint32_t end_addr, uint32_t crc_addr);

/*!
 * @brief Calculate the CRC checksum for specified data for OTP
 *
 * This function calculates the CRC checksum for specified data for OTP
 *
 * @param src the source address of data
 * @param numberOfWords number of Fuse words
 * @param crcChecksum   Buffer to store the CRC checksum
 *
 * @return kStatus_Success CRC checksum is computed successfully.
 *         kStatus_InvalidArgument - Invalid Argument
 */
status_t IAP_OtpCrcCalc(uint32_t *src, uint32_t numberOfWords, uint32_t *crcChecksum);
/*! @} */
#if defined(__cplusplus)
}
#endif

/*! @}*/

#endif /* __FSL_IAP_H_ */
