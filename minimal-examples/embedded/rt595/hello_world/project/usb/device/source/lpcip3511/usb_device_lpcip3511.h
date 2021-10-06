/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_DEVICE_LPC3511IP_H__
#define __USB_DEVICE_LPC3511IP_H__

#include "fsl_device_registers.h"

/*!
 * @addtogroup usb_device_controller_lpcip3511_driver
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* For bulk out endpoint in high speed mode, use long length data transfer to decrease the Ping packet count to increase
 * bulk bandwidth */
/* The bigger this macro's value is, the higher bandwidth bulk out endpoint has. However, you need to set a reasonable
 * value for this macro based on RAM size of Soc. If this macro's value is too big, link may be failed. */
/* Note that please set this value as integral multiple of 512U. When using USB RAM, you also can decrease the
 * USB_DEVICE_IP3511_USB_RAM_IN_USE_SIZE within a reasonable range to use more USB RAM */
#if (((defined(USB_DEVICE_CONFIG_MSC)) && (USB_DEVICE_CONFIG_MSC > 0U)) && \
     ((defined(USB_DEVICE_CONFIG_LPCIP3511HS)) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U)))
#define USB_DEVICE_IP3511HS_BULK_OUT_ONE_TIME_TRANSFER_SIZE_MAX (0U)
#endif

/* During enumeration for high speed, IP3511HS responds NYET to the host(HUAWEI smartphone P20,  Kirin 970 platform) for
   OUT transaction in the status stage of control transfer. \ The host can not handle NYET respond in this case. Then
   this leads to enumeration failure. This workaround is used to fix this issue, which force the prime length is 65
   bytes. This workaround is disabled by default */
#if ((defined(USB_DEVICE_CONFIG_LPCIP3511HS)) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U))
#define USB_DEVICE_IP3511HS_CONTROL_OUT_NYET_WORKAROUND (0U)
#endif

/*! @brief Prime all the double endpoint buffer at the same time, if the transfer length is larger than max packet size.
 */
#define USB_DEVICE_IP3511_DOUBLE_BUFFER_ENABLE (1U)
#if ((defined(USB_DEVICE_CONFIG_LPCIP3511HS)) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U))
#define USB_LPC3511IP_Type              USBHSD_Type
#define USB_DEVICE_IP3511_ENDPOINTS_NUM FSL_FEATURE_USBHSD_EP_NUM
#define USB_DEVICE_IP3511_USB_RAM_SIZE  FSL_FEATURE_USBHSD_USB_RAM
#else
#define USB_LPC3511IP_Type              USB_Type
#define USB_DEVICE_IP3511_ENDPOINTS_NUM FSL_FEATURE_USB_EP_NUM
#if ((defined(FSL_FEATURE_USB_USB_RAM)) && (FSL_FEATURE_USB_USB_RAM > 0U))
#define USB_DEVICE_IP3511_USB_RAM_SIZE FSL_FEATURE_USB_USB_RAM
#endif
#endif

/*! @brief Use the macro to represent the USB RAM that has been used. The remaining USB RAM will be used by the
     controller driver. If application needs to allocate variables into the USB RAM, please increase the macro or link
     may fail. Likewise, if requiring to assign more USB RAM to the controller driver, please decrease the macro.
     When USB_DEVICE_IP3511HS_BULK_OUT_ONE_TIME_TRANSFER_SIZE_MAX is used, USB_DEVICE_IP3511_USB_RAM_IN_USE_SIZE can be
   decreased within a reasonable range to use more USB RAM. */
#define USB_DEVICE_IP3511_USB_RAM_IN_USE_SIZE (3U * 1024U)
/*! @brief The reserved buffer size, the buffer is for the memory copy if the application transfer buffer is
     ((not 64 bytes alignment) || (not in the USB RAM) || (HS && OUT && not multiple of the maximum packet size)) */
#if ((defined(USB_DEVICE_IP3511_USB_RAM_SIZE)) && (USB_DEVICE_IP3511_USB_RAM_SIZE > 0U))
#define USB_DEVICE_IP3511_ENDPOINT_RESERVED_BUFFER_SIZE \
    ((uint32_t)USB_DEVICE_IP3511_USB_RAM_SIZE - USB_DEVICE_IP3511_USB_RAM_IN_USE_SIZE)
#else
#if ((defined(USB_DEVICE_IP3511HS_BULK_OUT_ONE_TIME_TRANSFER_SIZE_MAX)) && \
     (USB_DEVICE_IP3511HS_BULK_OUT_ONE_TIME_TRANSFER_SIZE_MAX > 0U))
/* if use USB_DEVICE_IP3511HS_BULK_OUT_ONE_TIME_TRANSFER_SIZE_MAX (>0U), need to increase the reserved buffer size */
#define USB_DEVICE_IP3511_ENDPOINT_RESERVED_BUFFER_SIZE \
    ((5U * 1024U) + (USB_DEVICE_IP3511HS_BULK_OUT_ONE_TIME_TRANSFER_SIZE_MAX / 512U) * 512U)
#else
#define USB_DEVICE_IP3511_ENDPOINT_RESERVED_BUFFER_SIZE (5U * 1024U)
#endif
#endif

/*! @brief Use one bit to represent one reserved 64 bytes to allocate the buffer by uint of 64 bytes. */
#define USB_DEVICE_IP3511_BITS_FOR_RESERVED_BUFFER ((USB_DEVICE_IP3511_ENDPOINT_RESERVED_BUFFER_SIZE + 63U) / 64U)
/*! @brief How many IPs support the reserved buffer */
#define USB_DEVICE_IP3511_RESERVED_BUFFER_FOR_COPY (USB_DEVICE_CONFIG_LPCIP3511FS + USB_DEVICE_CONFIG_LPCIP3511HS)

/* for out endpoint,only use buffer toggle, disable prime double buffer at the same time*/
/*host send data less than maxpacket size and in endpoint prime length more more than maxpacketsize, there will be state
 * mismtach*/
#if USB_DEVICE_IP3511_DOUBLE_BUFFER_ENABLE
#define USB_DEVICE_IP3511_DISABLE_OUT_DOUBLE_BUFFER (1U)
#else
#define USB_DEVICE_IP3511_DISABLE_OUT_DOUBLE_BUFFER (0U)
#endif

#define USB_DEVICE_IP3511HS_LPM_ADPPROBE_ATTACH_DEBOUNCE_COUNT (3)

/* if FSL_FEATURE_USBHSD_HAS_EXIT_HS_ISSUE is true:
 * Enable this macro to exit HS mode automatically if the user case is:
 *   host and device keep cable connected, and host turn off vbus to simulate detachment.
 * If user disconnects the cable, there is no issue and don't need enable this macro.
 * There is one delay in the isr if enable this macro.
 */
#define USB_DEVICE_IP3511HS_FORCE_EXIT_HS_MODE_ENABLE (0u)

/*! @brief Endpoint state structure */
typedef struct _usb_device_lpc3511ip_endpoint_state_struct
{
    uint8_t *transferBuffer;       /*!< Address of buffer containing the data to be transmitted */
    uint32_t transferLength;       /*!< Length of data to transmit. */
    uint32_t transferDone;         /*!< The data length has been transferred*/
    uint32_t transferPrimedLength; /*!< it may larger than transferLength, because the primed length may larger than the
                                      transaction length. */
    uint8_t *epPacketBuffer;       /*!< The max packet buffer for copying*/
    union
    {
        uint32_t state; /*!< The state of the endpoint */
        struct
        {
            uint32_t maxPacketSize : 11U; /*!< The maximum packet size of the endpoint */
            uint32_t stalled : 1U;        /*!< The endpoint is stalled or not */
            uint32_t transferring : 1U;   /*!< The endpoint is transferring */
            uint32_t zlt : 1U;            /*!< zlt flag */
            uint32_t stallPrimed : 1U;
            uint32_t epPacketCopyed : 1U;   /*!< whether use the copy buffer */
            uint32_t epControlDefault : 5u; /*!< The EP command/status 26~30 bits */
            uint32_t doubleBufferBusy : 2U; /*!< How many buffers are primed, for control endpoint it is not used */
            uint32_t producerOdd : 1U;      /*!< When priming one transaction, prime to this endpoint buffer */
            uint32_t consumerOdd : 1U;      /*!< When transaction is done, read result from this endpoint buffer */
            uint32_t endpointType : 2U;
#if (defined(USB_DEVICE_CONFIG_ROOT2_TEST) && (USB_DEVICE_CONFIG_ROOT2_TEST > 0U))
            uint32_t isOpened : 1U; /*!< whether the endpoint is initialized */
            uint32_t reserved1 : 4U;
#else
            uint32_t reserved1 : 5U;
#endif
        } stateBitField;
    } stateUnion;
    union
    {
        uint16_t epBufferStatus;
        /* If double buff is disable, only epBufferStatusUnion[0] is used;
           For control endpoint, only epBufferStatusUnion[0] is used. */
        struct
        {
            uint16_t transactionLength : 15U;
            uint16_t epPacketCopyed : 1U;
        } epBufferStatusField;
    } epBufferStatusUnion[2];
} usb_device_lpc3511ip_endpoint_state_struct_t;

/*! @brief LPC USB controller (IP3511) state structure */
typedef struct _usb_device_lpc3511ip_state_struct
{
    /*!< control data buffer, must align with 64 */
    uint8_t *controlData;
    /*!< 8 bytes' setup data, must align with 64 */
    uint8_t *setupData;
    /*!< 4 bytes for zero length transaction, must align with 64 */
    uint8_t *zeroTransactionData;
    /* Endpoint state structures */
    usb_device_lpc3511ip_endpoint_state_struct_t endpointState[(USB_DEVICE_IP3511_ENDPOINTS_NUM * 2)];
    usb_device_handle deviceHandle;   /*!< (4 bytes) Device handle used to identify the device object belongs to */
    USB_LPC3511IP_Type *registerBase; /*!< (4 bytes) ip base address */
    volatile uint32_t *epCommandStatusList; /* endpoint list */
#if (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U)) && \
    (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U))
    void *dcdHandle; /*!< Dcd handle used to identify the device object belongs to */
#endif
    uint8_t controllerId; /*!< Controller ID */
    uint8_t isResetting;  /*!< Is doing device reset or not */
    uint8_t deviceSpeed;  /*!< some controller support the HS */
#if ((defined(USB_DEVICE_CONFIG_LPCIP3511HS)) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U))
    uint8_t controllerSpeed;
#endif
#if (defined(USB_DEVICE_CONFIG_DETACH_ENABLE) && (USB_DEVICE_CONFIG_DETACH_ENABLE))
    uint8_t deviceState; /*!< Is device attached,1 attached,0 detached */
#endif
#if (defined(USB_DEVICE_CONFIG_LOW_POWER_MODE) && (USB_DEVICE_CONFIG_LOW_POWER_MODE > 0U))
#if (defined(USB_DEVICE_CONFIG_LPM_L1) && (USB_DEVICE_CONFIG_LPM_L1 > 0U))
    uint8_t lpmRemoteWakeUp;
#endif
#endif
#if ((defined(USB_DEVICE_CONFIG_LPCIP3511HS)) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U))
#if (defined(FSL_FEATURE_USBHSD_INTERRUPT_DATAX_ISSUE_VERSION_CHECK) && \
     (FSL_FEATURE_USBHSD_INTERRUPT_DATAX_ISSUE_VERSION_CHECK))
    uint8_t hsInterruptIssue;
#endif
#endif
} usb_device_lpc3511ip_state_struct_t;

/*!
 * @name USB device controller (IP3511) functions
 * @{
 */

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief Initializes the USB device controller instance.
 *
 * This function initializes the USB device controller module specified by the controllerId.
 *
 * @param[in] controllerId      The controller ID of the USB IP. See the enumeration type usb_controller_index_t.
 * @param[in] handle            Pointer of the device handle used to identify the device object belongs to.
 * @param[out] controllerHandle An out parameter used to return the pointer of the device controller handle to the
 * caller.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceLpc3511IpInit(uint8_t controllerId,
                                     usb_device_handle handle,
                                     usb_device_controller_handle *controllerHandle);

/*!
 * @brief Deinitializes the USB device controller instance.
 *
 * This function deinitializes the USB device controller module.
 *
 * @param[in] controllerHandle   Pointer of the device controller handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceLpc3511IpDeinit(usb_device_controller_handle controllerHandle);

/*!
 * @brief Sends data through a specified endpoint.
 *
 * This function sends data through a specified endpoint.
 *
 * @param[in] controllerHandle Pointer of the device controller handle.
 * @param[in] endpointAddress  Endpoint index.
 * @param[in] buffer           The memory address to hold the data need to be sent.
 * @param[in] length           The data length need to be sent.
 *
 * @return A USB error code or kStatus_USB_Success.
 *
 * @note The return value indicates whether the sending request is successful or not. The transfer completion is
 * notified by the
 * corresponding callback function.
 * Currently, only one transfer request can be supported for a specific endpoint.
 * If there is a specific requirement to support multiple transfer requests for a specific endpoint, the application
 * should implement a queue in the application level.
 * The subsequent transfer can begin only when the previous transfer is done (a notification is obtained through the
 * endpoint
 * callback).
 */
usb_status_t USB_DeviceLpc3511IpSend(usb_device_controller_handle controllerHandle,
                                     uint8_t endpointAddress,
                                     uint8_t *buffer,
                                     uint32_t length);

/*!
 * @brief Receives data through a specified endpoint.
 *
 * This function receives data through a specified endpoint.
 *
 * @param[in] controllerHandle Pointer of the device controller handle.
 * @param[in] endpointAddress  Endpoint index.
 * @param[in] buffer           The memory address to save the received data.
 * @param[in] length           The data length to be received.
 *
 * @return A USB error code or kStatus_USB_Success.
 *
 * @note The return value indicates whether the receiving request is successful or not. The transfer completion is
 * notified by the
 * corresponding callback function.
 * Currently, only one transfer request can be supported for a specific endpoint.
 * If there is a specific requirement to support multiple transfer requests for a specific endpoint, the application
 * should implement a queue in the application level.
 * The subsequent transfer can begin only when the previous transfer is done (a notification is obtained through the
 * endpoint
 * callback).
 */
usb_status_t USB_DeviceLpc3511IpRecv(usb_device_controller_handle controllerHandle,
                                     uint8_t endpointAddress,
                                     uint8_t *buffer,
                                     uint32_t length);

/*!
 * @brief Cancels the pending transfer in a specified endpoint.
 *
 * The function is used to cancel the pending transfer in a specified endpoint.
 *
 * @param[in] controllerHandle  ointer of the device controller handle.
 * @param[in] ep                Endpoint address, bit7 is the direction of endpoint, 1U - IN, abd 0U - OUT.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceLpc3511IpCancel(usb_device_controller_handle controllerHandle, uint8_t ep);

/*!
 * @brief Controls the status of the selected item.
 *
 * The function is used to control the status of the selected item.
 *
 * @param[in] controllerHandle      Pointer of the device controller handle.
 * @param[in] type             The selected item. Please refer to enumeration type usb_device_control_type_t.
 * @param[in,out] param            The parameter type is determined by the selected item.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceLpc3511IpControl(usb_device_controller_handle controllerHandle,
                                        usb_device_control_type_t type,
                                        void *param);

/*! @} */

#if defined(__cplusplus)
}
#endif

/*! @} */

#endif /* __USB_DEVICE_LPC3511IP_H__ */
