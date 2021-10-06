/*
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_device_config.h"
#include "usb.h"

#include "usb_device.h"
#include "usb_device_dci.h"
#include "usb_device_class.h"
#include "usb_device_ch9.h"
#if ((defined(USB_DEVICE_CONFIG_NUM)) && (USB_DEVICE_CONFIG_NUM > 0U))
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*!
 * @brief Standard request callback function typedef.
 *
 * This function is used to handle the standard request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
typedef usb_status_t (*usb_standard_request_callback_t)(usb_device_common_class_struct_t *classHandle,
                                                        usb_setup_struct_t *setup,
                                                        uint8_t **buffer,
                                                        uint32_t *length);

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static usb_status_t USB_DeviceCh9GetStatus(usb_device_common_class_struct_t *classHandle,
                                           usb_setup_struct_t *setup,
                                           uint8_t **buffer,
                                           uint32_t *length);
static usb_status_t USB_DeviceCh9SetClearFeature(usb_device_common_class_struct_t *classHandle,
                                                 usb_setup_struct_t *setup,
                                                 uint8_t **buffer,
                                                 uint32_t *length);

static usb_status_t USB_DeviceCh9SetAddress(usb_device_common_class_struct_t *classHandle,
                                            usb_setup_struct_t *setup,
                                            uint8_t **buffer,
                                            uint32_t *length);
static usb_status_t USB_DeviceCh9GetDescriptor(usb_device_common_class_struct_t *classHandle,
                                               usb_setup_struct_t *setup,
                                               uint8_t **buffer,
                                               uint32_t *length);
static usb_status_t USB_DeviceCh9GetConfiguration(usb_device_common_class_struct_t *classHandle,
                                                  usb_setup_struct_t *setup,
                                                  uint8_t **buffer,
                                                  uint32_t *length);
static usb_status_t USB_DeviceCh9SetConfiguration(usb_device_common_class_struct_t *classHandle,
                                                  usb_setup_struct_t *setup,
                                                  uint8_t **buffer,
                                                  uint32_t *length);
static usb_status_t USB_DeviceCh9GetInterface(usb_device_common_class_struct_t *classHandle,
                                              usb_setup_struct_t *setup,
                                              uint8_t **buffer,
                                              uint32_t *length);
static usb_status_t USB_DeviceCh9SetInterface(usb_device_common_class_struct_t *classHandle,
                                              usb_setup_struct_t *setup,
                                              uint8_t **buffer,
                                              uint32_t *length);
static usb_status_t USB_DeviceCh9SynchFrame(usb_device_common_class_struct_t *classHandle,
                                            usb_setup_struct_t *setup,
                                            uint8_t **buffer,
                                            uint32_t *length);

/*******************************************************************************
 * Variables
 ******************************************************************************/

/* The function list to handle the standard request. */
static const usb_standard_request_callback_t s_UsbDeviceStandardRequest[] = {
    USB_DeviceCh9GetStatus,
    USB_DeviceCh9SetClearFeature,
    (usb_standard_request_callback_t)NULL,
    USB_DeviceCh9SetClearFeature,
    (usb_standard_request_callback_t)NULL,
    USB_DeviceCh9SetAddress,
    USB_DeviceCh9GetDescriptor,
    (usb_standard_request_callback_t)NULL,
    USB_DeviceCh9GetConfiguration,
    USB_DeviceCh9SetConfiguration,
    USB_DeviceCh9GetInterface,
    USB_DeviceCh9SetInterface,
    USB_DeviceCh9SynchFrame,
};

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief Handle get status request.
 *
 * This function is used to handle get status request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @retval kStatus_USB_Success              The request is handled successfully.
 * @retval kStatus_USB_InvalidRequest       The request can not be handle in current device state,
 *                                          or, the request is unsupported.
 */
static usb_status_t USB_DeviceCh9GetStatus(usb_device_common_class_struct_t *classHandle,
                                           usb_setup_struct_t *setup,
                                           uint8_t **buffer,
                                           uint32_t *length)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t state      = 0U;

    if (((setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) != USB_REQUEST_TYPE_DIR_IN) || (setup->wValue != 0U) ||
        (setup->wLength != 2U))
    {
        return error;
    }

    (void)USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);

    if (((uint8_t)kUSB_DeviceStateAddress != state) && ((uint8_t)kUSB_DeviceStateConfigured != state))
    {
        return error;
    }

    if ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_DEVICE)
    {
#if (defined(USB_DEVICE_CONFIG_OTG) && (USB_DEVICE_CONFIG_OTG))
        if (setup->wIndex == USB_REQUEST_STANDARD_GET_STATUS_OTG_STATUS_SELECTOR)
        {
            error =
                USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusOtg, &classHandle->standardTranscationBuffer);
            classHandle->standardTranscationBuffer = USB_SHORT_TO_LITTLE_ENDIAN(classHandle->standardTranscationBuffer);
            /* The device status length must be USB_DEVICE_STATUS_SIZE. */
            *length = 1;
        }
        else /* Get the device status */
        {
#endif
            error = USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDevice,
                                        &classHandle->standardTranscationBuffer);
            classHandle->standardTranscationBuffer =
                classHandle->standardTranscationBuffer & USB_GET_STATUS_DEVICE_MASK;
            classHandle->standardTranscationBuffer = USB_SHORT_TO_LITTLE_ENDIAN(classHandle->standardTranscationBuffer);
            /* The device status length must be USB_DEVICE_STATUS_SIZE. */
            *length = USB_DEVICE_STATUS_SIZE;
#if (defined(USB_DEVICE_CONFIG_OTG) && (USB_DEVICE_CONFIG_OTG))
        }
#endif
    }
    else if ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_INTERFACE)
    {
#if ((defined(USB_DEVICE_CONFIG_ROOT2_TEST)) && (USB_DEVICE_CONFIG_ROOT2_TEST > 0U))
        if (((uint8_t)kUSB_DeviceStateAddress == state) ||
            (((uint8_t)kUSB_DeviceStateConfigured == state) && (0U == setup->wIndex)))
        {
            /* In valid address state, device must stall the status stage for get status (interface) request.
               In configured state, device must stall the status stage for get status (interface 0) request */
            return error;
        }
#endif
        /* Get the interface status */
        error                                  = kStatus_USB_Success;
        classHandle->standardTranscationBuffer = 0U;
        /* The interface status length must be USB_INTERFACE_STATUS_SIZE. */
        *length = USB_INTERFACE_STATUS_SIZE;
    }
    else if ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_ENDPOINT)
    {
#if ((defined(USB_DEVICE_CONFIG_ROOT2_TEST)) && (USB_DEVICE_CONFIG_ROOT2_TEST > 0U))
        if ((USB_CONTROL_ENDPOINT != (setup->wIndex & USB_ENDPOINT_NUMBER_MASK)) &&
            ((uint8_t)kUSB_DeviceStateAddress == state))
        {
            /* In valid address, device must stall the status stage for get status (EP) request for no-control endpoint
             */
            return error;
        }
#endif
        /* Get the endpoint status */
        usb_device_endpoint_status_struct_t endpointStatus;
        endpointStatus.endpointAddress = (uint8_t)setup->wIndex;
        endpointStatus.endpointStatus  = (uint16_t)kUSB_DeviceEndpointStateIdle;
        error = USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusEndpoint, &endpointStatus);
        classHandle->standardTranscationBuffer = endpointStatus.endpointStatus & USB_GET_STATUS_ENDPOINT_MASK;
        classHandle->standardTranscationBuffer = USB_SHORT_TO_LITTLE_ENDIAN(classHandle->standardTranscationBuffer);
        /* The endpoint status length must be USB_INTERFACE_STATUS_SIZE. */
        *length = USB_ENDPOINT_STATUS_SIZE;
    }
    else
    {
        /*no action*/
    }
    *buffer = (uint8_t *)&classHandle->standardTranscationBuffer;

    return error;
}

/*!
 * @brief Handle set or clear device feature request.
 *
 * This function is used to handle set or clear device feature request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @retval kStatus_USB_Success              The request is handled successfully.
 * @retval kStatus_USB_InvalidRequest       The request can not be handle in current device state,
 *                                          or, the request is unsupported.
 */
static usb_status_t USB_DeviceCh9SetClearFeature(usb_device_common_class_struct_t *classHandle,
                                                 usb_setup_struct_t *setup,
                                                 uint8_t **buffer,
                                                 uint32_t *length)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t state      = 0U;
    uint8_t isSet      = 0U;

    if (((setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) != USB_REQUEST_TYPE_DIR_OUT) || (setup->wLength != 0U))
    {
        return error;
    }

    (void)USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);

    if (((uint8_t)kUSB_DeviceStateAddress != state) && ((uint8_t)kUSB_DeviceStateConfigured != state))
    {
        return error;
    }

    /* Identify the request is set or clear the feature. */
    if (USB_REQUEST_STANDARD_SET_FEATURE == setup->bRequest)
    {
        isSet = 1U;
    }

    if ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_DEVICE)
    {
        /* Set or Clear the device feature. */
        if (USB_REQUEST_STANDARD_FEATURE_SELECTOR_DEVICE_REMOTE_WAKEUP == setup->wValue)
        {
#if ((defined(USB_DEVICE_CONFIG_REMOTE_WAKEUP)) && (USB_DEVICE_CONFIG_REMOTE_WAKEUP > 0U))
            USB_DeviceSetStatus(classHandle->handle, kUSB_DeviceStatusRemoteWakeup, &isSet);
#endif
            /* Set or Clear the device remote wakeup feature. */
            error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventSetRemoteWakeup, &isSet);
        }
#if ((defined(USB_DEVICE_CONFIG_EHCI) && (USB_DEVICE_CONFIG_EHCI > 0U)) ||                \
     (defined(USB_DEVICE_CONFIG_LPCIP3511HS) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U))) && \
    (defined(USB_DEVICE_CONFIG_USB20_TEST_MODE) && (USB_DEVICE_CONFIG_USB20_TEST_MODE > 0U))
        else if (USB_REQUEST_STANDARD_FEATURE_SELECTOR_DEVICE_TEST_MODE == setup->wValue)
        {
            state = kUSB_DeviceStateTestMode;
            error = USB_DeviceSetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);
        }
#endif
#if (defined(USB_DEVICE_CONFIG_OTG) && (USB_DEVICE_CONFIG_OTG))
        else if (USB_REQUEST_STANDARD_FEATURE_SELECTOR_B_HNP_ENABLE == setup->wValue)
        {
            error = USB_DeviceClassCallback(classHandle->handle, kUSB_DeviceEventSetBHNPEnable, &isSet);
        }
#endif
        else
        {
        }
    }
    else if ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_ENDPOINT)
    {
        /* Set or Clear the endpoint feature. */
        if (USB_REQUEST_STANDARD_FEATURE_SELECTOR_ENDPOINT_HALT == setup->wValue)
        {
#if ((defined(USB_DEVICE_CONFIG_ROOT2_TEST)) && (USB_DEVICE_CONFIG_ROOT2_TEST > 0U))
            if ((USB_CONTROL_ENDPOINT != (setup->wIndex & USB_ENDPOINT_NUMBER_MASK)) &&
                (kUSB_DeviceStateConfigured != state))
            {
                /* In no-configured state, device must stall the status stage for clear/set feature halt requests for
                 * no-control endpoint */
                return error;
            }
            else
            {
                /* In configured state, device must stall the status stage for clear/set feature halt for no-initialized
                   EP. For contol EP, device must accept status stage of Set Feature Halt (Endpoint 80) in Addressed
                   State */
                usb_device_endpoint_status_struct_t endpointStatus;
                endpointStatus.endpointAddress = (uint8_t)setup->wIndex;
                error = USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusEndpoint, &endpointStatus);
                if (kStatus_USB_Success != error)
                {
                    return error;
                }
            }
#else
            if (USB_CONTROL_ENDPOINT == (setup->wIndex & USB_ENDPOINT_NUMBER_MASK))
            {
                /* Set or Clear the control endpoint status(halt or not). */
                if (0U != isSet)
                {
                    (void)USB_DeviceStallEndpoint(classHandle->handle, (uint8_t)setup->wIndex);
                }
                else
                {
                    (void)USB_DeviceUnstallEndpoint(classHandle->handle, (uint8_t)setup->wIndex);
                }
            }
#endif
            /* Set or Clear the endpoint status feature. */
            if (0U != isSet)
            {
                error = USB_DeviceClassEvent(classHandle->handle, kUSB_DeviceClassEventSetEndpointHalt, &setup->wIndex);
            }
            else
            {
                error =
                    USB_DeviceClassEvent(classHandle->handle, kUSB_DeviceClassEventClearEndpointHalt, &setup->wIndex);
            }
        }
        else
        {
            /*no action*/
        }
    }
    else
    {
        /*no action*/
    }

    return error;
}

/*!
 * @brief Handle set address request.
 *
 * This function is used to handle set address request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @retval kStatus_USB_Success              The request is handled successfully.
 * @retval kStatus_USB_InvalidRequest       The request can not be handle in current device state.
 */
static usb_status_t USB_DeviceCh9SetAddress(usb_device_common_class_struct_t *classHandle,
                                            usb_setup_struct_t *setup,
                                            uint8_t **buffer,
                                            uint32_t *length)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t state      = 0U;

    if (((setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) != USB_REQUEST_TYPE_DIR_OUT) ||
        ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) != USB_REQUEST_TYPE_RECIPIENT_DEVICE) ||
        (setup->wIndex != 0U) || (setup->wLength != 0U))
    {
        return error;
    }

    (void)USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);

    if (((uint8_t)kUSB_DeviceStateAddressing != state) && ((uint8_t)kUSB_DeviceStateAddress != state) &&
        ((uint8_t)kUSB_DeviceStateDefault != state)
#if ((defined(USB_DEVICE_CONFIG_ROOT2_TEST)) && (USB_DEVICE_CONFIG_ROOT2_TEST > 0U))
#else
        && ((uint8_t)kUSB_DeviceStateConfigured != state)
#endif
    )
    {
        return error;
    }

    if ((uint8_t)kUSB_DeviceStateAddressing != state)
    {
        /* If the device address is not setting, pass the address and the device state will change to
         * kUSB_DeviceStateAddressing internally. */
        state = (uint8_t)(setup->wValue & 0xFFU);
#if ((defined(USB_DEVICE_CONFIG_ROOT2_TEST)) && (USB_DEVICE_CONFIG_ROOT2_TEST > 0U))
        /* Setting the address to 128 or above should not be allowed. */
        if (state >= 0x80U)
        {
            return error;
        }
#endif
        error = USB_DeviceSetStatus(classHandle->handle, kUSB_DeviceStatusAddress, &state);
    }
    else
    {
        /* If the device address is setting, set device address and the address will be write into the controller
         * internally. */
        error = USB_DeviceSetStatus(classHandle->handle, kUSB_DeviceStatusAddress, NULL);
        /* And then change the device state to kUSB_DeviceStateAddress. */
        if (kStatus_USB_Success == error)
        {
            state = (uint8_t)kUSB_DeviceStateAddress;
            error = USB_DeviceSetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);
        }
    }

    return error;
}

/*!
 * @brief Handle get descriptor request.
 *
 * This function is used to handle get descriptor request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @retval kStatus_USB_Success              The request is handled successfully.
 * @retval kStatus_USB_InvalidRequest       The request can not be handle in current device state,
 *                                          or, the request is unsupported.
 */
static usb_status_t USB_DeviceCh9GetDescriptor(usb_device_common_class_struct_t *classHandle,
                                               usb_setup_struct_t *setup,
                                               uint8_t **buffer,
                                               uint32_t *length)
{
    usb_device_get_descriptor_common_union_t commonDescriptor;
    usb_status_t error      = kStatus_USB_InvalidRequest;
    uint8_t state           = 0U;
    uint8_t descriptorType  = (uint8_t)((setup->wValue & 0xFF00U) >> 8U);
    uint8_t descriptorIndex = (uint8_t)((setup->wValue & 0x00FFU));

    if ((setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) != USB_REQUEST_TYPE_DIR_IN)
    {
        return error;
    }

    (void)USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);

    if (((uint8_t)kUSB_DeviceStateAddress != state) && ((uint8_t)kUSB_DeviceStateConfigured != state) &&
        ((uint8_t)kUSB_DeviceStateDefault != state))
    {
        return error;
    }
    commonDescriptor.commonDescriptor.length = setup->wLength;
    if (USB_DESCRIPTOR_TYPE_DEVICE == descriptorType)
    {
        /* Get the device descriptor */
        if (((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_DEVICE) &&
            (descriptorIndex == 0U) && (setup->wIndex == 0U))
        {
            error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventGetDeviceDescriptor,
                                            &commonDescriptor.deviceDescriptor);
        }
    }
    else if (USB_DESCRIPTOR_TYPE_CONFIGURE == descriptorType)
    {
        /* Get the configuration descriptor */
        if (((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_DEVICE) &&
            (setup->wIndex == 0U))
        {
            commonDescriptor.configurationDescriptor.configuration = descriptorIndex;
            error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventGetConfigurationDescriptor,
                                            &commonDescriptor.configurationDescriptor);
        }
    }
    else if (USB_DESCRIPTOR_TYPE_STRING == descriptorType)
    {
        /* Get the string descriptor */
        if ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_DEVICE)
        {
            commonDescriptor.stringDescriptor.stringIndex = descriptorIndex;
            commonDescriptor.stringDescriptor.languageId  = setup->wIndex;
            error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventGetStringDescriptor,
                                            &commonDescriptor.stringDescriptor);
        }
    }
#if (defined(USB_DEVICE_CONFIG_HID) && (USB_DEVICE_CONFIG_HID > 0U))
    else if (USB_DESCRIPTOR_TYPE_HID == descriptorType)
    {
        /* Get the hid descriptor */
        if (((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_INTERFACE) &&
            (descriptorIndex == 0U))
        {
            commonDescriptor.hidDescriptor.interfaceNumber = (uint8_t)setup->wIndex;
            error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventGetHidDescriptor,
                                            &commonDescriptor.hidDescriptor);
        }
    }
    else if (USB_DESCRIPTOR_TYPE_HID_REPORT == descriptorType)
    {
        /* Get the hid report descriptor */
        if (((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_INTERFACE) &&
            (descriptorIndex == 0U))
        {
            commonDescriptor.hidReportDescriptor.interfaceNumber = (uint8_t)setup->wIndex;
            error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventGetHidReportDescriptor,
                                            &commonDescriptor.hidReportDescriptor);
        }
    }
    else if (USB_DESCRIPTOR_TYPE_HID_PHYSICAL == descriptorType)
    {
        /* Get the hid physical descriptor */
        if ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_INTERFACE)
        {
            commonDescriptor.hidPhysicalDescriptor.index           = descriptorIndex;
            commonDescriptor.hidPhysicalDescriptor.interfaceNumber = (uint8_t)setup->wIndex;
            error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventGetHidPhysicalDescriptor,
                                            &commonDescriptor.hidPhysicalDescriptor);
        }
    }
#endif
#if (defined(USB_DEVICE_CONFIG_CV_TEST) && (USB_DEVICE_CONFIG_CV_TEST > 0U))
    else if (USB_DESCRIPTOR_TYPE_DEVICE_QUALITIER == descriptorType)
    {
        /* Get the device descriptor */
        if (((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_DEVICE) &&
            (descriptorIndex == 0U) && (setup->wIndex == 0U))
        {
            error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventGetDeviceQualifierDescriptor,
                                            &commonDescriptor.deviceDescriptor);
        }
    }
#endif
#if (defined(USB_DEVICE_CONFIG_LPM_L1) && (USB_DEVICE_CONFIG_LPM_L1 > 0U))
    else if (USB_DESCRIPTOR_TYPE_BOS == descriptorType)
    {
        /* Get the configuration descriptor */
        if (((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) == USB_REQUEST_TYPE_RECIPIENT_DEVICE) &&
            (setup->wIndex == 0U))
        {
            commonDescriptor.configurationDescriptor.configuration = descriptorIndex;
            error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventGetBOSDescriptor,
                                            &commonDescriptor.configurationDescriptor);
        }
    }
#endif
    else
    {
    }
    *buffer = commonDescriptor.commonDescriptor.buffer;
    *length = commonDescriptor.commonDescriptor.length;
    return error;
}

/*!
 * @brief Handle get current configuration request.
 *
 * This function is used to handle get current configuration request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @retval kStatus_USB_Success              The request is handled successfully.
 * @retval kStatus_USB_InvalidRequest       The request can not be handle in current device state,
 *                                          or, the request is unsupported.
 */
static usb_status_t USB_DeviceCh9GetConfiguration(usb_device_common_class_struct_t *classHandle,
                                                  usb_setup_struct_t *setup,
                                                  uint8_t **buffer,
                                                  uint32_t *length)
{
    uint8_t state = 0U;

    if (((setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) != USB_REQUEST_TYPE_DIR_IN) ||
        ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) != USB_REQUEST_TYPE_RECIPIENT_DEVICE) ||
        (setup->wValue != 0U) || (setup->wIndex != 0U) || (setup->wLength != 1U))
    {
        return kStatus_USB_InvalidRequest;
    }

    (void)USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);

    if (((uint8_t)kUSB_DeviceStateAddress != state) && (((uint8_t)kUSB_DeviceStateConfigured != state)))
    {
        return kStatus_USB_InvalidRequest;
    }

    *length = USB_CONFIGURE_SIZE;
    *buffer = (uint8_t *)&classHandle->standardTranscationBuffer;
    return USB_DeviceClassCallback(classHandle->handle, (uint8_t)kUSB_DeviceEventGetConfiguration,
                                   &classHandle->standardTranscationBuffer);
}

/*!
 * @brief Handle set current configuration request.
 *
 * This function is used to handle set current configuration request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @retval kStatus_USB_Success              The request is handled successfully.
 * @retval kStatus_USB_InvalidRequest       The request can not be handle in current device state,
 *                                          or, the request is unsupported.
 */
static usb_status_t USB_DeviceCh9SetConfiguration(usb_device_common_class_struct_t *classHandle,
                                                  usb_setup_struct_t *setup,
                                                  uint8_t **buffer,
                                                  uint32_t *length)
{
    uint8_t state = 0U;

    if (((setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) != USB_REQUEST_TYPE_DIR_OUT) ||
        ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) != USB_REQUEST_TYPE_RECIPIENT_DEVICE) ||
        (setup->wIndex != 0U) || (setup->wLength != 0U))
    {
        return kStatus_USB_InvalidRequest;
    }

    (void)USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);

    if (((uint8_t)kUSB_DeviceStateAddress != state) && ((uint8_t)kUSB_DeviceStateConfigured != state))
    {
        return kStatus_USB_InvalidRequest;
    }

    /* The device state is changed to kUSB_DeviceStateConfigured */
    state = (uint8_t)kUSB_DeviceStateConfigured;
    (void)USB_DeviceSetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);
    if (0U == setup->wValue)
    {
        /* If the new configuration is zero, the device state is changed to kUSB_DeviceStateAddress */
        state = (uint8_t)kUSB_DeviceStateAddress;
        (void)USB_DeviceSetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);
    }

    /* Notify the class layer the configuration is changed */
    (void)USB_DeviceClassEvent(classHandle->handle, kUSB_DeviceClassEventSetConfiguration, &setup->wValue);
    /* Notify the application the configuration is changed */
    return USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventSetConfiguration, &setup->wValue);
}

/*!
 * @brief Handle get the alternate setting of a interface request.
 *
 * This function is used to handle get the alternate setting of a interface request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @retval kStatus_USB_Success              The request is handled successfully.
 * @retval kStatus_USB_InvalidRequest       The request can not be handle in current device state,
 *                                          or, the request is unsupported.
 */
static usb_status_t USB_DeviceCh9GetInterface(usb_device_common_class_struct_t *classHandle,
                                              usb_setup_struct_t *setup,
                                              uint8_t **buffer,
                                              uint32_t *length)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t state      = 0U;

    if (((setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) != USB_REQUEST_TYPE_DIR_IN) ||
        ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) != USB_REQUEST_TYPE_RECIPIENT_INTERFACE) ||
        (setup->wValue != 0U) || (setup->wLength != 1U))
    {
        return error;
    }

    (void)USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);

    if (state != (uint8_t)kUSB_DeviceStateConfigured)
    {
        return error;
    }
    *length                                = USB_INTERFACE_SIZE;
    *buffer                                = (uint8_t *)&classHandle->standardTranscationBuffer;
    classHandle->standardTranscationBuffer = (uint16_t)(((uint32_t)setup->wIndex & 0xFFU) << 8U);
    /* The Bit[15~8] is used to save the interface index, and the alternate setting will be saved in Bit[7~0] by
     * application. */
    error = USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventGetInterface,
                                    &classHandle->standardTranscationBuffer);
    classHandle->standardTranscationBuffer = USB_SHORT_TO_LITTLE_ENDIAN(classHandle->standardTranscationBuffer);
    return error;
}

/*!
 * @brief Handle set the alternate setting of a interface request.
 *
 * This function is used to handle set the alternate setting of a interface request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @retval kStatus_USB_Success              The request is handled successfully.
 * @retval kStatus_USB_InvalidRequest       The request can not be handle in current device state,
 *                                          or, the request is unsupported.
 */
static usb_status_t USB_DeviceCh9SetInterface(usb_device_common_class_struct_t *classHandle,
                                              usb_setup_struct_t *setup,
                                              uint8_t **buffer,
                                              uint32_t *length)
{
    uint8_t state = 0U;

    if (((setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) != USB_REQUEST_TYPE_DIR_OUT) ||
        ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) != USB_REQUEST_TYPE_RECIPIENT_INTERFACE) ||
        (setup->wLength != 0U))
    {
        return kStatus_USB_InvalidRequest;
    }

    (void)USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);

    if (state != (uint8_t)kUSB_DeviceStateConfigured)
    {
        return kStatus_USB_InvalidRequest;
    }
    classHandle->standardTranscationBuffer = ((setup->wIndex & 0xFFU) << 8U) | (setup->wValue & 0xFFU);
    /* Notify the class driver the alternate setting of the interface is changed. */
    /* The Bit[15~8] is used to save the interface index, and the alternate setting is saved in Bit[7~0]. */
    (void)USB_DeviceClassEvent(classHandle->handle, kUSB_DeviceClassEventSetInterface,
                               &classHandle->standardTranscationBuffer);
    /* Notify the application the alternate setting of the interface is changed. */
    /* The Bit[15~8] is used to save the interface index, and the alternate setting will is saved in Bit[7~0]. */
    return USB_DeviceClassCallback(classHandle->handle, (uint32_t)kUSB_DeviceEventSetInterface,
                                   &classHandle->standardTranscationBuffer);
}

/*!
 * @brief Handle get sync frame request.
 *
 * This function is used to handle get sync frame request.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @retval kStatus_USB_Success              The request is handled successfully.
 * @retval kStatus_USB_InvalidRequest       The request can not be handle in current device state,
 *                                          or, the request is unsupported.
 */
static usb_status_t USB_DeviceCh9SynchFrame(usb_device_common_class_struct_t *classHandle,
                                            usb_setup_struct_t *setup,
                                            uint8_t **buffer,
                                            uint32_t *length)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t state      = 0U;

    if (((setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) != USB_REQUEST_TYPE_DIR_IN) ||
        ((setup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) != USB_REQUEST_TYPE_RECIPIENT_ENDPOINT) ||
        (setup->wValue != 0U) || (setup->wLength != 2U))
    {
        return error;
    }

    (void)USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusDeviceState, &state);

    if (state != (uint8_t)kUSB_DeviceStateConfigured)
    {
        return error;
    }
    /* Synch frame is not implemented by any MS devices. Expected response from device will be STALL until a device
       exists that supports this command. At that time this script will need to be updated to support a
       response other than STALL */
#if (defined(USB_DEVICE_CONFIG_ROOT2_TEST) && (USB_DEVICE_CONFIG_ROOT2_TEST > 0U))
    return error;
#else
    classHandle->standardTranscationBuffer = USB_SHORT_FROM_LITTLE_ENDIAN(setup->wIndex);
    /* Get the sync frame value */
    error =
        USB_DeviceGetStatus(classHandle->handle, kUSB_DeviceStatusSynchFrame, &classHandle->standardTranscationBuffer);
    *buffer = (uint8_t *)&classHandle->standardTranscationBuffer;
    *length = sizeof(classHandle->standardTranscationBuffer);
    return error;
#endif
}

/*!
 * @brief Send the response to the host.
 *
 * This function is used to send the response to the host.
 *
 * There are two cases this function will be called.
 * Case one when a setup packet is received in control endpoint callback function:
 *        1. If there is not data phase in the setup transfer, the function will prime an IN transfer with the data
 * length is zero for status phase.
 *        2. If there is an IN data phase, the function will prime an OUT transfer with the actual length to need to
 * send for data phase. And then prime an IN transfer with the data length is zero for status phase.
 *        3. If there is an OUT data phase, the function will prime an IN transfer with the actual length to want to
 * receive for data phase.
 *
 * Case two when is not a setup packet received in control endpoint callback function:
 *        1. The function will prime an IN transfer with data length is zero for status phase.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param setup           The pointer of the setup packet.
 * @param error           The error code returned from the standard request function.
 * @param stage           The stage of the control transfer.
 * @param buffer          It is an out parameter, is used to save the buffer address to response the host's request.
 * @param length          It is an out parameter, the data length.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceControlCallbackFeedback(usb_device_handle handle,
                                                      usb_setup_struct_t *setup,
                                                      usb_status_t error,
                                                      usb_device_control_read_write_sequence_t stage,
                                                      uint8_t **buffer,
                                                      uint32_t *length)
{
    usb_status_t status;

    if (kStatus_USB_InvalidRequest == error)
    {
        /* Stall the control pipe when the request is unsupported. */
        status = USB_DeviceStallEndpoint(handle, (uint8_t)USB_CONTROL_ENDPOINT);
    }
    else
    {
        if (*length > setup->wLength)
        {
            *length = setup->wLength;
        }

        if (kStatus_USB_Success == error)
        {
            status = USB_DeviceSendRequest(handle, (USB_CONTROL_ENDPOINT), *buffer, *length);
        }
        else
        {
            status = USB_DeviceSendRequest(handle, (USB_CONTROL_ENDPOINT), (uint8_t *)NULL, 0U);
        }

        if ((kStatus_USB_Success == status) &&
            (USB_REQUEST_TYPE_DIR_IN == (setup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK)))
        {
            status = USB_DeviceRecvRequest(handle, (USB_CONTROL_ENDPOINT), (uint8_t *)NULL, 0U);
        }
    }

    return status;
}

/*!
 * @brief Control endpoint callback function.
 *
 * This callback function is used to notify uplayer the transfser result of a transfer.
 * This callback pointer is passed when a specified endpoint initialized by calling API USB_DeviceInitEndpoint.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param message         The result of a transfer, includes transfer buffer, transfer length and whether is in setup
 * phase for control pipe.
 * @param callbackParam  The parameter for this callback. It is same with
 * usb_device_endpoint_callback_struct_t::callbackParam.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceControlCallback(usb_device_handle handle,
                                              usb_device_endpoint_callback_message_struct_t *message,
                                              void *callbackParam)
{
    usb_setup_struct_t *deviceSetup, *setup;
    usb_device_common_class_struct_t *classHandle;
    uint8_t *buffer = (uint8_t *)NULL;
    uint32_t length = 0U;
    void *temp;
    usb_status_t status = kStatus_USB_InvalidRequest;
    uint8_t state       = 0U;

    /* endpoint callback length is USB_CANCELLED_TRANSFER_LENGTH (0xFFFFFFFFU) when transfer is canceled */
    if ((USB_CANCELLED_TRANSFER_LENGTH == message->length) || (NULL == callbackParam))
    {
        return status;
    }

    classHandle = (usb_device_common_class_struct_t *)callbackParam;
    temp        = (void *)&classHandle->setupBuffer[0];
    deviceSetup = (usb_setup_struct_t *)temp;
    (void)USB_DeviceGetStatus(handle, kUSB_DeviceStatusDeviceState, &state);

    if (0U != message->isSetup)
    {
        if ((USB_SETUP_PACKET_SIZE != message->length) || (NULL == message->buffer))
        {
            /* If a invalid setup is received, the control pipes should be de-init and init again.
             * Due to the IP can not meet this require, it is reserved for feature.
             */
            /*
            USB_DeviceDeinitEndpoint(handle,
                         USB_CONTROL_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT));
            USB_DeviceDeinitEndpoint(handle,
                         USB_CONTROL_ENDPOINT | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT));
            USB_DeviceControlPipeInit(handle, callbackParam);
            */
            return status;
        }
        /* Receive a setup request */
        temp  = (void *)(message->buffer);
        setup = (usb_setup_struct_t *)temp;

        /* Copy the setup packet to the application buffer */
        deviceSetup->wValue        = USB_SHORT_FROM_LITTLE_ENDIAN(setup->wValue);
        deviceSetup->wIndex        = USB_SHORT_FROM_LITTLE_ENDIAN(setup->wIndex);
        deviceSetup->wLength       = USB_SHORT_FROM_LITTLE_ENDIAN(setup->wLength);
        deviceSetup->bRequest      = setup->bRequest;
        deviceSetup->bmRequestType = setup->bmRequestType;

        /* Check the invalid value */
        if ((deviceSetup->bmRequestType & USB_REQUEST_TYPE_RECIPIENT_MASK) > USB_REQUEST_TYPE_RECIPIENT_OTHER)
        {
            (void)USB_DeviceControlCallbackFeedback(handle, deviceSetup, kStatus_USB_InvalidRequest,
                                                    kUSB_DeviceControlPipeSetupStage, NULL, NULL);
            return status;
        }

        if ((deviceSetup->bmRequestType & USB_REQUEST_TYPE_TYPE_MASK) == USB_REQUEST_TYPE_TYPE_STANDARD)
        {
            /* Handle the standard request, only handle the request in request array. */
            if (deviceSetup->bRequest < (sizeof(s_UsbDeviceStandardRequest) / 4U))
            {
                if (s_UsbDeviceStandardRequest[deviceSetup->bRequest] != (usb_standard_request_callback_t)NULL)
                {
                    status =
                        s_UsbDeviceStandardRequest[deviceSetup->bRequest](classHandle, deviceSetup, &buffer, &length);
                }
            }
        }
        else
        {
            if ((0U != deviceSetup->wLength) &&
                ((deviceSetup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) == USB_REQUEST_TYPE_DIR_OUT))
            {
                /* Class or vendor request with the OUT data phase. */
                if ((0U != deviceSetup->wLength) &&
                    ((deviceSetup->bmRequestType & USB_REQUEST_TYPE_TYPE_MASK) == USB_REQUEST_TYPE_TYPE_CLASS))
                {
                    /* Get data buffer to receive the data from the host. */
                    usb_device_control_request_struct_t controlRequest;
                    controlRequest.buffer  = (uint8_t *)NULL;
                    controlRequest.isSetup = 1U;
                    controlRequest.setup   = deviceSetup;
                    controlRequest.length  = deviceSetup->wLength;
                    status = USB_DeviceClassEvent(handle, kUSB_DeviceClassEventClassRequest, &controlRequest);
                    length = controlRequest.length;
                    buffer = controlRequest.buffer;
                }
                else if ((0U != deviceSetup->wLength) &&
                         ((deviceSetup->bmRequestType & USB_REQUEST_TYPE_TYPE_MASK) == USB_REQUEST_TYPE_TYPE_VENDOR))
                {
                    /* Get data buffer to receive the data from the host. */
                    usb_device_control_request_struct_t controlRequest;
                    controlRequest.buffer  = (uint8_t *)NULL;
                    controlRequest.isSetup = 1U;
                    controlRequest.setup   = deviceSetup;
                    controlRequest.length  = deviceSetup->wLength;
                    status = USB_DeviceClassCallback(handle, (uint32_t)kUSB_DeviceEventVendorRequest, &controlRequest);
                    length = controlRequest.length;
                    buffer = controlRequest.buffer;
                }
                else
                {
                    /*no action*/
                }
                if (kStatus_USB_Success == status)
                {
                    /* Prime an OUT transfer */
                    if (length > deviceSetup->wLength)
                    {
                        length = deviceSetup->wLength;
                    }
                    status = USB_DeviceRecvRequest(handle, USB_CONTROL_ENDPOINT, buffer, length);
                    return status;
                }
                else
                {
                    /* Other error codes, will stall control endpoint */
                    status = kStatus_USB_InvalidRequest;
                }
            }
            else
            {
                /* Class or vendor request with the IN data phase. */
                if (((deviceSetup->bmRequestType & USB_REQUEST_TYPE_TYPE_MASK) == USB_REQUEST_TYPE_TYPE_CLASS))
                {
                    /* Get data buffer to response the host. */
                    usb_device_control_request_struct_t controlRequest;
                    controlRequest.buffer  = (uint8_t *)NULL;
                    controlRequest.isSetup = 1U;
                    controlRequest.setup   = deviceSetup;
                    controlRequest.length  = deviceSetup->wLength;
                    status = USB_DeviceClassEvent(handle, kUSB_DeviceClassEventClassRequest, &controlRequest);
                    length = controlRequest.length;
                    buffer = controlRequest.buffer;
                }
                else if (((deviceSetup->bmRequestType & USB_REQUEST_TYPE_TYPE_MASK) == USB_REQUEST_TYPE_TYPE_VENDOR))
                {
                    /* Get data buffer to response the host. */
                    usb_device_control_request_struct_t controlRequest;
                    controlRequest.buffer  = (uint8_t *)NULL;
                    controlRequest.isSetup = 1U;
                    controlRequest.setup   = deviceSetup;
                    controlRequest.length  = deviceSetup->wLength;
                    status = USB_DeviceClassCallback(handle, (uint32_t)kUSB_DeviceEventVendorRequest, &controlRequest);
                    length = controlRequest.length;
                    buffer = controlRequest.buffer;
                }
                else
                {
                    /*no action*/
                }
            }
        }
        /* Buffer that is equal to NULL means the application or classs driver does not prepare a buffer for
           sending or receiving the data, so control endpoint will be stalled here. */
        if ((0U != length) && (NULL == buffer))
        {
            status = kStatus_USB_InvalidRequest;
        }
        /* Send the response to the host. */
        status = USB_DeviceControlCallbackFeedback(handle, deviceSetup, status, kUSB_DeviceControlPipeSetupStage,
                                                   &buffer, &length);
    }
    else if ((uint8_t)kUSB_DeviceStateAddressing == state)
    {
        if (USB_REQUEST_STANDARD_SET_ADDRESS == deviceSetup->bRequest)
        {
            /* Set the device address to controller. */
            status = s_UsbDeviceStandardRequest[deviceSetup->bRequest](classHandle, deviceSetup, &buffer, &length);
        }
    }
#if ((defined(USB_DEVICE_CONFIG_EHCI) && (USB_DEVICE_CONFIG_EHCI > 0U)) ||                \
     (defined(USB_DEVICE_CONFIG_LPCIP3511HS) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U))) && \
    (defined(USB_DEVICE_CONFIG_USB20_TEST_MODE) && (USB_DEVICE_CONFIG_USB20_TEST_MODE > 0U))
    else if ((uint8_t)kUSB_DeviceStateTestMode == state)
    {
        uint8_t portTestControl = (uint8_t)(deviceSetup->wIndex >> 8);
        /* Set the controller.into test mode. */
        status = USB_DeviceSetStatus(handle, kUSB_DeviceStatusTestMode, &portTestControl);
    }
#endif
    else if ((0U != message->length) && (0U != deviceSetup->wLength) &&
             ((deviceSetup->bmRequestType & USB_REQUEST_TYPE_DIR_MASK) == USB_REQUEST_TYPE_DIR_OUT))
    {
        if (((deviceSetup->bmRequestType & USB_REQUEST_TYPE_TYPE_MASK) == USB_REQUEST_TYPE_TYPE_CLASS))
        {
            /* Data received in OUT phase, and notify the class driver. */
            usb_device_control_request_struct_t controlRequest;
            controlRequest.buffer  = message->buffer;
            controlRequest.isSetup = 0U;
            controlRequest.setup   = deviceSetup;
            controlRequest.length  = message->length;
            status                 = USB_DeviceClassEvent(handle, kUSB_DeviceClassEventClassRequest, &controlRequest);
        }
        else if (((deviceSetup->bmRequestType & USB_REQUEST_TYPE_TYPE_MASK) == USB_REQUEST_TYPE_TYPE_VENDOR))
        {
            /* Data received in OUT phase, and notify the application. */
            usb_device_control_request_struct_t controlRequest;
            controlRequest.buffer  = message->buffer;
            controlRequest.isSetup = 0U;
            controlRequest.setup   = deviceSetup;
            controlRequest.length  = message->length;
            status = USB_DeviceClassCallback(handle, (uint32_t)kUSB_DeviceEventVendorRequest, &controlRequest);
        }
        else
        {
            /*no action*/
        }
        /* Send the response to the host. */
        status = USB_DeviceControlCallbackFeedback(handle, deviceSetup, status, kUSB_DeviceControlPipeDataStage,
                                                   &buffer, &length);
    }
    else
    {
        /*no action*/
    }
    return status;
}

/*!
 * @brief Control endpoint initialization function.
 *
 * This callback function is used to initialize the control pipes.
 *
 * @param handle          The device handle. It equals the value returned from USB_DeviceInit.
 * @param param           The up layer handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceControlPipeInit(usb_device_handle handle, void *param)
{
    usb_device_endpoint_init_struct_t epInitStruct;
    usb_device_endpoint_callback_struct_t epCallback;
    usb_status_t status;

    epCallback.callbackFn    = USB_DeviceControlCallback;
    epCallback.callbackParam = param;

    epInitStruct.zlt             = 1U;
    epInitStruct.transferType    = USB_ENDPOINT_CONTROL;
    epInitStruct.interval        = 0;
    epInitStruct.endpointAddress = USB_CONTROL_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
    epInitStruct.maxPacketSize   = USB_CONTROL_MAX_PACKET_SIZE;
    /* Initialize the control IN pipe */
    status = USB_DeviceInitEndpoint(handle, &epInitStruct, &epCallback);

    if (kStatus_USB_Success != status)
    {
        return status;
    }
    epInitStruct.endpointAddress = USB_CONTROL_ENDPOINT | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
    /* Initialize the control OUT pipe */
    status = USB_DeviceInitEndpoint(handle, &epInitStruct, &epCallback);

    if (kStatus_USB_Success != status)
    {
        (void)USB_DeviceDeinitEndpoint(
            handle, USB_CONTROL_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT));
        return status;
    }

    return kStatus_USB_Success;
}
#endif /* USB_DEVICE_CONFIG_NUM */
