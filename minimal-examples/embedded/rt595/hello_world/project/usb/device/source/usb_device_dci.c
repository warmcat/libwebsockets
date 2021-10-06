/*
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 - 2017,2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_device_config.h"
#include "usb.h"

#include "usb_device.h"
#include "usb_device_dci.h"

#include "fsl_device_registers.h"

#if ((defined(USB_DEVICE_CONFIG_NUM)) && (USB_DEVICE_CONFIG_NUM > 0U))

#if ((defined(USB_DEVICE_CONFIG_KHCI)) && (USB_DEVICE_CONFIG_KHCI > 0U))
#include "usb_device_khci.h"
#endif

#if ((defined(USB_DEVICE_CONFIG_EHCI)) && (USB_DEVICE_CONFIG_EHCI > 0U))
#include "usb_device_ehci.h"
#endif

#if (((defined(USB_DEVICE_CONFIG_LPCIP3511FS)) && (USB_DEVICE_CONFIG_LPCIP3511FS > 0U)) || \
     ((defined(USB_DEVICE_CONFIG_LPCIP3511HS)) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U)))
#include "usb_device_lpcip3511.h"
#endif

#if ((defined(USB_DEVICE_CONFIG_DWC3)) && (USB_DEVICE_CONFIG_DWC3 > 0U))
#include "usb_device_dwc3.h"
#endif

#if (defined(USB_DEVICE_CONFIG_BUFFER_PROPERTY_CACHEABLE) && (USB_DEVICE_CONFIG_BUFFER_PROPERTY_CACHEABLE > 0U))
#include "fsl_cache.h"
#endif

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* Component ID definition, used by tools. */
#ifndef FSL_COMPONENT_ID
#define FSL_COMPONENT_ID "middleware.usb.device_stack"
#endif

#if defined __CORTEX_M && (__CORTEX_M == 7U)
#if (defined(USB_DEVICE_CONFIG_BUFFER_PROPERTY_CACHEABLE) && (USB_DEVICE_CONFIG_BUFFER_PROPERTY_CACHEABLE > 0U))
#warning USB_DEVICE_CONFIG_BUFFER_PROPERTY_CACHEABLE is not supported.
#endif
#endif

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
static usb_status_t USB_DeviceAllocateHandle(uint8_t controllerId, usb_device_struct_t **handle);
static usb_status_t USB_DeviceFreeHandle(usb_device_struct_t *handle);
static usb_status_t USB_DeviceGetControllerInterface(
    uint8_t controllerId, const usb_device_controller_interface_struct_t **controllerInterface);
static usb_status_t USB_DeviceTransfer(usb_device_handle handle,
                                       uint8_t endpointAddress,
                                       uint8_t *buffer,
                                       uint32_t length);
static usb_status_t USB_DeviceControl(usb_device_handle handle, usb_device_control_type_t type, void *param);
static usb_status_t USB_DeviceResetNotification(usb_device_struct_t *handle,
                                                usb_device_callback_message_struct_t *message);
#if (defined(USB_DEVICE_CONFIG_LOW_POWER_MODE) && (USB_DEVICE_CONFIG_LOW_POWER_MODE > 0U))
static usb_status_t USB_DeviceSuspendNotification(usb_device_struct_t *handle,
                                                  usb_device_callback_message_struct_t *message);
static usb_status_t USB_DeviceResumeNotification(usb_device_struct_t *handle,
                                                 usb_device_callback_message_struct_t *message);
#if (defined(USB_DEVICE_CONFIG_LPM_L1) && (USB_DEVICE_CONFIG_LPM_L1 > 0U))
static usb_status_t USB_DeviceSleepNotification(usb_device_struct_t *handle,
                                                usb_device_callback_message_struct_t *message);

#endif
#endif /* USB_DEVICE_CONFIG_LOW_POWER_MODE */
#if (defined(USB_DEVICE_CONFIG_DETACH_ENABLE) && (USB_DEVICE_CONFIG_DETACH_ENABLE > 0U))
static usb_status_t USB_DeviceDetachNotification(usb_device_struct_t *handle,
                                                 usb_device_callback_message_struct_t *message);
static usb_status_t USB_DeviceAttachNotification(usb_device_struct_t *handle,
                                                 usb_device_callback_message_struct_t *message);
#endif
static usb_status_t USB_DeviceNotification(usb_device_struct_t *handle, usb_device_callback_message_struct_t *message);

/*******************************************************************************
 * Variables
 ******************************************************************************/

USB_GLOBAL static usb_device_struct_t s_UsbDevice[USB_DEVICE_CONFIG_NUM];

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief Allocate a device handle.
 *
 * This function allocates a device handle.
 *
 * @param controllerId   The controller id of the USB IP. Please refer to the enumeration usb_controller_index_t.
 * @param handle          It is out parameter, is used to return pointer of the device handle to the caller.
 *
 * @retval kStatus_USB_Success              Get a device handle successfully.
 * @retval kStatus_USB_Busy                 Cannot allocate a device handle.
 * @retval kStatus_USB_Error                The device has been initialized.
 */
static usb_status_t USB_DeviceAllocateHandle(uint8_t controllerId, usb_device_struct_t **handle)
{
    uint32_t count;
    OSA_SR_ALLOC();

    OSA_ENTER_CRITICAL();
    /* Check the controller is initialized or not. */
    for (count = 0U; count < USB_DEVICE_CONFIG_NUM; count++)
    {
        if ((NULL != s_UsbDevice[count].controllerHandle) && (controllerId == s_UsbDevice[count].controllerId))
        {
            OSA_EXIT_CRITICAL();
            return kStatus_USB_Error;
        }
    }
    /* Get a free device handle. */
    for (count = 0U; count < USB_DEVICE_CONFIG_NUM; count++)
    {
        if (NULL == s_UsbDevice[count].controllerHandle)
        {
            s_UsbDevice[count].controllerId = controllerId;
            *handle                         = &s_UsbDevice[count];
            OSA_EXIT_CRITICAL();
            return kStatus_USB_Success;
        }
    }
    OSA_EXIT_CRITICAL();
    return kStatus_USB_Busy;
}

/*!
 * @brief Free a device handle.
 *
 * This function frees a device handle.
 *
 * @param handle          The device handle.
 *
 * @retval kStatus_USB_Success              Free device handle successfully.
 */
static usb_status_t USB_DeviceFreeHandle(usb_device_struct_t *handle)
{
    OSA_SR_ALLOC();

    OSA_ENTER_CRITICAL();
    handle->controllerHandle = NULL;
    handle->controllerId     = 0U;
    OSA_EXIT_CRITICAL();
    return kStatus_USB_Success;
}

#if ((defined(USB_DEVICE_CONFIG_KHCI)) && (USB_DEVICE_CONFIG_KHCI > 0U))
/* KHCI device driver interface */
static const usb_device_controller_interface_struct_t s_UsbDeviceKhciInterface = {
    USB_DeviceKhciInit, USB_DeviceKhciDeinit, USB_DeviceKhciSend,
    USB_DeviceKhciRecv, USB_DeviceKhciCancel, USB_DeviceKhciControl};
#endif

#if ((defined(USB_DEVICE_CONFIG_EHCI)) && (USB_DEVICE_CONFIG_EHCI > 0U))
/* EHCI device driver interface */
static const usb_device_controller_interface_struct_t s_UsbDeviceEhciInterface = {
    USB_DeviceEhciInit, USB_DeviceEhciDeinit, USB_DeviceEhciSend,
    USB_DeviceEhciRecv, USB_DeviceEhciCancel, USB_DeviceEhciControl};
#endif

#if (((defined(USB_DEVICE_CONFIG_LPCIP3511FS)) && (USB_DEVICE_CONFIG_LPCIP3511FS > 0U)) || \
     ((defined(USB_DEVICE_CONFIG_LPCIP3511HS)) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U)))
/* EHCI device driver interface */
static const usb_device_controller_interface_struct_t s_UsbDeviceLpc3511IpInterface = {
    USB_DeviceLpc3511IpInit, USB_DeviceLpc3511IpDeinit, USB_DeviceLpc3511IpSend,
    USB_DeviceLpc3511IpRecv, USB_DeviceLpc3511IpCancel, USB_DeviceLpc3511IpControl};
#endif

#if ((defined(USB_DEVICE_CONFIG_DWC3)) && (USB_DEVICE_CONFIG_DWC3 > 0U))
/* EHCI device driver interface */
static const usb_device_controller_interface_struct_t s_UsbDeviceDwc3Interface = {
    USB_DeviceDwc3Init, USB_DeviceDwc3Deinit, USB_DeviceDwc3Send,
    USB_DeviceDwc3Recv, USB_DeviceDwc3Cancel, USB_DeviceDwc3Control};
#endif

/*!
 * @brief Get the controller interface handle.
 *
 * This function is used to get the controller interface handle.
 *
 * @param controllerId          The controller id of the USB IP. Please refer to the enumeration usb_controller_index_t.
 * @param controllerInterface   It is out parameter, is used to return pointer of the device controller handle to the
 * caller.
 *
 * @retval kStatus_USB_Success              Get a device handle successfully.
 * @retval kStatus_USB_ControllerNotFound   The controller id is invalid.
 */
static usb_status_t USB_DeviceGetControllerInterface(
    uint8_t controllerId, const usb_device_controller_interface_struct_t **controllerInterface)
{
    usb_status_t error                    = kStatus_USB_ControllerNotFound;
    usb_controller_index_t controlerIndex = (usb_controller_index_t)controllerId;

#if ((defined(USB_DEVICE_CONFIG_KHCI)) && (USB_DEVICE_CONFIG_KHCI > 0U))
    /* Get the KHCI controller driver interface */
    if ((kUSB_ControllerKhci0 == controlerIndex) || (kUSB_ControllerKhci1 == controlerIndex))
    {
        *controllerInterface = (const usb_device_controller_interface_struct_t *)&s_UsbDeviceKhciInterface;
        error                = kStatus_USB_Success;
    }
#endif
#if ((defined(USB_DEVICE_CONFIG_EHCI)) && (USB_DEVICE_CONFIG_EHCI > 0U))
    /* Get the EHCI controller driver interface */
    if ((kUSB_ControllerEhci0 == controlerIndex) || (kUSB_ControllerEhci1 == controlerIndex))
    {
        *controllerInterface = (const usb_device_controller_interface_struct_t *)&s_UsbDeviceEhciInterface;
        error                = kStatus_USB_Success;
    }
#endif
#if (((defined(USB_DEVICE_CONFIG_LPCIP3511FS)) && (USB_DEVICE_CONFIG_LPCIP3511FS > 0U)) || \
     ((defined(USB_DEVICE_CONFIG_LPCIP3511HS)) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U)))
    /* Get the EHCI controller driver interface */
    if ((kUSB_ControllerLpcIp3511Fs0 == controlerIndex) || (kUSB_ControllerLpcIp3511Fs1 == controlerIndex) ||
        (kUSB_ControllerLpcIp3511Hs0 == controlerIndex) || (kUSB_ControllerLpcIp3511Hs1 == controlerIndex))
    {
        *controllerInterface = (const usb_device_controller_interface_struct_t *)&s_UsbDeviceLpc3511IpInterface;
        error                = kStatus_USB_Success;
    }
#endif
#if ((defined(USB_DEVICE_CONFIG_DWC3)) && (USB_DEVICE_CONFIG_DWC3 > 0U))
    /* Get the EHCI controller driver interface */
    if ((kUSB_ControllerDwc30 == controlerIndex) || (kUSB_ControllerDwc31 == controlerIndex))
    {
        *controllerInterface = (const usb_device_controller_interface_struct_t *)&s_UsbDeviceDwc3Interface;
        error                = kStatus_USB_Success;
    }
#endif

    return error;
}

/*!
 * @brief Start a new transfer.
 *
 * This function is used to start a new transfer.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param endpointAddress       Endpoint address. Bit7 is direction, 0U - USB_OUT, 1U - USB_IN.
 * @param buffer                 The memory address to be transferred, or the memory address to hold the data need to be
 * sent.
 * @param length                 The length of the data.
 *
 * @retval kStatus_USB_Success              Get a device handle successfully.
 * @retval kStatus_USB_InvalidHandle        The device handle is invalid.
 * @retval kStatus_USB_ControllerNotFound   The controller interface is not found.
 * @retval kStatus_USB_Error                The device is doing reset.
 */
static usb_status_t USB_DeviceTransfer(usb_device_handle handle,
                                       uint8_t endpointAddress,
                                       uint8_t *buffer,
                                       uint32_t length)
{
    usb_device_struct_t *deviceHandle = (usb_device_struct_t *)handle;
    usb_status_t status;
    uint8_t endpoint  = endpointAddress & USB_ENDPOINT_NUMBER_MASK;
    uint8_t direction = (endpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >>
                        USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;
    OSA_SR_ALLOC();

    if (NULL == deviceHandle)
    {
        return kStatus_USB_InvalidHandle;
    }

    if (NULL != deviceHandle->controllerInterface)
    {
        if (0U != deviceHandle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].isBusy)
        {
            return kStatus_USB_Busy;
        }
        OSA_ENTER_CRITICAL();
        deviceHandle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].isBusy = 1U;
        OSA_EXIT_CRITICAL();
        if (0U != (endpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
#if (defined(USB_DEVICE_CONFIG_BUFFER_PROPERTY_CACHEABLE) && (USB_DEVICE_CONFIG_BUFFER_PROPERTY_CACHEABLE > 0U))
            if (0U != length)
            {
                DCACHE_CleanByRange((uint32_t)buffer, length);
            }
#endif
            /* Call the controller send interface, the callbackFn is initialized in
            USB_DeviceGetControllerInterface */
            status = deviceHandle->controllerInterface->deviceSend(deviceHandle->controllerHandle, endpointAddress,
                                                                   buffer, length);
        }
        else
        {
#if (defined(USB_DEVICE_CONFIG_BUFFER_PROPERTY_CACHEABLE) && (USB_DEVICE_CONFIG_BUFFER_PROPERTY_CACHEABLE > 0U))
            if (length)
            {
                DCACHE_CleanInvalidateByRange((uint32_t)buffer, length);
            }
#endif
            /* Call the controller receive interface, the callbackFn is initialized in
            USB_DeviceGetControllerInterface */
            status = deviceHandle->controllerInterface->deviceRecv(deviceHandle->controllerHandle, endpointAddress,
                                                                   buffer, length);
        }
        if (kStatus_USB_Success != status)
        {
            OSA_ENTER_CRITICAL();
            deviceHandle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].isBusy = 0U;
            OSA_EXIT_CRITICAL();
        }
    }
    else
    {
        status = kStatus_USB_ControllerNotFound;
    }
    return status;
}

/*!
 * @brief Control the status of the selected item.
 *
 * This function is used to control the status of the selected item..
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param type                   The control type, please refer to the enumeration usb_device_control_type_t.
 * @param param                  The param type is determined by the selected item.
 *
 * @retval kStatus_USB_Success              Get a device handle successfully.
 * @retval kStatus_USB_InvalidHandle        The device handle is invalid.
 * @retval kStatus_USB_ControllerNotFound   The controller interface is not found.
 * @retval kStatus_USB_Error                Unsupported type.
 *                                          Or, the param is NULL pointer.
 */
static usb_status_t USB_DeviceControl(usb_device_handle handle, usb_device_control_type_t type, void *param)
{
    usb_device_struct_t *deviceHandle = (usb_device_struct_t *)handle;
    usb_status_t status;

    if (NULL == deviceHandle)
    {
        return kStatus_USB_InvalidHandle;
    }

    if (NULL != deviceHandle->controllerInterface)
    {
        /* Call the controller control interface. the controllerInterface is initialized in
        USB_DeviceGetControllerInterface */
        status = deviceHandle->controllerInterface->deviceControl(deviceHandle->controllerHandle, type, param);
    }
    else
    {
        status = kStatus_USB_ControllerNotFound;
    }
    return status;
}

/*!
 * @brief Handle the reset notification.
 *
 * This function is used to handle the reset notification.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param message                The device callback message handle.
 *
 * @retval kStatus_USB_Success              Get a device handle successfully.
 */
static usb_status_t USB_DeviceResetNotification(usb_device_struct_t *handle,
                                                usb_device_callback_message_struct_t *message)
{
    uint32_t count;

#if (defined(USB_DEVICE_CONFIG_USE_TASK) && (USB_DEVICE_CONFIG_USE_TASK > 0U))
    OSA_SR_ALLOC();
#endif

    handle->isResetting = 1U;

#if ((defined(USB_DEVICE_CONFIG_REMOTE_WAKEUP)) && (USB_DEVICE_CONFIG_REMOTE_WAKEUP > 0U))
    /* Clear remote wakeup feature */
    handle->remotewakeup = 0U;
#endif

#if (defined(USB_DEVICE_CONFIG_USE_TASK) && (USB_DEVICE_CONFIG_USE_TASK > 0U))
    OSA_ENTER_CRITICAL();
    handle->epCallbackDirectly = 1U;
    OSA_EXIT_CRITICAL();
#endif
    /* Set the controller to default status. */
    (void)USB_DeviceControl(handle, kUSB_DeviceControlSetDefaultStatus, NULL);
#if (defined(USB_DEVICE_CONFIG_USE_TASK) && (USB_DEVICE_CONFIG_USE_TASK > 0U))
    OSA_ENTER_CRITICAL();
    handle->epCallbackDirectly = 0U;
    OSA_EXIT_CRITICAL();
#endif

    handle->state         = (uint8_t)kUSB_DeviceStateDefault;
    handle->deviceAddress = 0U;

    for (count = 0U; count < (USB_DEVICE_CONFIG_ENDPOINTS * 2U); count++)
    {
        handle->epCallback[count].callbackFn    = (usb_device_endpoint_callback_t)NULL;
        handle->epCallback[count].callbackParam = NULL;
        handle->epCallback[count].isBusy        = 0U;
    }

    /* Call device callback to notify the application that the USB bus reset signal detected.
    the deviceCallback is the second parameter of USB_DeviceInit */
    (void)handle->deviceCallback(handle, kUSB_DeviceEventBusReset, NULL);

    handle->isResetting = 0U;
    return kStatus_USB_Success;
}

#if (defined(USB_DEVICE_CONFIG_LOW_POWER_MODE) && (USB_DEVICE_CONFIG_LOW_POWER_MODE > 0U))
/*!
 * @brief Handle the suspend notification.
 *
 * This function is used to handle the suspend notification.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param message                The device callback message handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceSuspendNotification(usb_device_struct_t *handle,
                                                  usb_device_callback_message_struct_t *message)
{
    /* Call device callback to notify the application that the USB bus suspend signal detected.
    the deviceCallback is the second parameter of USB_DeviceInit */

    return handle->deviceCallback(handle, kUSB_DeviceEventSuspend, NULL);
}

/*!
 * @brief Handle the resume notification.
 *
 * This function is used to handle the resume notification.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param message                The device callback message handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceResumeNotification(usb_device_struct_t *handle,
                                                 usb_device_callback_message_struct_t *message)
{
    /* Call device callback to notify the application that the USB bus resume signal detected.
    the deviceCallback is the second parameter of USB_DeviceInit */
    return handle->deviceCallback(handle, kUSB_DeviceEventResume, NULL);
}
#if (defined(USB_DEVICE_CONFIG_LPM_L1) && (USB_DEVICE_CONFIG_LPM_L1 > 0U))
/*!
 * @brief Handle the suspend notification.
 *
 * This function is used to handle the suspend notification.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param message                The device callback message handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceSleepNotification(usb_device_struct_t *handle,
                                                usb_device_callback_message_struct_t *message)
{
    /* Call device callback to notify the application that the USB bus suspend signal detected.
    the deviceCallback is the second parameter of USB_DeviceInit */

    (void)USB_DeviceSetStatus(handle, kUSB_DeviceStatusRemoteWakeup, message->buffer);

    return handle->deviceCallback(handle, kUSB_DeviceEventSleeped, NULL);
}
#endif

#endif /* USB_DEVICE_CONFIG_LOW_POWER_MODE */

#if (defined(USB_DEVICE_CONFIG_ERROR_HANDLING) && (USB_DEVICE_CONFIG_ERROR_HANDLING > 0U))
static usb_status_t USB_DeviceErrorNotification(usb_device_struct_t *handle,
                                                usb_device_callback_message_struct_t *message)
{
    /* Call device callback to notify the application that the USB bus error signal detected.
    the deviceCallback is the second parameter of USB_DeviceInit */
    return handle->deviceCallback(handle, kUSB_DeviceEventError, NULL);
}
#endif /* USB_DEVICE_CONFIG_ERROR_HANDLING */

#if (defined(USB_DEVICE_CONFIG_DETACH_ENABLE) && (USB_DEVICE_CONFIG_DETACH_ENABLE > 0U))
/*!
 * @brief Handle the detach notification.
 *
 * This function is used to handle the detach notification.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param message                The device callback message handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceDetachNotification(usb_device_struct_t *handle,
                                                 usb_device_callback_message_struct_t *message)
{
    /* Call device callback to notify the application that the device is disconnected from a host.
    the deviceCallback is the second parameter of USB_DeviceInit */
    return handle->deviceCallback(handle, kUSB_DeviceEventDetach, NULL);
}

/*!
 * @brief Handle the attach notification.
 *
 * This function is used to handle the attach notification.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param message                The device callback message handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceAttachNotification(usb_device_struct_t *handle,
                                                 usb_device_callback_message_struct_t *message)
{
    /* Call device callback to notify the application that the device is connected to a host.
    the deviceCallback is the second parameter of USB_DeviceInit */
    return handle->deviceCallback(handle, kUSB_DeviceEventAttach, NULL);
}
#endif

#if (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U))

/*!
 * @brief Handle the DCP detection finished notification.
 *
 * This function is used to notify detection notification.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param message                The device callback message handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */

static usb_status_t USB_DeviceDcdDetectFinihsedNotification(usb_device_struct_t *handle,
                                                            usb_device_callback_message_struct_t *message)
{
    /* Call device callback to notify the application that the DCP facility is detected.
    the deviceCallback is the second parameter of USB_DeviceInit */
    return handle->deviceCallback(handle, kUSB_DeviceEventDcdDetectionfinished, message->buffer);
}
#endif

/*!
 * @brief Handle the attach notification.
 *
 * This function is used to handle the attach notification.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param message                The device callback message handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceNotification(usb_device_struct_t *handle, usb_device_callback_message_struct_t *message)
{
    uint8_t endpoint  = message->code & USB_ENDPOINT_NUMBER_MASK;
    uint8_t direction = (message->code & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >>
                        USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;
    usb_status_t status                    = kStatus_USB_Error;
    usb_device_notification_t deviceNotify = (usb_device_notification_t)message->code;
    switch (deviceNotify)
    {
        case kUSB_DeviceNotifyBusReset:
            status = USB_DeviceResetNotification(handle, message);
            break;
#if (defined(USB_DEVICE_CONFIG_LOW_POWER_MODE) && (USB_DEVICE_CONFIG_LOW_POWER_MODE > 0U))
        case kUSB_DeviceNotifySuspend:
            status = USB_DeviceSuspendNotification(handle, message);
            break;
        case kUSB_DeviceNotifyResume:
            status = USB_DeviceResumeNotification(handle, message);
            break;
#if (defined(USB_DEVICE_CONFIG_LPM_L1) && (USB_DEVICE_CONFIG_LPM_L1 > 0U))
        case kUSB_DeviceNotifyLPMSleep:
            status = USB_DeviceSleepNotification(handle, message);
            break;
#endif
#endif

#if (defined(USB_DEVICE_CONFIG_ERROR_HANDLING) && (USB_DEVICE_CONFIG_ERROR_HANDLING > 0U))
        case kUSB_DeviceNotifyError:
            status = USB_DeviceErrorNotification(handle, message);
            break;
#endif

#if USB_DEVICE_CONFIG_DETACH_ENABLE
        case kUSB_DeviceNotifyDetach:
            status = USB_DeviceDetachNotification(handle, message);
            break;
        case kUSB_DeviceNotifyAttach:
            status = USB_DeviceAttachNotification(handle, message);
            break;
#endif
#if (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U))
        case kUSB_DeviceNotifyDcdDetectFinished:
            status = USB_DeviceDcdDetectFinihsedNotification(handle, message);
            break;
#endif

        default:
            if (endpoint < USB_DEVICE_CONFIG_ENDPOINTS)
            {
                if (NULL != handle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].callbackFn)
                {
                    usb_device_endpoint_callback_message_struct_t endpointCallbackMessage;
                    endpointCallbackMessage.buffer  = message->buffer;
                    endpointCallbackMessage.length  = message->length;
                    endpointCallbackMessage.isSetup = message->isSetup;
                    if (0U != message->isSetup)
                    {
                        handle->epCallback[0].isBusy = 0U;
                        handle->epCallback[1].isBusy = 0U;
                    }
                    else
                    {
                        handle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].isBusy = 0U;
                    }
                    /* Call endpoint callback, callbackFn is in the third parameter of USB_DeviceInitEndpoint */
                    status = handle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].callbackFn(
                        handle, &endpointCallbackMessage,
                        handle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].callbackParam);
                }
            }
            break;
    }
    return status;
}

/*!
 * @brief Notify the device that the controller status changed.
 *
 * This function is used to notify the device that the controller status changed.
 *
 * @param handle                 The device handle. It equals the value returned from USB_DeviceInit.
 * @param message                The device callback message handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceNotificationTrigger(void *handle, void *msg)
{
    usb_device_struct_t *deviceHandle             = (usb_device_struct_t *)handle;
    usb_device_callback_message_struct_t *message = (usb_device_callback_message_struct_t *)msg;

    if ((NULL == msg) || (NULL == handle))
    {
        return kStatus_USB_InvalidHandle;
    }

    /* The device callback is invalid or not. */
    if (NULL == deviceHandle->deviceCallback)
    {
        return kStatus_USB_Error;
    }

#if (defined(USB_DEVICE_CONFIG_USE_TASK) && (USB_DEVICE_CONFIG_USE_TASK > 0U))
    if (0U != deviceHandle->epCallbackDirectly)
    {
        if ((0U != (message->code & USB_ENDPOINT_NUMBER_MASK)) && (0U == (message->code & 0x70U)))
        {
            return USB_DeviceNotification(deviceHandle, message);
        }
    }

    /* Add the message to message queue when the device task is enabled. */
    if (KOSA_StatusSuccess != OSA_MsgQPut(deviceHandle->notificationQueue, (osa_msg_handle_t)message))
    {
        return kStatus_USB_Busy;
    }
    return kStatus_USB_Success;
#else
    /* Handle the notification by calling USB_DeviceNotification. */
    return USB_DeviceNotification(deviceHandle, message);
#endif
}

/*!
 * @brief Initialize the USB device stack.
 *
 * This function initializes the USB device module specified by the controllerId.
 *
 * @param controllerId   The controller id of the USB IP. Please refer to the enumeration usb_controller_index_t.
 * @param deviceCallback Function pointer of the device callback.
 * @param handle          It is out parameter, is used to return pointer of the device handle to the caller.
 *
 * @retval kStatus_USB_Success              The device is initialized successfully.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer.
 * @retval kStatus_USB_Busy                 Cannot allocate a device handle.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller according to the controller id.
 * @retval kStatus_USB_InvalidControllerInterface  The controller driver interfaces is invaild, There is an empty
 * interface entity.
 * @retval kStatus_USB_Error                The macro USB_DEVICE_CONFIG_ENDPOINTS is more than IP's endpoint number.
 *                                          Or, the device has been initialized.
 *                                          Or, the message queue is created failed.
 */
usb_status_t USB_DeviceInit(uint8_t controllerId, usb_device_callback_t deviceCallback, usb_device_handle *handle)
{
    usb_device_struct_t *deviceHandle = NULL;
    usb_status_t error;
    uint32_t count;

    if (NULL == handle)
    {
        return kStatus_USB_InvalidHandle;
    }

    /* Allocate a device handle by using the controller id. */
    error = USB_DeviceAllocateHandle(controllerId, &deviceHandle);

    if (kStatus_USB_Success != error)
    {
        return error;
    }

    /* Save the device callback */
    deviceHandle->deviceCallback = deviceCallback;
    /* Save the controller id */
    deviceHandle->controllerId = controllerId;
    /* Clear the device address */
    deviceHandle->deviceAddress = 0U;
    /* Clear the device reset state */
    deviceHandle->isResetting = 0U;

    /* Initialize the endpoints */
    for (count = 0U; count < (USB_DEVICE_CONFIG_ENDPOINTS * 2U); count++)
    {
        deviceHandle->epCallback[count].callbackFn    = (usb_device_endpoint_callback_t)NULL;
        deviceHandle->epCallback[count].callbackParam = NULL;
        deviceHandle->epCallback[count].isBusy        = 0U;
    }

    /* Get the controller interface according to the controller id */
    error = USB_DeviceGetControllerInterface(controllerId, &deviceHandle->controllerInterface);
    if (kStatus_USB_Success != error)
    {
        (void)USB_DeviceFreeHandle(deviceHandle);
        return error;
    }
    if (NULL == deviceHandle->controllerInterface)
    {
        (void)USB_DeviceFreeHandle(deviceHandle);
        return kStatus_USB_ControllerNotFound;
    }
    if (((usb_device_controller_init_t)NULL == deviceHandle->controllerInterface->deviceInit) ||
        ((usb_device_controller_deinit_t)NULL == deviceHandle->controllerInterface->deviceDeinit) ||
        ((usb_device_controller_send_t)NULL == deviceHandle->controllerInterface->deviceSend) ||
        ((usb_device_controller_recv_t)NULL == deviceHandle->controllerInterface->deviceRecv) ||
        ((usb_device_controller_cancel_t)NULL == deviceHandle->controllerInterface->deviceCancel) ||
        ((usb_device_controller_control_t)NULL == deviceHandle->controllerInterface->deviceControl))
    {
        (void)USB_DeviceFreeHandle(deviceHandle);
        return kStatus_USB_InvalidControllerInterface;
    }

#if USB_DEVICE_CONFIG_USE_TASK
    /* Create a message queue when the device handle is enabled. */
    deviceHandle->notificationQueue = (osa_msgq_handle_t)&deviceHandle->notificationQueueBuffer[0];
    if (KOSA_StatusSuccess !=
        OSA_MsgQCreate(deviceHandle->notificationQueue, USB_DEVICE_CONFIG_MAX_MESSAGES, USB_DEVICE_MESSAGES_SIZE))
    {
        (void)USB_DeviceDeinit(deviceHandle);
        return kStatus_USB_Error;
    }
#endif

    *handle = deviceHandle;

    /* Initialize the controller, the callbackFn is initialized in USB_DeviceGetControllerInterface */
    error = deviceHandle->controllerInterface->deviceInit(controllerId, deviceHandle, &deviceHandle->controllerHandle);
    if (kStatus_USB_Success != error)
    {
        (void)USB_DeviceDeinit(deviceHandle);
        *handle = NULL;
        return error;
    }
    /* Set the device to deafult state */
    deviceHandle->state = (uint8_t)kUSB_DeviceStateDefault;

    return error;
}

/*!
 * @brief Enable the device functionality.
 *
 * The function enables the device functionality, so that the device can be recognized by the host when the device
 * detects that it has been connected to a host.
 *
 * @param handle The device handle got from USB_DeviceInit.
 *
 * @retval kStatus_USB_Success              The device is run successfully.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 * @retval kStatus_USB_InvalidHandle        The device handle is a NULL pointer. Or the controller handle is invalid.
 *
 */
usb_status_t USB_DeviceRun(usb_device_handle handle)
{
    return USB_DeviceControl(handle, kUSB_DeviceControlRun, NULL);
}
/*!
 * @brief Disable the device functionality.
 *
 * The function disables the device functionality, after this function called, even the device is detached to the host,
 * and the device can't work.
 *
 * @param handle The device handle got from USB_DeviceInit.
 *
 * @retval kStatus_USB_Success              The device is stopped successfully.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 * @retval kStatus_USB_InvalidHandle        The device handle is a NULL pointer. Or the controller handle is invalid.
 */
usb_status_t USB_DeviceStop(usb_device_handle handle)
{
    return USB_DeviceControl(handle, kUSB_DeviceControlStop, NULL);
}
/*!
 * @brief De-initialize the device controller.
 *
 * The function de-initializes the device controller specified by the handle.
 *
 * @param handle The device handle got from USB_DeviceInit.
 *
 * @retval kStatus_USB_Success              The device is stopped successfully.
 * @retval kStatus_USB_InvalidHandle        The device handle is a NULL pointer. Or the controller handle is invalid.
 */
usb_status_t USB_DeviceDeinit(usb_device_handle handle)
{
    usb_device_struct_t *deviceHandle = (usb_device_struct_t *)handle;

    if (NULL == deviceHandle)
    {
        return kStatus_USB_InvalidHandle;
    }
    /* De-initialize the controller */
    if (NULL != deviceHandle->controllerInterface)
    {
        /* the callbackFn is initialized in USB_DeviceGetControllerInterface */
        (void)deviceHandle->controllerInterface->deviceDeinit(deviceHandle->controllerHandle);
        deviceHandle->controllerInterface = (usb_device_controller_interface_struct_t *)NULL;
    }

#if USB_DEVICE_CONFIG_USE_TASK
    /* Destroy the message queue. */
    if (NULL != deviceHandle->notificationQueue)
    {
        (void)OSA_MsgQDestroy(deviceHandle->notificationQueue);
        deviceHandle->notificationQueue = NULL;
    }
#endif

    /* Free the device handle. */
    (void)USB_DeviceFreeHandle(deviceHandle);
    return kStatus_USB_Success;
}

/*!
 * @brief Send data through a specified endpoint.
 *
 * The function is used to send data through a specified endpoint.
 *
 * @param handle The device handle got from USB_DeviceInit.
 * @param endpointAddress Endpoint index.
 * @param buffer The memory address to hold the data need to be sent.
 * @param length The data length need to be sent.
 *
 * @retval kStatus_USB_Success              The send request is sent successfully.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer. Or the controller handle is invalid.
 * @retval kStatus_USB_Busy                 Cannot allocate dtds for current transfer in EHCI driver.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 * @retval kStatus_USB_Error                The device is doing reset.
 *
 * @note The return value just means if the sending request is successful or not; the transfer done is notified by the
 * corresponding callback function.
 * Currently, only one transfer request can be supported for one specific endpoint.
 * If there is a specific requirement to support multiple transfer requests for one specific endpoint, the application
 * should implement a queue in the application level.
 * The subsequent transfer could begin only when the previous transfer is done (get notification through the endpoint
 * callback).
 */
usb_status_t USB_DeviceSendRequest(usb_device_handle handle, uint8_t endpointAddress, uint8_t *buffer, uint32_t length)
{
    return USB_DeviceTransfer(
        handle,
        (endpointAddress & USB_ENDPOINT_NUMBER_MASK) | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
        buffer, length);
}

/*!
 * @brief Receive data through a specified endpoint.
 *
 * The function is used to receive data through a specified endpoint.
 *
 * @param handle The device handle got from USB_DeviceInit.
 * @param endpointAddress Endpoint index.
 * @param buffer The memory address to save the received data.
 * @param length The data length want to be received.
 *
 * @retval kStatus_USB_Success              The receive request is sent successfully.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer. Or the controller handle is invalid.
 * @retval kStatus_USB_Busy                 Cannot allocate dtds for current transfer in EHCI driver.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 * @retval kStatus_USB_Error                The device is doing reset.
 *
 * @note The return value just means if the receiving request is successful or not; the transfer done is notified by the
 * corresponding callback function.
 * Currently, only one transfer request can be supported for one specific endpoint.
 * If there is a specific requirement to support multiple transfer requests for one specific endpoint, the application
 * should implement a queue in the application level.
 * The subsequent transfer could begin only when the previous transfer is done (get notification through the endpoint
 * callback).
 */
usb_status_t USB_DeviceRecvRequest(usb_device_handle handle, uint8_t endpointAddress, uint8_t *buffer, uint32_t length)
{
    return USB_DeviceTransfer(
        handle,
        (endpointAddress & USB_ENDPOINT_NUMBER_MASK) | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
        buffer, length);
}

/*!
 * @brief Cancel the pending transfer in a specified endpoint.
 *
 * The function is used to cancel the pending transfer in a specified endpoint.
 *
 * @param handle The device handle got from USB_DeviceInit.
 * @param endpointAddress Endpoint address, bit7 is the direction of endpoint, 1U - IN, abd 0U - OUT.
 *
 * @retval kStatus_USB_Success              The transfer is cancelled.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer. Or the controller handle is invalid.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 */
usb_status_t USB_DeviceCancel(usb_device_handle handle, uint8_t endpointAddress)
{
    usb_device_struct_t *deviceHandle = (usb_device_struct_t *)handle;
    usb_status_t status;

    if (NULL == deviceHandle)
    {
        return kStatus_USB_InvalidHandle;
    }

    if (NULL != deviceHandle->controllerInterface)
    {
        /* the callbackFn is initialized in USB_DeviceGetControllerInterface */
        status = deviceHandle->controllerInterface->deviceCancel(deviceHandle->controllerHandle, endpointAddress);
    }
    else
    {
        status = kStatus_USB_ControllerNotFound;
    }
    return status;
}

/*!
 * @brief Initialize a specified endpoint.
 *
 * The function is used to initialize a specified endpoint and the corresponding endpoint callback is also initialized.
 *
 * @param handle The device handle got from USB_DeviceInit.
 * @param epInit Endpoint initialization structure. Please refer to the structure usb_device_endpoint_init_struct_t.
 * @param epCallback Endpoint callback structure. Please refer to the structure
 * usb_device_endpoint_callback_struct_t.
 *
 * @retval kStatus_USB_Success              The endpoint is initialized successfully.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer. Or the controller handle is invalid.
 * @retval kStatus_USB_InvalidParameter     The epInit or epCallback is NULL pointer. Or the endpoint number is
 * not less than USB_DEVICE_CONFIG_ENDPOINTS.
 * @retval kStatus_USB_Busy                 The endpoint is busy in EHCI driver.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 */
usb_status_t USB_DeviceInitEndpoint(usb_device_handle handle,
                                    usb_device_endpoint_init_struct_t *epInit,
                                    usb_device_endpoint_callback_struct_t *epCallback)
{
    usb_device_struct_t *deviceHandle = (usb_device_struct_t *)handle;
    uint8_t endpoint;
    uint8_t direction;

    if (NULL == deviceHandle)
    {
        return kStatus_USB_InvalidHandle;
    }

    if ((NULL == epInit) || (NULL == epCallback))
    {
        return kStatus_USB_InvalidParameter;
    }

    endpoint  = epInit->endpointAddress & USB_ENDPOINT_NUMBER_MASK;
    direction = (epInit->endpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >>
                USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;

    if (endpoint < USB_DEVICE_CONFIG_ENDPOINTS)
    {
        deviceHandle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].callbackFn = epCallback->callbackFn;
        deviceHandle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].callbackParam =
            epCallback->callbackParam;
        deviceHandle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].isBusy = 0U;
    }
    else
    {
        return kStatus_USB_InvalidParameter;
    }
    return USB_DeviceControl(handle, kUSB_DeviceControlEndpointInit, epInit);
}

/*!
 * @brief De-initizlize a specified endpoint.
 *
 * The function is used to de-initizlize a specified endpoint.
 *
 * @param handle The device handle got from USB_DeviceInit.
 * @param endpointAddress Endpoint address, bit7 is the direction of endpoint, 1U - IN, abd 0U - OUT.
 *
 * @retval kStatus_USB_Success              The endpoint is de-initialized successfully.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer. Or the controller handle is invalid.
 * @retval kStatus_USB_InvalidParameter     The endpoint number is more than USB_DEVICE_CONFIG_ENDPOINTS.
 * @retval kStatus_USB_Busy                 The endpoint is busy in EHCI driver.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 */
usb_status_t USB_DeviceDeinitEndpoint(usb_device_handle handle, uint8_t endpointAddress)
{
    usb_device_struct_t *deviceHandle = (usb_device_struct_t *)handle;
    uint8_t endpoint                  = endpointAddress & USB_ENDPOINT_NUMBER_MASK;
    uint8_t direction                 = (endpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >>
                        USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;
    usb_status_t status;
#if (defined(USB_DEVICE_CONFIG_USE_TASK) && (USB_DEVICE_CONFIG_USE_TASK > 0U))
    OSA_SR_ALLOC();
#endif

    if (NULL == deviceHandle)
    {
        return kStatus_USB_InvalidHandle;
    }
#if (defined(USB_DEVICE_CONFIG_USE_TASK) && (USB_DEVICE_CONFIG_USE_TASK > 0U))
    OSA_ENTER_CRITICAL();
    deviceHandle->epCallbackDirectly = 1U;
    OSA_EXIT_CRITICAL();
#endif
    status = USB_DeviceControl(handle, kUSB_DeviceControlEndpointDeinit, &endpointAddress);
#if (defined(USB_DEVICE_CONFIG_USE_TASK) && (USB_DEVICE_CONFIG_USE_TASK > 0U))
    OSA_ENTER_CRITICAL();
    deviceHandle->epCallbackDirectly = 0U;
    OSA_EXIT_CRITICAL();
#endif

    if (endpoint < USB_DEVICE_CONFIG_ENDPOINTS)
    {
        deviceHandle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].callbackFn =
            (usb_device_endpoint_callback_t)NULL;
        deviceHandle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].callbackParam = NULL;
        deviceHandle->epCallback[(uint8_t)((uint32_t)endpoint << 1U) | direction].isBusy        = 0U;
    }
    else
    {
        return kStatus_USB_InvalidParameter;
    }
    return status;
}

/*!
 * @brief Stall a specified endpoint.
 *
 * The function is used to stall a specified endpoint.
 *
 * @param handle The device handle got from USB_DeviceInit.
 * @param endpointAddress Endpoint address, bit7 is the direction of endpoint, 1U - IN, abd 0U - OUT.
 *
 * @retval kStatus_USB_Success              The endpoint is stalled successfully.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer. Or the controller handle is invalid.
 * @retval kStatus_USB_InvalidParameter     The endpoint number is more than USB_DEVICE_CONFIG_ENDPOINTS.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 */
usb_status_t USB_DeviceStallEndpoint(usb_device_handle handle, uint8_t endpointAddress)
{
    if ((endpointAddress & USB_ENDPOINT_NUMBER_MASK) < USB_DEVICE_CONFIG_ENDPOINTS)
    {
        return USB_DeviceControl(handle, kUSB_DeviceControlEndpointStall, &endpointAddress);
    }
    else
    {
        return kStatus_USB_InvalidParameter;
    }
}

/*!
 * @brief Un-stall a specified endpoint.
 *
 * The function is used to un-stall a specified endpoint.
 *
 * @param handle The device handle got from USB_DeviceInit.
 * @param endpointAddress Endpoint address, bit7 is the direction of endpoint, 1U - IN, abd 0U - OUT.
 *
 * @retval kStatus_USB_Success              The endpoint is un-stalled successfully.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer. Or the controller handle is invalid.
 * @retval kStatus_USB_InvalidParameter     The endpoint number is more than USB_DEVICE_CONFIG_ENDPOINTS.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 */
usb_status_t USB_DeviceUnstallEndpoint(usb_device_handle handle, uint8_t endpointAddress)
{
    if ((endpointAddress & USB_ENDPOINT_NUMBER_MASK) < USB_DEVICE_CONFIG_ENDPOINTS)
    {
        return USB_DeviceControl(handle, kUSB_DeviceControlEndpointUnstall, &endpointAddress);
    }
    else
    {
        return kStatus_USB_InvalidParameter;
    }
}

/*!
 * @brief Get the status of the selected item.
 *
 * The function is used to get the status of the selected item.
 *
 * @param handle The device handle got from USB_DeviceInit.
 * @param type   The selected item. Please refer to the structure usb_device_status_t.
 * @param param  The param type is determined by the selected item.
 *
 * @retval kStatus_USB_Success              Get status successfully.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer. Or the controller handle is invalid.
 * @retval kStatus_USB_InvalidParameter     The param is NULL pointer.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 * @retval kStatus_USB_Error                Unsupported type.
 */
usb_status_t USB_DeviceGetStatus(usb_device_handle handle, usb_device_status_t type, void *param)
{
    uint8_t *temp8;
    usb_status_t status = kStatus_USB_Error;

    if (NULL == param)
    {
        return kStatus_USB_InvalidParameter;
    }
    switch (type)
    {
#if defined(USB_DEVICE_CONFIG_GET_SOF_COUNT) && (USB_DEVICE_CONFIG_GET_SOF_COUNT > 0U)
        case kUSB_DeviceStatusGetCurrentFrameCount:
            status = USB_DeviceControl(handle, kUSB_DeviceControlGetCurrentFrameCount, param);
            break;
#endif
        case kUSB_DeviceStatusSpeed:
            status = USB_DeviceControl(handle, kUSB_DeviceControlGetSpeed, param);
            break;
        case kUSB_DeviceStatusOtg:
            status = USB_DeviceControl(handle, kUSB_DeviceControlGetOtgStatus, param);
            break;
        case kUSB_DeviceStatusDeviceState:
            temp8  = (uint8_t *)param;
            status = kStatus_USB_Success;
            *temp8 = ((usb_device_struct_t *)handle)->state;
            break;
        case kUSB_DeviceStatusAddress:
            temp8  = (uint8_t *)param;
            status = kStatus_USB_Success;
            *temp8 = ((usb_device_struct_t *)handle)->deviceAddress;
            break;
        case kUSB_DeviceStatusDevice:
            status = USB_DeviceControl(handle, kUSB_DeviceControlGetDeviceStatus, param);
            break;
        case kUSB_DeviceStatusEndpoint:
            status = USB_DeviceControl(handle, kUSB_DeviceControlGetEndpointStatus, param);
            break;
        case kUSB_DeviceStatusSynchFrame:
            status = USB_DeviceControl(handle, kUSB_DeviceControlGetSynchFrame, param);
            break;
#if ((defined(USB_DEVICE_CONFIG_REMOTE_WAKEUP)) && (USB_DEVICE_CONFIG_REMOTE_WAKEUP > 0U))
        case kUSB_DeviceStatusRemoteWakeup:
            temp8  = (uint8_t *)param;
            status = kStatus_USB_Success;
            *temp8 = ((usb_device_struct_t *)handle)->remotewakeup;
            break;
#endif
        default:
            /*no action*/
            break;
    }
    return status;
}

/*!
 * @brief Set the status of the selected item.
 *
 * The function is used to set the status of the selected item.
 *
 * @param handle The device handle got from USB_DeviceInit.
 * @param type The selected item. Please refer to the structure usb_device_status_t.
 * @param param The param type is determined by the selected item.
 *
 * @retval kStatus_USB_Success              Set status successfully.
 * @retval kStatus_USB_InvalidHandle        The handle is a NULL pointer. Or the controller handle is invalid.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 * @retval kStatus_USB_Error                Unsupported type, or the param is NULL pointer.
 */
usb_status_t USB_DeviceSetStatus(usb_device_handle handle, usb_device_status_t type, void *param)
{
    usb_status_t status = kStatus_USB_Error;
    switch (type)
    {
#if (defined(USB_DEVICE_CONFIG_EHCI) && (USB_DEVICE_CONFIG_EHCI > 0U) ||                  \
     (defined(USB_DEVICE_CONFIG_LPCIP3511HS) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U))) && \
    (defined(USB_DEVICE_CONFIG_USB20_TEST_MODE) && (USB_DEVICE_CONFIG_USB20_TEST_MODE > 0U))
        case kUSB_DeviceStatusTestMode:
            status = USB_DeviceControl(handle, kUSB_DeviceControlSetTestMode, param);
            break;
#endif
        case kUSB_DeviceStatusOtg:
            status = USB_DeviceControl(handle, kUSB_DeviceControlSetOtgStatus, param);
            break;
        case kUSB_DeviceStatusDeviceState:
            if (NULL != param)
            {
                status                                 = kStatus_USB_Success;
                ((usb_device_struct_t *)handle)->state = (uint8_t)(*(uint8_t *)param);
            }
            break;
        case kUSB_DeviceStatusAddress:
            if ((uint8_t)kUSB_DeviceStateAddressing != ((usb_device_struct_t *)handle)->state)
            {
                if (NULL != param)
                {
                    status                                         = kStatus_USB_Success;
                    ((usb_device_struct_t *)handle)->deviceAddress = (uint8_t)(*(uint8_t *)param);
                    ((usb_device_struct_t *)handle)->state         = (uint8_t)kUSB_DeviceStateAddressing;
                    status = USB_DeviceControl(handle, kUSB_DeviceControlPreSetDeviceAddress,
                                               &((usb_device_struct_t *)handle)->deviceAddress);
                }
            }
            else
            {
                status = USB_DeviceControl(handle, kUSB_DeviceControlSetDeviceAddress,
                                           &((usb_device_struct_t *)handle)->deviceAddress);
            }
            break;
        case kUSB_DeviceStatusBusResume:
            status = USB_DeviceControl(handle, kUSB_DeviceControlResume, param);
            break;
        case kUSB_DeviceStatusBusSleepResume:
            status = USB_DeviceControl(handle, kUSB_DeviceControlSleepResume, param);
            break;
#if ((defined(USB_DEVICE_CONFIG_REMOTE_WAKEUP)) && (USB_DEVICE_CONFIG_REMOTE_WAKEUP > 0U))
        case kUSB_DeviceStatusRemoteWakeup:
            if (NULL != param)
            {
                status                                        = kStatus_USB_Success;
                ((usb_device_struct_t *)handle)->remotewakeup = (uint8_t)(*(uint8_t *)param);
            }
            break;
#endif
        case kUSB_DeviceStatusBusSuspend:
            status = USB_DeviceControl(handle, kUSB_DeviceControlSuspend, param);
            break;
        case kUSB_DeviceStatusBusSleep:
            status = USB_DeviceControl(handle, kUSB_DeviceControlSleep, param);
            break;
        default:
            /*no action*/
            break;
    }
    return status;
}

#if (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U))
/*!
 * @brief Enable the device dcd module.
 *
 * The function enable the device dcd module.
 *
 * @param[in] handle The device handle got from #USB_DeviceInit.
 *
 * @retval kStatus_USB_Success              The device could run.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 * @retval kStatus_USB_InvalidHandle        The device handle is a NULL pointer. Or the controller handle is invalid.
 *
 */
usb_status_t USB_DeviceDcdEnable(usb_device_handle handle)
{
    return USB_DeviceControl(handle, kUSB_DeviceControlDcdEnable, NULL);
}
/*!
 * @brief Disable the device dcd module.
 *
 * The function disable the device dcd module.
 *
 * @param[in] handle The device handle got from #USB_DeviceInit.
 *
 * @retval kStatus_USB_Success              The dcd is reset and stopped.
 * @retval kStatus_USB_ControllerNotFound   Cannot find the controller.
 * @retval kStatus_USB_InvalidHandle        The device handle is a NULL pointer or the controller handle is invalid.
 *
 */
usb_status_t USB_DeviceDcdDisable(usb_device_handle handle)
{
    return USB_DeviceControl(handle, kUSB_DeviceControlDcdDisable, NULL);
}
#endif

#if USB_DEVICE_CONFIG_USE_TASK
/*!
 * @brief Device task function.
 *
 * The function is used to handle controller message.
 * This function should not be called in application directly.
 *
 * @param handle The device handle got from USB_DeviceInit.
 */
void USB_DeviceTaskFunction(void *deviceHandle)
{
    usb_device_struct_t *handle = (usb_device_struct_t *)deviceHandle;
    usb_device_callback_message_struct_t message;

    if (NULL != deviceHandle)
    {
        message.buffer  = NULL;
        message.length  = 0U;
        message.code    = 0U;
        message.isSetup = 0U;
        /* Get the message from the queue */
        if (KOSA_StatusSuccess ==
            OSA_MsgQGet(handle->notificationQueue, (osa_msg_handle_t)&message, USB_OSA_WAIT_TIMEOUT))
        {
            /* Handle the message */
            (void)USB_DeviceNotification(handle, &message);
        }
    }
}
#endif

/*!
 * @brief Get device stack version function.
 *
 * The function is used to get device stack version.
 *
 * @param[out] version The version structure pointer to keep the device stack version.
 *
 */
void USB_DeviceGetVersion(uint32_t *version)
{
    if (NULL != version)
    {
        *version =
            (uint32_t)USB_MAKE_VERSION(USB_STACK_VERSION_MAJOR, USB_STACK_VERSION_MINOR, USB_STACK_VERSION_BUGFIX);
    }
}

#if ((defined(USB_DEVICE_CONFIG_REMOTE_WAKEUP)) && (USB_DEVICE_CONFIG_REMOTE_WAKEUP > 0U)) ||   \
    (((defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U)) && \
      (defined(FSL_FEATURE_SOC_USB_ANALOG_COUNT) && (FSL_FEATURE_SOC_USB_ANALOG_COUNT > 0U))))
/*!
 * @brief Update the hardware tick.
 *
 * The function is used to update the hardware tick.
 *
 * @param[in] handle The device handle got from #USB_DeviceInit.
 * @param[in] tick Current hardware tick.
 *
 */
usb_status_t USB_DeviceUpdateHwTick(usb_device_handle handle, uint64_t tick)
{
    usb_device_struct_t *deviceHandle;
    usb_status_t status = kStatus_USB_Success;
#if (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)) && \
    (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U))
#elif (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U)) && \
    (defined(FSL_FEATURE_SOC_USB_ANALOG_COUNT) && (FSL_FEATURE_SOC_USB_ANALOG_COUNT > 0U))
    /* fix misra 11.8 */
    uint64_t tempValue;
#endif

    if (handle == NULL)
    {
        return kStatus_USB_InvalidHandle;
    }
    deviceHandle = (usb_device_struct_t *)handle;

    deviceHandle->hwTick = tick;
#if (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)) && \
    (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U))
#ifndef USBHSDCD_IRQS
    status = USB_DeviceControl(handle, kUSB_DeviceControlUpdateHwTick, (void *)(&deviceHandle->hwTick));
#endif
#elif (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U)) && \
    (defined(FSL_FEATURE_SOC_USB_ANALOG_COUNT) && (FSL_FEATURE_SOC_USB_ANALOG_COUNT > 0U))
    tempValue = deviceHandle->hwTick;
    status    = USB_DeviceControl(handle, kUSB_DeviceControlUpdateHwTick, (void *)(&tempValue));
#endif
    return status;
}
#endif
#endif /* USB_DEVICE_CONFIG_NUM */
