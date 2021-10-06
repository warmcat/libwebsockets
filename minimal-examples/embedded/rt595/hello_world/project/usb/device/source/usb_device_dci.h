/*
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_DEVICE_DCI_H__
#define __USB_DEVICE_DCI_H__

/*!
 * @addtogroup usb_device_controller_driver
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief Macro to define controller handle */
#define usb_device_controller_handle usb_device_handle
#define USB_DEVICE_MESSAGES_SIZE \
    (sizeof(uint32_t) * (1U + (sizeof(usb_device_callback_message_struct_t) - 1U) / sizeof(uint32_t)))
/*! @brief Available notify types for device notification */
typedef enum _usb_device_notification
{
    kUSB_DeviceNotifyBusReset = 0x10U, /*!< Reset signal detected */
    kUSB_DeviceNotifySuspend,          /*!< Suspend signal detected */
    kUSB_DeviceNotifyResume,           /*!< Resume signal detected */
    kUSB_DeviceNotifyLPMSleep,         /*!< LPM signal detected */
    kUSB_DeviceNotifyLPMResume,        /*!< Resume signal detected */
    kUSB_DeviceNotifyError,            /*!< Errors happened in bus */
    kUSB_DeviceNotifyDetach,           /*!< Device disconnected from a host */
    kUSB_DeviceNotifyAttach,           /*!< Device connected to a host */
#if (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U))
    kUSB_DeviceNotifyDcdDetectFinished, /*!< Device charger detection finished */
#endif
} usb_device_notification_t;

/*! @brief Device notification message structure */
typedef struct _usb_device_callback_message_struct
{
    uint8_t *buffer; /*!< Transferred buffer */
    uint32_t length; /*!< Transferred data length */
    uint8_t code;    /*!< Notification code */
    uint8_t isSetup; /*!< Is in a setup phase */
} usb_device_callback_message_struct_t;

/*! @brief Control type for controller */
typedef enum _usb_device_control_type
{
    kUSB_DeviceControlRun = 0U,          /*!< Enable the device functionality */
    kUSB_DeviceControlStop,              /*!< Disable the device functionality */
    kUSB_DeviceControlEndpointInit,      /*!< Initialize a specified endpoint */
    kUSB_DeviceControlEndpointDeinit,    /*!< De-initialize a specified endpoint */
    kUSB_DeviceControlEndpointStall,     /*!< Stall a specified endpoint */
    kUSB_DeviceControlEndpointUnstall,   /*!< Un-stall a specified endpoint */
    kUSB_DeviceControlGetDeviceStatus,   /*!< Get device status */
    kUSB_DeviceControlGetEndpointStatus, /*!< Get endpoint status */
    kUSB_DeviceControlSetDeviceAddress,  /*!< Set device address */
    kUSB_DeviceControlGetSynchFrame,     /*!< Get current frame */
    kUSB_DeviceControlResume,            /*!< Drive controller to generate a resume signal in USB bus */
    kUSB_DeviceControlSleepResume,       /*!< Drive controller to generate a LPM resume signal in USB bus */
    kUSB_DeviceControlSuspend,           /*!< Drive controller to enter into suspend mode */
    kUSB_DeviceControlSleep,             /*!< Drive controller to enter into sleep mode */
    kUSB_DeviceControlSetDefaultStatus,  /*!< Set controller to default status */
    kUSB_DeviceControlGetSpeed,          /*!< Get current speed */
    kUSB_DeviceControlGetOtgStatus,      /*!< Get OTG status */
    kUSB_DeviceControlSetOtgStatus,      /*!< Set OTG status */
    kUSB_DeviceControlSetTestMode,       /*!< Drive xCHI into test mode */
    kUSB_DeviceControlGetRemoteWakeUp,   /*!< Get flag of LPM Remote Wake-up Enabled by USB host. */
#if (defined(USB_DEVICE_CONFIG_CHARGER_DETECT) && (USB_DEVICE_CONFIG_CHARGER_DETECT > 0U))
    kUSB_DeviceControlDcdDisable, /*!< disable dcd module function. */
    kUSB_DeviceControlDcdEnable,  /*!< enable dcd module function. */
#endif
    kUSB_DeviceControlPreSetDeviceAddress, /*!< Pre set device address */
    kUSB_DeviceControlUpdateHwTick,        /*!< update hardware tick */
#if defined(USB_DEVICE_CONFIG_GET_SOF_COUNT) && (USB_DEVICE_CONFIG_GET_SOF_COUNT > 0U)
    kUSB_DeviceControlGetCurrentFrameCount, /*!< Get current frame count */
#endif
} usb_device_control_type_t;

/*! @brief USB device controller initialization function typedef */
typedef usb_status_t (*usb_device_controller_init_t)(uint8_t controllerId,
                                                     usb_device_handle handle,
                                                     usb_device_controller_handle *controllerHandle);

/*! @brief USB device controller de-initialization function typedef */
typedef usb_status_t (*usb_device_controller_deinit_t)(usb_device_controller_handle controllerHandle);

/*! @brief USB device controller send data function typedef */
typedef usb_status_t (*usb_device_controller_send_t)(usb_device_controller_handle controllerHandle,
                                                     uint8_t endpointAddress,
                                                     uint8_t *buffer,
                                                     uint32_t length);

/*! @brief USB device controller receive data function typedef */
typedef usb_status_t (*usb_device_controller_recv_t)(usb_device_controller_handle controllerHandle,
                                                     uint8_t endpointAddress,
                                                     uint8_t *buffer,
                                                     uint32_t length);

/*! @brief USB device controller cancel transfer function in a specified endpoint typedef */
typedef usb_status_t (*usb_device_controller_cancel_t)(usb_device_controller_handle controllerHandle,
                                                       uint8_t endpointAddress);

/*! @brief USB device controller control function typedef */
typedef usb_status_t (*usb_device_controller_control_t)(usb_device_controller_handle controllerHandle,
                                                        usb_device_control_type_t command,
                                                        void *param);

/*! @brief USB device controller interface structure */
typedef struct _usb_device_controller_interface_struct
{
    usb_device_controller_init_t deviceInit;       /*!< Controller initialization */
    usb_device_controller_deinit_t deviceDeinit;   /*!< Controller de-initialization */
    usb_device_controller_send_t deviceSend;       /*!< Controller send data */
    usb_device_controller_recv_t deviceRecv;       /*!< Controller receive data */
    usb_device_controller_cancel_t deviceCancel;   /*!< Controller cancel transfer */
    usb_device_controller_control_t deviceControl; /*!< Controller control */
} usb_device_controller_interface_struct_t;

/*! @brief USB device status structure */
typedef struct _usb_device_struct
{
#if ((defined(USB_DEVICE_CONFIG_REMOTE_WAKEUP)) && (USB_DEVICE_CONFIG_REMOTE_WAKEUP > 0U)) || \
    (defined(FSL_FEATURE_SOC_USB_ANALOG_COUNT) && (FSL_FEATURE_SOC_USB_ANALOG_COUNT > 0U))
    volatile uint64_t hwTick; /*!< Current hw tick(ms)*/
#endif
    usb_device_controller_handle controllerHandle;                       /*!< Controller handle */
    const usb_device_controller_interface_struct_t *controllerInterface; /*!< Controller interface handle */
#if USB_DEVICE_CONFIG_USE_TASK
    OSA_MSGQ_HANDLE_DEFINE(notificationQueueBuffer,
                           USB_DEVICE_CONFIG_MAX_MESSAGES,
                           USB_DEVICE_MESSAGES_SIZE); /*!< Message queue buffer*/
    osa_msgq_handle_t notificationQueue;              /*!< Message queue*/
#endif
    usb_device_callback_t deviceCallback; /*!< Device callback function pointer */
    usb_device_endpoint_callback_struct_t
        epCallback[USB_DEVICE_CONFIG_ENDPOINTS << 1U]; /*!< Endpoint callback function structure */
    uint8_t deviceAddress;                             /*!< Current device address */
    uint8_t controllerId;                              /*!< Controller ID */
    uint8_t state;                                     /*!< Current device state */
#if ((defined(USB_DEVICE_CONFIG_REMOTE_WAKEUP)) && (USB_DEVICE_CONFIG_REMOTE_WAKEUP > 0U))
    uint8_t remotewakeup; /*!< Remote wakeup is enabled or not */
#endif
    uint8_t isResetting; /*!< Is doing device reset or not */
#if (defined(USB_DEVICE_CONFIG_USE_TASK) && (USB_DEVICE_CONFIG_USE_TASK > 0U))
    uint8_t epCallbackDirectly; /*!< Whether call ep callback directly when the task is enabled */
#endif
} usb_device_struct_t;

/*******************************************************************************
 * API
 ******************************************************************************/
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
usb_status_t USB_DeviceNotificationTrigger(void *handle, void *msg);
/*! @}*/

#endif /* __USB_DEVICE_DCI_H__ */
