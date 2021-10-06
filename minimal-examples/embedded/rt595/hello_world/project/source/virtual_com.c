/*
 * Copyright 2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
/*${standard_header_anchor}*/
#include "fsl_device_registers.h"
#include "clock_config.h"
#include "fsl_debug_console.h"
#include "board.h"

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_class.h"
#include "usb_device_cdc_acm.h"
#include "usb_device_ch9.h"

#include "usb_device_descriptor.h"
#include "composite.h"

#include "private.h"
#include <string.h>

#if ((defined FSL_FEATURE_SOC_USBPHY_COUNT) && (FSL_FEATURE_SOC_USBPHY_COUNT > 0U))
#include "usb_phy.h"
#endif

lws_dll2_owner_t scheduler;

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
extern usb_device_endpoint_struct_t g_cdcVcomDicEndpoints[];
extern usb_device_endpoint_struct_t g_cdcVcomDicEndpoints_2[];
extern usb_device_endpoint_struct_t g_cdcVcomCicEndpoints[];
extern usb_device_endpoint_struct_t g_cdcVcomCicEndpoints_2[];
extern usb_device_class_struct_t g_UsbDeviceCdcVcomConfig[2];
/* Line coding of cdc device */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
static uint8_t s_lineCoding[USB_DEVICE_CONFIG_CDC_ACM][LINE_CODING_SIZE] = {
    {/* E.g. 0x00,0xC2,0x01,0x00 : 0x0001C200 is 115200 bits per second */
     (LINE_CODING_DTERATE >> 0U) & 0x000000FFU, (LINE_CODING_DTERATE >> 8U) & 0x000000FFU,
     (LINE_CODING_DTERATE >> 16U) & 0x000000FFU, (LINE_CODING_DTERATE >> 24U) & 0x000000FFU, LINE_CODING_CHARFORMAT,
     LINE_CODING_PARITYTYPE, LINE_CODING_DATABITS},
    {/* E.g. 0x00,0xC2,0x01,0x00 : 0x0001C200 is 115200 bits per second */
     (LINE_CODING_DTERATE >> 0U) & 0x000000FFU, (LINE_CODING_DTERATE >> 8U) & 0x000000FFU,
     (LINE_CODING_DTERATE >> 16U) & 0x000000FFU, (LINE_CODING_DTERATE >> 24U) & 0x000000FFU, LINE_CODING_CHARFORMAT,
     LINE_CODING_PARITYTYPE, LINE_CODING_DATABITS},
};

/* Abstract state of cdc device */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
static uint8_t s_abstractState[USB_DEVICE_CONFIG_CDC_ACM][COMM_FEATURE_DATA_SIZE] = {
    {(STATUS_ABSTRACT_STATE >> 0U) & 0x00FFU, (STATUS_ABSTRACT_STATE >> 8U) & 0x00FFU},
    {(STATUS_ABSTRACT_STATE >> 0U) & 0x00FFU, (STATUS_ABSTRACT_STATE >> 8U) & 0x00FFU},
};

/* Country code of cdc device */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
static uint8_t s_countryCode[USB_DEVICE_CONFIG_CDC_ACM][COMM_FEATURE_DATA_SIZE] = {
    {(COUNTRY_SETTING >> 0U) & 0x00FFU, (COUNTRY_SETTING >> 8U) & 0x00FFU},
    {(COUNTRY_SETTING >> 0U) & 0x00FFU, (COUNTRY_SETTING >> 8U) & 0x00FFU},
};

/* CDC ACM information */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
usb_cdc_acm_info_t s_usbCdcAcmInfo[USB_DEVICE_CONFIG_CDC_ACM] = {
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0, 0, 0, 0},
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0, 0, 0, 0},
};
/* Data buffer for receiving and sending*/
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
	static uint8_t s_currRecvBuf[USB_DEVICE_CONFIG_CDC_ACM][DATA_BUFF_SIZE];
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
	static uint8_t s_currSendBuf[USB_DEVICE_CONFIG_CDC_ACM][DATA_BUFF_SIZE];
volatile static uint32_t s_recvSize[USB_DEVICE_CONFIG_CDC_ACM] = {0};
volatile static uint32_t s_sendSize[USB_DEVICE_CONFIG_CDC_ACM] = {0};

volatile static usb_device_composite_struct_t *g_deviceComposite;

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief CDC class specific callback function.
 *last_tick_low
 * This function handles the CDC class specific requests.
 *
 * @param handle          The CDC ACM class handle.
 * @param event           The CDC ACM class event type.
 * @param param           The parameter of the class specific request.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcVcomCallback(class_handle_t handle, uint32_t event, void *param)
{
    uint32_t len;
    uint8_t *uartBitmap;
    usb_cdc_acm_info_t *acmInfo;
    usb_device_cdc_acm_request_param_struct_t *acmReqParam;
    usb_device_endpoint_callback_message_struct_t *epCbParam;
    volatile usb_cdc_vcom_struct_t *vcomInstance;
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t i;
    acmReqParam = (usb_device_cdc_acm_request_param_struct_t *)param;
    epCbParam   = (usb_device_endpoint_callback_message_struct_t *)param;

    for (i = 0; i < USB_DEVICE_CONFIG_CDC_ACM; i++)
    {
        if (handle == g_deviceComposite->cdcVcom[i].cdcAcmHandle)
        {
            break;
        }
    }
    if (i >= USB_DEVICE_CONFIG_CDC_ACM)
    {
        return error;
    }
    vcomInstance = &g_deviceComposite->cdcVcom[i];
    acmInfo      = vcomInstance->usbCdcAcmInfo;
    switch (event)
    {
        case kUSB_DeviceCdcEventSendResponse:
        {
            if ((epCbParam->length != 0) && (!(epCbParam->length % vcomInstance->bulkInEndpointMaxPacketSize)))
            {
                /* If the last packet is the size of endpoint, then send also zero-ended packet,
                 ** meaning that we want to inform the host that we do not have any additional
                 ** data, so it can flush the output.
                 */
                error = USB_DeviceCdcAcmSend(handle, vcomInstance->bulkInEndpoint, NULL, 0);
            }
            else if ((1 == vcomInstance->attach) && (1 == vcomInstance->startTransactions))
            {
                if ((epCbParam->buffer != NULL) || ((epCbParam->buffer == NULL) && (epCbParam->length == 0)))
                {
                    /* User: add your own code for send complete event */
                    /* Schedule buffer for next receive event */
                    error = USB_DeviceCdcAcmRecv(handle, vcomInstance->bulkOutEndpoint, vcomInstance->currRecvBuf,
                                                 vcomInstance->bulkOutEndpointMaxPacketSize);
                }
            }
            else
            {
            }
        }
        break;
        case kUSB_DeviceCdcEventRecvResponse:
        {
            if ((1 == vcomInstance->attach) && (1 == vcomInstance->startTransactions))
            {
                vcomInstance->recvSize = epCbParam->length;

                if (!vcomInstance->recvSize)
                {
                    /* Schedule buffer for next rechttps://community.nxp.com/t5/LPCXpresso-IDE/CDC-BulkIn-in-USB-CDC-Example/td-p/550945eive event */
                    error = USB_DeviceCdcAcmRecv(handle, vcomInstance->bulkOutEndpoint, vcomInstance->currRecvBuf,
                                                 vcomInstance->bulkOutEndpointMaxPacketSize);
                }
            }
        }
        break;
        case kUSB_DeviceCdcEventSerialStateNotif:
            ((usb_device_cdc_acm_struct_t *)handle)->hasSentState = 0;
            error                                                 = kStatus_USB_Success;
            break;
        case kUSB_DeviceCdcEventSendEncapsulatedCommand:
            break;
        case kUSB_DeviceCdcEventGetEncapsulatedResponse:
            break;
        case kUSB_DeviceCdcEventSetCommFeature:
            if (USB_DEVICE_CDC_FEATURE_ABSTRACT_STATE == acmReqParam->setupValue)
            {
                if (1 == acmReqParam->isSetup)
                {
                    *(acmReqParam->buffer) = vcomInstance->abstractState;
                    *(acmReqParam->length) = COMM_FEATURE_DATA_SIZE;
                }
                else
                {
                    /* no action, data phase, s_abstractState has been assigned */
                }
                error = kStatus_USB_Success;
            }
            else if (USB_DEVICE_CDC_FEATURE_COUNTRY_SETTING == acmReqParam->setupValue)
            {
                if (1 == acmReqParam->isSetup)
                {
                    *(acmReqParam->buffer) = vcomInstance->countryCode;
                    *(acmReqParam->length) = COMM_FEATURE_DATA_SIZE;
                }
                else
                {
                    /* no action, data phase, s_countryCode has been assigned */
                }
                error = kStatus_USB_Success;
            }
            else
            {
                /* no action, return kStatus_USB_InvalidRequest */
            }
            break;
        case kUSB_DeviceCdcEventGetCommFeature:
            if (USB_DEVICE_CDC_FEATURE_ABSTRACT_STATE == acmReqParam->setupValue)
            {
                *(acmReqParam->buffer) = vcomInstance->abstractState;
                *(acmReqParam->length) = COMM_FEATURE_DATA_SIZE;
                error                  = kStatus_USB_Success;
            }
            else if (USB_DEVICE_CDC_FEATURE_COUNTRY_SETTING == acmReqParam->setupValue)
            {
                *(acmReqParam->buffer) = vcomInstance->countryCode;
                *(acmReqParam->length) = COMM_FEATURE_DATA_SIZE;
                error                  = kStatus_USB_Success;
            }
            else
            {
                /* no action, return kStatus_USB_InvalidRequest */
            }
            break;
        case kUSB_DeviceCdcEventClearCommFeature:
            break;
        case kUSB_DeviceCdcEventGetLineCoding:
            *(acmReqParam->buffer) = vcomInstance->lineCoding;
            *(acmReqParam->length) = LINE_CODING_SIZE;
            error                  = kStatus_USB_Success;
            break;
        case kUSB_DeviceCdcEventSetLineCoding:
        {
            if (1 == acmReqParam->isSetup)
            {
                *(acmReqParam->buffer) = vcomInstance->lineCoding;
                *(acmReqParam->length) = LINE_CODING_SIZE;
            }
            else
            {
                /* no action, data phase, s_lineCoding has been assigned */
            }
            error = kStatus_USB_Success;
        }
        break;
        case kUSB_DeviceCdcEventSetControlLineState:
        {
            error                     = kStatus_USB_Success;
            vcomInstance->usbCdcAcmInfo->dteStatus = acmReqParam->setupValue;
            /* activate/deactivate Tx carrier */
            if (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_CARRIER_ACTIVATION)
            {
                acmInfo->uartState |= USB_DEVICE_CDC_UART_STATE_TX_CARRIER;
            }
            else
            {
                acmInfo->uartState &= (uint16_t)~USB_DEVICE_CDC_UART_STATE_TX_CARRIER;
            }

            /* activate carrier and DTE. Com port of terminal tool running on PC is open now */
            if (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_DTE_PRESENCE)
            {
                acmInfo->uartState |= USB_DEVICE_CDC_UART_STATE_RX_CARRIER;
            }
            /* Com port of terminal tool running on PC is closed now */
            else
            {
                acmInfo->uartState &= (uint16_t)~USB_DEVICE_CDC_UART_STATE_RX_CARRIER;
            }

            /* Indicates to DCE if DTE is present or not */
            acmInfo->dtePresent = (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_DTE_PRESENCE) ? true : false;

            /* Initialize the serial state buffer */
            acmInfo->serialStateBuf[0] = NOTIF_REQUEST_TYPE;                /* bmRequestType */
            acmInfo->serialStateBuf[1] = USB_DEVICE_CDC_NOTIF_SERIAL_STATE; /* bNotification */
            acmInfo->serialStateBuf[2] = 0x00;                              /* wValue */
            acmInfo->serialStateBuf[3] = 0x00;
            acmInfo->serialStateBuf[4] = 0x00; /* wIndex */
            acmInfo->serialStateBuf[5] = 0x00;
            acmInfo->serialStateBuf[6] = UART_BITMAP_SIZE; /* wLength */
            acmInfo->serialStateBuf[7] = 0x00;
            /* Notify to host the line state */
            acmInfo->serialStateBuf[4] = acmReqParam->interfaceIndex;
            /* Lower byte of UART BITMAP */
            uartBitmap    = (uint8_t *)&acmInfo->serialStateBuf[NOTIF_PACKET_SIZE + UART_BITMAP_SIZE - 2];
            uartBitmap[0] = acmInfo->uartState & 0xFFu;
            uartBitmap[1] = (acmInfo->uartState >> 8) & 0xFFu;
            len           = (uint32_t)(NOTIF_PACKET_SIZE + UART_BITMAP_SIZE);
            if (0 == ((usb_device_cdc_acm_struct_t *)handle)->hasSentState)
            {
                error = USB_DeviceCdcAcmSend(handle, vcomInstance->interruptEndpoint, acmInfo->serialStateBuf, len);
                if (kStatus_USB_Success != error)
                {
                    usb_echo("kUSB_DeviceCdcEventSetControlLineState error!");
                }
                ((usb_device_cdc_acm_struct_t *)handle)->hasSentState = 1;
            }

            /* Update status */
            if (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_CARRIER_ACTIVATION)
            {
                /*  To do: CARRIER_ACTIVATED */
            }
            else
            {
                /* To do: CARRIER_DEACTIVATED */
            }
            if (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_DTE_PRESENCE)
            {
                /* DTE_ACTIVATED */
                if (1 == vcomInstance->attach)
                {
                    vcomInstance->startTransactions = 1;
                }
            }
            else
            {
                /* DTE_DEACTIVATED */
                if (1 == vcomInstance->attach)
                {
                    vcomInstance->startTransactions = 0;
                }
            }
        }
        break;
        case kUSB_DeviceCdcEventSendBreak:
            break;
        default:
            break;
    }

    return error;
}

vcring_t vcr_log, vcr_txp_out, vcr_txp_in;


extern usb_device_composite_struct_t g_composite;

/*!
 * @brief Application task function.
 *
 * This function runs the task for application.
 *
 * @return None.
 */
void USB_DeviceCdcVcomTask(void)
{
    usb_status_t error = kStatus_USB_Error;
    volatile usb_cdc_vcom_struct_t *vci = &g_deviceComposite->cdcVcom[0];
    const uint8_t *p;
    size_t n;

    /* emit logs on CDC 0 */

    n = next_chonk(&vcr_log, &p);

	if (vci->attach && vci->startTransactions && n) {

		if (n > vci->bulkInEndpointMaxPacketSize)
			n = vci->bulkInEndpointMaxPacketSize;

		if (USB_DeviceCdcAcmSend(vci->cdcAcmHandle, vci->bulkInEndpoint, (uint8_t *)p, n) == kStatus_USB_Success)
			consume_chonk(&vcr_log, n);
	}

	/* SS transport on CDC 1 */

    vci++;
	if (!vci->attach || !vci->startTransactions)
		return;

	if (vci->recvSize &&
		USB_CANCELLED_TRANSFER_LENGTH != vci->recvSize) {
		n = space_available(&vcr_txp_in);

	//	lwsl_warn("%s: len %u in", __func__, vci->recvSize);
	//	lwsl_hexdump_warn(vci->currRecvBuf, vci->recvSize);

		n = tm->info.txp_cpath.ops_in->event_read(
				tm->info.txp_cpath.priv_in, vci->currRecvBuf, vci->recvSize);
		vci->recvSize = 0;
		USB_DeviceSendRequest(g_composite.deviceHandle, vci->bulkOutEndpoint,0,0);
		if (n) {
			/*
			 * The SSS parser can identify the framing is broken,
			 * in that case the transport needs to re-link up
			 */
			tm->info.txp_cpath.ops_in->lost_coherence(
					tm->info.txp_cpath.priv_in);
		}

	}

    n = next_chonk(&vcr_txp_out, &p);

	if (vci->attach && vci->startTransactions && n) {

		if (n > vci->bulkInEndpointMaxPacketSize)
			n = vci->bulkInEndpointMaxPacketSize;

		if (USB_DeviceCdcAcmSend(vci->cdcAcmHandle, vci->bulkInEndpoint, (uint8_t *)p, n) == kStatus_USB_Success)
			consume_chonk(&vcr_txp_out, n);
	}
}

/*!
 * @brief Virtual COM device set configuration function.
 *
 * This function sets configuration for CDC class.
 *
 * @param handle The CDC ACM class handle.
 * @param configure The CDC ACM class configure index.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcVcomSetConfigure(class_handle_t handle, uint8_t configure)
{
    if (USB_COMPOSITE_CONFIGURE_INDEX == configure)
    {
        /*endpoint information for cdc 1*/
        g_deviceComposite->cdcVcom[0].attach = 1;

        g_deviceComposite->cdcVcom[0].interruptEndpoint              = USB_CDC_VCOM_CIC_INTERRUPT_IN_ENDPOINT;
        g_deviceComposite->cdcVcom[0].interruptEndpointMaxPacketSize = g_cdcVcomCicEndpoints[0].maxPacketSize;

        g_deviceComposite->cdcVcom[0].bulkInEndpoint              = USB_CDC_VCOM_DIC_BULK_IN_ENDPOINT;
        g_deviceComposite->cdcVcom[0].bulkInEndpointMaxPacketSize = g_cdcVcomDicEndpoints[0].maxPacketSize;

        g_deviceComposite->cdcVcom[0].bulkOutEndpoint              = USB_CDC_VCOM_DIC_BULK_OUT_ENDPOINT;
        g_deviceComposite->cdcVcom[0].bulkOutEndpointMaxPacketSize = g_cdcVcomDicEndpoints[1].maxPacketSize;

        /* Schedule buffer for receive */
        USB_DeviceCdcAcmRecv(g_deviceComposite->cdcVcom[0].cdcAcmHandle, g_deviceComposite->cdcVcom[0].bulkOutEndpoint,
                             s_currRecvBuf[0], g_deviceComposite->cdcVcom[0].bulkOutEndpointMaxPacketSize);

        /*endpoint information for cdc 2*/
        g_deviceComposite->cdcVcom[1].attach = 1;

        g_deviceComposite->cdcVcom[1].interruptEndpoint              = USB_CDC_VCOM_CIC_INTERRUPT_IN_ENDPOINT_2;
        g_deviceComposite->cdcVcom[1].interruptEndpointMaxPacketSize = g_cdcVcomCicEndpoints_2[0].maxPacketSize;

        g_deviceComposite->cdcVcom[1].bulkInEndpoint              = USB_CDC_VCOM_DIC_BULK_IN_ENDPOINT_2;
        g_deviceComposite->cdcVcom[1].bulkInEndpointMaxPacketSize = g_cdcVcomDicEndpoints_2[0].maxPacketSize;

        g_deviceComposite->cdcVcom[1].bulkOutEndpoint              = USB_CDC_VCOM_DIC_BULK_OUT_ENDPOINT_2;
        g_deviceComposite->cdcVcom[1].bulkOutEndpointMaxPacketSize = g_cdcVcomDicEndpoints_2[1].maxPacketSize;

        /* Schedule buffer for receive */
        USB_DeviceCdcAcmRecv(g_deviceComposite->cdcVcom[1].cdcAcmHandle, g_deviceComposite->cdcVcom[1].bulkOutEndpoint,
                             s_currRecvBuf[1], g_deviceComposite->cdcVcom[1].bulkOutEndpointMaxPacketSize);
    }
    return kStatus_USB_Success;
}

/*!
 * @brief Virtual COM device initialization function.
 *
 * This function initializes the device with the composite device class information.
 *
 * @param deviceComposite The pointer to the composite device structure.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcVcomInit(usb_device_composite_struct_t *deviceComposite)
{
    g_deviceComposite = deviceComposite;
    for (uint8_t i = 0; i < USB_DEVICE_CONFIG_CDC_ACM; i++)
    {
        g_deviceComposite->cdcVcom[i].lineCoding    = (uint8_t *)&s_lineCoding[i];
        g_deviceComposite->cdcVcom[i].abstractState = (uint8_t *)&s_abstractState[i];
        g_deviceComposite->cdcVcom[i].countryCode   = (uint8_t *)&s_countryCode[i];
        g_deviceComposite->cdcVcom[i].usbCdcAcmInfo = &s_usbCdcAcmInfo[i];
        g_deviceComposite->cdcVcom[i].currRecvBuf   = (uint8_t *)&s_currRecvBuf[i][0];
        ;
        g_deviceComposite->cdcVcom[i].currSendBuf = (uint8_t *)&s_currSendBuf[i][0];
    }
    return kStatus_USB_Success;
}
