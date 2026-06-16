/*
 * Copyright (c) 2015-2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2021 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_common.h"

#define SDK_MEM_MAGIC_NUMBER 12345U

typedef struct _mem_align_control_block
{
    uint16_t identifier; /*!< Identifier for the memory control block. */
    uint16_t offset;     /*!< offset from aligned address to real address */
} mem_align_cb_t;

/* Component ID definition, used by tools. */
#ifndef FSL_COMPONENT_ID
#define FSL_COMPONENT_ID "platform.drivers.common"
#endif

void *SDK_Malloc(size_t size, size_t alignbytes)
{
    mem_align_cb_t *p_cb = NULL;
    uint32_t alignedsize;

    /* Check overflow. */
    alignedsize = SDK_SIZEALIGN(size, alignbytes);
    if (alignedsize < size)
    {
        return NULL;
    }

    if (alignedsize > SIZE_MAX - alignbytes - sizeof(mem_align_cb_t))
    {
        return NULL;
    }

    alignedsize += alignbytes + sizeof(mem_align_cb_t);

    uint8_t *p_addr = (uint8_t *)malloc(alignedsize);

    if (p_addr == NULL)
    {
        return NULL;
    }

    uint8_t *p_align_addr = (uint8_t *)(uintptr_t)SDK_SIZEALIGN((uintptr_t)p_addr + sizeof(mem_align_cb_t), alignbytes);

    p_cb             = (mem_align_cb_t *)(p_align_addr - 4U);
    p_cb->identifier = SDK_MEM_MAGIC_NUMBER;
    p_cb->offset     = (uint16_t)(p_align_addr - p_addr);

    return p_align_addr;
}

void SDK_Free(void *ptr)
{
    uint8_t *p_free = (uint8_t *)ptr;
    mem_align_cb_t *p_cb = (mem_align_cb_t *)(p_free - 4U);

    if (p_cb->identifier != SDK_MEM_MAGIC_NUMBER)
    {
        return;
    }

    free(p_free - p_cb->offset);
}
