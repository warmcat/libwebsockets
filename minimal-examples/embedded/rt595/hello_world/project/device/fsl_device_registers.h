/*
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2016-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __FSL_DEVICE_REGISTERS_H__
#define __FSL_DEVICE_REGISTERS_H__

/*
 * Include the cpu specific register header files.
 *
 * The CPU macro should be declared in the project or makefile.
 */
#if (defined(CPU_MIMXRT595SFAWC_cm33) || defined(CPU_MIMXRT595SFFOC_cm33))

#define MIMXRT595S_cm33_SERIES

/* CMSIS-style register definitions */
#include "MIMXRT595S_cm33.h"
/* CPU specific feature definitions */
#include "MIMXRT595S_cm33_features.h"

#elif (defined(CPU_MIMXRT595SFAWC_dsp) || defined(CPU_MIMXRT595SFFOC_dsp))

#define MIMXRT595S_dsp_SERIES

/* CMSIS-style register definitions */
#include "MIMXRT595S_dsp.h"
/* CPU specific feature definitions */
#include "MIMXRT595S_dsp_features.h"

#else
    #error "No valid CPU defined!"
#endif

#endif /* __FSL_DEVICE_REGISTERS_H__ */

/*******************************************************************************
 * EOF
 ******************************************************************************/
