/*!
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2019 NXP
 *
 *
 * This is the source file for the OS Abstraction layer for MQXLite.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *********************************************************************************
*************************************************************************************
* Include
*************************************************************************************
********************************************************************************** */
#include "fsl_component_generic_list.h"
#include "fsl_os_abstraction.h"
#include "fsl_os_abstraction_bm.h"
#include <string.h>

/*! *********************************************************************************
*************************************************************************************
* Private macros
*************************************************************************************
********************************************************************************** */

/* Weak function. */
#if defined(__GNUC__)
#define __WEAK_FUNC __attribute__((weak))
#elif defined(__ICCARM__)
#define __WEAK_FUNC __weak
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
#define __WEAK_FUNC __attribute__((weak))
#endif

#ifdef DEBUG_ASSERT
#define OS_ASSERT(condition) \
    if (!(condition))        \
        while (1)            \
            ;
#else
#define OS_ASSERT(condition) (void)(condition);
#endif

/************************************************************************************
*************************************************************************************
* Private type definitions
*************************************************************************************
************************************************************************************/

/*! @brief Type for an semaphore */
typedef struct Semaphore
{
#if (defined(FSL_OSA_BM_TIMEOUT_ENABLE) && (FSL_OSA_BM_TIMEOUT_ENABLE > 0U))
    uint32_t time_start; /*!< The time to start timeout                        */
    uint32_t timeout;    /*!< Timeout to wait in milliseconds                  */
#endif
    volatile uint8_t isWaiting; /*!< Is any task waiting for a timeout on this object */
    volatile uint8_t semCount;  /*!< The count value of the object                    */

} semaphore_t;

/*! @brief Type for a mutex */
typedef struct Mutex
{
#if (defined(FSL_OSA_BM_TIMEOUT_ENABLE) && (FSL_OSA_BM_TIMEOUT_ENABLE > 0U))
    uint32_t time_start; /*!< The time to start timeout                       */
    uint32_t timeout;    /*!< Timeout to wait in milliseconds                 */
#endif
    volatile uint8_t isWaiting; /*!< Is any task waiting for a timeout on this mutex */
    volatile uint8_t isLocked;  /*!< Is the object locked or not                     */
} mutex_t;

#define gIdleTaskPriority_c    ((task_priority_t)0)
#define gInvalidTaskPriority_c ((task_priority_t)-1)

/*! @brief Type for a task handler, returned by the OSA_TaskCreate function */
typedef void (*task_t)(task_param_t param);
/*! @brief Task control block for bare metal. */
typedef struct TaskControlBlock
{
    list_element_t link;
    osa_task_ptr_t p_func;        /*!< Task's entry                           */
    osa_task_priority_t priority; /*!< Task's priority                        */
    osa_task_param_t param;       /*!< Task's parameter                       */
    uint8_t haveToRun;            /*!< Task was signaled                      */
} task_control_block_t;

/*! @brief Type for a task pointer */
typedef task_control_block_t *task_handler_t;

/*! @brief Type for a task stack */
typedef uint32_t task_stack_t;

/*! @brief Type for an event object */
typedef struct Event
{
    uint32_t time_start;          /*!< The time to start timeout                        */
    uint32_t timeout;             /*!< Timeout to wait in milliseconds                  */
    volatile event_flags_t flags; /*!< The flags status                                 */
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
    task_handler_t waitingTask; /*!< Handler to the waiting task                      */
#endif
    uint8_t autoClear;          /*!< Auto clear or manual clear                       */
    volatile uint8_t isWaiting; /*!< Is any task waiting for a timeout on this event  */
} event_t;

/*! @brief Type for a message queue */
typedef struct MsgQueue
{
    volatile uint8_t isWaiting; /*!< Is any task waiting for a timeout    */
    uint32_t time_start;        /*!< The time to start timeout            */
    uint32_t timeout;           /*!< Timeout to wait in milliseconds      */
    uint32_t size;              /*!< The size(byte) of a single message   */
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
    task_handler_t waitingTask; /*!< Handler to the waiting task          */
#endif
    uint8_t *queueMem; /*!< Points to the queue memory           */
    uint16_t number;   /*!< The number of messages in the queue  */
    uint16_t max;      /*!< The max number of queue messages     */
    uint16_t head;     /*!< Index of the next message to be read */
    uint16_t tail;     /*!< Index of the next place to write to  */
} msg_queue_t;

/*! @brief Type for a message queue handler */
typedef msg_queue_t *msg_queue_handler_t;

/*! @brief State structure for bm osa manager. */
typedef struct _osa_state
{
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
    list_label_t taskList;
    task_handler_t curTaskHandler;
#endif
    volatile uint32_t interruptDisableCount;
    volatile uint32_t tickCounter;
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
#if (defined(FSL_OSA_MAIN_FUNC_ENABLE) && (FSL_OSA_MAIN_FUNC_ENABLE > 0U))
    OSA_TASK_HANDLE_DEFINE(mainTaskHandle);
#endif
#endif
} osa_state_t;

/*! *********************************************************************************
*************************************************************************************
* Private prototypes
*************************************************************************************
********************************************************************************** */
__WEAK_FUNC void main_task(osa_task_param_t arg);
__WEAK_FUNC void main_task(osa_task_param_t arg)
{
}
__WEAK_FUNC void OSA_TimeInit(void);
__WEAK_FUNC uint32_t OSA_TimeDiff(uint32_t time_start, uint32_t time_end);

/*! *********************************************************************************
*************************************************************************************
* Public memory declarations
*************************************************************************************
********************************************************************************** */
const uint8_t gUseRtos_c = USE_RTOS; /* USE_RTOS = 0 for BareMetal and 1 for OS */

/*! *********************************************************************************
*************************************************************************************
* Private memory declarations
*************************************************************************************
********************************************************************************** */
static osa_state_t s_osaState;

/*! *********************************************************************************
*************************************************************************************
* Public functions
*************************************************************************************
********************************************************************************** */
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MemoryAllocate
 * Description   : Reserves the requested amount of memory in bytes.
 *
 *END**************************************************************************/
void *OSA_MemoryAllocate(uint32_t length)
{
    void *p = (void *)malloc(length);

    if (NULL != p)
    {
        (void)memset(p, 0, length);
    }

    return p;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MemoryFree
 * Description   : Frees the memory previously reserved.
 *
 *END**************************************************************************/
void OSA_MemoryFree(void *p)
{
    free(p);
}

void OSA_EnterCritical(uint32_t *sr)
{
    *sr = DisableGlobalIRQ();
}

void OSA_ExitCritical(uint32_t sr)
{
    EnableGlobalIRQ(sr);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_EnableIRQGlobal
 * Description   : Disable system interrupt.
 *
 *END**************************************************************************/
void OSA_EnableIRQGlobal(void)
{
    if (s_osaState.interruptDisableCount > 0U)
    {
        s_osaState.interruptDisableCount--;

        if (0U == s_osaState.interruptDisableCount)
        {
            __enable_irq();
        }
        /* call core API to enable the global interrupt*/
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_DisableIRQGlobal
 * Description   : Disable system interrupt
 * This function will disable the global interrupt by calling the core API
 *
 *END**************************************************************************/
void OSA_DisableIRQGlobal(void)
{
    /* call core API to disable the global interrupt*/
    __disable_irq();

    /* update counter*/
    s_osaState.interruptDisableCount++;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_TaskGetCurrentHandle
 * Description   : This function is used to get current active task's handler.
 *
 *END**************************************************************************/
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
osa_task_handle_t OSA_TaskGetCurrentHandle(void)
{
    return (osa_task_handle_t)s_osaState.curTaskHandler;
}
#endif
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_EXT_TaskYield
 * Description   : When a task calls this function, it will give up CPU and put
 * itself to the tail of ready list.
 *
 *END**************************************************************************/
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
osa_status_t OSA_TaskYield(void)
{
    return KOSA_StatusSuccess;
}
#endif
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_TaskGetPriority
 * Description   : This function returns task's priority by task handler.
 *
 *END**************************************************************************/
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
osa_task_priority_t OSA_TaskGetPriority(osa_task_handle_t taskHandle)
{
    assert(taskHandle);
    task_handler_t handler = (task_handler_t)taskHandle;
    return handler->priority;
}
#endif

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_TaskSetPriority
 * Description   : This function sets task's priority by task handler.
 *
 *END**************************************************************************/
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
osa_status_t OSA_TaskSetPriority(osa_task_handle_t taskHandle, osa_task_priority_t taskPriority)
{
    assert(taskHandle);
    list_element_handle_t list_element;
    task_control_block_t *tcb = NULL;
#if (defined(GENERIC_LIST_LIGHT) && (GENERIC_LIST_LIGHT > 0U))
    task_control_block_t *preTcb = NULL;
#endif
    task_control_block_t *ptaskStruct = (task_control_block_t *)taskHandle;
    uint32_t regPrimask;

    ptaskStruct->priority = taskPriority;
    (void)LIST_RemoveElement(&ptaskStruct->link);
    /* Insert task control block into the task list. */
    list_element = LIST_GetHead(&s_osaState.taskList);
    while (NULL != list_element)
    {
        tcb = (task_control_block_t *)(void *)list_element;
        if (ptaskStruct->priority <= tcb->priority)
        {
#if (defined(GENERIC_LIST_LIGHT) && (GENERIC_LIST_LIGHT > 0U))
            if (preTcb == NULL)
            {
                (&tcb->link)->list->head = (struct list_element_tag *)(void *)ptaskStruct;
            }
            else
            {
                (&preTcb->link)->next = (struct list_element_tag *)(void *)ptaskStruct;
            }
            (&ptaskStruct->link)->list = (&tcb->link)->list;
            (&ptaskStruct->link)->next = (struct list_element_tag *)(void *)tcb;
            (&ptaskStruct->link)->list->size++;
#else
            (void)LIST_AddPrevElement(&tcb->link, &ptaskStruct->link);
#endif
            break;
        }
#if (defined(GENERIC_LIST_LIGHT) && (GENERIC_LIST_LIGHT > 0U))
        preTcb = tcb;
#endif
        list_element = LIST_GetNext(list_element);
    }
    if (ptaskStruct->priority > tcb->priority)
    {
        OSA_EnterCritical(&regPrimask);
        (void)LIST_AddTail(&s_osaState.taskList, (list_element_handle_t)(void *)&(ptaskStruct->link));
        OSA_ExitCritical(regPrimask);
    }

    return KOSA_StatusSuccess;
}
#endif

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_TaskCreate
 * Description   : This function is used to create a task and make it ready.
 * Param[in]     :  threadDef  - Definition of the thread.
 *                  task_param - Parameter to pass to the new thread.
 * Return Thread handle of the new thread, or NULL if failed.
 *
 *END**************************************************************************/
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
osa_status_t OSA_TaskCreate(osa_task_handle_t taskHandle, const osa_task_def_t *thread_def, osa_task_param_t task_param)
{
    list_element_handle_t list_element;

    task_control_block_t *tcb = NULL;
#if (defined(GENERIC_LIST_LIGHT) && (GENERIC_LIST_LIGHT > 0U))
    task_control_block_t *preTcb = NULL;
#endif
    list_status_t listStatus;

    task_control_block_t *ptaskStruct = (task_control_block_t *)taskHandle;
    uint32_t regPrimask;
    assert(sizeof(task_control_block_t) == OSA_TASK_HANDLE_SIZE);
    assert(taskHandle);

    ptaskStruct->p_func    = thread_def->pthread;
    ptaskStruct->haveToRun = 1U;
    ptaskStruct->priority  = (uint16_t)PRIORITY_OSA_TO_RTOS(thread_def->tpriority);
    ptaskStruct->param     = task_param;

    list_element = LIST_GetHead(&s_osaState.taskList);
    while (NULL != list_element)
    {
        tcb = (task_control_block_t *)(void *)list_element;
        if (ptaskStruct->priority <= tcb->priority)
        {
            OSA_EnterCritical(&regPrimask);
#if (defined(GENERIC_LIST_LIGHT) && (GENERIC_LIST_LIGHT > 0U))
            if (preTcb == NULL)
            {
                (&tcb->link)->list->head = (struct list_element_tag *)(void *)ptaskStruct;
            }
            else
            {
                (&preTcb->link)->next = (struct list_element_tag *)(void *)ptaskStruct;
            }
            (&ptaskStruct->link)->list = (&tcb->link)->list;
            (&ptaskStruct->link)->next = (struct list_element_tag *)(void *)tcb;
            (&ptaskStruct->link)->list->size++;
            OSA_ExitCritical(regPrimask);
            return KOSA_StatusSuccess;
#else
            listStatus = LIST_AddPrevElement(&tcb->link, &ptaskStruct->link);
            OSA_ExitCritical(regPrimask);
            if (listStatus == (list_status_t)kLIST_DuplicateError)
            {
                return KOSA_StatusError;
            }
            break;
#endif
        }
#if (defined(GENERIC_LIST_LIGHT) && (GENERIC_LIST_LIGHT > 0U))
        preTcb = tcb;
#endif
        list_element = LIST_GetNext(list_element);
    }

    if ((NULL == tcb) || (ptaskStruct->priority > tcb->priority))
    {
        OSA_EnterCritical(&regPrimask);
        listStatus = LIST_AddTail(&s_osaState.taskList, (list_element_handle_t)(void *)&(ptaskStruct->link));
        (void)listStatus;
        assert(listStatus == kLIST_Ok);
        OSA_ExitCritical(regPrimask);
    }

    return KOSA_StatusSuccess;
}
#endif

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_TaskDestroy
 * Description   : This function destroy a task.
 * Param[in]     :taskHandle - Thread handle.
 * Return KOSA_StatusSuccess if the task is destroied, otherwise return KOSA_StatusError.
 *
 *END**************************************************************************/
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
osa_status_t OSA_TaskDestroy(osa_task_handle_t taskHandle)
{
    uint32_t regPrimask;
    assert(taskHandle);

    OSA_EnterCritical(&regPrimask);
    (void)LIST_RemoveElement(taskHandle);
    OSA_ExitCritical(regPrimask);
    return KOSA_StatusSuccess;
}
#endif

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_TimeInit
 * Description   : This function initializes the timer used in BM OSA, the
 * functions such as OSA_TimeDelay, OSA_TimeGetMsec, and the timeout are all
 * based on this timer.
 *
 *END**************************************************************************/
__WEAK_FUNC void OSA_TimeInit(void)
{
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
    SysTick->CTRL &= ~(SysTick_CTRL_ENABLE_Msk);
    SysTick->LOAD = (uint32_t)(SystemCoreClock / 1000U - 1U);
    SysTick->VAL  = 0;
    SysTick->CTRL |= SysTick_CTRL_ENABLE_Msk | SysTick_CTRL_TICKINT_Msk | SysTick_CTRL_CLKSOURCE_Msk;
#endif
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_TimeDiff
 * Description   : This function gets the difference between two time stamp,
 * time overflow is considered.
 *
 *END**************************************************************************/
__WEAK_FUNC uint32_t OSA_TimeDiff(uint32_t time_start, uint32_t time_end)
{
    if (time_end >= time_start)
    {
        return time_end - time_start;
    }
    else
    {
        return FSL_OSA_TIME_RANGE - time_start + time_end + 1UL;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA__TimeDelay
 * Description   : This function is used to suspend the active thread for the given number of milliseconds.
 *
 *END**************************************************************************/
void OSA_TimeDelay(uint32_t millisec)
{
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
    uint32_t currTime, timeStart;

    timeStart = OSA_TimeGetMsec();

    do
    {
        currTime = OSA_TimeGetMsec(); /* Get current time stamp */
    } while (millisec >= OSA_TimeDiff(timeStart, currTime));
#endif
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_TimeGetMsec
 * Description   : This function gets current time in milliseconds.
 *
 *END**************************************************************************/
__WEAK_FUNC uint32_t OSA_TimeGetMsec(void)
{
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
    return s_osaState.tickCounter;
#else
    return 0;
#endif
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_SemaphoreCreate
 * Description   : This function is used to create a semaphore.
 * Return         : Semaphore handle of the new semaphore, or NULL if failed.
 *
 *END**************************************************************************/

osa_status_t OSA_SemaphoreCreate(osa_semaphore_handle_t semaphoreHandle, uint32_t initValue)
{
    semaphore_t *pSemStruct = (semaphore_t *)semaphoreHandle;
    assert(sizeof(semaphore_t) <= OSA_SEM_HANDLE_SIZE);
    assert(semaphoreHandle);

    pSemStruct->semCount  = (uint8_t)initValue;
    pSemStruct->isWaiting = 0U;
#if (defined(FSL_OSA_BM_TIMEOUT_ENABLE) && (FSL_OSA_BM_TIMEOUT_ENABLE > 0U))
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)

    pSemStruct->time_start = 0U;
    pSemStruct->timeout    = 0U;
#endif
#endif
    return KOSA_StatusSuccess;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_SemaphoreDestroy
 * Description   : This function is used to destroy a semaphore.
 * Return        : KOSA_StatusSuccess if the semaphore is destroyed successfully, otherwise return KOSA_StatusError.
 *
 *END**************************************************************************/
osa_status_t OSA_SemaphoreDestroy(osa_semaphore_handle_t semaphoreHandle)
{
    assert(semaphoreHandle);
    semaphore_t *pSemStruct = (semaphore_t *)semaphoreHandle;

    /* Destroy semaphoreHandle's data */
    (void)memset(pSemStruct, 0, sizeof(semaphore_t));

    return KOSA_StatusSuccess;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_SemaphoreWait
 * Description   : This function checks the semaphore's counting value, if it is
 * positive, decreases it and returns KOSA_StatusSuccess, otherwise, timeout
 * will be used for wait. The parameter timeout indicates how long should wait
 * in milliseconds. Pass osaWaitForever_c to wait indefinitely, pass 0 will
 * return KOSA_StatusTimeout immediately if semaphore is not positive.
 * This function returns KOSA_StatusSuccess if the semaphore is received, returns
 * KOSA_StatusTimeout if the semaphore is not received within the specified
 * 'timeout', returns KOSA_StatusError if any errors occur during waiting.
 *
 *END**************************************************************************/
osa_status_t OSA_SemaphoreWait(osa_semaphore_handle_t semaphoreHandle, uint32_t millisec)
{
    semaphore_t *pSemStruct = (semaphore_t *)semaphoreHandle;
    uint32_t regPrimask;
    assert(semaphoreHandle);
#if (defined(FSL_OSA_BM_TIMEOUT_ENABLE) && (FSL_OSA_BM_TIMEOUT_ENABLE > 0U))
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
    uint32_t currentTime;
#endif
#endif
    /* Check the sem count first. Deal with timeout only if not already set */

    if (0U != pSemStruct->semCount)
    {
        OSA_EnterCritical(&regPrimask);
        pSemStruct->semCount--;
        pSemStruct->isWaiting = 0U;
        OSA_ExitCritical(regPrimask);
        return KOSA_StatusSuccess;
    }
    else
    {
        if (0U == millisec)
        {
            /* If timeout is 0 and semaphore is not available, return kStatus_OSA_Timeout. */
            return KOSA_StatusTimeout;
        }
#if (defined(FSL_OSA_BM_TIMEOUT_ENABLE) && (FSL_OSA_BM_TIMEOUT_ENABLE > 0U))
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
        else if (0U != pSemStruct->isWaiting)
        {
            /* Check for timeout */
            currentTime = OSA_TimeGetMsec();
            if (pSemStruct->timeout < OSA_TimeDiff(pSemStruct->time_start, currentTime))
            {
                OSA_EnterCritical(&regPrimask);
                pSemStruct->isWaiting = 0U;
                OSA_ExitCritical(regPrimask);
                return KOSA_StatusTimeout;
            }
        }
        else if (millisec != osaWaitForever_c) /* If don't wait forever, start the timer */
        {
            /* Start the timeout counter */
            OSA_EnterCritical(&regPrimask);
            pSemStruct->isWaiting = 1U;
            OSA_ExitCritical(regPrimask);
            pSemStruct->time_start = OSA_TimeGetMsec();
            pSemStruct->timeout    = millisec;
        }
#endif
#endif
        else
        {
            ;
        }
    }

    return KOSA_StatusIdle;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_SemaphorePost
 * Description   : This function is used to wake up one task that wating on the
 * semaphore. If no task is waiting, increase the semaphore. The function returns
 * KOSA_StatusSuccess if the semaphre is post successfully, otherwise returns
 * KOSA_StatusError.
 *
 *END**************************************************************************/
osa_status_t OSA_SemaphorePost(osa_semaphore_handle_t semaphoreHandle)
{
    semaphore_t *pSemStruct = (semaphore_t *)semaphoreHandle;
    uint32_t regPrimask;
    assert(semaphoreHandle);

    /* The max value is 0xFF */
    if (0xFFU == pSemStruct->semCount)
    {
        return KOSA_StatusError;
    }
    OSA_EnterCritical(&regPrimask);
    ++pSemStruct->semCount;
    OSA_ExitCritical(regPrimask);

    return KOSA_StatusSuccess;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MutexCreate
 * Description   : This function is used to create a mutex.
 * Return        : Mutex handle of the new mutex, or NULL if failed.
 *
 *END**************************************************************************/
osa_status_t OSA_MutexCreate(osa_mutex_handle_t mutexHandle)
{
    mutex_t *pMutexStruct = (mutex_t *)mutexHandle;
    assert(sizeof(mutex_t) <= OSA_MUTEX_HANDLE_SIZE);
    assert(mutexHandle);

    pMutexStruct->isLocked  = 0U;
    pMutexStruct->isWaiting = 0U;
#if (defined(FSL_OSA_BM_TIMEOUT_ENABLE) && (FSL_OSA_BM_TIMEOUT_ENABLE > 0U))
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)

    pMutexStruct->time_start = 0u;
    pMutexStruct->timeout    = 0u;
#endif
#endif
    return KOSA_StatusSuccess;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MutexLock
 * Description   : This function checks the mutex's status, if it is unlocked,
 * lock it and returns KOSA_StatusSuccess, otherwise, wait for the mutex.
 * MQX does not support timeout to wait for a mutex.
 * This function returns KOSA_StatusSuccess if the mutex is obtained, returns
 * KOSA_StatusError if any errors occur during waiting. If the mutex has been
 * locked, pass 0 as timeout will return KOSA_StatusTimeout immediately.
 *
 *END**************************************************************************/
osa_status_t OSA_MutexLock(osa_mutex_handle_t mutexHandle, uint32_t millisec)
{
#if (defined(FSL_OSA_BM_TIMEOUT_ENABLE) && (FSL_OSA_BM_TIMEOUT_ENABLE > 0U))
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
    uint32_t currentTime;
#endif
#endif
    mutex_t *pMutexStruct = (mutex_t *)mutexHandle;
    uint32_t regPrimask;

    /* Always check first. Deal with timeout only if not available. */
    if (0U == pMutexStruct->isLocked)
    {
        /* Get the lock and return success */
        OSA_EnterCritical(&regPrimask);
        pMutexStruct->isLocked  = 1U;
        pMutexStruct->isWaiting = 0U;
        OSA_ExitCritical(regPrimask);
        return KOSA_StatusSuccess;
    }
    else
    {
        if (0U == millisec)
        {
            /* If timeout is 0 and mutex is not available, return kStatus_OSA_Timeout. */
            return KOSA_StatusTimeout;
        }
#if (defined(FSL_OSA_BM_TIMEOUT_ENABLE) && (FSL_OSA_BM_TIMEOUT_ENABLE > 0U))
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
        else if (pMutexStruct->isWaiting != 0U)
        {
            /* Check for timeout */
            currentTime = OSA_TimeGetMsec();
            if (pMutexStruct->timeout < OSA_TimeDiff(pMutexStruct->time_start, currentTime))
            {
                OSA_EnterCritical(&regPrimask);
                pMutexStruct->isWaiting = 0U;
                OSA_ExitCritical(regPrimask);
                return KOSA_StatusTimeout;
            }
        }
        else if (millisec != osaWaitForever_c) /* If dont't wait forever, start timer. */
        {
            /* Start the timeout counter */
            OSA_EnterCritical(&regPrimask);
            pMutexStruct->isWaiting = 1U;
            OSA_ExitCritical(regPrimask);
            pMutexStruct->time_start = OSA_TimeGetMsec();
            pMutexStruct->timeout    = millisec;
        }
#endif
#endif
        else
        {
            ;
        }
    }

    return KOSA_StatusIdle;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MutexUnlock
 * Description   : This function is used to unlock a mutex.
 *
 *END**************************************************************************/
osa_status_t OSA_MutexUnlock(osa_mutex_handle_t mutexHandle)
{
    mutex_t *pMutexStruct = (mutex_t *)mutexHandle;
    uint32_t regPrimask;
    assert(mutexHandle);

    OSA_EnterCritical(&regPrimask);
    pMutexStruct->isLocked = 0U;
    OSA_ExitCritical(regPrimask);
    return KOSA_StatusSuccess;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MutexDestroy
 * Description   : This function is used to destroy a mutex.
 * Return        : KOSA_StatusSuccess if the lock object is destroyed successfully, otherwise return KOSA_StatusError.
 *
 *END**************************************************************************/
osa_status_t OSA_MutexDestroy(osa_mutex_handle_t mutexHandle)
{
    assert(mutexHandle);
    mutex_t *pMutexStruct = (mutex_t *)mutexHandle;

    /* Destory mutexHandle's data */
    (void)memset(pMutexStruct, 0, sizeof(mutex_t));

    return KOSA_StatusSuccess;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_EventCreate
 * Description   : This function is used to create a event object.
 * Return        : Event handle of the new event, or NULL if failed.
 *
 *END**************************************************************************/
osa_status_t OSA_EventCreate(osa_event_handle_t eventHandle, uint8_t autoClear)
{
    event_t *pEventStruct = eventHandle;
    assert(sizeof(event_t) == OSA_EVENT_HANDLE_SIZE);
    assert(eventHandle);

    pEventStruct->isWaiting  = 0U;
    pEventStruct->flags      = 0;
    pEventStruct->autoClear  = autoClear;
    pEventStruct->time_start = 0u;
    pEventStruct->timeout    = 0u;
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
    pEventStruct->waitingTask = NULL;
#endif
    return KOSA_StatusSuccess;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_EventSet
 * Description   : Set one or more event flags of an event object.
 * Return        : KOSA_StatusSuccess if set successfully, KOSA_StatusError if failed.
 *
 *END**************************************************************************/
osa_status_t OSA_EventSet(osa_event_handle_t eventHandle, osa_event_flags_t flagsToSet)
{
    event_t *pEventStruct;
    uint32_t regPrimask;
    pEventStruct = (event_t *)eventHandle;
    /* Set flags ensuring atomic operation */
    OSA_EnterCritical(&regPrimask);
    pEventStruct->flags |= flagsToSet;
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
    if (pEventStruct->waitingTask != NULL)
    {
        pEventStruct->waitingTask->haveToRun = 1U;
    }
#endif
    OSA_ExitCritical(regPrimask);

    return KOSA_StatusSuccess;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_EventClear
 * Description   : Clear one or more event flags of an event object.
 * Return        :KOSA_StatusSuccess if clear successfully, KOSA_StatusError if failed.
 *
 *END**************************************************************************/
osa_status_t OSA_EventClear(osa_event_handle_t eventHandle, osa_event_flags_t flagsToClear)
{
    event_t *pEventStruct;
    uint32_t regPrimask;
    pEventStruct = (event_t *)eventHandle;
    /* Clear flags ensuring atomic operation */
    OSA_EnterCritical(&regPrimask);
    pEventStruct->flags &= ~flagsToClear;
    if (0U != pEventStruct->flags)
    {
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
        if (NULL != pEventStruct->waitingTask)
        {
            pEventStruct->waitingTask->haveToRun = 1U;
        }
#endif
    }
    OSA_ExitCritical(regPrimask);

    return KOSA_StatusSuccess;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_EventGet
 * Description   : This function is used to get event's flags that specified by prameter
 * flagsMask, and the flags (user specified) are obatianed by parameter pFlagsOfEvent. So
 * you should pass the parameter 0xffffffff to specify you want to get all.
 * Return        :KOSA_StatusSuccess if event flags were successfully got, KOSA_StatusError if failed.
 *
 *END**************************************************************************/
osa_status_t OSA_EventGet(osa_event_handle_t eventHandle, osa_event_flags_t flagsMask, osa_event_flags_t *pFlagsOfEvent)
{
    event_t *pEventStruct;
    pEventStruct = (event_t *)eventHandle;
    OSA_SR_ALLOC();

    if (NULL == pFlagsOfEvent)
    {
        return KOSA_StatusError;
    }

    OSA_ENTER_CRITICAL();
    *pFlagsOfEvent = pEventStruct->flags & flagsMask;
    OSA_EXIT_CRITICAL();

    return KOSA_StatusSuccess;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_EventWait
 * Description   : This function checks the event's status, if it meets the wait
 * condition, return KOSA_StatusSuccess, otherwise, timeout will be used for
 * wait. The parameter timeout indicates how long should wait in milliseconds.
 * Pass osaWaitForever_c to wait indefinitely, pass 0 will return the value
 * KOSA_StatusTimeout immediately if wait condition is not met. The event flags
 * will be cleared if the event is auto clear mode. Flags that wakeup waiting
 * task could be obtained from the parameter setFlags.
 * This function returns KOSA_StatusSuccess if wait condition is met, returns
 * KOSA_StatusTimeout if wait condition is not met within the specified
 * 'timeout', returns KOSA_StatusError if any errors occur during waiting.
 *
 *END**************************************************************************/
osa_status_t OSA_EventWait(osa_event_handle_t eventHandle,
                           osa_event_flags_t flagsToWait,
                           uint8_t waitAll,
                           uint32_t millisec,
                           osa_event_flags_t *pSetFlags)
{
    event_t *pEventStruct;
    uint32_t regPrimask;
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
    uint32_t currentTime;
#endif
    osa_status_t retVal = KOSA_StatusIdle;
    if (NULL == pSetFlags)
    {
        return KOSA_StatusError;
    }

    pEventStruct = (event_t *)eventHandle;

    OSA_EnterCritical(&regPrimask);
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
#if (TASK_MAX_NUM > 0)
    pEventStruct->waitingTask = OSA_TaskGetCurrentHandle();
#endif
#endif

    *pSetFlags = pEventStruct->flags & flagsToWait;

    /* Check the event flag first, if does not meet wait condition, deal with timeout. */
    if (((0U == waitAll) && (0U != *pSetFlags)) || (*pSetFlags == flagsToWait))
    {
        pEventStruct->isWaiting = 0U;
        if (1U == pEventStruct->autoClear)
        {
            pEventStruct->flags &= ~flagsToWait;
        }
        retVal = KOSA_StatusSuccess;
    }
    else
    {
        if (0U == millisec)
        {
            /* If timeout is 0 and wait condition is not met, return kStatus_OSA_Timeout. */
            retVal = KOSA_StatusTimeout;
        }
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
        else if (0U != pEventStruct->isWaiting)
        {
            /* Check for timeout */
            currentTime = OSA_TimeGetMsec();
            if (pEventStruct->timeout < OSA_TimeDiff(pEventStruct->time_start, currentTime))
            {
                pEventStruct->isWaiting = 0U;
                retVal                  = KOSA_StatusTimeout;
            }
        }
        else if (millisec != osaWaitForever_c) /* If no timeout, don't start the timer */
        {
            /* Start the timeout counter */
            pEventStruct->isWaiting  = 1U;
            pEventStruct->time_start = OSA_TimeGetMsec();
            pEventStruct->timeout    = millisec;
        }
#endif
        else
        {
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
            pEventStruct->waitingTask->haveToRun = 0U;
#endif
        }
    }

    OSA_ExitCritical(regPrimask);

    return retVal;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_EventDestroy
 * Description   : This function is used to destroy a event object. Return
 * KOSA_StatusSuccess if the event object is destroyed successfully, otherwise
 * return KOSA_StatusError.
 *
 *END**************************************************************************/
osa_status_t OSA_EventDestroy(osa_event_handle_t eventHandle)
{
    assert(eventHandle);
    event_t *pEventStruct = (event_t *)eventHandle;

    /* Destroy eventHandle's data */
    (void)memset(pEventStruct, 0, sizeof(event_t));

    return KOSA_StatusSuccess;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MsgQCreate
 * Description   : This function is used to create a message queue.
 * Return        : the handle to the message queue if create successfully, otherwise
 * return NULL.
 *
 *END**************************************************************************/
osa_status_t OSA_MsgQCreate(osa_msgq_handle_t msgqHandle, uint32_t msgNo, uint32_t msgSize)
{
    msg_queue_t *pMsgQStruct = msgqHandle;
    assert(sizeof(msg_queue_t) == OSA_MSGQ_HANDLE_SIZE);
    assert(msgqHandle);

    pMsgQStruct->max      = (uint16_t)msgNo;
    pMsgQStruct->number   = 0;
    pMsgQStruct->head     = 0;
    pMsgQStruct->tail     = 0;
    pMsgQStruct->size     = msgSize;
    pMsgQStruct->queueMem = (uint8_t *)((uint8_t *)msgqHandle + sizeof(msg_queue_t));
    return KOSA_StatusSuccess;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MsgQPut
 * Description   : This function is used to put a message to a message queue.
 * Return         : KOSA_StatusSuccess if the message is put successfully, otherwise return KOSA_StatusError.
 *
 *END**************************************************************************/
osa_status_t OSA_MsgQPut(osa_msgq_handle_t msgqHandle, osa_msg_handle_t pMessage)
{
    assert(msgqHandle);
    msg_queue_t *pQueue;
    osa_status_t status = KOSA_StatusSuccess;
    uint32_t regPrimask;

    uint8_t *pMsgArray;

    pQueue = (msg_queue_t *)msgqHandle;

    if (NULL == pQueue->queueMem)
    {
        return KOSA_StatusError;
    }

    OSA_EnterCritical(&regPrimask);
    if (pQueue->number >= pQueue->max)
    {
        status = KOSA_StatusError;
    }
    else
    {
        pMsgArray = &pQueue->queueMem[pQueue->tail];
        for (uint32_t i = 0; i < pQueue->size; i++)
        {
            pMsgArray[i] = *((uint8_t *)pMessage + i);
        }

        pQueue->number++;
        pQueue->tail += (uint16_t)pQueue->size;

        if (pQueue->tail >= (pQueue->max * pQueue->size))
        {
            pQueue->tail = 0;
        }
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
        if (NULL != pQueue->waitingTask)
        {
            pQueue->waitingTask->haveToRun = 1U;
        }
#endif
    }
    OSA_ExitCritical(regPrimask);
    return status;
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MsgQGet
 * Description   : This function checks the queue's status, if it is not empty,
 * get message from it and return KOSA_StatusSuccess, otherwise, timeout will
 * be used for wait. The parameter timeout indicates how long should wait in
 * milliseconds. Pass osaWaitForever_c to wait indefinitely, pass 0 will return
 * KOSA_StatusTimeout immediately if queue is empty.
 * This function returns KOSA_StatusSuccess if message is got successfully,
 * returns KOSA_StatusTimeout if message queue is empty within the specified
 * 'timeout', returns KOSA_StatusError if any errors occur during waiting.
 *
 *END**************************************************************************/
osa_status_t OSA_MsgQGet(osa_msgq_handle_t msgqHandle, osa_msg_handle_t pMessage, uint32_t millisec)
{
    assert(msgqHandle);
    msg_queue_t *pQueue;
    osa_status_t status = KOSA_StatusSuccess;
    uint32_t regPrimask;

    uint8_t *pMsgArray;

#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
    uint32_t currentTime;
#endif

    pQueue = (msg_queue_t *)msgqHandle;

    if (NULL == pQueue->queueMem)
    {
        return KOSA_StatusError;
    }

#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
    pQueue->waitingTask = OSA_TaskGetCurrentHandle();
#endif

    OSA_EnterCritical(&regPrimask);
    if (0U != pQueue->number)
    {
        pMsgArray = (uint8_t *)pMessage;
        for (uint32_t i = 0; i < pQueue->size; i++)
        {
            pMsgArray[i] = pQueue->queueMem[pQueue->head + i];
        }

        pQueue->number--;
        pQueue->head += (uint16_t)pQueue->size;
        pQueue->isWaiting = 0U;

        if (pQueue->head >= (pQueue->max * pQueue->size))
        {
            pQueue->head = 0;
        }
        status = KOSA_StatusSuccess;
    }
    else
    {
        if (0U == millisec)
        {
            /* If timeout is 0 and wait condition is not met, return kStatus_OSA_Timeout. */
            status = KOSA_StatusTimeout;
        }
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
        else if (0U != pQueue->isWaiting)
        {
            /* Check for timeout */
            status      = KOSA_StatusIdle; /* Before a timeout, the status should be idle. */
            currentTime = OSA_TimeGetMsec();
            if (pQueue->timeout < OSA_TimeDiff(pQueue->time_start, currentTime))
            {
                pQueue->isWaiting = 0U;
                status            = KOSA_StatusTimeout;
            }
        }
        else if (millisec != osaWaitForever_c) /* If no timeout, don't start the timer */
        {
            /* Start the timeout counter */
            pQueue->isWaiting  = 1U;
            pQueue->time_start = OSA_TimeGetMsec();
            pQueue->timeout    = millisec;
            status             = KOSA_StatusIdle;
        }
#endif
        else
        {
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
            pQueue->waitingTask->haveToRun = 0U;
#endif
            status = KOSA_StatusIdle;
        }
    }
    OSA_ExitCritical(regPrimask);

    return status;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_MsgQAvailableMsgs
 * Description   : This function is used to get the available message.
 * Return        : Available message count
 *
 *END**************************************************************************/
int OSA_MsgQAvailableMsgs(osa_msgq_handle_t msgqHandle)
{
    assert(msgqHandle);
    msg_queue_t *pQueue = (msg_queue_t *)msgqHandle;

    return (int)pQueue->number;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_EXT_MsgQDestroy
 * Description   : This function is used to destroy the message queue.
 * Return        : KOSA_StatusSuccess if the message queue is destroyed successfully, otherwise return KOSA_StatusError.
 *
 *END**************************************************************************/
osa_status_t OSA_MsgQDestroy(osa_msgq_handle_t msgqHandle)
{
    assert(msgqHandle);
    msg_queue_t *pQueue = (msg_queue_t *)msgqHandle;

    /* Destory msgqHandle's data */
    /* OSA_MsgQGet() & OSA_MsgQPut() will check queueMem, if NULL will return an error. */
    (void)memset(pQueue, 0, sizeof(msg_queue_t));

    return KOSA_StatusSuccess;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_InterruptEnable
 * Description   : self explanatory.
 *
 *END**************************************************************************/
void OSA_InterruptEnable(void)
{
    OSA_EnableIRQGlobal();
}
/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_InterruptDisable
 * Description   : self explanatory.
 *
 *END**************************************************************************/
void OSA_InterruptDisable(void)
{
    OSA_DisableIRQGlobal();
}

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_InstallIntHandler
 * Description   : This function is used to install interrupt handler.
 *
 *END**************************************************************************/
void OSA_InstallIntHandler(uint32_t IRQNumber, void (*handler)(void))
{
#if defined(__IAR_SYSTEMS_ICC__)
    _Pragma("diag_suppress = Pm138")
#endif
#if defined(ENABLE_RAM_VECTOR_TABLE)
        (void) InstallIRQHandler((IRQn_Type)IRQNumber, (uint32_t) * (uint32_t *)&handler);
#endif /* ENABLE_RAM_VECTOR_TABLE. */
#if defined(__IAR_SYSTEMS_ICC__)
    _Pragma("diag_remark = PM138")
#endif
}

/*! *********************************************************************************
*************************************************************************************
* Private functions
*************************************************************************************
********************************************************************************** */
#if ((defined(FSL_OSA_TASK_ENABLE)) && (FSL_OSA_TASK_ENABLE > 0U))
#if (defined(FSL_OSA_MAIN_FUNC_ENABLE) && (FSL_OSA_MAIN_FUNC_ENABLE > 0U))
static OSA_TASK_DEFINE(main_task, gMainThreadPriority_c, 1, gMainThreadStackSize_c, 0);

void main(void)
{
    OSA_Init();

    /* Initialize MCU clock */
    extern void BOARD_InitHardware(void);
    BOARD_InitHardware();

    (void)OSA_TaskCreate((osa_task_handle_t)s_osaState.mainTaskHandle, OSA_TASK(main_task), NULL);

    OSA_Start();
}
#endif /*(defined(FSL_OSA_MAIN_FUNC_ENABLE) && (FSL_OSA_MAIN_FUNC_ENABLE > 0U))*/
#endif /* FSL_OSA_TASK_ENABLE */

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_Init
 * Description   : This function is used to setup the basic services, it should
 * be called first in function main.
 *
 *END**************************************************************************/
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
void OSA_Init(void)
{
    LIST_Init((&s_osaState.taskList), 0);
    s_osaState.curTaskHandler        = NULL;
    s_osaState.interruptDisableCount = 0U;
    s_osaState.tickCounter           = 0U;
}
#endif

/*FUNCTION**********************************************************************
 *
 * Function Name : OSA_Start
 * Description   : This function is used to start RTOS scheduler.
 *
 *END**************************************************************************/
#if (defined(FSL_OSA_TASK_ENABLE) && (FSL_OSA_TASK_ENABLE > 0U))
void OSA_Start(void)
{
    list_element_handle_t list_element;
    task_control_block_t *tcb;

#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
    OSA_TimeInit();
#endif

    while (true)
    {
        list_element = LIST_GetHead(&s_osaState.taskList);
        while (NULL != list_element)
        {
            tcb                       = (task_control_block_t *)(void *)list_element;
            s_osaState.curTaskHandler = (osa_task_handle_t)tcb;
            if (0U != tcb->haveToRun)
            {
                if (NULL != tcb->p_func)
                {
                    tcb->p_func(tcb->param);
                }
                list_element = LIST_GetHead(&s_osaState.taskList);
            }
            else
            {
                list_element = LIST_GetNext(list_element);
            }
        }
    }
}

#endif

/*FUNCTION**********************************************************************
 *
 * Function Name : SysTick_Handler
 * Description   : This ISR of the SYSTICK timer.
 *
 *END**************************************************************************/
#if (FSL_OSA_BM_TIMER_CONFIG != FSL_OSA_BM_TIMER_NONE)
void SysTick_Handler(void);
void SysTick_Handler(void)
{
    s_osaState.tickCounter++;
}
#endif
