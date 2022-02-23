/*
 * lws OTA updates
 *
 * Copyright (C) 2019 - 2022 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * This is the platform interface that lws_ota uses to flash new firmware.
 * The platform implementation for these ops is set via lws_system and consists
 * of user code.
 *
 * All the update-related calls have async interfaces with a callback and opaque
 * callback context that is called on completion.  This allows us to, eg,
 * download the next buffer while flashing the previous one.
 *
 * If the platform implementation is actually synchronous, then just call the
 * callback before returning.
 *
 * If it is async, because eg, erase is slow, in the platform ota op
 * implementation spawn a thread to do the platform operation, return
 * immediately with LWSOTARET_ONGOING, and call the callback from the spawned
 * thread context with the real return before terminating the thread.
 */

typedef void * lws_ota_process_t;

typedef enum {
	LWSOTARET_OK,
	LWSOTARET_ONGOING, /* result not ready to read yet */
	LWSOTARET_REJECTED,
	LWSOTARET_NOSLOT,

	LWSOTARET_UPDATE_AVAILABLE,
	LWSOTARET_PROGRESS,
	LWSOTARET_FAILED,
	LWSOTARET_COMPLETED
} lws_ota_ret_t;

typedef enum {
	LWS_OTA_ASYNC_START = 1,
	LWS_OTA_ASYNC_WRITE,
	LWS_OTA_ASYNC_ABORT,
	LWS_OTA_ASYNC_FINALIZE
} lws_ota_async_t;

struct lws_ota;

typedef void (*lws_ota_cb_t)(void *ctx, lws_ota_ret_t r);

typedef struct {

	/* asynchronous (completions via lws_cancel_service) */

	int (*ota_start)(struct lws_ota *g);
	/**< Creates the ota task and queues LWS_OTA_ASYNC_START on it. */

	void (*ota_queue)(struct lws_ota *g, lws_ota_async_t a);
	/**< Queue next command to OTA task (args are in g) */

	/* synchronous */

	int (*ota_report_current)(struct lws_ota *g, int bad);
	/**< Report information to the platform code about how we feel about the
	 * current boot... if we can check the OTA then we report it seems in
	 * good shape (bad = 0), if we can identify it's brain-damaged then
	 * (bad = 1).  What action the platform takes about these reports is up
	 * to the platform code */

	int (*ota_progress)(lws_ota_ret_t state, int percent);
	/**< Gets called so the platform can represent OTA progress, give
	 * platform a chance to choose what to do about an available update */

	int (*ota_get_last_fw_unixtime)(uint64_t *fw_unixtime);
	/**< tries to recover the newest firmware unixtime that had been
	 * OTA'd into fw_unixtime, updates from same or earlier unixtime are
	 * ignored for update purposes. */

	int ota_periodic_check_secs;
	/**< Check after this many seconds for a new update */
} lws_ota_ops_t;

/**
 * lws_ota_variant_name() - returns the build variant name
 *
 * Returns a string that uniquely identifies the kind of firmware build this
 * device is running.
 */

LWS_VISIBLE LWS_EXTERN const char *
lws_ota_variant_name(void);

LWS_VISIBLE LWS_EXTERN int
lws_plat_ota_start(struct lws_ota *g);


#define LWSOTAFIN_OK	0
#define LWSOTAFIN_BAD	1

LWS_VISIBLE LWS_EXTERN void
lws_plat_ota_queue(struct lws_ota *g, lws_ota_async_t a);

LWS_VISIBLE LWS_EXTERN int
lws_plat_ota_report_current(struct lws_ota *g, int bad);

LWS_VISIBLE LWS_EXTERN int
lws_plat_ota_get_last_fw_unixtime(uint64_t *fw_unixtime);
