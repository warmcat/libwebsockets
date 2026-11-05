/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 */

#include "private-lib-core.h"

#if defined(LWS_ESP_PLATFORM)
#include <esp_memory_utils.h>

/*
 * New allocations in the bulk arena come from PSRAM, and others are left to
 * IDF's malloc() policy, ie, internal RAM below
 * CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL.  A block that's moved stays in the heap
 * it is in, since IDF's realloc() would apply its policy to it again.  If the
 * heap a block should come from can't give it, eg, there is no PSRAM, it
 * comes from wherever malloc() can find it.
 */

void *
lws_plat_realloc_arena(void *ptr, size_t size, int arena)
{
	void *v;

	if (ptr) {
		if (esp_ptr_external_ram(ptr)) {
			v = heap_caps_realloc(ptr, size,
					      MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
			if (v)
				return v;
		}

		return realloc(ptr, size);
	}

	if (arena == LWS_ALLOC_ARENA_BULK) {
		v = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
		if (v)
			return v;
	}

	return malloc(size);
}
#endif

/* the sockets use it too, so it can't live in the LWS_WITH_FILE_OPS file */
int lws_plat_apply_FD_CLOEXEC(int n)
{
	return 0;
}

/*
 * Normally you don't want this, use lws_sul instead inside the event loop.
 * But sometimes for drivers it makes sense, so there's an internal-only
 * crossplatform api for it.
 */

void
lws_msleep(unsigned int ms)
{
	vTaskDelay(portTICK_PERIOD_MS > ms ? 1 : ms / portTICK_PERIOD_MS);
}

lws_usec_t
lws_now_usecs(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((unsigned long long)tv.tv_sec * 1000000LL) + tv.tv_usec;
}

size_t
lws_plat_get_random(struct lws_context *context, void *buf, size_t len)
{
#if defined(LWS_WITH_ESP32)
	uint8_t *pb = buf;

	while (len) {
		uint32_t r = esp_random();
		uint8_t *p = (uint8_t *)&r;
		int b = 4;

		if (len < (size_t)b)
			b = len;

		len -= b;

		while (b--)
			*pb++ = p[b];
	}

	return pb - (uint8_t *)buf;
#else
#if defined(LWS_WITH_MBEDTLS)
#if !defined(LWS_MBEDTLS_PSA_RNG)
	int n;

	n = mbedtls_ctr_drbg_random(&context->mcdc, buf, len);
	if (!n)
		return len;

	/* failed */

	lwsl_err("%s: mbedtls_ctr_drbg_random returned 0x%x\n", __func__, n);
#else
	/* mbedTLS 4 removed ctr_drbg; PSA provides the RNG */
	psa_status_t st = psa_generate_random((uint8_t *)buf, len);

	if (st == PSA_SUCCESS)
		return len;

	lwsl_err("%s: psa_generate_random returned %d\n", __func__, (int)st);
#endif
#endif
	return 0;
#endif
}


void lwsl_emit_syslog(int level, const char *line)
{
	lwsl_emit_stderr(level, line);
}

int
lws_plat_drop_app_privileges(struct lws_context *context, int actually_init)
{
	return 0;
}

int
lws_plat_user_to_uid(const char *username, uid_t *puid)
{
	return 1;
}

int
lws_plat_group_to_gid(const char *groupname, gid_t *pgid)
{
	return 1;
}

int
lws_plat_recommended_rsa_bits(void)
{
	/*
	 * 2048-bit key generation takes up to a minute on ESP32, 4096
	 * is like 15 minutes +
	 */
	return 2048;
}

#if defined(LWS_PLAT_CALLERS)
#include <esp_debug_helpers.h>
#include <esp_cpu_utils.h>

int
lws_plat_callers(uintptr_t *pcs, int max, int skip)
{
	esp_backtrace_frame_t f;
	int m = 0;

	/*
	 * This spills the register windows to the stack, and gives the frame
	 * of the function calling us, whose next_pc is its caller
	 */
	esp_backtrace_get_start(&f.pc, &f.sp, &f.next_pc);
	f.exc_frame = NULL;

	while (f.next_pc && m < max) {
		if (skip)
			skip--;
		else
			pcs[m++] = (uintptr_t)esp_cpu_process_stack_pc(
							f.next_pc);
		if (!esp_backtrace_get_next_frame(&f))
			break;
	}

	return m;
}
#endif

static void
lws_plat_timer_sync_cb(void *p, uint32_t u)
{
	(void)u;

	xSemaphoreGive((SemaphoreHandle_t)p);
}

void
lws_plat_timer_delete_sync(TimerHandle_t t)
{
	StaticSemaphore_t ss;
	SemaphoreHandle_t s;

	if (!t)
		return;

	xTimerDelete(t, portMAX_DELAY);

	if (xTaskGetCurrentTaskHandle() == xTimerGetTimerDaemonTaskHandle())
		/* the timer task would wait on itself */
		return;

	/*
	 * The timer task deals with what it is sent in order, and runs the
	 * callbacks: once it has run this, the delete is done, and no callback
	 * of the timer is running, or will
	 */

	s = xSemaphoreCreateBinaryStatic(&ss);
	if (xTimerPendFunctionCall(lws_plat_timer_sync_cb, s, 0,
				   portMAX_DELAY) == pdPASS)
		xSemaphoreTake(s, portMAX_DELAY);
	vSemaphoreDelete(s);
}
