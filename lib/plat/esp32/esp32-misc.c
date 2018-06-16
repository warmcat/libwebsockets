/*
 * libwebsockets - lib/plat/lws-plat-esp32.c
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "core/private.h"
#include "freertos/timers.h"
#include <esp_attr.h>
#include <esp_system.h>

#include "apps/sntp/sntp.h"

#include <lwip/sockets.h>
#include <esp_task_wdt.h>

unsigned long long time_in_microseconds(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((unsigned long long)tv.tv_sec * 1000000LL) + tv.tv_usec;
}

LWS_VISIBLE int
lws_get_random(struct lws_context *context, void *buf, int len)
{
	uint8_t *pb = buf;

	while (len) {
		uint32_t r = esp_random();
		uint8_t *p = (uint8_t *)&r;
		int b = 4;

		if (len < b)
			b = len;

		len -= b;

		while (b--)
			*pb++ = p[b];
	}

	return pb - (uint8_t *)buf;
}


LWS_VISIBLE void lwsl_emit_syslog(int level, const char *line)
{
	lwsl_emit_stderr(level, line);
}

void
lws_plat_drop_app_privileges(const struct lws_context_creation_info *info)
{
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

void esp32_uvtimer_cb(TimerHandle_t t)
{
	struct timer_mapping *p = pvTimerGetTimerID(t);

	p->cb(p->t);
}

