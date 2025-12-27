/*
 * sai-power com-warmcat-sai client protocol implementation
 *
 * Copyright (C) 2019 - 2025 Andy Green <andy@warmcat.com>
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

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#include "p-private.h"

static const char *tokens[] = {
	"Voltage",
	"Current",
	"Active",
	"Power",
	"Apparent",
	"Reactive",
	"Factor",
	"Energy",
	"Today",
	"Yesterday",
	"Total",
};

enum {
	TOKORD_VOLTAGE,
	TOKORD_CURRENT,
	TOKORD_ACTIVE,
	TOKORD_POWER,
	TOKORD_APPARENT,
	TOKORD_REACTIVE,
	TOKORD_FACTOR,
	TOKORD_ENERGY,
	TOKORD_TODAY,
	TOKORD_YESTERDAY,
	TOKORD_TOTAL
};

int
saip_parse_tasmota_status(tasmota_parse_t *tp)
{
	lws_tokenize_elem e;
	unsigned int *i;
	char *p;
	int n;

	do {
		e = lws_tokenize(&tp->ts);

		if (e == LWS_TOKZE_DELIMITER) {
			switch (tp->ts.token[0]) {
			case '<':
				tp->s |=  1u;
				break;
			case '>':
				tp->s &= (uint8_t)~1u;
				continue;
			case '{':
				tp->s |=  2u;
				break;
			case '}':
				tp->s &= (uint8_t)~2u;
				continue;
			case '&':
				tp->s |=  4u;
				break;
			case ';':
				tp->s &= (uint8_t)~4u;
				continue;
			}
		}

		if (tp->s)
			continue;

		switch (e) {
		case LWS_TOKZE_ENDED:
			return 1;

		case LWS_TOKZE_TOKEN:
			for (n = 0; n < (int)LWS_ARRAY_SIZE(tokens); n++) {
				if (strlen(tokens[n]) == tp->ts.token_len &&
				    !strcmp(tokens[n], tp->ts.token)) {
					tp->match = (uint16_t)((tp->match << 8) | n);
					break;
				}
			}

			if (n == LWS_ARRAY_SIZE(tokens)) {
				// lwsl_notice("%s: unknown token '%.*s'\n", __func__, (int)tp->ts.token_len, tp->ts.token);
				continue;
			}
			break;

		case LWS_TOKZE_INTEGER:
			if ((tp->match & 0xff) == TOKORD_VOLTAGE)
				tp->td.voltage_v = (unsigned int)atoi(tp->ts.token);
			if ((tp->match >> 8)   == TOKORD_ACTIVE   &&
			    (tp->match & 0xff) == TOKORD_POWER)
				tp->td.active_power_w = (unsigned int)atoi(tp->ts.token);
			if ((tp->match >> 8)   == TOKORD_APPARENT &&
			    (tp->match & 0xff) == TOKORD_POWER)
				tp->td.apparent_power_va = (unsigned int)atoi(tp->ts.token);
			if ((tp->match >> 8)   == TOKORD_REACTIVE &&
			    (tp->match & 0xff) == TOKORD_POWER)
				tp->td.reactive_power_var = (unsigned int)atoi(tp->ts.token);
			break;

		case LWS_TOKZE_FLOAT:
			i = NULL;

			if ((tp->match & 0xff) == TOKORD_CURRENT)
				i = &tp->td.current_ma;
			if ((tp->match >> 8)   == TOKORD_POWER  &&
			    (tp->match & 0xff) == TOKORD_FACTOR)
				i = &tp->td.power_factor_scaled_1000;
			if ((tp->match >> 8)   == TOKORD_ENERGY &&
			    (tp->match & 0xff) == TOKORD_TODAY)
				i = &tp->td.energy_today_wh;
			if ((tp->match >> 8)   == TOKORD_ENERGY &&
			    (tp->match & 0xff) == TOKORD_YESTERDAY)
				i = &tp->td.energy_yesterday_wh;
			if ((tp->match >> 8)   == TOKORD_ENERGY &&
			    (tp->match & 0xff) == TOKORD_TOTAL)
				i = &tp->td.energy_total_wh;

			if (i) {
				*i = 1000 * (unsigned int)atoi(tp->ts.token);
				p = strchr(tp->ts.token, '.');
				if (p++) {
					static const unsigned int mu[] = { 0, 100, 10, 1 };

					n = (int)strlen(p);
					if (n > 3)
						n = 3;
					*i += (unsigned int)atoi(p) * mu[n];
				}
			}
			break;
		default:
			break;
		}

	} while (e > 0);

	return e;
}

