/*
 * libwebsockets include/libwebsockets/abstract/transports/unit-test.c
 *
 * Copyright (C) 2019 Andy Green <andy@warmcat.com>
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

enum {
	LWS_AUT_EXPECT_TEST_END					= (1 << 0),
	LWS_AUT_EXPECT_LOCAL_CLOSE				= (1 << 1),
	LWS_AUT_EXPECT_DO_REMOTE_CLOSE				= (1 << 2),
	LWS_AUT_EXPECT_TX /* expect this as tx from protocol */	= (1 << 3),
	LWS_AUT_EXPECT_RX /* present this as rx to protocol */	= (1 << 4),
};

typedef enum {
	LPE_CONTINUE,
	LPE_SUCCEEDED,
	LPE_FAILED,
} lws_expect_disposition;

typedef struct lws_expect {
	void *buffer;
	size_t len;

	uint32_t flags;
} lws_expect_t;

typedef int (*lws_expect_test_instance_init)(lws_abs_t *instance);

typedef struct lws_expect_test {
	const char *name;		/* NULL indicates end of test array */
	lws_expect_t *expect;
	lws_expect_test_instance_init *init;
} lws_expect_test_t;

enum {
	LTMI_PEER_V_EXPECT_TEST = LTMI_TRANSPORT_BASE,	/* u.value */
	LTMI_PEER_V_EXPECT_TEST_ARRAY,			/* u.value */
};
