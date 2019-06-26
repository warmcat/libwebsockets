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
 *
 * This is an abstract transport useful for unit testing abstract protocols.
 *
 * Instead of passing data anywhere, you give the transport a list of packets
 * to deliver and packets you expect back from the abstract protocol it's
 * bound to.
 */

enum {
	LWS_AUT_EXPECT_TEST_END					= (1 << 0),
	LWS_AUT_EXPECT_LOCAL_CLOSE				= (1 << 1),
	LWS_AUT_EXPECT_DO_REMOTE_CLOSE				= (1 << 2),
	LWS_AUT_EXPECT_TX /* expect this as tx from protocol */	= (1 << 3),
	LWS_AUT_EXPECT_RX /* present this as rx to protocol */	= (1 << 4),
	LWS_AUT_EXPECT_SHOULD_FAIL				= (1 << 5),
	LWS_AUT_EXPECT_SHOULD_TIMEOUT				= (1 << 6),
};

typedef enum {
	LPE_CONTINUE,
	LPE_SUCCEEDED,
	LPE_FAILED,
	LPE_FAILED_UNEXPECTED_TIMEOUT,
	LPE_FAILED_UNEXPECTED_PASS,
	LPE_FAILED_UNEXPECTED_CLOSE,
	LPE_SKIPPED,
	LPE_CLOSING
} lws_unit_test_packet_disposition;

typedef int (*lws_unit_test_packet_test_cb)(const void *cb_user, int disposition);
typedef int (*lws_unit_test_packet_cb)(lws_abs_t *instance);

/* each step in the unit test */

typedef struct lws_unit_test_packet {
	void				*buffer;
	lws_unit_test_packet_cb		pre;
	size_t				len;

	uint32_t			flags;
} lws_unit_test_packet_t;

/* each unit test */

typedef struct lws_unit_test {
	const char *		name; /* NULL indicates end of test array */
	lws_unit_test_packet_t *		expect_array;
	int			max_secs;
} lws_unit_test_t;

enum {
	LTMI_PEER_V_EXPECT_TEST = LTMI_TRANSPORT_BASE,	/* u.value */
	LTMI_PEER_V_EXPECT_RESULT_CB,			/* u.value */
	LTMI_PEER_V_EXPECT_RESULT_CB_ARG,		/* u.value */
};

LWS_VISIBLE LWS_EXTERN const char *
lws_unit_test_result_name(int in);

