/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
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
 * included from libwebsockets.h
 *
 * lws_test_sequencer manages running an array of unit tests.
 */

typedef void (*lws_test_sequence_cb)(const void *cb_user);

typedef struct lws_test_sequencer_args {
	lws_abs_t		*abs; /* abstract protocol + unit test txport */
	lws_unit_test_t	*tests; /* array of lws_unit_test_t */
	int			*results; /* takes result dispositions */
	int			results_max; /* max space usable in results */
	int			*count_tests; /* count of done tests */
	int			*count_passes; /* count of passed tests */
	lws_test_sequence_cb	cb; /* completion callback */
	void			*cb_user; /* opaque user ptr given to cb */
} lws_test_sequencer_args_t;

/**
 * lws_abs_unit_test_sequencer() - helper to sequence multiple unit tests
 *
 * \param args: lws_test_sequencer_args_t prepared with arguments for the tests
 *
 * This helper sequences one or more unit tests to run and collects the results.
 *
 * The incoming abs should be set up for the abstract protocol you want to test
 * and the lws unit-test transport.
 *
 * Results are one of
 *
 * 	LPE_SUCCEEDED
 *	LPE_FAILED
 *	LPE_FAILED_UNEXPECTED_TIMEOUT
 *	LPE_FAILED_UNEXPECTED_PASS
 *	LPE_FAILED_UNEXPECTED_CLOSE
 *
 * The callback args->cb is called when the tests have been done.
 */
LWS_VISIBLE LWS_EXTERN int
lws_abs_unit_test_sequencer(const lws_test_sequencer_args_t *args);
