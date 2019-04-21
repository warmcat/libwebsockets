/*
 * libwebsockets lib/abstruct/smtp/private.h
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

#include "abstract/private.h"

/** enum lwsgs_smtp_states - where we are in SMTP protocol sequence */
typedef enum lwsgs_smtp_states {
	LGSSMTP_IDLE,		/**< awaiting new email */
	LGSSMTP_CONNECTING,	/**< opening tcp connection to MTA */
	LGSSMTP_CONNECTED,	/**< tcp connection to MTA is connected */
	LGSSMTP_SENT_HELO,	/**< sent the HELO */
	LGSSMTP_SENT_FROM,	/**< sent FROM */
	LGSSMTP_SENT_TO,	/**< sent TO */
	LGSSMTP_SENT_DATA,	/**< sent DATA request */
	LGSSMTP_SENT_BODY,	/**< sent the email body */
	LGSSMTP_SENT_QUIT,	/**< sent the session quit */
} lwsgs_smtp_states_t;

/** struct lws_email - abstract context for performing SMTP operations */
typedef struct lws_smtp_client {
	struct lws_dll2_owner pending_owner;

	lws_smtp_client_info_t i;
	lws_abstract_t abs;

	lws_abs_user_t *abs_conn;

	lwsgs_smtp_states_t estate;
	time_t email_connect_started;

	unsigned char send_pending:1;
} lws_smtp_client_t;

