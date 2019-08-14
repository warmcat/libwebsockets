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

#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>

#include <sqlite3.h>
#include <string.h>

#define LWSGS_VERIFIED_ACCEPTED 100

enum {
	FGS_USERNAME,
	FGS_PASSWORD,
	FGS_PASSWORD2,
	FGS_EMAIL,
	FGS_REGISTER,
	FGS_GOOD,
	FGS_BAD,
	FGS_REG_GOOD,
	FGS_REG_BAD,
	FGS_ADMIN,
	FGS_FORGOT,
	FGS_FORGOT_GOOD,
	FGS_FORGOT_BAD,
	FGS_FORGOT_POST_GOOD,
	FGS_FORGOT_POST_BAD,
	FGS_CHANGE,
	FGS_CURPW,
	FGS_DELETE,
};

struct lwsgs_user {
	char username[32];
	char ip[16];
	lwsgw_hash pwhash;
	lwsgw_hash pwsalt;
	lwsgw_hash token;
	time_t created;
	time_t last_forgot_validated;
	char email[100];
	int verified;
};

struct per_vhost_data__gs {
	lws_abs_t *smtp_client;
	struct lwsgs_user u;
	lws_token_map_t transport_tokens[3];
	lws_token_map_t protocol_tokens[2];
	char helo[64], ip[64];
	struct lws_context *context;
	char session_db[256];
	char admin_user[32];
	char urlroot[48];
	char confounder[32];
	char email_contact_person[128];
	char email_title[128];
	char email_template[128];
	char email_confirm_url[128];
	char email_from[128];
	lwsgw_hash admin_password_sha256;
	sqlite3 *pdb;
	int timeout_idle_secs;
	int timeout_absolute_secs;
	int timeout_anon_absolute_secs;
	int timeout_email_secs;
	time_t last_session_expire;
};

struct per_session_data__gs {
	struct lws_spa *spa;
	lwsgw_hash login_session;
	lwsgw_hash delete_session;
	unsigned int login_expires;
	char onward[256];
	char result[500 + LWS_PRE];
	char urldec[500 + LWS_PRE];
	int result_len;
	char ip[46];
	struct lws_process_html_state phs;
	int spos;
	char check_response_value;

	unsigned int logging_out:1;
	unsigned int check_response:1;
};

/* utils.c */

int
lwsgs_lookup_callback_user(void *priv, int cols, char **col_val,
			   char **col_name);
void
lwsgw_cookie_from_session(lwsgw_hash *sid, time_t expires, char **p, char *end);
int
lwsgs_get_sid_from_wsi(struct lws *wsi, lwsgw_hash *sid);
int
lwsgs_lookup_session(struct per_vhost_data__gs *vhd,
		     const lwsgw_hash *sid, char *username, int len);
int
lwsgs_get_auth_level(struct per_vhost_data__gs *vhd,
		     const char *username);
int
lwsgs_check_credentials(struct per_vhost_data__gs *vhd,
			const char *username, const char *password);
void
sha256_to_lwsgw_hash(unsigned char *hash, lwsgw_hash *shash);
unsigned int
lwsgs_now_secs(void);
int
lwsgw_check_admin(struct per_vhost_data__gs *vhd,
		  const char *username, const char *password);
int
lwsgs_hash_password(struct per_vhost_data__gs *vhd,
		    const char *password, struct lwsgs_user *u);
int
lwsgs_new_session_id(struct per_vhost_data__gs *vhd,
		     lwsgw_hash *sid, const char *username, int exp);
int
lwsgs_lookup_user(struct per_vhost_data__gs *vhd,
		  const char *username, struct lwsgs_user *u);
int
lwsgw_update_session(struct per_vhost_data__gs *vhd,
		     lwsgw_hash *hash, const char *user);
int
lwsgw_expire_old_sessions(struct per_vhost_data__gs *vhd);


/* handlers.c */

int
lwsgs_handler_confirm(struct per_vhost_data__gs *vhd, struct lws *wsi,
		      struct per_session_data__gs *pss);
int
lwsgs_handler_forgot(struct per_vhost_data__gs *vhd, struct lws *wsi,
		     struct per_session_data__gs *pss);
int
lwsgs_handler_check(struct per_vhost_data__gs *vhd, struct lws *wsi,
		      struct per_session_data__gs *pss, const char *in);
int
lwsgs_handler_change_password(struct per_vhost_data__gs *vhd, struct lws *wsi,
			      struct per_session_data__gs *pss);
int
lwsgs_handler_forgot_pw_form(struct per_vhost_data__gs *vhd, struct lws *wsi,
			     struct per_session_data__gs *pss);
int
lwsgs_handler_register_form(struct per_vhost_data__gs *vhd, struct lws *wsi,
			     struct per_session_data__gs *pss);

