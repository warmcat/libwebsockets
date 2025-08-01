/*
 * lws-minimal-http-server-form-post-file
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http server that performs POST with a couple
 * of parameters and a file upload, all in multipart (mime) form mode.
 * It saves the uploaded file in the current directory, dumps the parameters to
 * the console log and redirects to another page.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#if !defined(WIN32)
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>

/*
 * Unlike ws, http is a stateless protocol.  This pss only exists for the
 * duration of a single http transaction.  With http/1.1 keep-alive and http/2,
 * that is unrelated to (shorter than) the lifetime of the network connection.
 */
struct pss {
	struct lws_spa *spa;		/* lws helper decodes multipart form */
	char filename[128];		/* the filename of the uploaded file */
	unsigned long long file_length; /* the amount of bytes uploaded */
	int fd;				/* fd on file being saved */
};

static int interrupted;

static const char * const param_names[] = {
	"text1",
	"send",
};

enum enum_param_names {
	EPN_TEXT1,
	EPN_SEND,
};

static int
file_upload_cb(void *data, const char *name, const char *filename,
	       char *buf, int len, enum lws_spa_fileupload_states state)
{
	struct pss *pss = (struct pss *)data;

	switch (state) {
	case LWS_UFS_OPEN:
		/* take a copy of the provided filename */
		lws_strncpy(pss->filename, filename, sizeof(pss->filename) - 1);
		/* remove any scary things like .. */
		lws_filename_purify_inplace(pss->filename);
		/* open a file of that name for write in the cwd */
		pss->fd = lws_open(pss->filename, O_CREAT | O_TRUNC | O_RDWR, 0600);
		if (pss->fd == -1) {
			lwsl_notice("Failed to open output file %s\n",
				    pss->filename);
			return 1;
		}
		break;
	case LWS_UFS_FINAL_CONTENT:
	case LWS_UFS_CONTENT:
		if (len) {
			int n;

			pss->file_length += (unsigned int)len;

			n = (int)write(pss->fd, buf, (unsigned int)len);
			if (n < len) {
				lwsl_notice("Problem writing file %d\n", errno);
			}
		}
		if (state == LWS_UFS_CONTENT)
			/* wasn't the last part of the file */
			break;

		/* the file upload is completed */

		lwsl_user("%s: upload done, written %lld to %s\n", __func__,
			  pss->file_length, pss->filename);

		close(pss->fd);
		pss->fd = -1;
		break;
	case LWS_UFS_CLOSE:
		break;
	}

	return 0;
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	uint8_t buf[LWS_PRE + LWS_RECOMMENDED_MIN_HEADER_SPACE], *start = &buf[LWS_PRE],
		*p = start, *end = &buf[sizeof(buf) - 1];
	struct pss *pss = (struct pss *)user;
	int n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:

		/*
		 * Manually report that our form target URL exists
		 *
		 * you can also do this by adding a mount for the form URL
		 * to the protocol with type LWSMPRO_CALLBACK, then no need
		 * to trap LWS_CALLBACK_HTTP.
		 */

		if (!strcmp((const char *)in, "/form1"))
			/* assertively allow it to exist in the URL space */
			return 0;

		/* default to 404-ing the URL if not mounted */
		break;

	case LWS_CALLBACK_HTTP_BODY:

		/* create the POST argument parser if not already existing */

		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
					LWS_ARRAY_SIZE(param_names), 1024,
					file_upload_cb, pss);
			if (!pss->spa)
				return -1;
		}

		/* let it parse the POST data */

		if (lws_spa_process(pss->spa, in, (int)len))
			return -1;
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:

		/* inform the spa no more payload data coming */

		lws_spa_finalize(pss->spa);

		/* we just dump the decoded things to the log */

		for (n = 0; n < (int)LWS_ARRAY_SIZE(param_names); n++) {
			if (!lws_spa_get_string(pss->spa, n))
				lwsl_user("%s: undefined\n", param_names[n]);
			else
				lwsl_user("%s: (len %d) '%s'\n",
				    param_names[n],
				    lws_spa_get_length(pss->spa, n),
				    lws_spa_get_string(pss->spa, n));
		}

		/*
		 * Our response is to redirect to a static page.  We could
		 * have generated a dynamic html page here instead.
		 */

		if (lws_http_redirect(wsi, HTTP_STATUS_MOVED_PERMANENTLY,
				      (unsigned char *)"after-form1.html",
				      16, &p, end) < 0)
			return -1;

		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		/* called when our wsi user_space is going to be destroyed */
		if (pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols[] = {
	{ "http", callback_http, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* default mount serves the URL space from ./mount-origin */

static const struct lws_http_mount mount = {
	.mountpoint		= "/",			/* mountpoint URL */
	.origin			= "./mount-origin",	/* serve from dir */
	.def			= "index.html",		/* default filename */
	.origin_protocol	= LWSMPRO_FILE,		/* files in a dir */
	.mountpoint_len		= 1,			/* char count */
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal http server POST file | visit http://localhost:7681\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.protocols = protocols;
	info.mounts = &mount;
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
