/*
 * lws-minimal-http-server-form-post-file
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http server that performs POST with a couple
 * of parameters and a file upload, all in multipart (mime) form mode.
 * It saves the uploaded file in an upload directory, dumps the parameters to
 * the console log and redirects to another page.
 *
 * Everything about an upload comes from the peer, and is untrusted:
 *
 *  - the filename the client gives is reduced to a single path component by
 *    lws_filename_purify_inplace(), and only ever used inside the upload dir
 *
 *  - files are created with O_CREAT | O_EXCL | O_NOFOLLOW, so an existing
 *    file, or a symlink planted at the name, is refused, never followed or
 *    overwritten
 *
 *  - a file is limited to --max-size bytes, and at most --max-files files are
 *    stored per run of the server, so peers can't fill the disk
 *
 *  - an upload that does not complete, for whatever reason, is removed
 *
 * A real server must also authenticate who may upload at all.
 */

#include <libwebsockets.h>

#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#if !defined(WIN32)
#include <unistd.h>
#else
#include <io.h>
#include <direct.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>

#if !defined(O_NOFOLLOW)
/* eg, windows: O_CREAT | O_EXCL alone refuses any existing name */
#define O_NOFOLLOW 0
#endif
#if !defined(O_BINARY)
#define O_BINARY 0
#endif

/*
 * The request body may be this much bigger than the largest file, for the
 * multipart framing and the form's other fields
 */
#define FORM_OVERHEAD		(16 * 1024)

enum {
	LWS_SW_D,
	LWS_SW_PORT,
	LWS_SW_UPLOAD_DIR,
	LWS_SW_MAX_SIZE,
	LWS_SW_MAX_FILES,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]		= { "-d",		"Debug logs (e.g. -d 15)" },
	[LWS_SW_PORT]		= { "--port",		"Port to listen on (default 7681)" },
	[LWS_SW_UPLOAD_DIR]	= { "--upload-dir",	"Directory uploads are saved in, created if missing (default ./uploads)" },
	[LWS_SW_MAX_SIZE]	= { "--max-size",	"Largest file accepted, in bytes (default 10485760)" },
	[LWS_SW_MAX_FILES]	= { "--max-files",	"Most files stored per run of the server (default 100)" },
	[LWS_SW_HELP]		= { "--help",		"Show this help information" },
};

/*
 * Unlike ws, http is a stateless protocol.  This pss only exists for the
 * duration of a single http transaction.  With http/1.1 keep-alive and http/2,
 * that is unrelated to (shorter than) the lifetime of the network connection.
 */
struct pss {
	struct lws_spa *spa;		/* lws helper decodes multipart form */
	char path[512];			/* the file being saved, while it is */
	unsigned long long file_length; /* the amount of bytes uploaded */
	unsigned int refused;		/* 0, or HTTP status refusing the POST */
	int fd;				/* fd on file being saved, or -1 */
};

/* how and where we store uploads, for the whole server */

static struct {
	const char		*dir;		/* the upload directory */
	unsigned long long	max_size;	/* largest file we store */
	unsigned int		max_files;	/* most files stored per run */
	unsigned int		files;		/* files stored, or being stored */
} up = { "./uploads", 10 * 1024 * 1024, 100, 0 };

static struct lws_context *context;

static const char * const param_names[] = {
	"text1",
	"send",
};

enum enum_param_names {
	EPN_TEXT1,
	EPN_SEND,
};

/*
 * An upload that did not complete: close its file and remove what it wrote,
 * so it leaves neither an fd nor a partial file behind, and give back its
 * place in the file budget
 */

static void
file_upload_abandon(struct pss *pss)
{
	if (pss->fd == -1)
		return;

	close(pss->fd);
	pss->fd = -1;

	if (unlink(pss->path) < 0)
		lwsl_notice("%s: unlink %s failed: %d\n", __func__,
			    pss->path, errno);
	pss->path[0] = '\0';
	up.files--;
}

/*
 * Something about the request means we won't store (any more of) it.  The
 * rest of the body is read and ignored, and the response is this status.
 */

static void
file_upload_refuse(struct pss *pss, unsigned int status, const char *why)
{
	lwsl_notice("%s: %u: %s\n", __func__, status, why);
	file_upload_abandon(pss);
	if (!pss->refused)
		pss->refused = status;
}

static int
file_upload_cb(void *data, const char *name, const char *filename,
	       char *buf, int len, enum lws_spa_fileupload_states state)
{
	struct pss *pss = (struct pss *)data;
	char safe[256];

	switch (state) {
	case LWS_UFS_OPEN:
		/*
		 * One file at a time: one still open here did not complete,
		 * and the open below would otherwise leak it
		 */
		file_upload_abandon(pss);

		if (pss->refused)
			/* we already refused this request: store nothing */
			break;

		if (up.files >= up.max_files) {
			file_upload_refuse(pss, HTTP_STATUS_SERVICE_UNAVAILABLE,
					   "upload file budget used up");
			break;
		}

		/*
		 * The client's filename is never a path for us: it becomes
		 * one path component, inside the upload dir
		 */
		lws_strncpy(safe, filename, sizeof(safe));
		lws_filename_purify_inplace(safe);
		if (!safe[0] ||
		    lws_snprintf(pss->path, sizeof(pss->path), "%s/%s",
				 up.dir, safe) >= (int)sizeof(pss->path) - 1) {
			pss->path[0] = '\0';
			file_upload_refuse(pss, HTTP_STATUS_BAD_REQUEST,
					   "unusable filename");
			break;
		}

		/*
		 * Only ever a new file: an existing one, or a symlink at the
		 * name, is refused, not followed or overwritten
		 */
		pss->fd = lws_open(pss->path, O_CREAT | O_EXCL | O_WRONLY |
					      O_NOFOLLOW | O_BINARY, 0600);
		if (pss->fd == -1) {
			lwsl_notice("%s: unable to create %s: %d\n", __func__,
				    pss->path, errno);
			pss->path[0] = '\0';
			file_upload_refuse(pss, errno == EEXIST ?
					HTTP_STATUS_CONFLICT :
					HTTP_STATUS_INTERNAL_SERVER_ERROR,
					"can't create file");
			break;
		}

		up.files++;
		pss->file_length = 0;
		break;

	case LWS_UFS_FINAL_CONTENT:
	case LWS_UFS_CONTENT:
		if (pss->fd == -1)
			/* not a file we are storing */
			break;

		if (len) {
			if ((unsigned long long)len >
					up.max_size - pss->file_length) {
				file_upload_refuse(pss,
					HTTP_STATUS_REQ_ENTITY_TOO_LARGE,
					"file too large");
				break;
			}

			pss->file_length += (unsigned int)len;

			if (write(pss->fd, buf, (unsigned int)len) != len) {
				lwsl_err("%s: write failed: %d\n", __func__,
					 errno);
				file_upload_refuse(pss,
					HTTP_STATUS_INTERNAL_SERVER_ERROR,
					"write failed");
				break;
			}
		}
		if (state == LWS_UFS_CONTENT)
			/* wasn't the last part of the file */
			break;

		/* the file upload is completed */

		lwsl_user("%s: upload done, written %llu to %s\n", __func__,
			  pss->file_length, pss->path);

		/* it's complete: keep it */
		close(pss->fd);
		pss->fd = -1;
		pss->path[0] = '\0';
		break;

	case LWS_UFS_CLOSE:
		/* the form ended, or the client went, mid-file */
		file_upload_abandon(pss);
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
			pss->fd = -1;
			pss->path[0] = '\0';
			pss->refused = 0;
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

		if (!pss->spa) {
			/* there was no body to parse */
			if (lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST,
						   NULL) ||
			    lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}

		/*
		 * Inform the spa no more payload data coming: a file still
		 * open now did not complete, and is removed
		 */

		lws_spa_finalize(pss->spa);

		/* we just dump the decoded things to the log */

		if (!pss->refused)
			for (n = 0; n < (int)LWS_ARRAY_SIZE(param_names); n++) {
				if (!lws_spa_get_string(pss->spa, n))
					lwsl_user("%s: undefined\n",
						  param_names[n]);
				else
					lwsl_user("%s: (len %d) '%s'\n",
					    param_names[n],
					    lws_spa_get_length(pss->spa, n),
					    lws_spa_get_string(pss->spa, n));
			}

		/*
		 * We are done with the spa: free it now.  Our pss is going to
		 * be freed when this transaction completes, and we get no
		 * callback about that (LWS_CALLBACK_HTTP_DROP_PROTOCOL only
		 * comes after a protocol was bound to a mount).
		 */

		lws_spa_destroy(pss->spa);
		pss->spa = NULL;

		if (pss->refused) {
			/*
			 * A status page isn't sent as HTTP headers alone, so
			 * the dummy callback can't tell we responded: we
			 * complete the transaction ourselves
			 */
			if (lws_return_http_status(wsi, pss->refused, NULL) ||
			    lws_http_transaction_completed(wsi))
				return -1;

			return 0;
		}

		/*
		 * Our response is to redirect to a static page.  We could
		 * have generated a dynamic html page here instead.
		 */

		if (lws_http_redirect(wsi, HTTP_STATUS_SEE_OTHER,
				      (unsigned char *)"after-form1.html",
				      16, &p, end) < 0)
			return -1;

		break;

	case LWS_CALLBACK_CLOSED_HTTP:
		/*
		 * The connection went before the body completed: destroying
		 * the spa gives the upload callback its LWS_UFS_CLOSE, which
		 * removes an incomplete file
		 */
		if (pss && pss->spa) {
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
	lws_default_loop_exit(context);
}

/* a decimal number from a switch, nonzero and no bigger than max */

static int
parse_limit(const char *s, unsigned long long max, unsigned long long *out)
{
	char *e;

	errno = 0;
	*out = strtoull(s, &e, 10);

	return *s < '0' || *s > '9' || *e || errno || !*out || *out > max;
}

/* the upload dir must exist and be a directory: make it if it is missing */

static int
upload_dir_prepare(const char *dir)
{
	struct stat st;

#if defined(WIN32)
	if (_mkdir(dir) < 0 && errno != EEXIST) {
#else
	if (mkdir(dir, 0700) < 0 && errno != EEXIST) {
#endif
		lwsl_err("Unable to create upload dir %s: %d\n", dir, errno);
		return 1;
	}

	if (stat(dir, &st) || (st.st_mode & S_IFMT) != S_IFDIR) {
		lwsl_err("Upload dir %s is not a directory\n", dir);
		return 1;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	unsigned long long ull;
	const char *p;
	int n = 0;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS minimal http server POST file | visit http://localhost:7681\n");

	lws_context_info_defaults(&info, NULL);
	/* a server: size the fds tables to the process limit */
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = 7681;
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw))) {
		int pt = atoi(p);

		if (pt <= 0 || pt > 65535) {
			lwsl_err("Port %d is outside valid 16-bit range\n", pt);
			return 1;
		}
		info.port = pt;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_UPLOAD_DIR].sw)))
		up.dir = p;
	if (!up.dir[0] || strlen(up.dir) > 256) {
		lwsl_err("Upload dir must be 1 to 256 chars\n");
		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_MAX_SIZE].sw))) {
		/* the body limit below must not wrap */
		if (parse_limit(p, 1ull << 48, &ull)) {
			lwsl_err("Bad --max-size %s\n", p);
			return 1;
		}
		up.max_size = ull;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_MAX_FILES].sw))) {
		if (parse_limit(p, 1000000, &ull)) {
			lwsl_err("Bad --max-files %s\n", p);
			return 1;
		}
		up.max_files = (unsigned int)ull;
	}

	if (upload_dir_prepare(up.dir))
		return 1;

	lwsl_user("Saving uploads in %s, max %llu bytes each, max %u files\n",
		  up.dir, up.max_size, up.max_files);

	info.protocols = protocols;
	info.mounts = &mount;
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;
	/*
	 * lws refuses a bigger request body with a 413 before we see any of
	 * it, when it is told the length up front
	 */
	info.max_http_body_size = up.max_size + FORM_OVERHEAD;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
