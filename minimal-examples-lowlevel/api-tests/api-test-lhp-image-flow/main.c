/*
 * lws-api-test-lhp-image-flow
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences how much of an image a browsed page holds, and when.  A raster image
 * is fetched with the page, but its pixels are only wanted while the raster
 * is going down its rows: until then all the layout needs from it is its
 * dimensions, from the start of its header.  So:
 *
 *  - before the raster reaches an image, it holds no more of its payload
 *    than its header needs, however much the server has ready: the fetch is
 *    allowed to send LWS_DLO_IMAGE_HEAD_CREDIT at a time until the header is
 *    complete, and nothing after it
 *
 *  - while the raster is on its rows, it holds no more than the flow control
 *    window ahead of the decoder, however slowly the decoder takes it
 *
 *  - once the raster has passed its last row, the image's stream and payload
 *    are gone: in a retained render (--retained), where the dlo stays for the
 *    display list to be rendered again, the dlo is left without them; else
 *    the dlo itself is gone
 *
 * and every row of every image is drawn.  A retained display list is rendered
 * twice, as a touch panel does: the second time the images are fetched again,
 * hold nothing until the raster reaches them, and come out the same.
 *
 * A tls server vhost in this process serves the page and its images over
 * h2 and h3, and the page is browsed with lws_lhp_ss_browse() over the
 * protocol given with --alpn, with a small window as on the small targets.
 * The page stacks a png and two jpegs vertically, below a gap, so the raster
 * reaches each some time after the layout has finished.  The last jpeg,
 * bigheader.jpg, has a comment segment that puts its dimensions beyond the
 * first few LWS_DLO_IMAGE_HEAD_CREDIT of it, so the layout depends on its
 * fetch being given more, a little at a time.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#if !defined(WIN32)
#include <unistd.h>
#endif

enum {
	LWS_SW_PORT,
	LWS_SW_ALPN,
	LWS_SW_CERT,
	LWS_SW_KEY,
	LWS_SW_SRC,
	LWS_SW_WINDOW,
	LWS_SW_RETAINED,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	= { "-p",	"Port for the test server" },
	[LWS_SW_ALPN]	= { "--alpn",	"Browse over h1, h2 or h3 (default h2)" },
	[LWS_SW_CERT]	= { "--cert",	"The test server's certificate, also "
					"the client's trust store" },
	[LWS_SW_KEY]	= { "--key",	"The test server's private key" },
	[LWS_SW_SRC]	= { "--src",	"The lws source tree, for the page and "
					"its images" },
	[LWS_SW_WINDOW]	= { "--window",	"Flow control window to browse with "
					"(default 4096)" },
	[LWS_SW_RETAINED] = { "--retained", "Render retained, as for a touch "
					"panel, keeping the DLOs as the raster "
					"passes them" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

#define IF_TIMEOUT_S		30
#define IF_MAX_IMAGES		4

/* the server's name, which lws resolves to loopback itself */
#define IF_SERVER		"srv.localhost"

struct if_image {
	lws_dlo_t		*dlo;
	char			name[32]; /* the dlo may go before we report */
	lws_flow_t		*flow;
	int			top, bottom; /* surface lines it covers */
	size_t			peak_before; /* held before the raster */
	size_t			peak_on; /* held while on its rows */
	uint32_t		rows; /* decoded rows issued by its last line */
	uint32_t		rows_min; /* ... at least, to draw them all */
	char			released; /* stream and payload gone after */
	char			seen_after; /* the raster got past it */
};

static struct lws_context *cx;
static lws_display_render_state_t drs;
static lws_sorted_usec_list_t sul_watchdog, sul_sample;
static struct if_image images[IF_MAX_IMAGES];
static int nimages, fails, finished, port = 7681, window = 4096, retained,
	   pass;
static uint32_t line_hash[1024]; /* each line of the first pass */
static char url[128];

static lws_surface_info_t ic = {
	.wh_px = { { 600,0 },       { 560,0 } },
	.wh_mm = { { 114,5000000 }, { 106,5000000 } },
	.type  = LWSSURF_TRUECOLOR32,
};

static void
finish(int fail)
{
	if (fail)
		fails++;
	finished = 1;
	lws_cancel_service(cx);
}

/*
 * Find the raster image dlos, with the surface lines they cover: their boxes
 * are relative to their parents'
 */

static void
find_images(lws_dll2_owner_t *owner, int y)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(owner)) {
		lws_dlo_t *dlo = lws_container_of(d, lws_dlo_t, list);
		struct if_image *im;
		int top = y + dlo->box.y.whole;

		find_images(&dlo->children, top);

		if (dlo->render != lws_display_render_png &&
		    dlo->render != lws_display_render_jpeg)
			continue;

		if (nimages == IF_MAX_IMAGES)
			return;

		im = &images[nimages++];
		im->dlo = dlo;
		im->top = top;
		im->bottom = top + dlo->box.h.whole;
		if (dlo->render == lws_display_render_png) {
			lws_dlo_png_t *p = lws_container_of(dlo,
						lws_dlo_png_t, dlo);
			im->flow = &p->flow;
			lws_strncpy(im->name, p->name, sizeof(im->name));
		} else {
			lws_dlo_jpeg_t *j = lws_container_of(dlo,
						lws_dlo_jpeg_t, dlo);
			im->flow = &j->flow;
			lws_strncpy(im->name, j->name, sizeof(im->name));
		}

	} lws_end_foreach_dll(d);
}

/*
 * How much of each image's payload is held now, against where the raster is
 * (the layout is "before" all of them).  The payload only leaves the buflist
 * as the decoder takes it, so a sample at any time sees all that is held.
 */

static void
sample(int curr)
{
	int n;

	for (n = 0; n < nimages; n++) {
		struct if_image *im = &images[n];
		size_t held;

		if (im->seen_after)
			continue; /* not retained, it may be gone */

		held = lws_buflist_total_len(&im->flow->bl);

		/*
		 * The raster calls on a dlo from the line before its top, so
		 * the decoder may start from there
		 */
		if (curr < im->top - 1) {
			if (held > im->peak_before)
				im->peak_before = held;
		} else if (curr <= im->bottom) {
			/*
			 * Its last row is bottom - 1: drawing line bottom is
			 * when the raster finds it has left it
			 */
			if (held > im->peak_on)
				im->peak_on = held;
		} else {
			/*
			 * The line after that, the dlo is still there, even if
			 * it is not retained: drawing this line destroys it
			 */
			im->seen_after = 1;
			im->released = !im->flow->h && !held;
		}
	}
}

static void
sample_cb(lws_sorted_usec_list_t *sul)
{
	if (nimages && !drs.line)
		sample(-1);

	lws_sul_schedule(cx, 0, &sul_sample, sample_cb, 2 * LWS_US_PER_MS);
}

/*
 * The image's last line was just drawn: how many of its rows had the decoder
 * issued?  The rows are scaled to the box, so the last line shows the image
 * row (bh - 1) * ih / bh, and all of them up to it have to have come out
 */

static void
last_line(struct if_image *im)
{
	int bh = im->bottom - im->top;
	uint32_t ih;

	if (im->dlo->render == lws_display_render_png) {
		lws_dlo_png_t *p = lws_container_of(im->dlo, lws_dlo_png_t,
						    dlo);

		ih = p->png ? lws_upng_get_height(p->png) : 0;
		im->rows = p->emitted;
	} else {
		lws_dlo_jpeg_t *j = lws_container_of(im->dlo, lws_dlo_jpeg_t,
						     dlo);

		ih = j->j ? lws_jpeg_get_height(j->j) : 0;
		im->rows = j->emitted;
	}

	im->rows_min = ih && bh > 0 ?
		(uint32_t)(((int64_t)(bh - 1) * ih) / bh) + 1 : 1;
}

static uint32_t
hash(const uint8_t *p, size_t len)
{
	uint32_t h = 2166136261u;

	while (len--)
		h = (h ^ *p++) * 16777619u;

	return h;
}

static void
check(int again)
{
	/*
	 * Before the raster: only the header's credit, in the first pass, and
	 * nothing in the second, it was given back.  The png and bluecat.jpg
	 * have their dimensions in the first LWS_DLO_IMAGE_HEAD_CREDIT, but a
	 * comment segment puts bigheader.jpg's SOF at 2762 bytes, so it is
	 * given the credit three times: the header parse consumes what came
	 * each time, so it never holds more than one credit's worth either
	 */
	size_t before_max = pass ? 0 : LWS_DLO_IMAGE_HEAD_CREDIT,
	       on_max = (size_t)window;
	int n;

	if (nimages != 3) {
		lwsl_err("%s: %d images laid out, expected 3\n", __func__,
			 nimages);
		fails++;
		return;
	}

	for (n = 0; n < nimages; n++) {
		struct if_image *im = &images[n];

		lwsl_user("%s: pass %d: %s lines %d - %d: held %u before the "
			  "raster, %u on it, %u / %u rows, %sreleased after\n",
			  __func__, pass + 1, im->name, im->top, im->bottom,
			  (unsigned int)im->peak_before,
			  (unsigned int)im->peak_on, (unsigned int)im->rows,
			  (unsigned int)im->rows_min,
			  im->released ? "" : "NOT ");

		if (im->peak_before > before_max) {
			lwsl_err("%s: %s: held %u before the raster, max %u\n",
				 __func__, im->name,
				 (unsigned int)im->peak_before,
				 (unsigned int)before_max);
			fails++;
		}
		if (im->peak_on > on_max) {
			lwsl_err("%s: %s: held %u on the raster, max %u\n",
				 __func__, im->name, (unsigned int)im->peak_on,
				 (unsigned int)on_max);
			fails++;
		}
		if (im->rows < im->rows_min) {
			lwsl_err("%s: %s: only %u of its rows were drawn\n",
				 __func__, im->name, (unsigned int)im->rows);
			fails++;
		}
		if (!im->released) {
			lwsl_err("%s: %s: still held after the raster\n",
				 __func__, im->name);
			fails++;
		}

		if (!again)
			/* the images may be gone: sampling stays off them */
			continue;

		/* the next pass measures afresh */
		im->peak_before = im->peak_on = 0;
		im->rows = im->rows_min = 0;
		im->released = im->seen_after = 0;
	}
}

static void
list_done(lws_display_render_state_t *rs)
{
	nimages = 0; /* sampling stays off the dlos from now */
	lws_display_list_destroy(cx, &rs->displaylist);
}

static void
render(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = lws_container_of(sul,
					lws_display_render_state_t, sul);
	size_t lbuflen = (size_t)rs->ic->wh_px[0].whole * 3;
	lws_stateful_ret_t r;
	uint32_t h;
	int n;

	if (rs->html == 1)
		return;

	if (rs->layout_failed) {
		lwsl_err("%s: layout failed\n", __func__);
		list_done(rs);
		finish(1);
		return;
	}

	if (!rs->line) {
		if (!pass)
			find_images(&rs->displaylist.dl, 0);
		sample(-1);

		rs->line = malloc(lbuflen);
		if (!rs->line) {
			list_done(rs);
			finish(1);
			return;
		}
		rs->curr = 0;
	}

	while (rs->curr != rs->ic->wh_px[1].whole) {

		sample(rs->curr);
		memset(rs->line, 0xff, lbuflen);

		r = lws_display_list_render_line(rs);
		if (r) {
			/* waiting for more of an image: its rx wakes us */
			if (r & LWS_SRET_YIELD)
				lws_sul_schedule(cx, 0, &rs->sul, render,
						 20 * LWS_US_PER_MS);
			return;
		}

		for (n = 0; n < nimages; n++)
			if (rs->curr == images[n].bottom - 1)
				last_line(&images[n]);

		/* a second pass must draw exactly what the first did */

		h = hash(rs->line, lbuflen);
		if (rs->curr < (int)LWS_ARRAY_SIZE(line_hash)) {
			if (!pass)
				line_hash[rs->curr] = h;
			else if (line_hash[rs->curr] != h) {
				lwsl_err("%s: line %d differs in pass 2\n",
					 __func__, rs->curr);
				fails++;
			}
		}

		rs->curr++;
	}

	sample(rs->curr);

	free(rs->line);
	rs->line = NULL;

	check(rs->retained && !pass);

	if (rs->retained && !pass++) {
		/*
		 * Render the retained display list again, as a touch panel
		 * does: the images were given back, so they must be fetched
		 * again, and come out the same
		 */
		lws_sul_schedule(cx, 0, &rs->sul, render, 1);
		return;
	}

	list_done(rs);
	finish(0);
}

static void
watchdog(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out at line %d\n", __func__, drs.curr);
	finish(1);
}

static void
start(lws_sorted_usec_list_t *sul)
{
	memset(&drs, 0, sizeof(drs));
	drs.ic = &ic;
	drs.window = window;
	drs.retained = (char)retained;

	lws_snprintf(url, sizeof(url), "https://" IF_SERVER ":%d/page.html",
		     port);
	lwsl_user("%s: browsing %s, window %d\n", __func__, url, window);

	if (lws_lhp_ss_browse(cx, &drs, url, render)) {
		lwsl_err("%s: browse failed\n", __func__);
		finish(1);
	}
}

/*
 * The server's certificate is the client's trust store: the policy wants it
 * as base64 DER, which is the PEM without its armour and line breaks
 */

static int
cert_b64(const char *path, char *out, size_t len)
{
	char pem[8192], *p, *e;
	size_t o = 0;
	ssize_t n;
	int fd;

	fd = lws_open(path, LWS_O_RDONLY);
	if (fd < 0)
		return 1;
	n = read(fd, pem, sizeof(pem) - 1);
	close(fd);
	if (n <= 0)
		return 1;
	pem[n] = '\0';

	p = strstr(pem, "-----BEGIN CERTIFICATE-----");
	if (!p)
		return 1;
	p = strchr(p, '\n');
	e = p ? strstr(p, "-----END CERTIFICATE-----") : NULL;
	if (!e)
		return 1;

	for (; p < e; p++)
		if (*p != '\n' && *p != '\r') {
			if (o + 1 >= len)
				return 1;
			out[o++] = *p;
		}
	out[o] = '\0';

	return !o;
}

int
main(int argc, const char **argv)
{
	struct lws_http_mount m_page, m_png, m_jpg;
	char b64[4096], policy[6144], o_page[256], o_png[256], o_jpg[256];
	const char *cert = NULL, *key = NULL, *src = NULL, *alpn = "h2", *p;
	struct lws_context_creation_info info;
	int n = 0;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw)))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_ALPN].sw)))
		alpn = p;
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_CERT].sw)))
		cert = p;
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_KEY].sw)))
		key = p;
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SRC].sw)))
		src = p;
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_WINDOW].sw)))
		window = atoi(p);
	retained = !!lws_cmdline_option(argc, argv,
					switches[LWS_SW_RETAINED].sw);

	lwsl_user("LWS API selftest: lhp image payload flow over %s\n", alpn);

	if (!cert || !key || !src || window < 1024 ||
	    (strcmp(alpn, "h1") && strcmp(alpn, "h2") && strcmp(alpn, "h3"))) {
		lwsl_err("%s: needs --cert, --key, --src, --alpn h1|h2|h3, "
			 "and a --window of 1024 or more\n", __func__);
		return 1;
	}

	if (cert_b64(cert, b64, sizeof(b64))) {
		lwsl_err("%s: can't use %s\n", __func__, cert);
		return 1;
	}

	/* lhp fetches the page and its images with "__default" */

	lws_snprintf(policy, sizeof(policy),
		"{\"release\":\"1\",\"product\":\"lhp-image-flow\","
		 "\"schema-version\":1,"
		 "\"retry\":[{\"none\":{\"backoff\":[],"
			"\"conceal\":0,\"jitterpc\":0,"
			"\"svalidping\":30,\"svalidhup\":35}}],"
		 "\"certs\":[{\"self_localhost\":\"%s\"}],"
		 "\"trust_stores\":[{\"name\":\"self\","
			"\"stack\":[\"self_localhost\"]}],"
		 "\"s\":[{\"__default\":{"
			"\"endpoint\":\"${endpoint}\","
			"\"port\":443,"
			"\"protocol\":\"%s\","
			"\"http_method\":\"GET\","
			"\"http_url\":\"\","
			"\"metadata\":[{"
				"\"endpoint\":\"\","
				"\"acc\":\"accept\","
				"\"ua\":\"user-agent\""
			"}],"
			"\"tls\":true,\"tls_trust_store\":\"self\","
			"\"retry\":\"none\","
			"\"timeout_ms\":10000"
		 "}}]}", b64, alpn);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.pss_policies_json = policy;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: context creation failed\n", __func__);
		return 1;
	}

	/* the page, and the images from where they live in the tree */

	lws_snprintf(o_page, sizeof(o_page), "%s/minimal-examples-lowlevel/"
		     "api-tests/api-test-lhp-image-flow", src);
	lws_snprintf(o_png, sizeof(o_png), "%s/doc-assets", src);
	lws_snprintf(o_jpg, sizeof(o_jpg), "%s/minimal-examples-lowlevel/"
		     "api-tests/api-test-lhp-dlo", src);

	memset(&m_jpg, 0, sizeof(m_jpg));
	m_jpg.mountpoint		= "/jpg";
	m_jpg.mountpoint_len		= 4;
	m_jpg.origin_protocol		= LWSMPRO_FILE;
	m_jpg.origin			= o_jpg;

	m_png				= m_jpg;
	m_png.mountpoint		= "/png";
	m_png.origin			= o_png;
	m_png.mount_next		= &m_jpg;

	m_page				= m_jpg;
	m_page.mountpoint		= "/";
	m_page.mountpoint_len		= 1;
	m_page.origin			= o_page;
	m_page.def			= "page.html";
	m_page.mount_next		= &m_png;

	info.port			= port;
	info.vhost_name			= IF_SERVER;
	info.mounts			= &m_page;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "h2,http/1.1,h3";

	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("%s: server vhost creation failed\n", __func__);
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog,
			 IF_TIMEOUT_S * LWS_US_PER_SEC);
	lws_sul_schedule(cx, 0, &sul_sample, sample_cb, 1);
	lws_sul_schedule(cx, 0, &drs.sul, start, 1);

	while (n >= 0 && !finished)
		n = lws_service(cx, 0);

	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_sample);
	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", fails || !finished ? "FAIL" : "PASS");

	return fails || !finished;

bail:
	lws_context_destroy(cx);

	return 1;
}
