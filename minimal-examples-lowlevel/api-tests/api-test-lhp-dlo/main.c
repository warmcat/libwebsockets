/*
 * lws-api-test-lhp-dlo
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>

//#define SEVENCOL

struct lws_context *cx;

LWS_SS_USER_TYPEDEF
	lws_flow_t			flow;
	lhp_ctx_t			lhp; /* html ss owns html parser */
	lws_dl_rend_t			drt;
	lws_sorted_usec_list_t		sul;
	lws_display_render_state_t	*rs;
} htmlss_t;

static lws_display_render_state_t drs;

static const uint8_t fira_c_r_10[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular10.mcufont.h"
};
static const uint8_t fira_c_r_12[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular12.mcufont.h"
};
static const uint8_t fira_c_r_14[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular14.mcufont.h"
};
static const uint8_t fira_c_r_16[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular16.mcufont.h"
};
static const uint8_t fira_c_r_20[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular20.mcufont.h"
};
static const uint8_t fira_c_r_24[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular24.mcufont.h"
};
static const uint8_t fira_c_r_32[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular32.mcufont.h"
};

static const uint8_t fira_c_b_10[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold10.mcufont.h"
};
static const uint8_t fira_c_b_12[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold12.mcufont.h"
};
static const uint8_t fira_c_b_14[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold14.mcufont.h"
};
static const uint8_t fira_c_b_16[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold16.mcufont.h"
};
static const uint8_t fira_c_b_20[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold20.mcufont.h"
};

#if defined(SEVENCOL)
static const lws_display_colour_t palette[] = {
        LWSDC_RGBA(0, 0, 0, 255),               /* black */
        LWSDC_RGBA(255, 255, 255, 255),         /* white */
        LWSDC_RGBA(0, 255, 0, 255),             /* green */
        LWSDC_RGBA(0, 0, 255, 255),             /* blue */
        LWSDC_RGBA(255, 0, 0, 255),             /* red */
        LWSDC_RGBA(255, 255, 0, 255),           /* yellow */
        LWSDC_RGBA(255, 127, 0, 255),           /* orange */
};
#endif

static const lws_surface_info_t ic = {
	.wh_px = { { 1600,0 },       { 2000,0 } },
	.wh_mm = { { 114,5000000 }, {  82,5000000 } },
#if defined(SEVENCOL)
        .palette                = palette,
        .palette_depth          = LWS_ARRAY_SIZE(palette),
	.type			= LWSSURF_PALETTE,
#else
	.type			= LWSSURF_TRUECOLOR32,
#endif
	.greyscale		= 0
};

int fdin = 0, fdout = 1;

static void
write_bmp_header(int fd, int w, int h)
{
	uint8_t head[54];
	int filesize = 54 + (w * h * 3);

	memset(head, 0, sizeof(head));

	head[0] = 'B';
	head[1] = 'M';
	head[2] = (uint8_t)(filesize & 0xff);
	head[3] = (uint8_t)((filesize >> 8) & 0xff);
	head[4] = (uint8_t)((filesize >> 16) & 0xff);
	head[5] = (uint8_t)((filesize >> 24) & 0xff);
	head[10] = 54;

	head[14] = 40;
	head[18] = (uint8_t)(w & 0xff);
	head[19] = (uint8_t)((w >> 8) & 0xff);
	head[20] = (uint8_t)((w >> 16) & 0xff);
	head[21] = (uint8_t)((w >> 24) & 0xff);

	h = -h; /* top-down */
	head[22] = (uint8_t)(h & 0xff);
	head[23] = (uint8_t)((h >> 8) & 0xff);
	head[24] = (uint8_t)((h >> 16) & 0xff);
	head[25] = (uint8_t)((h >> 24) & 0xff);

	head[26] = 1;
	head[28] = 24;

	if (write(fd, head, 54) < 54)
		lwsl_err("%s: write failed\n", __func__);
}

#if defined(SEVENCOL)
static void
expand(uint8_t nyb, uint8_t *rgba)
{
	*rgba++ = LWSDC_R(palette[nyb]);
	*rgba++ = LWSDC_G(palette[nyb]);
	*rgba++ = LWSDC_B(palette[nyb]);
	*rgba++ = 255;
}
#endif

static void
render(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = lws_container_of(sul,
					lws_display_render_state_t, sul);
	size_t lbuflen = (size_t)rs->ic->wh_px[0].whole *
					(rs->ic->greyscale ? 1 : 3);
	lws_stateful_ret_t r;

	lwsl_notice("%s: line %d\n", __func__, rs->curr);

	if (rs->html == 1)
		return;

	if (!rs->line) {

		lws_display_get_ids_boxes(rs);
		//lws_display_dl_dump(&rs->displaylist);

		/* allocate one line of RGB output pixels to render into */

		rs->line = malloc(lbuflen);
		if (!rs->line) {
			lwsl_err("%s: OOM\n", __func__);
			/* !!! cleanup */
			return;
		}

		memset(rs->line, 0, lbuflen);
		rs->curr = 0;

		if (fdout != 1)
			write_bmp_header(fdout, rs->ic->wh_px[0].whole,
					 rs->ic->wh_px[1].whole);
	}

	while (rs->curr != rs->lowest_id_y) {

		r = lws_display_list_render_line(rs);

		if (r) {
			/* eg, waiting for more jpg or whatever */
			lwsl_notice("%s: leaving 0x%x\n", __func__, (unsigned int)r);
			return;
		}

#if defined(SEVENCOL)
		/* convert from paletteized result to RGBA for dump purposes */
		{
			uint8_t dump[2048 * 4];
			int n;

			for (n = 0; n < rs->box.w.whole; n += 2) {
				expand(rs->line[(n >> 1)] >> 4, dump + (4 * n));
				expand(rs->line[(n >> 1)] & 0xf, dump + (4 * (n + 1)));
			}

			if (write(fdout, dump, (size_t)rs->box.w.whole * 4) < (ssize_t)((size_t)rs->box.w.whole * 4))
				lwsl_err("%s: write failed\n", __func__);
		}
#else
		{
			/* swap RGB -> BGR */
			uint8_t *p = (uint8_t *)rs->line;
			size_t n;

			for (n = 0; n < lbuflen; n += 3) {
				uint8_t t = p[0];
				p[0] = p[2];
				p[2] = t;
				p += 3;
			}
		}

#if defined(WIN32)
		if (write(fdout, rs->line, (unsigned int)lbuflen) < 0) {
#else
		if (write(fdout, rs->line, lbuflen) < 0) {
#endif
#endif
			lwsl_err("%s: unable to write\n", __func__);
		}

		rs->curr++;
	}

        free(rs->line);

	lwsl_warn("%s: render has reached end and destroys displaylist\n", __func__);
	lws_display_list_destroy(cx, &rs->displaylist);

	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int result = 0;
	const char *p;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS LHP DLO test tool - %s https://site.com [--bmp file.bmp]\n", argv[0]);

	if ((p = lws_cmdline_option(argc, argv, "--bmp"))) {
		fdout = open(p, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0600);
		if (fdout < 0) {
			result = 1;
			lwsl_err("%s: unable to open bmp file\n", __func__);
			goto bail;
		}
	}

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
			LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW;

	cx = lws_create_context(&info);
	if (!cx)
		goto bail;

	/* register the available fonts */

	lws_font_register(cx, fira_c_r_10, sizeof(fira_c_r_10));
	lws_font_register(cx, fira_c_r_12, sizeof(fira_c_r_12));
	lws_font_register(cx, fira_c_r_14, sizeof(fira_c_r_14));
	lws_font_register(cx, fira_c_r_16, sizeof(fira_c_r_16));
	lws_font_register(cx, fira_c_r_20, sizeof(fira_c_r_20));
	lws_font_register(cx, fira_c_r_24, sizeof(fira_c_r_24));
	lws_font_register(cx, fira_c_r_32, sizeof(fira_c_r_32));
	lws_font_register(cx, fira_c_b_10, sizeof(fira_c_b_10));
	lws_font_register(cx, fira_c_b_12, sizeof(fira_c_b_12));
	lws_font_register(cx, fira_c_b_14, sizeof(fira_c_b_14));
	lws_font_register(cx, fira_c_b_16, sizeof(fira_c_b_16));
	lws_font_register(cx, fira_c_b_20, sizeof(fira_c_b_20));

	drs.ic = &ic;

	/* create the SS to the html using the URL on argv[1] */

	if (argv[1] == NULL) {
		lwsl_err("Give a url like https://warmcat.com on the commandline\n");
		result = 1;
		goto bail;
	}

	if (lws_lhp_ss_browse(cx, &drs, argv[1], render)) {
		lws_context_destroy(cx);
		goto bail;
	}

	lws_context_default_loop_run_destroy(cx);

	if (fdout != 1)
		close(fdout);

bail:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
