/*
 * lws-api-test-fx
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Checks the lws_fx fixed-point operators, including the trigonometry
 * operators, against reference values.
 */

#include <libwebsockets.h>
#include <stdlib.h>

enum {
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",		"Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

static int checks, fails;

static double
fx2d(const lws_fx_t *f)
{
	return (double)f->whole + (double)f->frac / 100000000.0;
}

static void
d2f(lws_fx_t *f, double v)
{
	f->whole = (int32_t)v;
	f->frac = (int32_t)((v - (double)(int32_t)v) * 100000000.0);
}

#define CHK(_cond, _fmt, ...) do { \
	checks++; \
	if (!(_cond)) { \
		fails++; \
		lwsl_user("FAIL L%d: " _fmt "\n", __LINE__, ##__VA_ARGS__); \
	} \
} while (0)

static const struct { double a; double sin, cos; } fx_trig_ref[] = {
	{ 0.0, 0.000000000000000, 1.000000000000000 },
	{ 0.5, 0.479425538604203, 0.877582561890373 },
	{ 1.0, 0.841470984807897, 0.540302305868140 },
	{ 1.5707963267948966, 1.000000000000000, 0.000000000000000 },
	{ 2.0, 0.909297426825682, -0.416146836547142 },
	{ 3.0, 0.141120008059867, -0.989992496600445 },
	{ 3.141592653589793, 0.000000000000000, -1.000000000000000 },
	{ 4.5, -0.977530117665097, -0.210795799430780 },
	{ 6.283185307179586, -0.000000000000000, 1.000000000000000 },
	{ -0.5, -0.479425538604203, 0.877582561890373 },
	{ -1.0, -0.841470984807897, 0.540302305868140 },
	{ -2.5, -0.598472144103957, -0.801143615546934 },
	{ -3.141592653589793, -0.000000000000000, -1.000000000000000 },
	{ -6.0, 0.279415498198926, 0.960170286650366 },
	{ 12.566370614359172, -0.000000000000000, 1.000000000000000 },
	{ 100.0, -0.506365641109759, 0.862318872287684 },
	{ -100.0, 0.506365641109759, 0.862318872287684 },
};

static const struct { double y, x, r; } fx_atan2_ref[] = {
	{ 1, 1, 0.785398163397448 },
	{ 1, -1, 2.356194490192345 },
	{ -1, 1, -0.785398163397448 },
	{ -1, -1, -2.356194490192345 },
	{ 0, 1, 0.000000000000000 },
	{ 0, -1, 3.141592653589793 },
	{ 1, 0, 1.570796326794897 },
	{ -1, 0, -1.570796326794897 },
	{ 3, 4, 0.643501108793284 },
	{ 4, -3, 2.214297435588181 },
	{ -5, 12, -0.394791119699761 },
	{ 1e-07, 10000000.0, 0.000000000000010 },
	{ 10000000.0, 1e-07, 1.570796326794887 },
	{ -1e-07, -10000000.0, -3.141592653589783 },
	{ 2000000000.0, 1, 1.570796326294897 },
	{ 1, -2000000000.0, 3.141592653089793 },
	{ 7.25, -2.5, 1.902855794337782 },
	{ -7.25, 2.5, -1.238736859252011 },
};

static const struct { double a, r; } fx_tan_ref[] = {
	{ 0.0, 0.000000000000000 },
	{ 0.25, 0.255341921221036 },
	{ 0.5, 0.546302489843790 },
	{ 0.7853981633974483, 1.000000000000000 },
	{ 1.0, 1.557407724654902 },
	{ 1.2, 2.572151622126319 },
	{ -0.5, -0.546302489843790 },
	{ -1.0, -1.557407724654902 },
};

int
main(int argc, const char **argv)
{
	int n, result = 0;
	lws_fx_t a, b, r;

	(void)argc;
	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}
	lws_set_log_level(LLL_USER, NULL);

	lwsl_user("LWS fx api test tool\n");

	/* arithmetic operators sanity */

	lws_fx_set(a, 1, 50000000);	/* 1.5 */
	lws_fx_set(b, 2, 25000000);	/* 2.25 */
	lws_fx_add(&r, &a, &b);
	CHK(fx2d(&r) == 3.75, "add 1.5 + 2.25 = %f", fx2d(&r));

	lws_fx_sub(&r, &b, &a);
	CHK(fx2d(&r) == 0.75, "sub 2.25 - 1.5 = %f", fx2d(&r));

	lws_fx_set(a, 3, 0);
	lws_fx_set(b, 2, 50000000);	/* 2.5 */
	lws_fx_mul(&r, &a, &b);
	CHK(fx2d(&r) == 7.5, "mul 3 * 2.5 = %f", fx2d(&r));

	lws_fx_set(a, 10, 0);
	lws_fx_set(b, 4, 0);
	lws_fx_div(&r, &a, &b);
	CHK(fx2d(&r) == 2.5, "div 10 / 4 = %f", fx2d(&r));

	lws_fx_set(a, 2, 25000000);	/* 2.25 */
	lws_fx_sqrt(&r, &a);
	CHK(fx2d(&r) == 1.5, "sqrt 2.25 = %f", fx2d(&r));

	lws_fx_set(a, -1, 50000000);
	lws_fx_set(b, 1, 25000000);
	CHK(lws_fx_comp(&a, &b) < 0, "comp -1.5 < 1.25");

	lws_fx_set(a, 5, 50000000);
	CHK(lws_fx_roundup(&a) == 6, "roundup 5.5 = %d", lws_fx_roundup(&a));
	CHK(lws_fx_rounddown(&a) == 5, "rounddown 5.5 = %d",
							lws_fx_rounddown(&a));

	/* sin / cos against references */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(fx_trig_ref); n++) {
		double t = fx_trig_ref[n].a;

		d2f(&a, t);
		lws_fx_sin(&r, &a);
		CHK(fx2d(&r) > fx_trig_ref[n].sin - 2e-7 &&
		    fx2d(&r) < fx_trig_ref[n].sin + 2e-7,
		    "sin(%f) = %f vs %f", t, fx2d(&r), fx_trig_ref[n].sin);

		lws_fx_cos(&r, &a);
		CHK(fx2d(&r) > fx_trig_ref[n].cos - 2e-7 &&
		    fx2d(&r) < fx_trig_ref[n].cos + 2e-7,
		    "cos(%f) = %f vs %f", t, fx2d(&r), fx_trig_ref[n].cos);
	}

	/* sin² + cos² = 1 sweep */

	for (n = -628; n <= 628; n += 7) {
		double t = (double)n / 100.0, s2c2;

		d2f(&a, t);
		lws_fx_sin(&r, &a);
		s2c2 = fx2d(&r) * fx2d(&r);
		lws_fx_cos(&r, &a);
		s2c2 += fx2d(&r) * fx2d(&r);

		CHK(s2c2 > 0.9999995 && s2c2 < 1.0000005,
				"sin(%f)²+cos² = %f", t, s2c2);
	}

	/* atan2 against references, including extreme magnitudes */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(fx_atan2_ref); n++) {
		d2f(&a, fx_atan2_ref[n].y);
		d2f(&b, fx_atan2_ref[n].x);
		lws_fx_atan2(&r, &a, &b);
		CHK(fx2d(&r) > fx_atan2_ref[n].r - 2e-6 &&
		    fx2d(&r) < fx_atan2_ref[n].r + 2e-6,
		    "atan2(%f, %f) = %f vs %f", fx_atan2_ref[n].y,
		    fx_atan2_ref[n].x, fx2d(&r), fx_atan2_ref[n].r);
	}

	/* atan2(y, x) + atan2(-y, x) = 0 */

	for (n = 1; n < 200; n += 13) {
		double t, yn = (double)n / 7.0, xn = (double)n / 3.0 + 0.25;

		d2f(&a, yn);
		d2f(&b, xn);
		lws_fx_atan2(&r, &a, &b);
		t = fx2d(&r);
		d2f(&a, -yn);
		lws_fx_atan2(&r, &a, &b);
		CHK(fx2d(&r) + t > -2e-6 && fx2d(&r) + t < 2e-6,
				"atan2 antisymmetry at n=%d: %f", n,
				fx2d(&r) + t);
	}

	/* tan against references, away from the poles */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(fx_tan_ref); n++) {
		double t = fx_tan_ref[n].a, rt = fx_tan_ref[n].r, d;

		d2f(&a, t);
		lws_fx_tan(&r, &a);
		d = fx2d(&r) - rt;
		if (d < 0)
			d = -d;
		CHK(d < (rt < 0 ? -rt : rt) * 1e-4 + 1e-6,
		    "tan(%f) = %f vs %f", t, fx2d(&r), rt);
	}

	/* tan(x) = sin(x)/cos(x) for moderate angles */

	for (n = -120; n <= 120; n += 11) {
		double t = (double)n / 100.0, sc;

		d2f(&a, t);
		lws_fx_tan(&r, &a);
		lws_fx_sin(&b, &a);
		sc = fx2d(&b);
		lws_fx_cos(&b, &a);
		sc /= fx2d(&b);

		CHK(fx2d(&r) > sc - 1e-4 * (sc < 0 ? -sc : sc) - 1e-6 &&
		    fx2d(&r) < sc + 1e-4 * (sc < 0 ? -sc : sc) + 1e-6,
		    "tan/sin-cos mismatch at %f: %f vs %f", t, fx2d(&r), sc);
	}

	lwsl_user("Completed: %s (%d checks, %d failures)\n",
		  fails ? "FAIL" : "PASS", checks, fails);
	result = fails ? 1 : 0;

	return result;
}
