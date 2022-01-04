#define set_nyb(_line, _x, _c) \
	{ if ((_x) & 1) { _line[(_x) >> 1] &= 0xf0; _line[(_x) >> 1]  |= _c; } else \
		    { _line[(_x) >> 1] &= 0x0f; _line[(_x) >> 1] |= (uint8_t)((_c) << 4); }}

#define get_nyb(_line, _x)  ((_x) & 1) ? ((line[(_x) >> 1]) >> 4) : \
					 ((line[(_x) >> 1]) & 0xf)

void
lws_display_raster(const struct lws_surface_info *ic, struct lws_dlo *dlo,
			lws_display_scalar curr, int s, int e, uint8_t *line,
			lws_colour_error_t **nle);

void
dist_err(const lws_colour_error_t *in, lws_colour_error_t *out, int sixteenths);

unsigned int
_isqrt(unsigned int n);
