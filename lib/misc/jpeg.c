/*
 * lws jpeg
 *
 * Copyright (C) 2019 - 2022 Andy Green <andy@warmcat.com>
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
 *
 * Based on public domain original with notice -->
 *
 * picojpeg.c v1.1 - Public domain, Rich Geldreich <richgel99@gmail.com>
 * Nov. 27, 2010 - Initial release
 * Feb. 9, 2013 - Added H1V2/H2V1 support, cleaned up macros, signed shift fixes
 * Also integrated and tested changes from Chris Phoenix <cphoenix@gmail.com>.
 *
 * https://github.com/richgel999/picojpeg
 *
 * This version is rewritten for lws, changing the whole approach to decode on
 * demand to issue a line of output at a time, statefully.  This version is
 * licensed MIT.
 *
 * Rasterization works into an 8 or 16-line buffer on Y, 444, 422 and 420 MCU
 * layouts.
 */

#include <private-lib-core.h>

#define jpeg_loglevel		LLL_NOTICE
#if (_LWS_ENABLED_LOGS & jpeg_loglevel)
#define lwsl_jpeg(...)		_lws_log(jpeg_loglevel, __VA_ARGS__)
#else
#define lwsl_jpeg(...)
#endif

#define MARKER_SCAN_LIMIT	1536

/*
 * Set to 1 if right shifts on signed ints are always unsigned (logical) shifts
 * When 1, arithmetic right shifts will be emulated by using a logical shift
 * with special case code to ensure the sign bit is replicated.
 */

#define PJPG_RIGHT_SHIFT_IS_ALWAYS_UNSIGNED 0

typedef enum {
	LWSJDS_FIND_SOI_INIT1,
	LWSJDS_FIND_SOI_INIT2,
	LWSJDS_FIND_SOI,
	LWSJDS_FIND_SOF1,
	LWSJDS_FIND_SOF2,
	LWSJDS_INIT_FRAME,
	LWSJDS_INIT_SCAN,
	LWSJDS_DECODE_MCU,

} lws_jpeg_decode_state_t;

// Scan types
typedef enum
{
   PJPG_GRAYSCALE,
   PJPG_YH1V1,
   PJPG_YH2V1,
   PJPG_YH1V2,
   PJPG_YH2V2
} pjpeg_scan_type_t;

#if PJPG_RIGHT_SHIFT_IS_ALWAYS_UNSIGNED
static int16_t replicateSignBit16(int8_t n)
{
   switch (n)
   {
      case 0:  return 0x0000;
      case 1:  return 0x8000;
      case 2:  return 0xC000;
      case 3:  return 0xE000;
      case 4:  return 0xF000;
      case 5:  return 0xF800;
      case 6:  return 0xFC00;
      case 7:  return 0xFE00;
      case 8:  return 0xFF00;
      case 9:  return 0xFF80;
      case 10: return 0xFFC0;
      case 11: return 0xFFE0;
      case 12: return 0xFFF0; 
      case 13: return 0xFFF8;
      case 14: return 0xFFFC;
      case 15: return 0xFFFE;
      default: return 0xFFFF;
   }
}
static LWS_INLINE int16_t arithmeticRightShiftN16(int16_t x, int8_t n) 
{
   int16_t r = (uint16_t)x >> (uint8_t)n;
   if (x < 0)
      r |= replicateSignBit16(n);
   return r;
}
static LWS_INLINE long arithmeticRightShift8L(long x) 
{
   long r = (unsigned long)x >> 8U;
   if (x < 0)
      r |= ~(~(unsigned long)0U >> 8U);
   return r;
}
#define PJPG_ARITH_SHIFT_RIGHT_N_16(x, n) arithmeticRightShiftN16(x, n)
#define PJPG_ARITH_SHIFT_RIGHT_8_L(x) arithmeticRightShift8L(x)
#else
#define PJPG_ARITH_SHIFT_RIGHT_N_16(x, n) ((x) >> (n))
#define PJPG_ARITH_SHIFT_RIGHT_8_L(x) ((x) >> 8)
#endif

#define PJPG_MAX_WIDTH 16384
#define PJPG_MAX_HEIGHT 16384
#define PJPG_MAXCOMPSINSCAN 3

enum {
	PJM_SOF0		= 0xC0,
	PJM_SOF1		= 0xC1,
	PJM_SOF2		= 0xC2,
	PJM_SOF3		= 0xC3,

	PJM_SOF5		= 0xC5,
	PJM_SOF6		= 0xC6,
	PJM_SOF7		= 0xC7,

	PJM_JPG			= 0xC8,
	PJM_SOF9		= 0xC9,
	PJM_SOF10		= 0xCA,
	PJM_SOF11		= 0xCB,

	PJM_SOF13		= 0xCD,
	PJM_SOF14		= 0xCE,
	PJM_SOF15		= 0xCF,

	PJM_DHT			= 0xC4,

	PJM_DAC			= 0xCC,

	PJM_RST0		= 0xD0,
	PJM_RST1		= 0xD1,
	PJM_RST2		= 0xD2,
	PJM_RST3		= 0xD3,
	PJM_RST4		= 0xD4,
	PJM_RST5		= 0xD5,
	PJM_RST6		= 0xD6,
	PJM_RST7		= 0xD7,

	PJM_SOI			= 0xD8,
	PJM_EOI			= 0xD9,
	PJM_SOS			= 0xDA,
	PJM_DQT			= 0xDB,
	PJM_DNL			= 0xDC,
	PJM_DRI			= 0xDD,
	PJM_DHP			= 0xDE,
	PJM_EXP			= 0xDF,

	PJM_APP0		= 0xE0,
	PJM_APP15		= 0xEF,

	PJM_JPG0		= 0xF0,
	PJM_JPG13		= 0xFD,
	PJM_COM			= 0xFE,

	PJM_TEM			= 0x01,

	PJM_ERROR		= 0x100,

	RST0			= 0xD0
};

typedef struct huff_table {
	uint16_t		min_code[16];
	uint16_t		max_code[16];
	uint8_t			value[16];
} huff_table_t;

struct lws_jpeg {

	pjpeg_scan_type_t	scan_type;
	
	const uint8_t		*inbuf;
	uint8_t			*lines;
	size_t			insize;

	lws_jpeg_decode_state_t	dstate;

	int16_t			coeffs[8 * 8];
	int16_t			quant0[8 * 8];
	int16_t			quant1[8 * 8];
	int16_t			last_dc[3];
	uint16_t		bits;
	uint16_t		image_width;
	uint16_t		image_height;
	uint16_t		restart_interval;
	uint16_t		restart_num;
	uint16_t		restarts_left;
	uint16_t		mcu_max_row;
	uint16_t		mcu_max_col;

	uint16_t		mcu_ofs_x;
	uint16_t		mcu_ofs_y;

	uint16_t		mcu_count_left_x;
	uint16_t		mcu_count_left_y;

	huff_table_t		huff_tab0;
	huff_table_t		huff_tab1;
	huff_table_t		huff_tab2;
	huff_table_t		huff_tab3;

	uint8_t			mcu_buf_R[256];
	uint8_t			mcu_buf_G[256];
	uint8_t			mcu_buf_B[256];

	uint8_t			huff_val0[16];
	uint8_t			huff_val1[16];
	uint8_t			huff_val2[256];
	uint8_t			huff_val3[256];

	uint8_t			mcu_org_id[6];
	uint8_t			comp_id[3];
	uint8_t			comp_h_samp[3];
	uint8_t			comp_v_samp[3];
	uint8_t			comp_quant[3];

	uint8_t			comp_scan_count;
	uint8_t			comp_list[3];
	uint8_t			comp_dc[3]; // 0,1
	uint8_t			comp_ac[3]; // 0,1

	uint8_t			mcu_max_blocks;
	uint8_t			mcu_max_size_x;
	uint8_t			mcu_max_size_y;

	uint8_t			stash[2];
	uint8_t			stashc;
	uint8_t			ringy;

	uint8_t			huff_valid;
	uint8_t			quant_valid;

	uint8_t			seen_eoi;

	uint8_t			bits_left;

	uint8_t			frame_comps;
	
	uint8_t			ff_skip;
	char			hold_at_metadata;
	
	/* interruptible fine states */
	uint16_t		fs_hd_code; /* huff_decode() */
	uint16_t		fs_emit_budget; /* lws_jpeg_emit_next_line */
	uint16_t		fs_pm_skip_budget;
	uint16_t		fs_pm_count;
	uint16_t		fs_pm_temp;
	uint16_t		fs_sos_left;
	uint16_t		fs_sof_left;
	uint16_t		fs_ir_i;
	uint8_t			fs_gb16; /* get_bits16() */
	uint8_t			fs_hd;   /* huff_decode() */
	uint8_t			fs_hd_i; /* huff_decode() */
	uint8_t			fs_emit_lc;
	uint8_t			fs_emit_tc;
	uint8_t			fs_emit_c;
	uint8_t			fs_pm_s1;
	uint8_t			fs_pm_c;
	uint8_t			fs_pm_skip;
	uint8_t			fs_pm_bits[16];
	uint8_t			fs_pm_i;
	uint8_t			fs_pm_n;
	uint8_t			fs_pm_have_n;
	uint8_t			fs_pm_ti;
	uint8_t			fs_sos_phase;
	uint8_t			fs_sos_phase_loop;
	uint8_t			fs_sos_i;
	uint8_t			fs_sos_cc;
	uint8_t			fs_sos_c;
	uint8_t			fs_mcu_phase;
	uint8_t			fs_mcu_phase_loop;
	uint8_t			fs_mcu_mb;
	uint8_t			fs_mcu_k;
	uint8_t			fs_mcu_s;
	uint8_t			fs_sof_phase;
	uint8_t			fs_sof_i;
	uint8_t			fs_ir_phase;
	uint8_t			fs_is_phase;

};

static const int8_t ZAG[] = { 0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18,
			      11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27,
			      20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57,
			      50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
			      58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61,
			      54, 47, 55, 62, 63, };

static LWS_INLINE lws_stateful_ret_t
get_char(lws_jpeg_t *j, uint8_t *c)
{
	if (j->stashc) {
		*c = j->stash[0];
		j->stash[0] = j->stash[1];
		j->stashc--;
		return LWS_SRET_OK;
	}

	if (!j->insize)
		return LWS_SRET_WANT_INPUT;
	
	*c = *j->inbuf++;
	j->insize--;
	
	return LWS_SRET_OK;
}

static lws_stateful_ret_t
get_octet(lws_jpeg_t *j, uint8_t *c, uint8_t ffcheck)
{
	lws_stateful_ret_t r;
	uint8_t c1;

	if (!j->ff_skip) {
		r = get_char(j, c);
		if (r)
			return r;
	}

	if (ffcheck && (j->ff_skip || *c == 0xff)) {
		j->ff_skip = 1;
		r = get_char(j, &c1);
		if (r)
			return r;
		j->ff_skip = 0;
		if (c1) {
			if (c1 == PJM_EOI) {
				j->seen_eoi = 1;
				return LWS_SRET_OK;
			}
			lwsl_jpeg("%s: nonzero stuffed 0x%02X\n", __func__, c1);
			return LWS_SRET_FATAL + 1;
		}

		*c = 0xff;
	}

	return LWS_SRET_OK;
}

static lws_stateful_ret_t
get_bits8(lws_jpeg_t *j, uint8_t *v, uint8_t numBits, uint8_t ffcheck)
{
	uint8_t origBits = numBits, c = 0;
	uint16_t ret = j->bits;
	lws_stateful_ret_t r;

	if (j->bits_left < numBits) {
		
		r = get_octet(j, &c, ffcheck);
		if (r)
			return r;
		
		j->bits = (uint16_t)(j->bits << j->bits_left);
		j->bits = (uint16_t)(j->bits | c);
		j->bits = (uint16_t)(j->bits << (numBits - j->bits_left));

		j->bits_left = (uint8_t)(8 - (numBits - j->bits_left));
	} else {
		j->bits_left = (uint8_t) (j->bits_left - numBits);
		j->bits = (uint16_t)(j->bits << numBits);
	}

	*v = (uint8_t)(ret >> (16 - origBits));
	
	return LWS_SRET_OK;
}

static lws_stateful_ret_t
get_bits16(lws_jpeg_t *j, uint16_t *v, uint8_t numBits, uint8_t ffcheck)
{
	uint8_t origBits = numBits, c = 0;
	uint16_t ret = j->bits;
	lws_stateful_ret_t r;

	assert(numBits > 8); /* otherwise, use get_bits8 */
	numBits = (uint8_t)(numBits - 8);

	if (!j->fs_gb16) { /* if not interrupted in second part */
	
		r = get_octet(j, &c, ffcheck);
		if (r)
			return r;
	
		j->bits = (uint16_t)(j->bits << j->bits_left);
		j->bits = (uint16_t)(j->bits | c);
		j->bits = (uint16_t)(j->bits << (8 - j->bits_left));
	}

	ret = (uint16_t)((ret & 0xff00) | (j->bits >> 8));

	if (j->bits_left < numBits) {
		
		j->fs_gb16 = 1; /* so we skip to here if retrying */
		r = get_octet(j, &c, ffcheck);
		if (r)
			return r;

		j->fs_gb16 = 0; /* cancel skip to here flag */
		
		j->bits = (uint16_t)(j->bits << j->bits_left);
		j->bits = (uint16_t)(j->bits | c);
		j->bits = (uint16_t)(j->bits << (numBits - j->bits_left));
		j->bits_left = (uint8_t)(8 - (numBits - j->bits_left));
	} else {
		j->bits_left = (uint8_t) (j->bits_left - numBits);
		j->bits = (uint16_t)(j->bits << numBits);
	}

	*v = (uint16_t)(ret >> (16 - origBits));
	
	return LWS_SRET_OK;
}

static LWS_INLINE lws_stateful_ret_t
get_bit(lws_jpeg_t *j, uint16_t *v)
{
	lws_stateful_ret_t r;
	uint16_t ret = 0;
	uint8_t c = 0;

	if (j->bits & 0x8000)
		ret = 1;

	if (!j->bits_left) {
		r = get_octet(j, &c, 1);
		if (r)
			return r;

		j->bits = (uint16_t)(j->bits | c);
		j->bits_left = (uint8_t)(j->bits_left + 8);
	}

	j->bits_left--;
	j->bits = (uint16_t)(j->bits << 1);

	*v = ret;
	
	return LWS_SRET_OK;
}

static uint16_t
get_extend_test(uint8_t i)
{
	if (!i || i > 15)
		return 0;

	return (uint16_t)(1 << (i - 1));
}

static int16_t
get_extend_offset(uint8_t i)
{
	if (!i || i > 15)
		return 0;
	
	return (int16_t)((int16_t)(0xffffffff << i) + 1);
}

static LWS_INLINE int16_t
huff_extend(uint16_t x, uint8_t s)
{
	return (int16_t)(((x < get_extend_test(s)) ?
				x + get_extend_offset(s) : x));
}

static LWS_INLINE lws_stateful_ret_t
huff_decode(lws_jpeg_t *j, uint8_t *v, const huff_table_t *ht, const uint8_t *p)
{
	lws_stateful_ret_t r;
	uint16_t c;
	
	if (!j->fs_hd) {
		r = get_bit(j, &j->fs_hd_code);
		if (r)
			return r;
		if (j->seen_eoi)
			return LWS_SRET_OK;
		j->fs_hd = 1;
		j->fs_hd_i = 0;
	}

	for (;;) {
		uint16_t maxCode;

		if (j->fs_hd_i == 16) {
			j->fs_hd = 0;
			*v = 0;
			return LWS_SRET_OK;
		}

		maxCode = ht->max_code[j->fs_hd_i];
		if ((j->fs_hd_code <= maxCode) && (maxCode != 0xFFFF))
			break;
		
		r = get_bit(j, &c);
		if (r)
			return r;

		if (j->seen_eoi)
			return LWS_SRET_OK;

		j->fs_hd_i++;
		j->fs_hd_code = (uint16_t)((j->fs_hd_code << 1) | c);
	}

	j->fs_hd = 0;

	*v = p[(ht->value[j->fs_hd_i] +
		(j->fs_hd_code - ht->min_code[j->fs_hd_i]))];
	
	return LWS_SRET_OK;
}

static void
huffCreate(const uint8_t *pBits, huff_table_t *ht)
{
	uint8_t i = 0;
	uint8_t jj = 0;

	uint16_t code = 0;

	for (;;) {
		uint8_t num = pBits[i];

		if (!num) {
			ht->min_code[i] = 0x0000;
			ht->max_code[i] = 0xFFFF;
			ht->value[i] = 0;
		} else {
			ht->min_code[i] = code;
			ht->max_code[i] = (uint16_t)(code + num - 1);
			ht->value[i] = jj;

			jj = (uint8_t) (jj + num);

			code = (uint16_t) (code + num);
		}

		code = (uint16_t)(code << 1);

		i++;
		if (i > 15)
			break;
	}
}

static huff_table_t *
get_huff_table(lws_jpeg_t *j, uint8_t index)
{
	// 0-1 = DC
	// 2-3 = AC
	switch (index) {
	case 0:
		return &j->huff_tab0;
	case 1:
		return &j->huff_tab1;
	case 2:
		return &j->huff_tab2;
	case 3:
		return &j->huff_tab3;
	default:
		return NULL;
	}
}

static uint8_t *
get_huff_value(lws_jpeg_t *j, uint8_t index)
{
	// 0-1 = DC
	// 2-3 = AC
	switch (index) {
	case 0:
		return j->huff_val0;
	case 1:
		return j->huff_val1;
	case 2:
		return j->huff_val2;
	case 3:
		return j->huff_val3;
	default:
		return 0;
	}
}

static uint16_t
getMaxHuffCodes(uint8_t index)
{
	return (index < 2) ? 12 : 255;
}

static void createWinogradQuant(lws_jpeg_t *j, int16_t *pq);


static lws_stateful_ret_t
read_sof_marker(lws_jpeg_t *j)
{
	lws_stateful_ret_t r;
	uint8_t c;

	switch (j->fs_sof_phase) {
	case 0:
		r = get_bits16(j, &j->fs_sof_left, 16, 0);
		if (r)
			return r;

		j->fs_sof_phase++;
		
		/* fallthru */

	case 1:
		r = get_bits8(j, &c, 8, 0);
		if (r)
			return r;
		
		if (c != 8) {
			lwsl_jpeg("%s: required 8\n", __func__);
			return LWS_SRET_FATAL + 2;
		}

		j->fs_sof_phase++;
		
		/* fallthru */

	case 2:
		r = get_bits16(j, &j->image_height, 16, 0);
		if (r)
			return r;
	
		if ((!j->image_height) || (j->image_height > PJPG_MAX_HEIGHT)) {
			lwsl_jpeg("%s: image height range\n", __func__);
			return LWS_SRET_FATAL + 3;
		}
		
		j->fs_sof_phase++;
		
		/* fallthru */
		
	case 3:
		r = get_bits16(j, &j->image_width, 16, 0);
		if (r)
			return r;

		if ((!j->image_width) || (j->image_width > PJPG_MAX_WIDTH)) {
			lwsl_jpeg("%s: image width range\n", __func__);
			return LWS_SRET_FATAL + 4;
		}

		lwsl_warn("%s: %d x %d\n", __func__, j->image_width, j->image_height);

		j->fs_sof_phase++;
		
		/* fallthru */
		
	case 4:
		r = get_bits8(j, &j->frame_comps, 8, 0);
		if (r)
			return r;

		if (j->frame_comps > 3) {
			lwsl_jpeg("%s: too many comps\n", __func__);
			return LWS_SRET_FATAL + 5;
		}
	
		if (j->fs_sof_left !=
		    (j->frame_comps + j->frame_comps + j->frame_comps + 8)) {
			lwsl_jpeg("%s: unexpected soft_left\n", __func__);
			return LWS_SRET_FATAL + 6;
		}
		
		j->fs_sof_i = 0;
		
		j->fs_sof_phase++;
		
		/* fallthru */
		
	default:

		while (j->fs_sof_i < j->frame_comps) {
			switch (j->fs_sof_phase) {
			case 5:
				r = get_bits8(j, &j->comp_id[j->fs_sof_i], 8, 0);
				if (r)
					return r;

				j->fs_sof_phase++;
				
				/* fallthru */

			case 6:
				r = get_bits8(j, &j->comp_h_samp[j->fs_sof_i], 4, 0);
				if (r)
					return r;

				j->fs_sof_phase++;
				
				/* fallthru */

			case 7:
				r = get_bits8(j, &j->comp_v_samp[j->fs_sof_i], 4, 0);
				if (r)
					return r;

				j->fs_sof_phase++;
				
				/* fallthru */

			case 8:
				r = get_bits8(j, &j->comp_quant[j->fs_sof_i], 8, 0);
				if (r)
					return r;
		
				if (j->comp_quant[j->fs_sof_i] > 1) {
					lwsl_jpeg("%s: comp_quant > 1\n", __func__);
					return LWS_SRET_FATAL + 7;
				}
				break;
			} /* loop switch */
			
			j->fs_sof_phase = 5;
			j->fs_sof_i++;
		} /* while */

	} /* switch */

	return LWS_SRET_OK;
}

// Read a start of scan (SOS) marker.
static lws_stateful_ret_t
read_sos_marker(lws_jpeg_t *j)
{
	lws_stateful_ret_t r;
	uint8_t c;

	switch (j->fs_sos_phase) {
	case 0:
		r = get_bits16(j, &j->fs_sos_left, 16, 0);
		if (r)
			return r;
		
		j->fs_sos_i = 0;
		j->fs_sos_phase++;

		/* fallthru */
		
	case 1:
		r = get_bits8(j, &j->comp_scan_count, 8, 0);
		if (r)
			return r;

		j->fs_sos_left = (uint16_t)(j->fs_sos_left - 3);

		if ((j->fs_sos_left !=
				(j->comp_scan_count + j->comp_scan_count + 3)) ||
		    (j->comp_scan_count < 1) ||
		    (j->comp_scan_count > PJPG_MAXCOMPSINSCAN)) {
			lwsl_jpeg("%s: scan comps limit\n", __func__);
			return LWS_SRET_FATAL + 8;
		}

		j->fs_sos_phase++;
		j->fs_sos_phase_loop = 0;

		/* fallthru */
		
	case 2:
		while (j->fs_sos_i < j->comp_scan_count) {
			switch (j->fs_sos_phase_loop) {
			case 0:
				r = get_bits8(j, &j->fs_sos_cc, 8, 0);
				if (r)
					return r;
				j->fs_sos_phase_loop++;
				
				/* fallthru */
				
			case 1:
				r = get_bits8(j, &j->fs_sos_c, 8, 0);
				if (r)
					return r;
				
				j->fs_sos_left = (uint16_t)(j->fs_sos_left - 2);
				
				for (c = 0; c < j->frame_comps; c++)
					if (j->fs_sos_cc == j->comp_id[c])
						break;
		
				if (c >= j->frame_comps) {
					lwsl_jpeg("%s: SOS comps\n", __func__);
					return LWS_SRET_FATAL + 9;
				}
				
				j->comp_list[j->fs_sos_i] = c;
				j->comp_dc[c] = (j->fs_sos_c >> 4) & 15;
				j->comp_ac[c] = (j->fs_sos_c & 15);
				
				break;
			}
			
			j->fs_sos_i++;
			j->fs_sos_phase_loop = 0;
		}
		
		j->fs_sos_phase++;

		/* fallthru */
				
	case 3:
		r = get_bits8(j, &c, 8, 0);
		if (r)
			return r;

		j->fs_sos_phase++;

		/* fallthru */
				
	case 4:
		r = get_bits8(j, &c, 8, 0);
		if (r)
			return r;

		j->fs_sos_phase++;

		/* fallthru */
				
	case 5:
		r = get_bits8(j, &c, 4, 0);
		if (r)
			return r;

		j->fs_sos_phase++;

		/* fallthru */
				
	case 6:
		r = get_bits8(j, &c, 4, 0);
		if (r)
			return r;
		
		j->fs_sos_left = (uint16_t)(j->fs_sos_left - 3);

		j->fs_sos_phase++;

		/* fallthru */
				
	case 7:
		while (j->fs_sos_left) {
			r = get_bits8(j, &c, 8, 0);
			if (r)
				return r;

			j->fs_sos_left--;
		}
		
		j->fs_sos_phase = 0;

		return LWS_SRET_OK;
	}

	lwsl_jpeg("%s: SOS marker fail\n", __func__);

	return LWS_SRET_FATAL + 10;
}

// Process markers. Returns when an SOFx, SOI, EOI, or SOS marker is
// encountered.
static lws_stateful_ret_t
process_markers(lws_jpeg_t *j, uint8_t *pMarker)
{
	lws_stateful_ret_t r;
	uint16_t w;
	uint8_t c;

	do {
		if (j->fs_pm_s1 < 2) {
			do {
				if (j->fs_pm_s1 == 0) {
					do {
						r = get_bits8(j, &j->fs_pm_c, 8, 0);
						if (r)
							return r;
			
					} while (j->fs_pm_c != 0xFF);
						
					j->fs_pm_s1 = 1;
				}
	
				do {
					r = get_bits8(j, &j->fs_pm_c, 8, 0);
					if (r)
						return r;
	
				} while (j->fs_pm_c == 0xFF);
	
			} while (!j->fs_pm_c);
			
			j->fs_pm_skip = 0;
			j->fs_pm_i = 0;
			j->fs_pm_s1 = 2;
		}

		switch (j->fs_pm_c) {
		case PJM_SOF0:
		case PJM_SOF1:
		case PJM_SOF2:
		case PJM_SOF3:
		case PJM_SOF5:
		case PJM_SOF6:
		case PJM_SOF7:
			//      case PJM_JPG:
		case PJM_SOF9:
		case PJM_SOF10:
		case PJM_SOF11:
		case PJM_SOF13:
		case PJM_SOF14:
		case PJM_SOF15:
		case PJM_SOI:
		case PJM_EOI:
		case PJM_SOS:
			*pMarker = j->fs_pm_c;

			goto exit_ok;

		case PJM_DHT:
			if (!j->fs_pm_skip) { /* step zero */
				r = get_bits16(j, &j->fs_pm_skip_budget, 16, 0);
				if (r)
					return r;

				if (j->fs_pm_skip_budget < 2) {
					lwsl_jpeg("%s: inadequate skip\n",
								__func__);
					return LWS_SRET_FATAL + 11;
				}

				j->fs_pm_skip_budget = (uint16_t)(
						j->fs_pm_skip_budget -  2);
				j->fs_pm_skip = 1;
				j->fs_pm_i = 0;
			}

			while (j->fs_pm_skip_budget) {
				uint8_t index;
				uint16_t totalRead;
				huff_table_t *ht;
				uint8_t *p;

				switch (j->fs_pm_skip) {
				case 1:
					r = get_bits8(j, &index, 8, 0);
					if (r)
						return r;

					if (((index & 0x0f) > 1) ||
					    ((index & 0xf0) > 0x10)) {
						lwsl_jpeg("%s: idx range\n", __func__);
						return LWS_SRET_FATAL + 12;
					}

					j->fs_pm_ti = (uint8_t)
						(((index >> 3) & 2) + (index & 1));
					j->huff_valid = (uint8_t)(j->huff_valid |
							(1 << j->fs_pm_ti));
					j->fs_pm_count = 0;
					j->fs_pm_i = 0;
					j->fs_pm_skip = 2;

					/* fallthru */

				case 2:
					while (j->fs_pm_i <= 15) {
						r = get_bits8(j, &j->fs_pm_bits[
						     j->fs_pm_i], 8, 0);
						if (r)
							return r;
						j->fs_pm_count =
							(uint16_t)(
							j->fs_pm_count +
							j->fs_pm_bits[j->fs_pm_i]);
						j->fs_pm_i++;
					}

					if (j->fs_pm_count >
					    getMaxHuffCodes(j->fs_pm_ti)) {
						lwsl_jpeg("%s: huff count\n", __func__);
						return LWS_SRET_FATAL + 13;
					}
					
					j->fs_pm_i = 0;
					j->fs_pm_skip = 3;

					/* fallthru */

				case 3:
					ht = get_huff_table(j, j->fs_pm_ti);
					p = get_huff_value(j, j->fs_pm_ti);

					while (j->fs_pm_i < j->fs_pm_count) {
						r = get_bits8(j, &p[j->fs_pm_i], 8, 0);
						if (r)
							return r;
	
						j->fs_pm_i++;
					}
	
					totalRead = (uint16_t)(1 + 16 +
								j->fs_pm_count);
	
					if (j->fs_pm_skip_budget < totalRead) {
						lwsl_jpeg("%s: read budget\n",
								__func__);
						return LWS_SRET_FATAL + 14;
					}
	
					j->fs_pm_skip_budget = (uint16_t)
						(j->fs_pm_skip_budget - totalRead);
	
					huffCreate(j->fs_pm_bits, ht);
					break;
				}
			}
			break;

			/* No arithmetic coding support */
		case PJM_DAC:
			lwsl_jpeg("%s: arithmetic coding not supported\n",
								__func__);

			return LWS_SRET_FATAL;

		case PJM_DQT:
			switch (j->fs_pm_skip) {
			case 0:
				r = get_bits16(j, &j->fs_pm_skip_budget, 16, 0);
				if (r)
					return r;

				if (j->fs_pm_skip_budget < 2) {
					lwsl_jpeg("%s: inadequate DQT skip\n",
								__func__);

					return LWS_SRET_FATAL + 15;
				}

				j->fs_pm_skip_budget = (uint16_t)
						(j->fs_pm_skip_budget - 2);
				j->fs_pm_skip = 1;
				j->fs_pm_have_n = 0;

				/* fallthru */
				
			case 1:
				while (j->fs_pm_skip_budget) {
					uint16_t totalRead;

					if (!j->fs_pm_have_n) {
						r = get_bits8(j, &j->fs_pm_n, 8, 0);
						if (r)
							return r;
						if ((j->fs_pm_n & 0xf) > 1) {
							lwsl_jpeg("%s: PM n too big\n",
									__func__);
							return LWS_SRET_FATAL + 16;
						}
						
						j->quant_valid = (uint8_t)(
							j->quant_valid |
							((j->fs_pm_n & 0xf) ? 2 : 1));
						
						j->fs_pm_i = 0;
						j->fs_pm_have_n = 1;
					}

					// read quantization entries, in zag order
					while (j->fs_pm_i < 64) {
						switch (j->fs_pm_have_n) {
						case 1:
							r = get_bits8(j, &c, 8, 0);
							if (r)
								return r;
							
							j->fs_pm_temp = (uint16_t)c;
							
							j->fs_pm_have_n++;

							/* fallthru */

						case 2:
							if (j->fs_pm_n >> 4) {
								r = get_bits8(j, &c, 8, 0);
								if (r)
									return r;
								j->fs_pm_temp =
									(uint16_t)(
									(j->fs_pm_temp << 8) + c);
							}

							if (j->fs_pm_n & 0xf)
								j->quant1[j->fs_pm_i] =
									(int16_t)j->fs_pm_temp;
							else
								j->quant0[j->fs_pm_i] =
									(int16_t)j->fs_pm_temp;
							break;
						}
						
						j->fs_pm_i++;
						j->fs_pm_have_n = 1;

					} /* 64 zags */
					
					j->fs_pm_have_n = 0;

					createWinogradQuant(j,
						(j->fs_pm_n & 0xf) ?
							j->quant1 : j->quant0);

					totalRead = 64 + 1;

					if (j->fs_pm_n >> 4)
						totalRead = (uint16_t)(totalRead + 64);

					if (j->fs_pm_skip_budget < totalRead) {
						lwsl_jpeg("%s: DQT: skip budget"
							  " underflow\n", __func__);
						return LWS_SRET_FATAL + 17;
					}

					j->fs_pm_skip_budget = (uint16_t)
						(j->fs_pm_skip_budget - totalRead);
				} /* while skip_budget / left */

				j->fs_pm_skip = 0;
				break;
			} /* DQT phase separation */
			break;

		case PJM_DRI:
			switch (j->fs_pm_i) {
			case 0:
				r = get_bits16(j, &w, 16, 0);
				if (r)
					return r;
				if (w != 4) {
					lwsl_jpeg("%s: DRI wrong val\n", __func__);
					return LWS_SRET_FATAL + 18;
				}
				
				j->fs_pm_i = 1;

				/* fallthru */

			case 1:
				r = get_bits16(j, &j->restart_interval, 16, 0);
				if (r)
					return r;

				break;
			}
			break;

			//case PJM_APP0:  /* no need to read the JFIF marker */

		case PJM_JPG:
		case PJM_RST0: /* no parameters */
		case PJM_RST1:
		case PJM_RST2:
		case PJM_RST3:
		case PJM_RST4:
		case PJM_RST5:
		case PJM_RST6:
		case PJM_RST7:
		case PJM_TEM:
			lwsl_jpeg("%s: bad MCU type\n", __func__);

			return LWS_SRET_FATAL;

		default: /* must be DNL, DHP, EXP, APPn, JPGn, COM, or RESn or APP0
			  * Used to skip unrecognized markers.
			  */

			if (!j->fs_pm_skip) {
				r = get_bits16(j, &j->fs_pm_skip_budget, 16, 0);
				if (r)
					return r;
				if (j->fs_pm_skip_budget < 2) {
					lwsl_jpeg("%s: inadequate skip 3\n",
								__func__);

					return LWS_SRET_FATAL + 19;
				}

				j->fs_pm_skip_budget = (uint16_t)
						(j->fs_pm_skip_budget - 2);
				j->fs_pm_skip = 1;
			}

			while (j->fs_pm_skip_budget) {
				uint8_t c;
				r = get_bits8(j, &c, 8, 0);
				if (r)
					return r;
				j->fs_pm_skip_budget--;
			}
			break;
		} /* switch */
		
		j->fs_pm_s1 = 0; /* do next_marker() flow next loop */
		
	} while(1);
	
exit_ok:
	j->fs_pm_s1 = 0;

	return LWS_SRET_OK;
}

// Restart interval processing.
static lws_stateful_ret_t
interval_restart(lws_jpeg_t *j)
{
	lws_stateful_ret_t r;
	uint8_t c;

	switch (j->fs_ir_phase) {
	case 0:
		while (j->fs_ir_i < MARKER_SCAN_LIMIT) {
			r = get_char(j, &c);
			if (r)
				return r;
	
			if (c == 0xFF)
				break;
	
			j->fs_ir_i++;
		}
	
		if (j->fs_ir_i == MARKER_SCAN_LIMIT) {
			/* we judge it unreasonable */
			lwsl_jpeg("%s: scan limit exceeded\n", __func__);

			return LWS_SRET_FATAL;
		}
		
		j->fs_ir_phase++;
		
		/* fallthru */
		
	case 1:
		while (j->fs_ir_i < MARKER_SCAN_LIMIT) {
			r = get_char(j, &c);
			if (r)
				return r;
	
			if (c != 0xFF)
				break;
			j->fs_ir_i++;
		}

		if (j->fs_ir_i == MARKER_SCAN_LIMIT) {
			/* we judge it unreasonable */
			lwsl_jpeg("%s: scan limit exceeded 2\n", __func__);

			return LWS_SRET_FATAL + 20;
		}

		/* Is it the expected marker? If not, something bad happened. */
		if (c != (j->restart_num + PJM_RST0)) {
			lwsl_jpeg("%s: unexpected marker\n", __func__);

			return LWS_SRET_FATAL + 21;
		}

		/* Reset each component's DC prediction values. */
		j->last_dc[0] = 0;
		j->last_dc[1] = 0;
		j->last_dc[2] = 0;
	
		j->restarts_left = j->restart_interval;
	
		j->restart_num = (j->restart_num + 1) & 7;
		
		j->bits_left = 8;

		j->fs_ir_phase++;
		
		/* fallthru */
		
	case 2:
		r = get_bits8(j, &c, 8, 1);
		if (r)
			return r;
		j->fs_ir_phase++;
		
		/* fallthru */
		
	case 3:
		r = get_bits8(j, &c, 8, 1);
		if (r)
			return r;

		j->fs_ir_phase = 0;
		break;
	}

	return LWS_SRET_OK;
}

static lws_stateful_ret_t
check_huff_tables(lws_jpeg_t *j)
{
	uint8_t i;

	for (i = 0; i < j->comp_scan_count; i++) {
		uint8_t compDCTab = j->comp_dc[j->comp_list[i]];
		uint8_t compACTab = (uint8_t)(j->comp_ac[j->comp_list[i]] + 2);

		if (((j->huff_valid & (1 << compDCTab)) == 0) ||
		    ((j->huff_valid & (1 << compACTab)) == 0)) {
			lwsl_jpeg("%s: invalid hufftable\n", __func__);

			return LWS_SRET_FATAL;
		}
	}

	return LWS_SRET_OK;
}

static lws_stateful_ret_t
check_quant_tables(lws_jpeg_t *j)
{
	uint8_t i;

	for (i = 0; i < j->comp_scan_count; i++) {
		uint8_t compqMask = j->comp_quant[j->comp_list[i]] ? 2 : 1;

		if ((j->quant_valid & compqMask) == 0) {
			lwsl_jpeg("%s: invalid quant table\n", __func__);

			return LWS_SRET_FATAL + 22;
		}
	}

	return LWS_SRET_OK;
}

static lws_stateful_ret_t
init_scan(lws_jpeg_t *j)
{
	lws_stateful_ret_t r;
	uint8_t c;

	switch (j->fs_is_phase) {
	case 0:
		r = process_markers(j, &c);
		if (r)
			return r;

		if (c == PJM_EOI) {
			lwsl_jpeg("%s: scan reached EOI\n", __func__);

			return LWS_SRET_FATAL + 23;
		}

		if (c != PJM_SOS) {
			lwsl_jpeg("%s: not SOS\n", __func__);

			return LWS_SRET_FATAL + 24;
		}

		j->fs_is_phase++;

		/* fallthru */

	case 1:
		r = read_sos_marker(j);
		if (r)
			return r;

		j->fs_is_phase++;

		/* fallthru */

	case 2:
		r = check_huff_tables(j);
		if (r)
			return r;

		r = check_quant_tables(j);
		if (r)
			return r;

		j->last_dc[0] = 0;
		j->last_dc[1] = 0;
		j->last_dc[2] = 0;

		if (j->restart_interval) {
			j->restarts_left = j->restart_interval;
			j->restart_num = 0;
		}

		if (j->bits_left > 0)
			j->stash[j->stashc++] = (uint8_t)j->bits;

		j->stash[j->stashc++] = (uint8_t) (j->bits >> 8);
		j->bits_left = 8;

		j->fs_is_phase++;

		/* fallthru */

	case 3:
		r = get_bits8(j, &c, 8, 1);
		if (r)
			return r;
		j->fs_is_phase++;

		/* fallthru */

	case 4:
		r = get_bits8(j, &c, 8, 1);
		if (r)
			return r;
		break;
	}

	j->fs_is_phase = 0;

	return LWS_SRET_OK;
}

static lws_stateful_ret_t
init_frame(lws_jpeg_t *j)
{
	switch (j->frame_comps) {
	case 1:
		if ((j->comp_h_samp[0] != 1) || (j->comp_v_samp[0] != 1)) {
			lwsl_jpeg("%s: samps not 1\n", __func__);

			return LWS_SRET_FATAL + 25;
		}

		j->scan_type = PJPG_GRAYSCALE;

		j->mcu_max_blocks = 1;
		j->mcu_org_id[0] = 0;

		j->mcu_max_size_x = 8;
		j->mcu_max_size_y = 8;
		break;
		
	case 3:
		if (((j->comp_h_samp[1] != 1) || (j->comp_v_samp[1] != 1)) ||
		    ((j->comp_h_samp[2] != 1) || (j->comp_v_samp[2] != 1))) {
			lwsl_jpeg("%s: samps not 1 (2)\n", __func__);

			return LWS_SRET_FATAL + 26;
		}

		if ((j->comp_h_samp[0] == 1) && (j->comp_v_samp[0] == 1)) {
			j->scan_type = PJPG_YH1V1;

			j->mcu_max_blocks = 3;
			j->mcu_org_id[0] = 0;
			j->mcu_org_id[1] = 1;
			j->mcu_org_id[2] = 2;

			j->mcu_max_size_x = 8;
			j->mcu_max_size_y = 8;
			break;
		}
		
		if ((j->comp_h_samp[0] == 1) && (j->comp_v_samp[0] == 2)) {
			j->scan_type = PJPG_YH1V2;

			j->mcu_max_blocks = 4;
			j->mcu_org_id[0] = 0;
			j->mcu_org_id[1] = 0;
			j->mcu_org_id[2] = 1;
			j->mcu_org_id[3] = 2;

			j->mcu_max_size_x = 8;
			j->mcu_max_size_y = 16;
			
			break;
		}
		
		if ((j->comp_h_samp[0] == 2) && (j->comp_v_samp[0] == 1)) {
			j->scan_type = PJPG_YH2V1;

			j->mcu_max_blocks = 4;
			j->mcu_org_id[0] = 0;
			j->mcu_org_id[1] = 0;
			j->mcu_org_id[2] = 1;
			j->mcu_org_id[3] = 2;

			j->mcu_max_size_x = 16;
			j->mcu_max_size_y = 8;
			
			break;
		}
		
		if ((j->comp_h_samp[0] == 2) && (j->comp_v_samp[0] == 2)) {
			j->scan_type = PJPG_YH2V2;

			j->mcu_max_blocks = 6;
			j->mcu_org_id[0] = 0;
			j->mcu_org_id[1] = 0;
			j->mcu_org_id[2] = 0;
			j->mcu_org_id[3] = 0;
			j->mcu_org_id[4] = 1;
			j->mcu_org_id[5] = 2;

			j->mcu_max_size_x = 16;
			j->mcu_max_size_y = 16;
			
			break;
		}
		
		/* fallthru */

	default:
		lwsl_jpeg("%s: unknown chroma scheme\n", __func__);

		return LWS_SRET_FATAL;
	}

	j->mcu_max_row = (uint16_t)
			((j->image_width + (j->mcu_max_size_x - 1)) >>
	                ((j->mcu_max_size_x == 8) ? 3 : 4));
	j->mcu_max_col = (uint16_t)
			((j->image_height + (j->mcu_max_size_y - 1)) >>
	                ((j->mcu_max_size_y == 8) ? 3 : 4));

	j->mcu_count_left_x = j->mcu_max_row;
	j->mcu_count_left_y = j->mcu_max_col;

	return LWS_SRET_OK;
}
//----------------------------------------------------------------------------
// Winograd IDCT: 5 multiplies per row/col, up to 80 muls for the 2D IDCT

#define PJPG_DCT_SCALE_BITS 7

#define PJPG_DCT_SCALE (1U << PJPG_DCT_SCALE_BITS)

#define PJPG_DESCALE(x) PJPG_ARITH_SHIFT_RIGHT_N_16(((x) + \
		(1 << (PJPG_DCT_SCALE_BITS - 1))), PJPG_DCT_SCALE_BITS)

#define PJPG_WFIX(x) ((x) * PJPG_DCT_SCALE + 0.5f)

#define PJPG_WINOGRAD_QUANT_SCALE_BITS 10

const uint8_t winograd[] = { 128, 178, 178, 167, 246, 167, 151, 232, 232,
                151, 128, 209, 219, 209, 128, 101, 178, 197, 197, 178, 101, 69,
                139, 167, 177, 167, 139, 69, 35, 96, 131, 151, 151, 131, 96, 35,
                49, 91, 118, 128, 118, 91, 49, 46, 81, 101, 101, 81, 46, 42, 69,
                79, 69, 42, 35, 54, 54, 35, 28, 37, 28, 19, 19, 10, };

// Multiply quantization matrix by the Winograd IDCT scale factors
static void
createWinogradQuant(lws_jpeg_t *j, int16_t *pq)
{
	uint8_t i;

	for (i = 0; i < 64; i++) {
		long x = pq[i];

		x *= winograd[i];
		pq[i] = (int16_t)((x + (1 << (PJPG_WINOGRAD_QUANT_SCALE_BITS -
		                                  PJPG_DCT_SCALE_BITS - 1))) >>
		                       (PJPG_WINOGRAD_QUANT_SCALE_BITS -
		                        PJPG_DCT_SCALE_BITS));
	}
}

/*
 * These multiply helper functions are the 4 types of signed multiplies needed
 * by the Winograd IDCT.
 * A smart C compiler will optimize them to use 16x8 = 24 bit muls, if not you
 * may need to tweak these functions or drop to CPU specific inline assembly.
 */

// 1/cos(4*pi/16)
// 362, 256+106
static LWS_INLINE int16_t
imul_b1_b3(int16_t w)
{
	long x = (w * 362L);

	x += 128L;
	return (int16_t) (PJPG_ARITH_SHIFT_RIGHT_8_L(x));
}

// 1/cos(6*pi/16)
// 669, 256+256+157
static LWS_INLINE int16_t
imul_b2(int16_t w)
{
	long x = (w * 669L);

	x += 128L;
	return (int16_t) (PJPG_ARITH_SHIFT_RIGHT_8_L(x));
}

// 1/cos(2*pi/16)
// 277, 256+21
static LWS_INLINE int16_t
imul_b4(int16_t w)
{
	long x = (w * 277L);

	x += 128L;
	return (int16_t) (PJPG_ARITH_SHIFT_RIGHT_8_L(x));
}

// 1/(cos(2*pi/16) + cos(6*pi/16))
// 196, 196
static LWS_INLINE int16_t
imul_b5(int16_t w)
{
	long x = (w * 196L);

	x += 128L;
	return (int16_t) (PJPG_ARITH_SHIFT_RIGHT_8_L(x));
}

static LWS_INLINE uint8_t
clamp(int16_t s)
{
	if (s < 0)
		return 0;

	if (s > 255)
		return 255;

	return (uint8_t)s;
}

static void
idct_rows(lws_jpeg_t *j)
{
	int16_t *ps = j->coeffs;
	uint8_t i;

	for (i = 0; i < 8; i++) {
		if (!(ps[1] | ps[2] | ps[3] | ps[4] | ps[5] | ps[6] | ps[7])) {
			/*
			 * Short circuit the 1D IDCT if only the DC component
			 * is non-zero
			 */
			int16_t src0 = *ps;

			*(ps + 1) = src0;
			*(ps + 2) = src0;
			*(ps + 3) = src0;
			*(ps + 4) = src0;
			*(ps + 5) = src0;
			*(ps + 6) = src0;
			*(ps + 7) = src0;
			ps += 8;
			continue;
		}

		int16_t src4 = *(ps + 5);
		int16_t src7 = *(ps + 3);
		int16_t x4 = (int16_t)(src4 - src7);
		int16_t x7 = (int16_t)(src4 + src7);

		int16_t src5 = *(ps + 1);
		int16_t src6 = *(ps + 7);
		int16_t x5 = (int16_t)(src5 + src6);
		int16_t x6 = (int16_t)(src5 - src6);

		int16_t tmp1 = (int16_t)(imul_b5((int16_t)(x4 - x6)));
		int16_t stg26 = (int16_t)(imul_b4(x6) - tmp1);

		int16_t x24 = (int16_t)(tmp1 - imul_b2(x4));

		int16_t x15 = (int16_t)(x5 - x7);
		int16_t x17 = (int16_t)(x5 + x7);

		int16_t tmp2 = (int16_t)(stg26 - x17);
		int16_t tmp3 = (int16_t)(imul_b1_b3(x15) - tmp2);
		int16_t x44 = (int16_t)(tmp3 + x24);

		int16_t src0 = *(ps + 0);
		int16_t src1 = *(ps + 4);
		int16_t x30 = (int16_t)(src0 + src1);
		int16_t x31 = (int16_t)(src0 - src1);

		int16_t src2 = *(ps + 2);
		int16_t src3 = *(ps + 6);
		int16_t x12 = (int16_t)(src2 - src3);
		int16_t x13 = (int16_t)(src2 + src3);

		int16_t x32 = (int16_t)(imul_b1_b3(x12) - x13);

		int16_t x40 = (int16_t)(x30 + x13);
		int16_t x43 = (int16_t)(x30 - x13);
		int16_t x41 = (int16_t)(x31 + x32);
		int16_t x42 = (int16_t)(x31 - x32);

		*(ps + 0) = (int16_t)(x40 + x17);
		*(ps + 1) = (int16_t)(x41 + tmp2);
		*(ps + 2) = (int16_t)(x42 + tmp3);
		*(ps + 3) = (int16_t)(x43 - x44);
		*(ps + 4) = (int16_t)(x43 + x44);
		*(ps + 5) = (int16_t)(x42 - tmp3);
		*(ps + 6) = (int16_t)(x41 - tmp2);
		*(ps + 7) = (int16_t)(x40 - x17);

		ps += 8;
	}
}

static void
idct_cols(lws_jpeg_t *j)
{
	int16_t *ps = j->coeffs;
	uint8_t i;

	for (i = 0; i < 8; i++) {
		if (!(ps[1 * 8] | ps[2 * 8] | ps[3 * 8] | ps[4 * 8]
		                | ps[5 * 8] | ps[6 * 8] | ps[7 * 8])) {
			/*
			 * Short circuit the 1D IDCT if only the DC component
			 * is non-zero
			 */
			uint8_t c = clamp((int16_t)(PJPG_DESCALE(*ps) + 128));
			*(ps + 0 * 8) = c;
			*(ps + 1 * 8) = c;
			*(ps + 2 * 8) = c;
			*(ps + 3 * 8) = c;
			*(ps + 4 * 8) = c;
			*(ps + 5 * 8) = c;
			*(ps + 6 * 8) = c;
			*(ps + 7 * 8) = c;
			ps++;
			continue;
		}

		int16_t src4 = *(ps + 5 * 8);
		int16_t src7 = *(ps + 3 * 8);
		int16_t x4 = (int16_t)(src4 - src7);
		int16_t x7 = (int16_t)(src4 + src7);

		int16_t src5 = *(ps + 1 * 8);
		int16_t src6 = *(ps + 7 * 8);
		int16_t x5 = (int16_t)(src5 + src6);
		int16_t x6 = (int16_t)(src5 - src6);

		int16_t tmp1 = (int16_t)(imul_b5((int16_t)(x4 - x6)));
		int16_t stg26 = (int16_t)(imul_b4(x6) - tmp1);

		int16_t x24 = (int16_t)(tmp1 - imul_b2(x4));

		int16_t x15 = (int16_t)(x5 - x7);
		int16_t x17 = (int16_t)(x5 + x7);

		int16_t tmp2 = (int16_t)(stg26 - x17);
		int16_t tmp3 = (int16_t)(imul_b1_b3(x15) - tmp2);
		int16_t x44 = (int16_t)(tmp3 + x24);

		int16_t src0 = *(ps + 0 * 8);
		int16_t src1 = *(ps + 4 * 8);
		int16_t x30 = (int16_t)(src0 + src1);
		int16_t x31 = (int16_t)(src0 - src1);

		int16_t src2 = *(ps + 2 * 8);
		int16_t src3 = *(ps + 6 * 8);
		int16_t x12 = (int16_t)(src2 - src3);
		int16_t x13 = (int16_t)(src2 + src3);

		int16_t x32 = (int16_t)(imul_b1_b3(x12) - x13);

		int16_t x40 = (int16_t)(x30 + x13);
		int16_t x43 = (int16_t)(x30 - x13);
		int16_t x41 = (int16_t)(x31 + x32);
		int16_t x42 = (int16_t)(x31 - x32);

		// descale, convert to unsigned and clamp to 8-bit
		*(ps + 0 * 8) = clamp((int16_t)(PJPG_DESCALE(x40 + x17) + 128));
		*(ps + 1 * 8) = clamp((int16_t)(PJPG_DESCALE(x41 + tmp2) + 128));
		*(ps + 2 * 8) = clamp((int16_t)(PJPG_DESCALE(x42 + tmp3) + 128));
		*(ps + 3 * 8) = clamp((int16_t)(PJPG_DESCALE(x43 - x44) + 128));
		*(ps + 4 * 8) = clamp((int16_t)(PJPG_DESCALE(x43 + x44) + 128));
		*(ps + 5 * 8) = clamp((int16_t)(PJPG_DESCALE(x42 - tmp3) + 128));
		*(ps + 6 * 8) = clamp((int16_t)(PJPG_DESCALE(x41 - tmp2) + 128));
		*(ps + 7 * 8) = clamp((int16_t)(PJPG_DESCALE(x40 - x17) + 128));

		ps++;
	}
}

static LWS_INLINE uint8_t
add_clamp(uint8_t a, int16_t b)
{
	b = (int16_t)(a + b);

	if (b > 255)
		return 255;

	if (b < 0)
		return 0;

	return (uint8_t)b;
}

static LWS_INLINE uint8_t
sub_clamp(uint8_t a, int16_t b)
{
	b = (int16_t)(a - b);

	if (b > 255)
		return 255;

	if (b < 0)
		return 0;

	return (uint8_t)b;
}

// 103/256
//R = Y + 1.402 (Cr-128)
// 88/256, 183/256
//G = Y - 0.34414 (Cb-128) - 0.71414 (Cr-128)
// 198/256
//B = Y + 1.772 (Cb-128)

// Cb upsample and accumulate, 4x4 to 8x8
static void
upsample_cb(lws_jpeg_t *j, uint8_t src_ofs, uint8_t dst_ofs)
{
	// Cb - affects G and B
	uint8_t x, y;
	int16_t *ps = j->coeffs + src_ofs;
	uint8_t *pg = j->mcu_buf_G + dst_ofs;
	uint8_t *pb = j->mcu_buf_B + dst_ofs;

	for (y = 0; y < 4; y++) {
		for (x = 0; x < 4; x++) {
			uint8_t cb = (uint8_t) *ps++;
			int16_t cbG, cbB;

			cbG = (int16_t)(((cb * 88U) >> 8U) - 44U);
			pg[0] = sub_clamp(pg[0], cbG);
			pg[1] = sub_clamp(pg[1], cbG);
			pg[8] = sub_clamp(pg[8], cbG);
			pg[9] = sub_clamp(pg[9], cbG);

			cbB = (int16_t)((cb + ((cb * 198U) >> 8U)) - 227U);
			pb[0] = add_clamp(pb[0], cbB);
			pb[1] = add_clamp(pb[1], cbB);
			pb[8] = add_clamp(pb[8], cbB);
			pb[9] = add_clamp(pb[9], cbB);

			pg += 2;
			pb += 2;
		}

		ps = ps - 4 + 8;
		pg = pg - 8 + 16;
		pb = pb - 8 + 16;
	}
}

// Cb upsample and accumulate, 4x8 to 8x8
static void
upsample_cbh(lws_jpeg_t *j, uint8_t src_ofs, uint8_t dst_ofs)
{
	// Cb - affects G and B
	int16_t *ps = j->coeffs + src_ofs;
	uint8_t *pg = j->mcu_buf_G + dst_ofs;
	uint8_t *pb = j->mcu_buf_B + dst_ofs;
	uint8_t x, y;

	for (y = 0; y < 8; y++) {
		for (x = 0; x < 4; x++) {
			uint8_t cb = (uint8_t) *ps++;
			int16_t cbG, cbB;

			cbG = (int16_t)(((cb * 88U) >> 8U) - 44U);
			pg[0] = sub_clamp(pg[0], cbG);
			pg[1] = sub_clamp(pg[1], cbG);

			cbB = (int16_t)((cb + ((cb * 198U) >> 8U)) - 227U);
			pb[0] = add_clamp(pb[0], cbB);
			pb[1] = add_clamp(pb[1], cbB);

			pg += 2;
			pb += 2;
		}

		ps = ps - 4 + 8;
	}
}

// Cb upsample and accumulate, 8x4 to 8x8
static void
upsample_cbv(lws_jpeg_t *j, uint8_t src_ofs, uint8_t dst_ofs)
{
	// Cb - affects G and B
	int16_t *ps = j->coeffs + src_ofs;
	uint8_t *pg = j->mcu_buf_G + dst_ofs;
	uint8_t *pb = j->mcu_buf_B + dst_ofs;
	uint8_t x, y;

	for (y = 0; y < 4; y++) {
		for (x = 0; x < 8; x++) {
			uint8_t cb = (uint8_t) *ps++;
			int16_t cbG, cbB;

			cbG = (int16_t)(((cb * 88U) >> 8U) - 44U);
			pg[0] = sub_clamp(pg[0], cbG);
			pg[8] = sub_clamp(pg[8], cbG);

			cbB = (int16_t)((cb + ((cb * 198U) >> 8U)) - 227U);
			pb[0] = add_clamp(pb[0], cbB);
			pb[8] = add_clamp(pb[8], cbB);

			++pg;
			++pb;
		}

		pg = pg - 8 + 16;
		pb = pb - 8 + 16;
	}
}

// 103/256
//R = Y + 1.402 (Cr-128)
// 88/256, 183/256
//G = Y - 0.34414 (Cb-128) - 0.71414 (Cr-128)
// 198/256
//B = Y + 1.772 (Cb-128)

// Cr upsample and accumulate, 4x4 to 8x8
static void
upsample_cr(lws_jpeg_t *j, uint8_t src_ofs, uint8_t dst_ofs)
{
	// Cr - affects R and G
	uint8_t x, y;
	int16_t *ps = j->coeffs + src_ofs;
	uint8_t *pr = j->mcu_buf_R + dst_ofs;
	uint8_t *pg = j->mcu_buf_G + dst_ofs;

	for (y = 0; y < 4; y++) {
		for (x = 0; x < 4; x++) {
			uint8_t cr = (uint8_t) *ps++;
			int16_t crR, crG;

			crR = (int16_t)((cr + ((cr * 103U) >> 8U)) - 179);
			pr[0] = add_clamp(pr[0], crR);
			pr[1] = add_clamp(pr[1], crR);
			pr[8] = add_clamp(pr[8], crR);
			pr[9] = add_clamp(pr[9], crR);

			crG = (int16_t)(((cr * 183U) >> 8U) - 91);
			pg[0] = sub_clamp(pg[0], crG);
			pg[1] = sub_clamp(pg[1], crG);
			pg[8] = sub_clamp(pg[8], crG);
			pg[9] = sub_clamp(pg[9], crG);

			pr += 2;
			pg += 2;
		}

		ps = ps - 4 + 8;
		pr = pr - 8 + 16;
		pg = pg - 8 + 16;
	}
}

// Cr upsample and accumulate, 4x8 to 8x8
static void
upsample_crh(lws_jpeg_t *j, uint8_t src_ofs, uint8_t dst_ofs)
{
	// Cr - affects R and G
	uint8_t x, y;
	int16_t *ps = j->coeffs + src_ofs;
	uint8_t *pr = j->mcu_buf_R + dst_ofs;
	uint8_t *pg = j->mcu_buf_G + dst_ofs;

	for (y = 0; y < 8; y++) {
		for (x = 0; x < 4; x++) {
			uint8_t cr = (uint8_t) *ps++;
			int16_t crR, crG;

			crR = (int16_t)((cr + ((cr * 103U) >> 8U)) - 179);
			pr[0] = add_clamp(pr[0], crR);
			pr[1] = add_clamp(pr[1], crR);

			crG = (int16_t)(((cr * 183U) >> 8U) - 91);
			pg[0] = sub_clamp(pg[0], crG);
			pg[1] = sub_clamp(pg[1], crG);

			pr += 2;
			pg += 2;
		}

		ps = ps - 4 + 8;
	}
}

// Cr upsample and accumulate, 8x4 to 8x8
static void
upsample_crv(lws_jpeg_t *j, uint8_t src_ofs, uint8_t dst_ofs)
{
	// Cr - affects R and G
	uint8_t x, y;
	int16_t *ps = j->coeffs + src_ofs;
	uint8_t *pr = j->mcu_buf_R + dst_ofs;
	uint8_t *pg = j->mcu_buf_G + dst_ofs;

	for (y = 0; y < 4; y++) {
		for (x = 0; x < 8; x++) {
			uint8_t cr = (uint8_t) *ps++;
			int16_t crR, crG;

			crR = (int16_t)((cr + ((cr * 103U) >> 8U)) - 179);
			pr[0] = add_clamp(pr[0], crR);
			pr[8] = add_clamp(pr[8], crR);

			crG = (int16_t)(((cr * 183U) >> 8U) - 91);
			pg[0] = sub_clamp(pg[0], crG);
			pg[8] = sub_clamp(pg[8], crG);

			++pr;
			++pg;
		}

		pr = pr - 8 + 16;
		pg = pg - 8 + 16;
	}
}

// Convert Y to RGB
static void
copy_y(lws_jpeg_t *j, uint8_t dst_ofs)
{
	uint8_t i;
	uint8_t *pRDst = j->mcu_buf_R + dst_ofs;
	uint8_t *pGDst = j->mcu_buf_G + dst_ofs;
	uint8_t *pBDst = j->mcu_buf_B + dst_ofs;
	int16_t *ps = j->coeffs;

	for (i = 64; i > 0; i--) {
		uint8_t c = (uint8_t) *ps++;

		*pRDst++ = c;
		*pGDst++ = c;
		*pBDst++ = c;
	}
}

// Cb convert to RGB and accumulate
static void
convert_cb(lws_jpeg_t *j, uint8_t dst_ofs)
{
	uint8_t i;
	uint8_t *pg = j->mcu_buf_G + dst_ofs;
	uint8_t *pb = j->mcu_buf_B + dst_ofs;
	int16_t *ps = j->coeffs;

	for (i = 64; i > 0; i--) {
		uint8_t cb = (uint8_t) *ps++;
		int16_t cbG, cbB;

		cbG = (int16_t)(((cb * 88U) >> 8U) - 44U);
		*pg = sub_clamp(pg[0], cbG);
		pg++;

		cbB = (int16_t)((cb + ((cb * 198U) >> 8U)) - 227U);
		*pb = add_clamp(pb[0], cbB);
		pb++;
	}
}

// Cr convert to RGB and accumulate
static void
convert_cr(lws_jpeg_t *j, uint8_t dst_ofs)
{
	uint8_t i;
	uint8_t *pr = j->mcu_buf_R + dst_ofs;
	uint8_t *pg = j->mcu_buf_G + dst_ofs;
	int16_t *ps = j->coeffs;

	for (i = 64; i > 0; i--) {
		uint8_t cr = (uint8_t) *ps++;
		int16_t crR, crG;

		crR = (int16_t)((cr + ((cr * 103U) >> 8U)) - 179);
		*pr = add_clamp(pr[0], crR);
		pr++;

		crG = (int16_t)(((cr * 183U) >> 8U) - 91);
		*pg = sub_clamp(pg[0], crG);
		pg++;
	}
}

static void
transform_block(lws_jpeg_t *j, uint8_t mb)
{
	idct_rows(j);
	idct_cols(j);

	switch (j->scan_type) {
	case PJPG_GRAYSCALE:
		// MCU size: 1, 1 block per MCU
		copy_y(j, 0);
		break;

	case PJPG_YH1V1:
		// MCU size: 8x8, 3 blocks per MCU
		switch (mb) {
		case 0:
			copy_y(j, 0);
			break;

		case 1:
			convert_cb(j, 0);
			break;

		case 2:
			convert_cr(j, 0);
			break;
		}

		break;

	case PJPG_YH1V2:
		// MCU size: 8x16, 4 blocks per MCU
		switch (mb) {
		case 0:
			copy_y(j, 0);
			break;

		case 1:
			copy_y(j, 128);
			break;

		case 2:
			upsample_cbv(j, 0, 0);
			upsample_cbv(j, 4 * 8, 128);
			break;

		case 3:
			upsample_crv(j, 0, 0);
			upsample_crv(j, 4 * 8, 128);
			break;
		}
		break;

	case PJPG_YH2V1:
		// MCU size: 16x8, 4 blocks per MCU
		switch (mb) {
		case 0:
			copy_y(j, 0);
			break;

		case 1:
			copy_y(j, 64);
			break;

		case 2:
			upsample_cbh(j, 0, 0);
			upsample_cbh(j, 4, 64);
			break;

		case 3:
			upsample_crh(j, 0, 0);
			upsample_crh(j, 4, 64);
			break;
		}
		break;

	case PJPG_YH2V2:
		// MCU size: 16x16, 6 blocks per MCU
		switch (mb) {
		case 0:
			copy_y(j, 0);
			break;

		case 1:
			copy_y(j, 64);
			break;

		case 2:
			copy_y(j, 128);
			break;

		case 3:
			copy_y(j, 192);
			break;

		case 4:
			upsample_cb(j, 0, 0);
			upsample_cb(j, 4, 64);
			upsample_cb(j, 4 * 8, 128);
			upsample_cb(j, 4 + 4 * 8, 192);
			break;

		case 5:
			upsample_cr(j, 0, 0);
			upsample_cr(j, 4, 64);
			upsample_cr(j, 4 * 8, 128);
			upsample_cr(j, 4 + 4 * 8, 192);
			break;
		}
		break;
	}
}

static lws_stateful_ret_t
lws_jpeg_mcu_next(lws_jpeg_t *j)
{
	unsigned int x, y, row_pitch = (unsigned int)(j->frame_comps *
						      j->image_width);
	lws_stateful_ret_t r;

	if (!j->fs_mcu_phase) {
		if (j->restart_interval) {
			if (j->restarts_left == 0) {
				lwsl_err("%s: process_restart\n", __func__);
				r = interval_restart(j);
				if (r)
					return r;
			} else
				j->restarts_left--;
		}
		
		j->fs_mcu_mb = 0;
		j->fs_mcu_phase++;
	}

	while (j->fs_mcu_mb < j->mcu_max_blocks) {
		uint8_t id = j->mcu_org_id[j->fs_mcu_mb];
		uint8_t compDCTab = j->comp_dc[id];
		uint8_t compq = j->comp_quant[id];
		const int16_t *pQ = compq ? j->quant1 : j->quant0;
		uint8_t nexb, compACTab, c;
		uint16_t xr;
		int16_t dc;
		uint8_t s;

		switch (j->fs_mcu_phase) {
		case 1:
			r = huff_decode(j, &j->fs_mcu_s, compDCTab ?
					 &j->huff_tab1 : &j->huff_tab0,
				       compDCTab ?
					 j->huff_val1 : j->huff_val0);
			if (r)
				return r;

			if (j->seen_eoi)
				return LWS_SRET_OK;

			j->fs_mcu_phase++;
			
			/* fallthru */

		case 2:
			xr = 0;
			nexb = j->fs_mcu_s & 0xf;
			if (nexb) {
				if (nexb > 8)
					r = get_bits16(j, &xr, nexb, 1);
				else {
					c = 0;
					r = get_bits8(j, &c, nexb, 1);
					xr = c;
				}

				if (r)
					return r;
			}

			dc = (int16_t)(huff_extend(xr, j->fs_mcu_s) +
								j->last_dc[id]);
			j->last_dc[id] = (int16_t)dc;
			j->coeffs[0] = (int16_t)(dc * pQ[0]);

			j->fs_mcu_k = 1;
			j->fs_mcu_phase_loop = 0;
			j->fs_mcu_phase++;

			/* fallthru */

		case 3:
			compACTab = j->comp_ac[id];

			/* Decode and dequantize AC coefficients */
			while (j->fs_mcu_k < 64) {
				uint16_t exb;

				if (!j->fs_mcu_phase_loop) {
					r = huff_decode(j, &j->fs_mcu_s,
							compACTab ?
						&j->huff_tab3 : &j->huff_tab2,
							compACTab ?
						j->huff_val3 : j->huff_val2);
					if (j->seen_eoi)
						return LWS_SRET_OK;
					if (r)
						return r;

					j->fs_mcu_phase_loop = 1;
				}

				exb = 0;
				nexb = j->fs_mcu_s & 0xf;
				if (nexb) {
					if (nexb > 8)
						r = get_bits16(j, &exb, nexb, 1);
					else {
						c = 0;
						r = get_bits8(j, &c, nexb, 1);
						exb = (uint16_t)c;
					}
					if (r)
						return r;
				}

				xr = (j->fs_mcu_s >> 4) & 0xf;
				s = j->fs_mcu_s & 15;

				if (s) {
					if (xr) {
						if ((j->fs_mcu_k + xr) > 63) {
							lwsl_jpeg("%s: k oflow\n",
									__func__);

							return LWS_SRET_FATAL;
						}

						while (xr--)
							j->coeffs[(int)ZAG[
							  (unsigned int)
							  j->fs_mcu_k++]] = 0;
					}

					j->coeffs[(int)ZAG[(unsigned int)
					        j->fs_mcu_k]] = (int16_t)(
						huff_extend(exb, s) *
						pQ[(unsigned int)j->fs_mcu_k]);
				} else {
					if (xr != 15)
						break; /* early loop exit */

					if (((unsigned int)j->fs_mcu_k + 16) > 64) {
						lwsl_jpeg("%s: k > 64\n", __func__);
						return LWS_SRET_FATAL;
					}

					for (xr = 16; xr > 0; xr--)
						j->coeffs[(int)ZAG[(unsigned int)
						            j->fs_mcu_k++]] = 0;

					j->fs_mcu_k--;
				}

				j->fs_mcu_phase_loop = 0;
				j->fs_mcu_k++;
			} /* while k < 64 */

			while (j->fs_mcu_k < 64)
				j->coeffs[(int)ZAG[(unsigned int)
				                   j->fs_mcu_k++]] = 0;

			transform_block(j, j->fs_mcu_mb);

			break;
		} /* switch */

		j->fs_mcu_phase = 1;
		j->fs_mcu_mb++;
	} /* while mb */

	/*
	 * Place the MCB into the allocated, MCU-height pixel buffer
	 */

	 uint8_t *dr = j->lines + (j->mcu_ofs_x * j->mcu_max_size_x *
				   j->frame_comps);

         for (y = 0; y < j->mcu_max_size_y; y += 8) {
		unsigned int by_limit = (unsigned int)((unsigned int)j->image_height -
					(unsigned int)((unsigned int)j->mcu_ofs_y *
					(unsigned int)j->mcu_max_size_y +
							(unsigned int)y));

		if (by_limit > 8)
			by_limit = 8;

		for (x = 0; x < j->mcu_max_size_x; x += 8) {
			uint8_t *db = dr + (x * j->frame_comps);
			uint8_t src_ofs = (uint8_t)((x * 8U) + (y * 16U));
			const uint8_t *pSrcR = j->mcu_buf_R + src_ofs;
			const uint8_t *pSrcG = j->mcu_buf_G + src_ofs;
			const uint8_t *pSrcB = j->mcu_buf_B + src_ofs;
			unsigned int bx_limit = (unsigned int)(
				(unsigned int)j->image_width -
				(unsigned int)((unsigned int)j->mcu_ofs_x *
				(unsigned int)j->mcu_max_size_x +
							(unsigned int)x));
			unsigned int bx, by;

			if (bx_limit > 8)
				bx_limit = 8;

			if (j->scan_type == PJPG_GRAYSCALE) {
				for (by = 0; by < by_limit; by++) {
					uint8_t *pDst = db;

					for (bx = 0; bx < bx_limit; bx++)
						*pDst++ = *pSrcR++;

					pSrcR += (8 - bx_limit);

					db += row_pitch;
				}
			} else {
				for (by = 0; by < by_limit; by++) {
					uint8_t *pDst = db;

					for (bx = 0; bx < bx_limit; bx++) {
						pDst[0] = *pSrcR++;
						pDst[1] = *pSrcG++;
						pDst[2] = *pSrcB++;
						pDst += 3;
					}

					pSrcR += (8 - bx_limit);
					pSrcG += (8 - bx_limit);
					pSrcB += (8 - bx_limit);

					db += row_pitch;
				}
			}
		} /* x */

		dr += (row_pitch * 8);
	} /* y */

	if (j->mcu_ofs_x++ == j->mcu_max_row - 1) {
		j->mcu_ofs_x = 0;
		j->mcu_ofs_y++;
	}

	j->fs_mcu_phase = 0;

	return LWS_SRET_OK;
}

lws_jpeg_t *
lws_jpeg_new(void)
{
	lws_jpeg_t *j = lws_zalloc(sizeof(*j), __func__);

	if (!j)
		return NULL;

	return j;
}

void
lws_jpeg_free(lws_jpeg_t **j)
{
	lws_free_set_NULL((*j)->lines);
	lws_free_set_NULL(*j);
}

lws_stateful_ret_t
lws_jpeg_emit_next_line(lws_jpeg_t *j, const uint8_t **ppix,
			const uint8_t **buf, size_t *size, char hold_at_metadata)
{
	lws_stateful_ret_t r = 0;
	size_t mcu_buf_len;

	j->inbuf = *buf;
	j->insize = *size;
	j->hold_at_metadata = hold_at_metadata;

	do {
		switch (j->dstate) {

		case LWSJDS_FIND_SOI_INIT1:
			j->fs_emit_budget = 4096;
			r = get_bits8(j, &j->fs_emit_lc, 8, 0);
			if (r)
				goto fin;
			j->dstate++;

			/* fallthru */

		case LWSJDS_FIND_SOI_INIT2:
			r = get_bits8(j, &j->fs_emit_tc, 8, 0);
			if (r)
				goto fin;
			
			if ((j->fs_emit_lc == 0xFF) &&
			    (j->fs_emit_tc == PJM_SOI)) {
				j->dstate = LWSJDS_FIND_SOI;
				break;
			}
			
			j->dstate++;
	
			/* fallthru */

		case LWSJDS_FIND_SOI:
	
			for (;;) {
	
				j->fs_emit_lc = j->fs_emit_tc;
				r = get_bits8(j, &j->fs_emit_tc, 8, 0);
				if (r)
					goto fin;
				
				if (--j->fs_emit_budget == 0) {
					lwsl_jpeg("%s: SOI emit budget gone\n",
								__func__);

					return LWS_SRET_FATAL + 28;
				}
	
				if (j->fs_emit_lc == 0xFF) {
					if (j->fs_emit_tc == PJM_SOI)
						break;
					if (j->fs_emit_tc == PJM_EOI) {
						lwsl_jpeg("%s: SOI reached EOI\n",
								__func__);

						return LWS_SRET_FATAL + 29;
					}
					lwsl_jpeg("%s: skipping 0x%02x\n", __func__, j->fs_emit_lc);
				}
			}
	
			/*
			 * Check the next character after marker:
			 * if it's not 0xFF, it can't be the start of the
			 * next marker, so the file is bad
			 */
	
			j->fs_emit_tc = (uint8_t)((j->bits >> 8) & 0xFF);
	
			if (j->fs_emit_tc != 0xFF) {
				lwsl_jpeg("%s: not marker\n", __func__);

				return LWS_SRET_FATAL + 30;
			}
			
			j->dstate = LWSJDS_FIND_SOF1;
			
			/* fallthru */
			
		case LWSJDS_FIND_SOF1:

			r = process_markers(j, &j->fs_emit_c);
			if (r)
				goto fin;
			
			if (j->fs_emit_c == PJM_SOF2) {
				lwsl_warn("%s: progressive JPEG not supported\n", __func__);
				return LWS_SRET_FATAL + 31;
			}

			if (j->fs_emit_c != PJM_SOF0) {
				lwsl_jpeg("%s: not SOF0 (%d)\n", __func__, (int)j->fs_emit_c);

				return LWS_SRET_FATAL + 31;
			}
			
			j->dstate++;
	
			/* fallthru */

		case LWSJDS_FIND_SOF2:
			
			r = read_sof_marker(j);
			if (r)
				goto fin;

			j->dstate++;
	
			/* fallthru */
			
		case LWSJDS_INIT_FRAME:
			
			r = init_frame(j);
			if (r)
				goto fin;

			j->dstate++;
	
			/* fallthru */
			
		case LWSJDS_INIT_SCAN:
			
			r = init_scan(j);
			if (r)
				goto fin;

			if (j->hold_at_metadata)
				return LWS_SRET_AWAIT_RETRY;

			/*
			 * 8, or 16 lines of 24-bpp according to MCU height
			 */
			/*
			 * row_pitch = (size_t)j->image_witdh * j->frame_comps
			 *
			 * max dr
			 * j->lines + (size_t)(j->mcu_max_row * j->mcu_max_size_x * j->frame_comps) + (size_t)(row_pitch * j->mcu_max_size_y)
			 *
			 * max db
			 * max dr + (size_t)(j->mcu_max_size_x * j->frame_comps) + (size_t)(by_limit * row_pitch)
			 *
			 * max pDst
			 * max db + (size_t)(bx_limit * 3)
			 *
			 * max by_limit and bx_limit = 8
			*/
			mcu_buf_len = (size_t)(j->mcu_max_row * j->mcu_max_size_x * j->frame_comps)
				+ (size_t)(j->image_width * j->frame_comps * j->mcu_max_size_y)
				+ (size_t)(j->mcu_max_size_x * j->frame_comps)
				+ (size_t)(8 * j->frame_comps * j->image_width)
				+ (size_t)(8 * 3);

			j->lines = lws_zalloc(mcu_buf_len, __func__);
			if (!j->lines) {
				lwsl_jpeg("%s: OOM\n", __func__);
				return LWS_SRET_FATAL + 32;
			}

			j->dstate++;
	
			/* fallthru */

		case LWSJDS_DECODE_MCU:

			/*
			 * Once we started dumping the line buffer, continue
			 * until we cleared the prepared MCU height
			 */
			if (j->ringy & (j->mcu_max_size_y - 1))
				goto intra;

			if (j->seen_eoi) {
				r = LWS_SRET_OK;
				goto intra;
			}

			r = lws_jpeg_mcu_next(j);
			if (j->seen_eoi) {
				r = LWS_SRET_OK;
				goto intra;
			}
			if (r)
				goto fin;

			j->mcu_count_left_x--;
			if (!j->mcu_count_left_x) {
				j->mcu_count_left_y--;

				if (j->mcu_count_left_y > 0)
					j->mcu_count_left_x = j->mcu_max_row;

				if (!j->mcu_count_left_x && !j->mcu_count_left_y) {
					lwsl_notice("%s: seems finished2\n", __func__);
					r = LWS_SRET_NO_FURTHER_IN;
					goto intra;
				}

				goto intra;
			}
			break;
		}
	} while (1);

intra:
	*ppix = j->lines + (((j->ringy++) & (j->mcu_max_size_y - 1)) *
				j->frame_comps * j->image_width);

	r |= LWS_SRET_WANT_OUTPUT;

fin:
	*buf = j->inbuf;
	*size = j->insize;

	return r;
}

unsigned int
lws_jpeg_get_width(const lws_jpeg_t *j)
{
	return j->image_width;
}

unsigned int
lws_jpeg_get_height(const lws_jpeg_t *j)
{
	return j->image_height;
}

unsigned int
lws_jpeg_get_bpp(const lws_jpeg_t *j)
{
	return j->scan_type == PJPG_GRAYSCALE ? 8 : 24;
}

unsigned int
lws_jpeg_get_bitdepth(const lws_jpeg_t *j)
{
	return 8;
}

unsigned int
lws_jpeg_get_components(const lws_jpeg_t *j)
{
	return j->scan_type == PJPG_GRAYSCALE ? 1 : 3;
}

unsigned int
lws_jpeg_get_pixelsize(const lws_jpeg_t *j)
{
	return j->scan_type == PJPG_GRAYSCALE ? 8 : 24;
}
