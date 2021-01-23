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

/** \defgroup lejp JSON parser
 * ##JSON parsing related functions
 * \ingroup lwsapi
 *
 * LEJP is an extremely lightweight JSON stream parser included in lws.
 */
//@{
struct lejp_ctx;

#if !defined(LWS_ARRAY_SIZE)
#define LWS_ARRAY_SIZE(_x) (sizeof(_x) / sizeof(_x[0]))
#endif
#define LEJP_FLAG_WS_KEEP 64
#define LEJP_FLAG_WS_COMMENTLINE 32

enum lejp_states {
	LEJP_IDLE = 0,
	LEJP_MEMBERS = 1,
	LEJP_M_P = 2,
	LEJP_MP_STRING = LEJP_FLAG_WS_KEEP | 3,
	LEJP_MP_STRING_ESC = LEJP_FLAG_WS_KEEP | 4,
	LEJP_MP_STRING_ESC_U1 = LEJP_FLAG_WS_KEEP | 5,
	LEJP_MP_STRING_ESC_U2 = LEJP_FLAG_WS_KEEP | 6,
	LEJP_MP_STRING_ESC_U3 = LEJP_FLAG_WS_KEEP | 7,
	LEJP_MP_STRING_ESC_U4 = LEJP_FLAG_WS_KEEP | 8,
	LEJP_MP_DELIM = 9,
	LEJP_MP_VALUE = 10,
	LEJP_MP_VALUE_NUM_INT = LEJP_FLAG_WS_KEEP | 11,
	LEJP_MP_VALUE_NUM_EXP = LEJP_FLAG_WS_KEEP | 12,
	LEJP_MP_VALUE_TOK = LEJP_FLAG_WS_KEEP | 13,
	LEJP_MP_COMMA_OR_END = 14,
	LEJP_MP_ARRAY_END = 15,
};

enum lejp_reasons {
	LEJP_CONTINUE = -1,
	LEJP_REJECT_IDLE_NO_BRACE = -2,
	LEJP_REJECT_MEMBERS_NO_CLOSE = -3,
	LEJP_REJECT_MP_NO_OPEN_QUOTE = -4,
	LEJP_REJECT_MP_STRING_UNDERRUN = -5,
	LEJP_REJECT_MP_ILLEGAL_CTRL = -6,
	LEJP_REJECT_MP_STRING_ESC_ILLEGAL_ESC = -7,
	LEJP_REJECT_ILLEGAL_HEX = -8,
	LEJP_REJECT_MP_DELIM_MISSING_COLON = -9,
	LEJP_REJECT_MP_DELIM_BAD_VALUE_START = -10,
	LEJP_REJECT_MP_VAL_NUM_INT_NO_FRAC = -11,
	LEJP_REJECT_MP_VAL_NUM_FORMAT = -12,
	LEJP_REJECT_MP_VAL_NUM_EXP_BAD_EXP = -13,
	LEJP_REJECT_MP_VAL_TOK_UNKNOWN = -14,
	LEJP_REJECT_MP_C_OR_E_UNDERF = -15,
	LEJP_REJECT_MP_C_OR_E_NOTARRAY = -16,
	LEJP_REJECT_MP_ARRAY_END_MISSING = -17,
	LEJP_REJECT_STACK_OVERFLOW = -18,
	LEJP_REJECT_MP_DELIM_ISTACK = -19,
	LEJP_REJECT_NUM_TOO_LONG = -20,
	LEJP_REJECT_MP_C_OR_E_NEITHER = -21,
	LEJP_REJECT_UNKNOWN = -22,
	LEJP_REJECT_CALLBACK = -23
};

#define LEJP_FLAG_CB_IS_VALUE 64

enum lejp_callbacks {
	LEJPCB_CONSTRUCTED	= 0,
	LEJPCB_DESTRUCTED	= 1,

	LEJPCB_START		= 2,
	LEJPCB_COMPLETE		= 3,
	LEJPCB_FAILED		= 4,

	LEJPCB_PAIR_NAME	= 5,

	LEJPCB_VAL_TRUE		= LEJP_FLAG_CB_IS_VALUE | 6,
	LEJPCB_VAL_FALSE	= LEJP_FLAG_CB_IS_VALUE | 7,
	LEJPCB_VAL_NULL		= LEJP_FLAG_CB_IS_VALUE | 8,
	LEJPCB_VAL_NUM_INT	= LEJP_FLAG_CB_IS_VALUE | 9,
	LEJPCB_VAL_NUM_FLOAT	= LEJP_FLAG_CB_IS_VALUE | 10,
	LEJPCB_VAL_STR_START	= 11, /* notice handle separately */
	LEJPCB_VAL_STR_CHUNK	= LEJP_FLAG_CB_IS_VALUE | 12,
	LEJPCB_VAL_STR_END	= LEJP_FLAG_CB_IS_VALUE | 13,

	LEJPCB_ARRAY_START	= 14,
	LEJPCB_ARRAY_END	= 15,

	LEJPCB_OBJECT_START	= 16,
	LEJPCB_OBJECT_END	= 17,
};

/**
 * _lejp_callback() - User parser actions
 * \param ctx:	LEJP context
 * \param reason:	Callback reason
 *
 *	Your user callback is associated with the context at construction time,
 *	and receives calls as the parsing progresses.
 *
 *	All of the callbacks may be ignored and just return 0.
 *
 *	The reasons it might get called, found in @reason, are:
 *
 *  LEJPCB_CONSTRUCTED:  The context was just constructed... you might want to
 *		perform one-time allocation for the life of the context.
 *
 *  LEJPCB_DESTRUCTED:	The context is being destructed... if you made any
 *		allocations at construction-time, you can free them now
 *
 *  LEJPCB_START:	Parsing is beginning at the first byte of input
 *
 *  LEJPCB_COMPLETE:	Parsing has completed successfully.  You'll get a 0 or
 *			positive return code from lejp_parse indicating the
 *			amount of unused bytes left in the input buffer
 *
 *  LEJPCB_FAILED:	Parsing failed.  You'll get a negative error code
 *  			returned from lejp_parse
 *
 *  LEJPCB_PAIR_NAME:	When a "name":"value" pair has had the name parsed,
 *			this callback occurs.  You can find the new name at
 *			the end of ctx->path[]
 *
 *  LEJPCB_VAL_TRUE:	The "true" value appeared
 *
 *  LEJPCB_VAL_FALSE:	The "false" value appeared
 *
 *  LEJPCB_VAL_NULL:	The "null" value appeared
 *
 *  LEJPCB_VAL_NUM_INT:	A string representing an integer is in ctx->buf
 *
 *  LEJPCB_VAL_NUM_FLOAT: A string representing a float is in ctx->buf
 *
 *  LEJPCB_VAL_STR_START: We are starting to parse a string, no data yet
 *
 *  LEJPCB_VAL_STR_CHUNK: We filled the string buffer in the ctx, but it's not
 *			  the end of the string.  We produce this to spill the
 *			  intermediate buffer to the user code, so we can handle
 *			  huge JSON strings using only the small buffer in the
 *			  ctx.  If the whole JSON string fits in the ctx buffer,
 *			  you won't get these callbacks.
 *
 *  LEJPCB_VAL_STR_END:	String parsing has completed, the last chunk of the
 *			string is in ctx->buf.
 *
 *  LEJPCB_ARRAY_START:	An array started
 *
 *  LEJPCB_ARRAY_END:	An array ended
 *
 *  LEJPCB_OBJECT_START: An object started
 *
 *  LEJPCB_OBJECT_END:	An object ended
 */
LWS_EXTERN signed char _lejp_callback(struct lejp_ctx *ctx, char reason);

typedef signed char (*lejp_callback)(struct lejp_ctx *ctx, char reason);

#ifndef LEJP_MAX_PARSING_STACK_DEPTH
#define LEJP_MAX_PARSING_STACK_DEPTH 5
#endif
#ifndef LEJP_MAX_DEPTH
#define LEJP_MAX_DEPTH 12
#endif
#ifndef LEJP_MAX_INDEX_DEPTH
#define LEJP_MAX_INDEX_DEPTH 8
#endif
#ifndef LEJP_MAX_PATH
#define LEJP_MAX_PATH 128
#endif
#ifndef LEJP_STRING_CHUNK
/* must be >= 30 to assemble floats */
#define LEJP_STRING_CHUNK 254
#endif

enum num_flags {
	LEJP_SEEN_MINUS = (1 << 0),
	LEJP_SEEN_POINT = (1 << 1),
	LEJP_SEEN_POST_POINT = (1 << 2),
	LEJP_SEEN_EXP = (1 << 3)
};

struct _lejp_stack {
	char s; /* lejp_state stack*/
	char p;	/* path length */
	char i; /* index array length */
	char b; /* user bitfield */
};

struct _lejp_parsing_stack {
	void *user;	/* private to the stack level */
	signed char (*callback)(struct lejp_ctx *ctx, char reason);
	const char * const *paths;
	uint8_t count_paths;
	uint8_t ppos;
	uint8_t path_match;
};

struct lejp_ctx {

	/* sorted by type for most compact alignment
	 *
	 * pointers
	 */
	void *user;

	/* arrays */

	struct _lejp_parsing_stack pst[LEJP_MAX_PARSING_STACK_DEPTH];
	struct _lejp_stack st[LEJP_MAX_DEPTH];
	uint16_t i[LEJP_MAX_INDEX_DEPTH]; /* index array */
	uint16_t wild[LEJP_MAX_INDEX_DEPTH]; /* index array */
	char path[LEJP_MAX_PATH];
	char buf[LEJP_STRING_CHUNK + 1];

	/* size_t */

	size_t path_stride; /* 0 means default ptr size, else stride */

	/* int */

	uint32_t line;

	/* short */

	uint16_t uni;

	/* char */

	uint8_t npos;
	uint8_t dcount;
	uint8_t f;
	uint8_t sp; /* stack head */
	uint8_t ipos; /* index stack depth */
	uint8_t count_paths;
	uint8_t path_match;
	uint8_t path_match_len;
	uint8_t wildcount;
	uint8_t pst_sp; /* parsing stack head */
	uint8_t outer_array;
};

LWS_VISIBLE LWS_EXTERN void
lejp_construct(struct lejp_ctx *ctx,
	       signed char (*callback)(struct lejp_ctx *ctx, char reason),
	       void *user, const char * const *paths, unsigned char paths_count);

LWS_VISIBLE LWS_EXTERN void
lejp_destruct(struct lejp_ctx *ctx);

LWS_VISIBLE LWS_EXTERN int
lejp_parse(struct lejp_ctx *ctx, const unsigned char *json, int len);

LWS_VISIBLE LWS_EXTERN void
lejp_change_callback(struct lejp_ctx *ctx,
		     signed char (*callback)(struct lejp_ctx *ctx, char reason));

/*
 * push the current paths / paths_count and lejp_cb to a stack in the ctx, and
 * start using the new ones
 */
LWS_VISIBLE LWS_EXTERN int
lejp_parser_push(struct lejp_ctx *ctx, void *user, const char * const *paths,
		 unsigned char paths_count, lejp_callback lejp_cb);

/*
 * pop the previously used paths / paths_count and lejp_cb, and continue
 * parsing using those as before
 */
LWS_VISIBLE LWS_EXTERN int
lejp_parser_pop(struct lejp_ctx *ctx);

/* exported for use when reevaluating a path for use with a subcontext */
LWS_VISIBLE LWS_EXTERN void
lejp_check_path_match(struct lejp_ctx *ctx);

LWS_VISIBLE LWS_EXTERN int
lejp_get_wildcard(struct lejp_ctx *ctx, int wildcard, char *dest, int len);

LWS_VISIBLE LWS_EXTERN const char *
lejp_error_to_string(int e);
//@}
