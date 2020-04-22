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

/** \defgroup log Logging
 *
 * ##Logging
 *
 * Lws provides flexible and filterable logging facilities, which can be
 * used inside lws and in user code.
 *
 * Log categories may be individually filtered bitwise, and directed to built-in
 * sinks for syslog-compatible logging, or a user-defined function.
 */
///@{

#define LLL_ERR		(1 << 0)
#define	LLL_WARN	(1 << 1)
#define	LLL_NOTICE	(1 << 2)
#define	LLL_INFO	(1 << 3)
#define	LLL_DEBUG	(1 << 4)
#define	LLL_PARSER	(1 << 5)
#define	LLL_HEADER	(1 << 6)
#define	LLL_EXT		(1 << 7)
#define	LLL_CLIENT	(1 << 8)
#define	LLL_LATENCY	(1 << 9)
#define	LLL_USER	(1 << 10)
#define	LLL_THREAD	(1 << 11)

#define	LLL_COUNT	(12) /* set to count of valid flags */

/**
 * lwsl_timestamp: generate logging timestamp string
 *
 * \param level:	logging level
 * \param p:		char * buffer to take timestamp
 * \param len:	length of p
 *
 * returns length written in p
 */
LWS_VISIBLE LWS_EXTERN int
lwsl_timestamp(int level, char *p, int len);

#if defined(LWS_PLAT_OPTEE) && !defined(LWS_WITH_NETWORK)
#define _lws_log(aaa, ...) SMSG(__VA_ARGS__)
#else
LWS_VISIBLE LWS_EXTERN void _lws_log(int filter, const char *format, ...) LWS_FORMAT(2);
LWS_VISIBLE LWS_EXTERN void _lws_logv(int filter, const char *format, va_list vl);
#endif

/*
 * Figure out which logs to build in or not
 */

#if defined(_DEBUG)
 /*
  * In DEBUG build, select all logs unless NO_LOGS
  */
 #if defined(LWS_WITH_NO_LOGS)
  #define _LWS_LINIT (LLL_ERR | LLL_USER)
 #else
   #define _LWS_LINIT ((1 << LLL_COUNT) - 1)
 #endif
#else /* not _DEBUG */
 #define _LWS_LINIT (LLL_ERR | LLL_USER | LLL_WARN | LLL_NOTICE)
#endif /* _DEBUG */

/*
 * Create either empty overrides or the ones forced at build-time.
 * These overrides have the final say... any bits set in
 * LWS_LOGGING_BITFIELD_SET force the build of those logs, any bits
 * set in LWS_LOGGING_BITFIELD_CLEAR disable the build of those logs.
 *
 * If not defined lws decides based on CMAKE_BUILD_TYPE=DEBUG or not
 */

#if defined(LWS_LOGGING_BITFIELD_SET)
 #define _LWS_LBS (LWS_LOGGING_BITFIELD_SET)
#else
 #define _LWS_LBS 0
#endif

#if defined(LWS_LOGGING_BITFIELD_CLEAR)
 #define _LWS_LBC (LWS_LOGGING_BITFIELD_CLEAR)
#else
 #define _LWS_LBC 0
#endif

/*
 * Compute the final active logging bitfield for build
 */
#define _LWS_ENABLED_LOGS (((_LWS_LINIT) | (_LWS_LBS)) & ~(_LWS_LBC))

/*
 * Individually enable or disable log levels for build
 * depending on what was computed
 */

#if (_LWS_ENABLED_LOGS & LLL_ERR)
#define lwsl_err(...) _lws_log(LLL_ERR, __VA_ARGS__)
#else
#define lwsl_err(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_WARN)
#define lwsl_warn(...) _lws_log(LLL_WARN, __VA_ARGS__)
#else
#define lwsl_warn(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
#define lwsl_notice(...) _lws_log(LLL_NOTICE, __VA_ARGS__)
#else
#define lwsl_notice(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_INFO)
#define lwsl_info(...) _lws_log(LLL_INFO, __VA_ARGS__)
#else
#define lwsl_info(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_DEBUG)
#define lwsl_debug(...) _lws_log(LLL_DEBUG, __VA_ARGS__)
#else
#define lwsl_debug(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_PARSER)
#define lwsl_parser(...) _lws_log(LLL_PARSER, __VA_ARGS__)
#else
#define lwsl_parser(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_HEADER)
#define lwsl_header(...) _lws_log(LLL_HEADER, __VA_ARGS__)
#else
#define lwsl_header(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_EXT)
#define lwsl_ext(...) _lws_log(LLL_EXT, __VA_ARGS__)
#else
#define lwsl_ext(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_CLIENT)
#define lwsl_client(...) _lws_log(LLL_CLIENT, __VA_ARGS__)
#else
#define lwsl_client(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_LATENCY)
#define lwsl_latency(...) _lws_log(LLL_LATENCY, __VA_ARGS__)
#else
#define lwsl_latency(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_THREAD)
#define lwsl_thread(...) _lws_log(LLL_THREAD, __VA_ARGS__)
#else
#define lwsl_thread(...) do {} while(0)
#endif

#if (_LWS_ENABLED_LOGS & LLL_USER)
#define lwsl_user(...) _lws_log(LLL_USER, __VA_ARGS__)
#else
#define lwsl_user(...) do {} while(0)
#endif


#define lwsl_hexdump_err(...) lwsl_hexdump_level(LLL_ERR, __VA_ARGS__)
#define lwsl_hexdump_warn(...) lwsl_hexdump_level(LLL_WARN, __VA_ARGS__)
#define lwsl_hexdump_notice(...) lwsl_hexdump_level(LLL_NOTICE, __VA_ARGS__)
#define lwsl_hexdump_info(...) lwsl_hexdump_level(LLL_INFO, __VA_ARGS__)
#define lwsl_hexdump_debug(...) lwsl_hexdump_level(LLL_DEBUG, __VA_ARGS__)

/**
 * lwsl_hexdump_level() - helper to hexdump a buffer at a selected debug level
 *
 * \param level: one of LLL_ constants
 * \param vbuf: buffer start to dump
 * \param len: length of buffer to dump
 *
 * If \p level is visible, does a nice hexdump -C style dump of \p vbuf for
 * \p len bytes.  This can be extremely convenient while debugging.
 */
LWS_VISIBLE LWS_EXTERN void
lwsl_hexdump_level(int level, const void *vbuf, size_t len);

/**
 * lwsl_hexdump() - helper to hexdump a buffer (DEBUG builds only)
 *
 * \param buf: buffer start to dump
 * \param len: length of buffer to dump
 *
 * Calls through to lwsl_hexdump_level(LLL_DEBUG, ... for compatability.
 * It's better to use lwsl_hexdump_level(level, ... directly so you can control
 * the visibility.
 */
LWS_VISIBLE LWS_EXTERN void
lwsl_hexdump(const void *buf, size_t len);

/**
 * lws_is_be() - returns nonzero if the platform is Big Endian
 */
static LWS_INLINE int lws_is_be(void) {
	const int probe = ~0xff;

	return *(const char *)&probe;
}

/**
 * lws_set_log_level() - Set the logging bitfield
 * \param level:	OR together the LLL_ debug contexts you want output from
 * \param log_emit_function:	NULL to leave it as it is, or a user-supplied
 *			function to perform log string emission instead of
 *			the default stderr one.
 *
 *	log level defaults to "err", "warn" and "notice" contexts enabled and
 *	emission on stderr.  If stderr is a tty (according to isatty()) then
 *	the output is coloured according to the log level using ANSI escapes.
 */
LWS_VISIBLE LWS_EXTERN void
lws_set_log_level(int level,
		  void (*log_emit_function)(int level, const char *line));

/**
 * lwsl_emit_syslog() - helper log emit function writes to system log
 *
 * \param level: one of LLL_ log level indexes
 * \param line: log string
 *
 * You use this by passing the function pointer to lws_set_log_level(), to set
 * it as the log emit function, it is not called directly.
 */
LWS_VISIBLE LWS_EXTERN void
lwsl_emit_syslog(int level, const char *line);

/**
 * lwsl_emit_stderr() - helper log emit function writes to stderr
 *
 * \param level: one of LLL_ log level indexes
 * \param line: log string
 *
 * You use this by passing the function pointer to lws_set_log_level(), to set
 * it as the log emit function, it is not called directly.
 *
 * It prepends a system timestamp like [2018/11/13 07:41:57:3989]
 *
 * If stderr is a tty, then ansi colour codes are added.
 */
LWS_VISIBLE LWS_EXTERN void
lwsl_emit_stderr(int level, const char *line);

/**
 * lwsl_emit_stderr_notimestamp() - helper log emit function writes to stderr
 *
 * \param level: one of LLL_ log level indexes
 * \param line: log string
 *
 * You use this by passing the function pointer to lws_set_log_level(), to set
 * it as the log emit function, it is not called directly.
 *
 * If stderr is a tty, then ansi colour codes are added.
 */
LWS_VISIBLE LWS_EXTERN void
lwsl_emit_stderr_notimestamp(int level, const char *line);

/**
 * lwsl_visible() - returns true if the log level should be printed
 *
 * \param level: one of LLL_ log level indexes
 *
 * This is useful if you have to do work to generate the log content, you
 * can skip the work if the log level used to print it is not actually
 * enabled at runtime.
 */
LWS_VISIBLE LWS_EXTERN int
lwsl_visible(int level);

///@}
