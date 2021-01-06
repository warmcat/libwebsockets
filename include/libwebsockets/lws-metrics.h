 /*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
 * Public apis related to metric collection and reporting
 */

/* lws_metrics public part */

typedef uint64_t u_mt_t;

enum {
	LWSMTFL_REPORT_OUTLIERS				= (1 << 0),
	/**< track outliers and report them internally */
	LWSMTFL_REPORT_OOB				= (1 << 1),
	/**< report events as they happen */
	LWSMTFL_REPORT_INACTIVITY_AT_PERIODIC		= (1 << 2),
	/**< explicitly externally report no activity at periodic cb, by
	 * default no events in the period is just not reported */
	LWSMTFL_REPORT_MEAN				= (1 << 3),
	/**< average/min/max is meaningful, else only sum is meaningful */
	LWSMTFL_REPORT_ONLY_GO				= (1 << 4),
	/**< no-go pieces invalid */
	LWSMTFL_REPORT_DUTY_WALLCLOCK_US		= (1 << 5),
	/**< aggregate compares to wallclock us for duty cycle */
	LWSMTFL_REPORT_HIST				= (1 << 6),
	/**< our type is histogram (otherwise, sum / mean aggregation) */
};

/* histogram bucket */

typedef struct lws_metric_bucket {
	struct lws_metric_bucket	*next;
	uint64_t			count;

	/* name + NUL is overallocated */
} lws_metric_bucket_t;

/* get overallocated name of bucket from bucket pointer */
#define lws_metric_bucket_name_len(_b) (*((uint8_t *)&(_b)[1]))
#define lws_metric_bucket_name(_b) (((const char *)&(_b)[1]) + 1)

/*
 * These represent persistent local event measurements.  They may aggregate
 * a large number of events inbetween external dumping of summaries of the
 * period covered, in two different ways
 *
 * 1) aggregation by sum or mean, to absorb multiple scalar readings
 *
 *  - go / no-go ratio counting
 *  - mean averaging for, eg, latencies
 *  - min / max for averaged values
 *  - period the stats covers
 *
 * 2) aggregation by histogram, to absorb a range of outcomes that may occur
 *    multiple times
 *
 *  - add named buckets to histogram
 *  - bucket has a 64-bit count
 *  - bumping a bucket just increments the count if already exists, else adds
 *    a new one with count set to 1
 *
 * The same type with a union covers both cases.
 *
 * The lws_system ops api that hooks lws_metrics up to a metrics backend is
 * given a pointer to these according to the related policy, eg, hourly, or
 * every event passed straight through.
 */

typedef struct lws_metric_pub {
	const char		*name;
	/**< eg, "n.cn.dns", "vh.myendpoint" */
	void			*backend_opaque;
	/**< ignored by lws, backend handler completely owns it */

	lws_usec_t		us_first;
	/**< us time metric started collecting, reset to us_dumped at dump */
	lws_usec_t		us_last;
	/**< 0, or us time last event, reset to 0 at last dump */
	lws_usec_t		us_dumped;
	/**< 0 if never, else us time of last dump to external api */

	/* scope of data in .u is "since last dump" --> */

	union {
		/* aggregation, by sum or mean */

		struct {
			u_mt_t			sum[2];
			/**< go, no-go summed for mean or plan sum */
			u_mt_t			min;
			/**< smallest individual measurement */
			u_mt_t			max;
			/**< largest individual measurement */

			uint32_t		count[2];
			/**< go, no-go count of measurements in sum */
		} agg;

		/* histogram with dynamic named buckets */

		struct {
			lws_metric_bucket_t	*head;
			/**< first bucket in our bucket list */

			uint64_t		total_count;
			/**< total count in all of our buckets */
			uint32_t		list_size;
			/**< number of buckets in our bucket list */
		} hist;
	} u;

	uint8_t			flags;

} lws_metric_pub_t;

/*
 * Calipers are a helper struct for implementing "hanging latency" detection,
 * where setting the start time and finding the end time may happen in more than
 * one place.
 *
 * There are convenience wrappers to eliminate caliper definitions and code
 * cleanly if WITH_SYS_METRICS is disabled for the build.
 */

typedef struct lws_metric lws_metric_t;

typedef struct lws_metric_caliper {
	lws_metric_t		*mt; /**< NULL == inactive */
	lws_usec_t		us_start;
} lws_metric_caliper_t;

#if defined(LWS_WITH_SYS_METRICS)
#define lws_metrics_caliper_compose(_name) \
		lws_metric_caliper_t _name;
#define lws_metrics_caliper_bind(_name, _mt) \
	_name.mt = _mt; _name.us_start = lws_now_usecs()
#define lws_metrics_caliper_declare(_name, _mt) \
	lws_metric_caliper_t _name = { _mt, lws_now_usecs() }
#define lws_metrics_caliper_report(_name, _go_nogo) \
	if (_name.us_start) { lws_metric_event(_name.mt, _go_nogo, \
			   (u_mt_t)(lws_now_usecs() - \
					   _name.us_start)); \
			   _name.us_start = 0; }
#define lws_metrics_caliper_cancel(_name) { _name.us_start = 0; }
#define lws_metrics_hist_bump(_mt, _name) \
		lws_metrics_hist_bump_(_mt, _name)
#else
#define lws_metrics_caliper_compose(_name)
#define lws_metrics_caliper_bind(_name, _mt)
#define lws_metrics_caliper_declare(_name, _mp)
#define lws_metrics_caliper_report(_name, _go_nogo)
#define lws_metrics_caliper_cancel(_name)
#define lws_metrics_hist_bump(_mt, _name)
#endif

/**
 * lws_metrics_format() - helper to format a metrics object for logging
 *
 * \param pub: public part of metrics object
 * \param buf: output buffer to place string in
 * \param len: available length of \p buf
 *
 * Helper for describing the state of a metrics object as a human-readable
 * string, accounting for how its flags indicate what it contains.  This is not
 * how you would report metrics, but during development it can be useful to
 * log them inbetween possibily long report intervals.
 *
 * It uses the metric's flags to adapt the format shown appropriately, eg,
 * as a histogram if LWSMTFL_REPORT_HIST etc
 */
LWS_EXTERN LWS_VISIBLE int
lws_metrics_format(lws_metric_pub_t *pub, char *buf, size_t len);

/**
 * lws_metrics_hist_bump() - add or increment histogram bucket
 *
 * \param pub: public part of metrics object
 * \param name: bucket name to increment
 *
 * Either increment the count of an existing bucket of the right name in the
 * metrics object, or add a new bucket of the given name and set its count to 1.
 *
 * The metrics object must have been created with flag LWSMTFL_REPORT_HIST
 *
 * Normally, you will actually use the preprocessor wrapper
 * lws_metrics_hist_bump() defined above, since this automatically takes care of
 * removing itself from the build if WITH_SYS_METRICS is not defined, without
 * needing any preprocessor conditionals.
 */
LWS_EXTERN LWS_VISIBLE int
lws_metrics_hist_bump_(lws_metric_pub_t *pub, const char *name);

enum {
	LMT_NORMAL = 0,	/* related to successful events */
	LMT_OUTLIER,	/* related to successful events outside of bounds */

	LMT_FAIL,	/* related to failed events */

	LMT_COUNT,
};

typedef enum lws_metric_rpt {
	LMR_PERIODIC = 0,	/* we are reporting on a schedule */
	LMR_OUTLIER,		/* we are reporting the last outlier */
} lws_metric_rpt_kind_t;

#define METRES_GO	0
#define METRES_NOGO	1


