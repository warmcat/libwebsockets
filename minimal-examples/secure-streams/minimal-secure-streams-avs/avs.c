/*
 * lws-minimal-secure-streams-avs
 *
 * Written in 2019-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This sends a canned WAV and received (and discards) the mp3 response.
 * However it rate-limits the response reception to manage a small ringbuffer
 * using ss / h2 flow control apis, reflecting consumption at 64kbps and only
 * and 8KB buffer, indtended to model optimizing rx buffering on mp3 playback
 * on a constrained device.
 */

#include <libwebsockets.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>

extern int interrupted, bad;
static struct lws_ss_handle *hss_avs_event, *hss_avs_sync;
static uint8_t *wav;
static size_t wav_len;

typedef struct ss_avs_event {
	struct lws_ss_handle 	*ss;
	void			*opaque_data;
	/* ... application specific state ... */
	struct lejp_ctx		jctx;
} ss_avs_event_t;

typedef struct ss_avs_metadata {
	struct lws_ss_handle 	*ss;
	void			*opaque_data;
	/* ... application specific state ... */
	struct lejp_ctx		jctx;
	size_t			pos;

	/*
	 * We simulate a ringbuffer that is used up by a sul at 64Kbit/sec
	 * rate, and managed at the same rate using tx credit
	 */

	lws_sorted_usec_list_t	sul;
	uint8_t			buf[8192];
	int			head;
	int			tail;

	char			filled;

} ss_avs_metadata_t;

static const char *metadata = "{"
	"\"event\": {"
		"\"header\": {"
			"\"namespace\": \"SpeechRecognizer\","
			"\"name\": \"Recognize\","
			"\"messageId\": \"message-123\","
			"\"dialogRequestId\": \"dialog-request-321\""
		"},"
		"\"payload\": {"
			"\"profile\":"	"\"CLOSE_TALK\","
			"\"format\":"	"\"AUDIO_L16_RATE_16000_CHANNELS_1\""
		"}"
	"}"
"}";

/*
 * avs metadata
 */

static void
use_buffer_50ms(lws_sorted_usec_list_t *sul)
{
	ss_avs_metadata_t *m = lws_container_of(sul, ss_avs_metadata_t, sul);
	struct lws_context *context = (struct lws_context *)m->opaque_data;
	size_t n;
	int e;

	/*
	 * Use up 50ms-worth (8KB / 20) == 401 bytes of buffered data
	 */

	/* remaining data in buffer */
	n = ((m->head - m->tail) % sizeof(m->buf));
	lwsl_info("%s: avail %d\n", __func__, (int)n);

	if (n < 401)
		lwsl_err("%s: underrun\n", __func__);

	m->tail = (m->tail + 401) % sizeof(m->buf);
	n = ((m->head - m->tail) % sizeof(m->buf));

	e = lws_ss_get_est_peer_tx_credit(m->ss);

	lwsl_info("%s: avail after: %d, curr est %d\n", __func__, (int)n, e);

	if (n < (sizeof(m->buf) * 2) / 3 && e < (int)(sizeof(m->buf) - 1 - n)) {
		lwsl_info("%s: requesting additional %d\n", __func__,
				(int)(sizeof(m->buf) - 1 - e - n));
		lws_ss_add_peer_tx_credit(m->ss, (sizeof(m->buf) - 1 - e - n));
	}

	lws_sul_schedule(context, 0, &m->sul, use_buffer_50ms,
			 50 * LWS_US_PER_MS);
}

static int
ss_avs_metadata_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	ss_avs_metadata_t *m = (ss_avs_metadata_t *)userobj;
	struct lws_context *context = (struct lws_context *)m->opaque_data;
	size_t n, n1;

	lwsl_notice("%s: rideshare %s, len %d, flags 0x%x\n", __func__,
			lws_ss_rideshare(m->ss), (int)len, flags);
	// lwsl_hexdump_warn(buf, len);

	n = sizeof(m->buf) - ((m->head - m->tail) % sizeof(m->buf));
	lwsl_info("%s: len %d, buf h %d, t %d, space %d\n", __func__,
		    (int)len, (int)m->head, (int)m->tail, (int)n);
	lws_ss_get_est_peer_tx_credit(m->ss);
	assert (len <= n);

	if (m->head < m->tail)				/* |****h-------t**| */
		memcpy(&m->buf[m->head], buf, len);
	else {						/* |---t*****h-----| */
		n1 = sizeof(m->buf) - m->head;
		if (len < n1)
			n1 = len;
		memcpy(&m->buf[m->head], buf, n1);
		if (n1 != len)
			memcpy(m->buf, buf, len - n1);
	}

	m->head = (m->head + len) % sizeof(m->buf);

	lws_sul_schedule(context, 0, &m->sul, use_buffer_50ms,
			 50 * LWS_US_PER_MS);

	return 0;
}

static int
ss_avs_metadata_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
		   size_t *len, int *flags)
{
	ss_avs_metadata_t *m = (ss_avs_metadata_t *)userobj;
	//struct lws_context *context = (struct lws_context *)m->opaque_data;
	size_t tot;

	if ((long)m->pos < 0) {
		*len = 0;
		lwsl_notice("%s: skip tx\n", __func__);
		return 1;
	}

	lwsl_notice("%s: rideshare '%s'\n", __func__, lws_ss_rideshare(m->ss));

	if (!strcmp(lws_ss_rideshare(m->ss), "avs_audio")) {
		/* audio rideshare */

		if (!m->pos)
			*flags |= LWSSS_FLAG_SOM;

		if (*len > wav_len - m->pos)
			*len = wav_len - m->pos;

		memcpy(buf, wav + m->pos, *len);
		m->pos += *len;

		if (m->pos == wav_len) {
			*flags |= LWSSS_FLAG_EOM;
			lwsl_info("%s: tx done\n", __func__);
			m->pos = (long)-1l; /* ban subsequent until new stream */
		} else
			lws_ss_request_tx(m->ss);

		lwsl_hexdump_info(buf, *len);

		return 0;
	}

	/* metadata part */

	tot = strlen(metadata);

	if (!m->pos)
		*flags |= LWSSS_FLAG_SOM;

	if (*len > tot - m->pos)
		*len = tot - m->pos;

	memcpy(buf, metadata + m->pos, *len);

	m->pos += *len;

	if (m->pos == tot) {
		*flags |= LWSSS_FLAG_EOM;
		m->pos = 0; /* for next time */
		lws_ss_request_tx(m->ss);
	}

	lwsl_hexdump_info(buf, *len);

	return 0;
}

static int
ss_avs_metadata_state(void *userobj, void *sh,
		      lws_ss_constate_t state, lws_ss_tx_ordinal_t ack)
{

	ss_avs_metadata_t *m = (ss_avs_metadata_t *)userobj;
	struct lws_context *context = (struct lws_context *)m->opaque_data;

	lwsl_user("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name(state),
		  (unsigned int)ack);

	switch (state) {
	case LWSSSCS_CREATING:
		lwsl_user("%s: CREATING\n", __func__);
		lws_ss_client_connect(m->ss);
		m->pos = 0;
		break;
	case LWSSSCS_CONNECTING:
		break;
	case LWSSSCS_CONNECTED:
		lws_ss_request_tx(m->ss);
		break;
	case LWSSSCS_ALL_RETRIES_FAILED:
		/* for this demo app, we want to exit on fail to connect */
	case LWSSSCS_DISCONNECTED:
		/* for this demo app, we want to exit after complete flow */
		lws_sul_schedule(context, 0, &m->sul, use_buffer_50ms,
				 LWS_SET_TIMER_USEC_CANCEL);
		interrupted = 1;
		break;
	case LWSSSCS_DESTROYING:
		lws_sul_schedule(context, 0, &m->sul, use_buffer_50ms,
				 LWS_SET_TIMER_USEC_CANCEL);
		break;
	default:
		break;
	}

	return 0;
}

/*
 * avs event
 */

static int
ss_avs_event_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	ss_avs_event_t *m = (ss_avs_event_t *)userobj;
	// struct lws_context *context = (struct lws_context *)m->opaque_data;

	lwsl_notice("%s: rideshare %s, len %d, flags 0x%x\n", __func__,
			lws_ss_rideshare(m->ss), (int)len, flags);

	//lwsl_hexdump_warn(buf, len);

	bad = 0; /* for this demo, receiving something here == success */

	return 0;
}

static int
ss_avs_event_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
		      size_t *len, int *flags)
{
	ss_avs_event_t *m = (ss_avs_event_t *)userobj;
	lwsl_notice("%s: rideshare %s\n", __func__, lws_ss_rideshare(m->ss));

	return 1; /* don't transmit anything */
}

static int
ss_avs_event_state(void *userobj, void *sh,
		   lws_ss_constate_t state, lws_ss_tx_ordinal_t ack)
{
	ss_avs_event_t *m = (ss_avs_event_t *)userobj;
	struct lws_context *context = (struct lws_context *)m->opaque_data;
	lws_ss_info_t ssi;

	lwsl_user("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name(state),
		  (unsigned int)ack);

	switch (state) {
	case LWSSSCS_CREATING:
	case LWSSSCS_CONNECTING:
		break;
	case LWSSSCS_CONNECTED:
		if (hss_avs_sync)
			break;

		lwsl_notice("%s: starting the second avs stream\n", __func__);

		/*
		 * When we have established the event stream, we must POST
		 * on another stream within 10s
		 */

		memset(&ssi, 0, sizeof(ssi));
		ssi.handle_offset	    = offsetof(ss_avs_metadata_t, ss);
		ssi.opaque_user_data_offset = offsetof(ss_avs_metadata_t,
						       opaque_data);
		ssi.rx			    = ss_avs_metadata_rx;
		ssi.tx			    = ss_avs_metadata_tx;
		ssi.state		    = ss_avs_metadata_state;
		ssi.user_alloc		    = sizeof(ss_avs_metadata_t);
		ssi.streamtype		    = "avs_metadata";

		/*
		 * We want to allow the other side to fill our buffer, but no
		 * more.  But it's a bit tricky when the payload is inside
		 * framing like multipart MIME and contains other parts
		 */

		ssi.manual_initial_tx_credit =
				sizeof(((ss_avs_metadata_t *)0)->buf) / 2;

		if (lws_ss_create(context, 0, &ssi, context, &hss_avs_sync,
				  NULL, NULL)) {
			lwsl_err("%s: failed to create avs metadata secstream\n",
				 __func__);
		}
		break;
	case LWSSSCS_ALL_RETRIES_FAILED:
		/* for this demo app, we want to exit on fail to connect */
		interrupted = 1;
		break;
	case LWSSSCS_DISCONNECTED:
		break;
	case LWSSSCS_DESTROYING:
		lwsl_notice("%s: DESTROYING\n", __func__);
		if (wav) {
			free(wav);
			wav = NULL;
		}
		break;
	default:
		break;
	}

	return 0;
}

int
avs_example_start(struct lws_context *context)
{
	lws_ss_info_t ssi;
	struct stat stat;
	int fd;

	if (hss_avs_event)
		return 0;

	fd = open("./year.wav", O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: failed to open wav file\n", __func__);

		return 1;
	}
	if (fstat(fd, &stat) < 0) {
		lwsl_err("%s: failed to stat wav file\n", __func__);

		goto bail;
	}

	wav_len = stat.st_size;
	wav = malloc(wav_len);
	if (!wav) {
		lwsl_err("%s: failed to alloc wav buffer", __func__);

		goto bail;
	}
	if (read(fd, wav, wav_len) != (int)wav_len) {
		lwsl_err("%s: failed to read wav\n", __func__);

		goto bail;
	}
	close(fd);

	lwsl_user("%s: Starting AVS stream\n", __func__);

	/* AVS wants us to establish the long poll event stream first */

	memset(&ssi, 0, sizeof(ssi));
	ssi.handle_offset	    = offsetof(ss_avs_event_t, ss);
	ssi.opaque_user_data_offset = offsetof(ss_avs_event_t, opaque_data);
	ssi.rx			    = ss_avs_event_rx;
	ssi.tx			    = ss_avs_event_tx;
	ssi.state		    = ss_avs_event_state;
	ssi.user_alloc		    = sizeof(ss_avs_event_t);
	ssi.streamtype		    = "avs_event";

	if (lws_ss_create(context, 0, &ssi, context, &hss_avs_event, NULL, NULL)) {
		lwsl_err("%s: failed to create avs event secure stream\n",
			 __func__);
		free(wav);
		wav = NULL;
		return 1;
	}

	return 0;

bail:
	close(fd);

	return 1;
}
