
#if 0
#ifdef WIN32
static
#else
static inline
#endif
void muxdebug(const char *format, ...)
{
	va_list ap;
	va_start(ap, format); vfprintf(stderr, format, ap); va_end(ap);
}
#else
#ifdef WIN32
static
#else
static inline
#endif
void muxdebug(const char *format, ...)
{
}
#endif

#define MAX_XGM_SUBCHANNELS 8192

enum lws_ext_x_google_mux__parser_states {
	LWS_EXT_XGM_STATE__MUX_BLOCK_1,
	LWS_EXT_XGM_STATE__MUX_BLOCK_2,
	LWS_EXT_XGM_STATE__MUX_BLOCK_3,
	LWS_EXT_XGM_STATE__ADDCHANNEL_LEN,
	LWS_EXT_XGM_STATE__ADDCHANNEL_LEN16_1,
	LWS_EXT_XGM_STATE__ADDCHANNEL_LEN16_2,
	LWS_EXT_XGM_STATE__ADDCHANNEL_LEN32_1,
	LWS_EXT_XGM_STATE__ADDCHANNEL_LEN32_2,
	LWS_EXT_XGM_STATE__ADDCHANNEL_LEN32_3,
	LWS_EXT_XGM_STATE__ADDCHANNEL_LEN32_4,
	LWS_EXT_XGM_STATE__ADDCHANNEL_HEADERS,
	LWS_EXT_XGM_STATE__FLOWCONTROL_1,
	LWS_EXT_XGM_STATE__FLOWCONTROL_2,
	LWS_EXT_XGM_STATE__FLOWCONTROL_3,
	LWS_EXT_XGM_STATE__FLOWCONTROL_4,
	LWS_EXT_XGM_STATE__DATA,
};

enum lws_ext_x_goole_mux__mux_opcodes {
	LWS_EXT_XGM_OPC__DATA,
	LWS_EXT_XGM_OPC__ADDCHANNEL,
	LWS_EXT_XGM_OPC__DROPCHANNEL,
	LWS_EXT_XGM_OPC__FLOWCONTROL,
	LWS_EXT_XGM_OPC__RESERVED_4,
	LWS_EXT_XGM_OPC__RESERVED_5,
	LWS_EXT_XGM_OPC__RESERVED_6,
	LWS_EXT_XGM_OPC__RESERVED_7,
};

/* one of these per context (server or client) */

struct lws_ext_x_google_mux_context {
	/*
	 * these are listing physical connections, not children sharing a
	 * parent mux physical connection
	 */
	struct libwebsocket *wsi_muxconns[MAX_CLIENTS];
	/*
	 * when this is < 2, we do not do any mux blocks
	 * just pure websockets
	 */
	int active_conns;
};

/* one of these per connection (server or client) */

struct lws_ext_x_google_mux_conn {
	enum lws_ext_x_goole_mux__mux_opcodes block_subopcode;
	int block_subchannel;
	unsigned int length;
	enum lws_ext_x_google_mux__parser_states state;
	/* child points to the mux wsi using this */
	struct libwebsocket *wsi_parent;
	int subchannel;
	struct libwebsocket *wsi_children[MAX_CLIENTS];
	int highest_child_subchannel;
	char awaiting_POLLOUT;
	int count_children_needing_POLLOUT;
	int sticky_mux_used;
	int defeat_mux_opcode_wrapping;
	int original_ch1_closed;
	int ignore_cmd;
};

extern int
lws_extension_callback_x_google_mux(struct libwebsocket_context *context,
			struct libwebsocket_extension *ext,
			struct libwebsocket *wsi,
			enum libwebsocket_extension_callback_reasons reason,
					      void *user, void *in, size_t len);
