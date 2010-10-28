
#define LWS_MAX_HEADER_NAME_LENGTH 64
#define LWS_MAX_HEADER_LEN 4096
#define LWS_INITIAL_HDR_ALLOC 256
#define LWS_ADDITIONAL_HDR_ALLOC 64


enum lws_connection_states {
	WSI_STATE_CLOSED,
	WSI_STATE_HANDSHAKE_RX,
	WSI_STATE_ISSUE_HANDSHAKE,
	WSI_STATE_DEAD_SOCKET,
	WSI_STATE_ESTABLISHED
};

enum lws_token_indexes {
	WSI_TOKEN_GET_URI,
	WSI_TOKEN_HOST,
	WSI_TOKEN_CONNECTION,
	WSI_TOKEN_KEY1,
	WSI_TOKEN_KEY2,
	WSI_TOKEN_PROTOCOL,
	WSI_TOKEN_UPGRADE,
	WSI_TOKEN_ORIGIN,
	WSI_TOKEN_CHALLENGE,
	
	/* always last real token index*/
	WSI_TOKEN_COUNT,
	/* parser state additions */
	WSI_TOKEN_NAME_PART,
	WSI_TOKEN_SKIPPING,
	WSI_TOKEN_SKIPPING_SAW_CR,
	WSI_PARSING_COMPLETE
};


struct lws_tokens {
	char * token;
	int token_len;
};

struct libwebsocket {
	
	/* set these up before calling libwebsocket_init */
	
	int (*websocket_established_callback)(struct libwebsocket *);
	int (*websocket_closed_callback)(struct libwebsocket *);
	int (*websocket_send_callback)(struct libwebsocket *);
	int (*websocket_receive_callback)(struct libwebsocket *);
	
	/* these are all opaque and maintained by the library */
	
	enum lws_connection_states state;

	char name_buffer[LWS_MAX_HEADER_NAME_LENGTH];
	int name_buffer_pos;
	int current_alloc_len;
	enum lws_token_indexes parser_state;
	struct lws_tokens utf8_token[WSI_TOKEN_COUNT];
	char * response;
	int response_length;
	
	int sock;
};


extern int libwebsocket_init(struct libwebsocket *wsi, int port);

