
/*
 * Since we're using JIT Trust, we don't need explict CA trust for this.
 */

static const char * const ss_policy =
	"{"
	  "\"release\":"			"\"01234567\","
	  "\"product\":"			"\"myproduct\","
	  "\"schema-version\":"			"1,"

	  "\"retry\": ["	/* named backoff / retry strategies */
		"{\"default\": {"
			"\"backoff\": ["	 "1000,"
						 "2000,"
						 "3000,"
						 "5000,"
						"10000"
				"],"
			"\"conceal\":"		"25,"
			"\"jitterpc\":"		"20,"
			"\"svalidping\":"	"30,"
			"\"svalidhup\":"	"35"
		"}}"
	  "],"
	  "\"s\": ["

		"{\"__default\": {"
			"\"endpoint\":"		"\"${endpoint}\","
			"\"port\":"		"443,"
			"\"protocol\":"		"\"h2\","
			"\"http_method\":"	"\"GET\","
			"\"http_url\":"		"\"\","
			"\"metadata\": [{\n"
				"\"endpoint\":"      "\"\",\n"
				"\"acc\":"      "\"accept\",\n"
				"\"ua\":"	"\"user-agent\"\n"
			"}],\n"
			"\"tls\":"		"true,"
			"\"allow_redirects\": true,\n"
			"\"nghttp2_quirk_end_stream\": true,\n"
			"\"h2q_oflow_txcr\": true,\n"
			"\"opportunistic\":"	"true,"
			"\"retry\":"		"\"default\""

			"}},{\"ota\": {"
				"\"endpoint\":"		"\"libwebsockets.org\","
				"\"port\":"		"443,"
				"\"protocol\":"		"\"h2\","
				"\"http_method\":"	"\"GET\","
				"\"http_url\":"		"\"firmware/examples/${ota_variant}/${file}\","
				"\"metadata\": [{\n"
					"\"ota_variant\":"	"\"\",\n"
					"\"file\":"		"\"\"\n"
				"}],\n"
				"\"tls\":"		"true,"
				"\"allow_redirects\": true,\n"
				"\"nghttp2_quirk_end_stream\": true,\n"
				"\"h2q_oflow_txcr\":"	"true,\n"
				"\"opportunistic\":"	"true,"
				"\"retry\":"		"\"default\""
	
			"}},{"
			/*
			 * "captive_portal_detect" describes
			 * what to do in order to check if the path to
			 * the Internet is being interrupted by a
			 * captive portal.
			 */
		    "\"captive_portal_detect\": {"
                        "\"endpoint\":"		"\"connectivitycheck.android.com\","
			"\"http_url\":"		"\"generate_204\","
			"\"port\":"		"80,"
                        "\"protocol\":"		"\"h1\","
                        "\"http_method\":"	"\"GET\","
                        "\"opportunistic\":"	"true,"
                        "\"http_expect\":"	"204,"
			"\"http_fail_redirect\": true"
                "}}"
	"]}"
;


