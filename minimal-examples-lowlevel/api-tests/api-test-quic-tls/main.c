#include <libwebsockets.h>
#include <string.h>

int main(int argc, const char **argv)
{
	
	int res;

	lwsl_user("api-test-quic-tls\n");

	res = lws_tls_quic_api_test();
	if (res) {
		lwsl_err("lws_tls_quic_api_test failed\n");
		return 1;
	}

	lwsl_user("Completed: PASS\n");
	return 0;
}
