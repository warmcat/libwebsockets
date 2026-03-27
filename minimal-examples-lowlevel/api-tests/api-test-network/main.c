#include <libwebsockets.h>
#include <string.h>

int main(void)
{
	int e = 0;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);

	lwsl_user("LWS network api tests\n");

	if (!lws_is_lan_address("10.1.2.3")) { lwsl_err("10.x failed\n"); e++; }
	if (!lws_is_lan_address("192.168.1.5")) { lwsl_err("192.168.x failed\n"); e++; }
	if (!lws_is_lan_address("172.16.0.1")) { lwsl_err("172.16.x failed\n"); e++; }
	if (lws_is_lan_address("8.8.8.8")) { lwsl_err("8.8.8.8 failed\n"); e++; }

	if (!lws_is_local_address("127.0.0.1") && !lws_is_local_address("::1")) {
		lwsl_err("local address check failed\n");
		e++;
	}

	lwsl_user("Completed: %d fails\n", e);

	return e;
}
