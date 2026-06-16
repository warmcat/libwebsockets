/*
 * test-sni-mismatch.c
 *
 * Test Sni (Server Name Indication) scenarios with OpenHITLS
 *
 * Test stages:
 *   Stage 0: Client SNI="sni.com", Server vhost="nosni.com" -> Success, use default cert
 *   Stage 1: Client sni="sni.com", Server vhost "sni.com" with sni cert -> success, use sni.com cert
 *   Stage 2: Client sni="sni.com", Server vhost "sni.com" with default cert -> success, use default cert
 *   Stage 3: Client sni="sni.com", Server no Sni vhost -> success, use default cert
 *
 * Each stage uses a separate context to avoid OpenHitLS certificate caching issues.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad, completed;
static struct lws_context *context;
static struct lws *client_wsi;

static int test_stage;
static int connection_success;
static char received_cert_cn[128];

static const char *expected_cert_cn[] = {
	"localhost",  /* Stage 0: Sni mismatch, default cert */
	"sni.com",    /* Stage 1: sni match, sni.com cert */
	"localhost",  /* Stage 2: sni match with default cert */
	"localhost"   /* Stage 3: no sni vhost, default cert */
};

static int test_ports[] = {
	7781,  /* Stage 0 */
	7782,  /* Stage 1 */
    7783,  /* Stage 2 */
    7784   /* Stage 3 */
};
static const struct lws_protocols protocols[];

struct pss_sni_server {
    int established;
};

static int
callback_sni_server(struct lws *wsi, enum lws_callback_reasons reason,
            void *user, void *in, size_t len)
{
    struct pss_sni_server *pss = (struct pss_sni_server *)user;
    switch (reason) {
    case LWS_CALLBACK_ESTABLISHED:
        memset(pss, 0, sizeof(*pss));
        pss->established = 1;
        break;
    case LWS_CALLBACK_RECEIVE:
        break;
    default:
        break;
    }
    return 0;
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
              void *user, void *in, size_t len)
{
    union lws_tls_cert_info_results ir;
    int n;
    switch (reason) {
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
                 in ? (char *)in : "(null)");
        bad = 1;
        completed = 1;
        break;
    case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
        lwsl_user("Stage %d: HTTP connection established\n", test_stage);
        connection_success++;
        
        /* Get server certificate CN */
        n = lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME,
                       &ir, sizeof(ir.ns.name));
        if (n == 0 && ir.ns.name[0]) {
            strncpy(received_cert_cn, ir.ns.name, sizeof(received_cert_cn) - 1);
            received_cert_cn[sizeof(received_cert_cn) - 1] = '\0';
            lwsl_user("Stage %d: Received certificate CN: %s\n",
                      test_stage, received_cert_cn);
            lwsl_user("Stage %d: Expected certificate CN: %s\n",
                      test_stage, expected_cert_cn[test_stage]);
            
            if (strcmp(received_cert_cn, expected_cert_cn[test_stage]) == 0) {
                lwsl_user("Stage %d: ✓ Certificate matches expected\n", test_stage);
            } else {
                lwsl_err("Stage %d: ✗ Certificate MISMATCH! Got '%s', expected '%s'\n",
                     test_stage, received_cert_cn, expected_cert_cn[test_stage]);
                bad = 1;
            }
        } else {
            lwsl_err("Stage %d: Failed to get server certificate CN\n", test_stage);
            bad = 1;
        }
        
        client_wsi = NULL;
        completed = 1;
        break;
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
        return 0;
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
        {
            uint8_t rbuf[LWS_PRE + 512];
            n = sizeof(rbuf) - LWS_PRE;
            if (lws_http_client_read(wsi, (char **)&rbuf[LWS_PRE], &n) < 0)
                return -1;
        }
        return 0;
    case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
        if (!client_wsi)
            break;
        client_wsi = NULL;
        break;
    default:
        break;
    }
    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
    { "http", callback_http, 0, 0, 0, NULL, 0 },
    { "lws-sni-test", callback_sni_server,
      sizeof(struct pss_sni_server), 512, 0, NULL, 0 },
    LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
    interrupted = 1;
}

static struct lws_vhost *
create_vhost_with_sni(struct lws_context *ctx, int port, const char *vhost_name,
                      const char *cert_path, const char *key_path)
{
    struct lws_context_creation_info vhost_info;
    struct lws_vhost *vh;
    
    memset(&vhost_info, 0, sizeof(vhost_info));
    vhost_info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    vhost_info.protocols = protocols;
    vhost_info.port = port;
    vhost_info.vhost_name = vhost_name;
    
    if (cert_path && key_path) {
        vhost_info.ssl_cert_filepath = cert_path;
        vhost_info.ssl_private_key_filepath = key_path;
    }
    
    vh = lws_create_vhost(ctx, &vhost_info);
    if (!vh) {
        lwsl_err("Failed to create vhost '%s' on port %d\n", vhost_name, port);
        return NULL;
    }
    
    lwsl_user("Created vhost '%s' on port %d (cert: %s)\n",
          vhost_name, port, cert_path ? cert_path : "none");
    
    return vh;
}

static struct lws_context *
create_context_for_stage(int stage)
{
    struct lws_context_creation_info info;
    struct lws_vhost *vh;
    
    memset(&info, 0, sizeof(info));
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.protocols = protocols;
    info.port = CONTEXT_PORT_NO_LISTEN;
    
    context = lws_create_context(&info);
    if (!context) {
        lwsl_err("Failed to create context\n");
        return NULL;
    }
    
    switch (stage) {
        case 0:
            /* Stage 0: vhost="nosni.com" with default cert */
            lwsl_user("Stage 0: Creating vhost 'nosni.com' with default cert\n");
            vh = create_vhost_with_sni(context, test_ports[0], "nosni.com",
                              "certs/default.pem", "certs/default.key");
            break;
        case 1:
            /* Stage 1: vhost="sni.com" with sni.com cert */
            lwsl_user("Stage 1: Creating vhost 'sni.com' with sni.com cert\n");
            vh = create_vhost_with_sni(context, test_ports[1], "sni.com",
                              "certs/sni.pem", "certs/sni.key");
            break;
        case 2:
            /* Stage 2: vhost="sni.com" with default cert */
            lwsl_user("Stage 2: Creating vhost 'sni.com' with default cert\n");
            vh = create_vhost_with_sni(context, test_ports[2], "sni.com",
                              "certs/default.pem", "certs/default.key");
            break;
        case 3:
            /* Stage 3: no SNI vhost at all, only default vhost */
            lwsl_user("Stage 3: Creating default vhost 'localhost' (no SNI vhost)\n");
            vh = create_vhost_with_sni(context, test_ports[3], "localhost",
                              "certs/default.pem", "certs/default.key");
            break;
    }
    
    if (!vh) {
        lwsl_err("Stage %d: Failed to create vhost\n", stage);
        lws_context_destroy(context);
        return NULL;
    }
    
    return context;
}

static int
connect_to_stage(int stage)
{
    struct lws_client_connect_info i;
    
    memset(&i, 0, sizeof(i));
    i.context = context;
    i.port = test_ports[stage];
    i.address = "localhost";
    i.ssl_connection = LCCSCF_USE_SSL |
                   LCCSCF_ALLOW_SELFSIGNED |
                   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    i.host = "sni.com";  /* Client always sends SNI="sni.com" */
    i.origin = i.address;
    i.path = "/";
    i.method = "GET";
    i.protocol = protocols[0].name;
    i.pwsi = &client_wsi;
    i.alpn = "h1";
    
    lwsl_user("Stage %d: Client connecting with SNI='sni.com' to port %d\n",
              stage, i.port);
    
    if (!lws_client_connect_via_info(&i)) {
        lwsl_err("Stage %d: Connection failed\n", stage);
        return -1;
    }
    
    return 0;
}

int main(int argc, const char **argv)
{
    int n = 0;
    int stage;

    signal(SIGINT, sigint_handler);

    lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
    lwsl_user("LWS SNI Test - 4 Scenarios\n\n");

    /* Test all 4 stages */
    for (stage = 0; stage < 4 && !bad && !interrupted; stage++) {
        test_stage = stage;
        completed = 0;
        client_wsi = NULL;
        
        lwsl_user("========================================\n");
        lwsl_user("  Starting Stage %d\n", stage);
        lwsl_user("========================================\n");
        
        /* Create context for this stage */
        context = create_context_for_stage(stage);
        if (!context) {
            lwsl_err("Stage %d: Failed to create context\n", stage);
            bad = 1;
            break;
        }
        
        /* Connect to server */
        if (connect_to_stage(stage) < 0) {
            lwsl_err("Stage %d: Failed to start connection\n", stage);
            lws_context_destroy(context);
            bad = 1;
            break;
        }
        
        /* Service the connection */
        while (n >= 0 && !completed && !interrupted) {
            n = lws_service(context, 0);
        }
        
        lwsl_user("Stage %d: Completed\n\n", stage);

        /*
         * OpenHiTLS currently traps in context teardown when a client
         * and embedded TLS server share the same context.  The test
         * verdict is known when the loop exits, so allow process exit
         * to reclaim it.
         */
    }

    lwsl_user("========================================\n");
    lwsl_user("TEST RESULTS SUMMARY\n");
    lwsl_user("========================================\n");
    lwsl_user("Test completed: %s\n", bad ? "FAILED" : "SUCCESS");
    lwsl_user("Stages tested: %d\n", test_stage + 1);
    lwsl_user("Connections succeeded: %d\n", connection_success);
    lwsl_user("========================================\n");

    return bad;
}
