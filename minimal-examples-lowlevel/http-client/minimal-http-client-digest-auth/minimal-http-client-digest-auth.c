/*
 * lws-minimal-http-client
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the a minimal http client using lws.
 *
 * It visits https://warmcat.com/ and receives the html page there.  You
 * can dump the page data by changing the #if 0 below.
 */

#include <libwebsockets.h>
#include <openssl/rand.h>
#include <openssl/md5.h>

#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
static int interrupted, bad = 1, status;
int last_try = 0;

static struct lws *client_wsi;
struct lws_client_connect_info i;
char *www_authenticate_buffer = NULL;
int auth_type = 0;
char path[512] ;

static const char *ba_user, *ba_password;


static const char *ua = "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/51.0.2704.103 Safari/537.36",
          *acc = "*/*";

#define SESSION_ALGO 1 /* for algos with this bit set */

#define ALGO_MD5 0
#define ALGO_MD5SESS (ALGO_MD5 | SESSION_ALGO)
#define ALGO_SHA256 2
#define ALGO_SHA256SESS (ALGO_SHA256 | SESSION_ALGO)
#define ALGO_SHA512_256 4
#define ALGO_SHA512_256SESS (ALGO_SHA512_256 | SESSION_ALGO)
#define DIGEST_MAX_VALUE_LENGTH           256
#define DIGEST_MAX_CONTENT_LENGTH         1024
#define DIGEST_QOP_VALUE_STRING_AUTH      "auth"
#define DIGEST_QOP_VALUE_STRING_AUTH_INT  "auth-int"
#define DIGEST_QOP_VALUE_STRING_AUTH_CONF "auth-conf"
#define ISBLANK(x)  (((x) == ' ') || ((x) == '\t'))

/* Struct used for Digest challenge-response authentication from libcurl*/
struct digestdata {
  char *nonce;
  char *cnonce;
  char *realm;
  char *opaque;
  char *qop;
  char *algorithm;
  char *domain;
  int nc; /* nonce count */
  unsigned char algo;
  bool stale; /* set true for re-negotiation */
};


void digest_cleanup(struct digestdata *digest)
{
  if(digest->nonce){
    free(digest->nonce);
    digest->nonce = NULL;
  }
  if(digest->cnonce){
    free(digest->cnonce);
    digest->cnonce = NULL;
  }
  if(digest->realm){
    free(digest->realm);
    digest->realm = NULL;
  }
  if(digest->opaque){
    free(digest->opaque);
    digest->opaque = NULL;
  }
  if(digest->qop){
    free(digest->qop);
    digest->qop = NULL;
  }
  if(digest->algorithm){
    free(digest->algorithm);
    digest->algorithm = NULL;
  }
  if(digest->domain){
    free(digest->domain);
    digest->domain = NULL;
  }
  digest->nc = 0;
  digest->algo = ALGO_MD5; /* default algorithm */
  digest->stale = false; /* default means normal, not stale */
}


int auth_decode_digest_http_message(const char *chlg,
                                              struct digestdata *digest)
{
  char *sentence_start= NULL;
  char *sentence_end= NULL;
  size_t sentence_len = 0;
  size_t sentence_offset = 0;

  if(chlg == NULL){
    goto end_error;
  }
  if(digest == NULL){
    goto end_error;
  }
  sentence_start = (char*)chlg;
  while(1){

    if(0 == strncmp(sentence_start,"realm=\"",strlen("realm=\""))){
      /**
       * Realm parsing
       */
      sentence_offset = strlen("realm=\"");
      sentence_start += sentence_offset;
      sentence_end = strstr(sentence_start,"\"");
      if(sentence_end == NULL){
        goto end_cleanup;
      }

      sentence_len = (size_t)(sentence_end-sentence_start);
      digest->realm = malloc(sizeof(char) *sentence_len +1);
      if(NULL == digest->realm)
      {
        goto end_cleanup;
      }
      memset(digest->realm,0x0,sentence_len+1);
      strncpy(digest->realm,sentence_start,sentence_len);
      sentence_end++;
      if(sentence_end[0] != ','){
        break;
      }else{
        sentence_end +=2;
        sentence_start = sentence_end;
        continue;
      }
    }


    if(0 == strncmp(sentence_start,"nonce=\"",strlen("nonce=\""))){
      /**
       * nonce parsing
       */
      sentence_offset = strlen("nonce=\"");

      sentence_start += sentence_offset;
      sentence_end = strstr(sentence_start,"\"");
      if(sentence_end == NULL){
        goto end_cleanup;
      }

      sentence_len = (size_t)(sentence_end-sentence_start);
      digest->nonce = malloc(sizeof(char) *sentence_len +1);
      if(NULL == digest->nonce)
      {
        goto end_cleanup;
      }
      memset(digest->nonce,0x0,sentence_len+1);
      strncpy(digest->nonce,sentence_start,sentence_len);
      sentence_end++;
      if(sentence_end[0] != ','){
        break;
      }else{
        sentence_end +=2;
        sentence_start = sentence_end;
        continue;
      }
    }
    if(0 == strncmp(sentence_start,"algorithm=",strlen("algorithm="))){
          /**
           * Algorithm parsing
           */
          sentence_offset = strlen("algorithm=");
          sentence_start += sentence_offset;
          if(strncasecmp(sentence_start, "MD5-sess", 8) == 0)
            digest->algo = ALGO_MD5SESS;
          else if(strncasecmp(sentence_start, "MD5", 3) == 0)
            digest->algo = ALGO_MD5;
          else if(strncasecmp(sentence_start, "SHA-256", 7) == 0)
            digest->algo = ALGO_SHA256;
          else if(strncasecmp(sentence_start, "SHA-256-SESS", 12) == 0)
            digest->algo = ALGO_SHA256SESS;
          else if(strncasecmp(sentence_start, "SHA-512-256", 11) == 0)
            digest->algo = ALGO_SHA512_256;
          else if(strncasecmp(sentence_start, "SHA-512-256-SESS", 16) == 0)
            digest->algo = ALGO_SHA512_256SESS;
          else
            goto end_cleanup;
          sentence_end = strstr(sentence_start,", ");
          if(sentence_end != NULL){
            sentence_len = (size_t)(sentence_end-sentence_start);
            digest->algorithm = malloc(sizeof(char) *sentence_len +1);
            if(NULL == digest->algorithm)
            {
              goto end_cleanup;
            }
            memset(digest->algorithm,0x0,sentence_len+1);
            strncpy(digest->algorithm,sentence_start,sentence_len);
            sentence_end +=2;
            sentence_start = sentence_end;
            continue;
          }else{
            digest->algorithm = malloc(sizeof(char) *strlen(sentence_start)+1);
            if(NULL == digest->algorithm)
            {
              goto end_cleanup;
            }
            memset(digest->algorithm,0x0,sentence_len+1);
            strncpy(digest->algorithm,sentence_start,strlen(sentence_start));
            break;
          }
    }
    if(0 == strncmp(sentence_start,"domain=\"",strlen("domain=\""))){
      /**
       * Domain parsing
       */
      sentence_offset = strlen("domain=\"");
      sentence_start += sentence_offset;
      sentence_end = strstr(sentence_start,"\"");
      if(sentence_end == NULL){
        goto end_cleanup;
      }

      sentence_len = (size_t)(sentence_end-sentence_start);
      digest->domain = malloc(sizeof(char) *sentence_len +1);
      if(NULL == digest->domain)
      {
        goto end_cleanup;
      }
      memset(digest->domain,0x0,sentence_len+1);
      strncpy(digest->domain,sentence_start,sentence_len);
      sentence_end++;
      if(sentence_end[0] != ','){
        break;
      }else{
        sentence_end +=2;
        sentence_start = sentence_end;
        continue;
      }
    }
    if(0 == strncmp(sentence_start,"qop=\"",strlen("qop=\""))){
      /**
       * qop parsing
       */
      sentence_offset = strlen("qop=\"");
      sentence_start += sentence_offset;
      sentence_end = strstr(sentence_start,"\"");
      if(sentence_end == NULL){
        goto end_cleanup;
      }

      sentence_len = (size_t)(sentence_end-sentence_start);
      digest->qop = malloc(sizeof(char) *sentence_len +1);
      if(NULL == digest->realm)
      {
        goto end_cleanup;
      }
      memset(digest->qop,0x0,sentence_len+1);
      strncpy(digest->qop,sentence_start,sentence_len);
      sentence_end++;
      if(sentence_end[0] != ','){
        break;
      }else{
        sentence_end +=2;
        sentence_start = sentence_end;
        continue;
      }
    }
    break;
  }

  return 0;
end_cleanup:
  digest_cleanup(digest);
end_error:
  return -1;
}

int md5_hash(uint8_t *output, uint8_t* input, size_t len){
  MD5_CTX ctx;
  int result =MD5_Init(&ctx);
  if(result) {
    MD5_Update(&ctx, input, len);
    MD5_Final(output, &ctx);
  }
  return result;
}


/* Convert md5 chunk to RFC2617 (section 3.1.3) -suitable ascii string */
static void convert_to_ascii(unsigned char *source, /* 16 bytes */
                                     unsigned char *dest) /* 33 bytes */
{
  int i;

  for(i = 0; i < 16; i++){
    snprintf((char *) &dest[i * 2], 3, "%02x", source[i]);
  }
}
/* Perform quoted-string escaping as described in RFC2616 and its errata */
static char *auth_digest_string_quoted(const char *source)
{
  char *dest;
  const char *s = source;
  size_t n = 1; /* null terminator */

  /* Calculate size needed */
  while(*s) {
    ++n;
    if(*s == '"' || *s == '\\') {
      ++n;
    }
    ++s;
  }

  dest = malloc(n);
  if(dest) {
    char *d = dest;
    s = source;
    while(*s) {
      if(*s == '"' || *s == '\\') {
        *d++ = '\\';
      }
      *d++ = *s++;
    }
    *d = '\0';
  }

  return dest;
}

int output_digest(struct lws *wsi, char *http_req,  char *uri, char *user, char *password, char *challenge,
    char **outptr, size_t *outlen
    )
{

  unsigned char hashbuf[32]; /* 32 bytes/256 bits */
  unsigned char request_digest[65];
  unsigned char ha1[65];    /* 64 digits and 1 zero byte */
  unsigned char ha2[65];    /* 64 digits and 1 zero byte */
  char cnonce[65];
  char *userp_quoted;
  char *realm_quoted;
  char *nonce_quoted;
  char *response = NULL;
  char *hashthis = NULL;
  char *tmp = NULL;
  struct digestdata digest;

  char *ch = challenge;
  char cnoncebuf[33] = {0x0};

  ch += strlen("Digest ");

  memset(&digest,0x0,sizeof(struct digestdata));

  if(auth_decode_digest_http_message(ch, &digest) != 0){
    lwsl_user("Digest decode error\r\n");
    return -1;
  }

  if(digest.algo != ALGO_MD5){
    lwsl_user("Unhandled algo\r\n");
    return -1;
  }
  digest.nc = 1;
  memset(hashbuf,0x0,32);
  memset(cnonce,0x0,sizeof(cnonce));
  memset(cnoncebuf,0x0,33);
  lws_get_random(lws_get_context(wsi), cnoncebuf, sizeof(cnoncebuf));
  lws_b64_encode_string(cnoncebuf, sizeof(cnoncebuf), cnonce, sizeof(cnonce));
  digest.cnonce = malloc(sizeof(char)*sizeof(cnonce));
  if(NULL == digest.cnonce){
    return -1;
  }
  memcpy(digest.cnonce,cnonce,sizeof(cnonce));

  hashthis = malloc(sizeof(char) * (strlen(user) + strlen(password) + strlen(digest.realm) +3)  );
  if(!hashthis)
    return -1;
  sprintf(hashthis,"%s:%s:%s", user, digest.realm ? digest.realm : "",
      password);

  md5_hash(hashbuf, (uint8_t *)hashthis, strlen(hashthis));
  free(hashthis);
  convert_to_ascii(hashbuf, ha1);


  /*
    If the "qop" directive's value is "auth" or is unspecified, then A2 is:

      A2 = Method ":" digest-uri-value

    If the "qop" value is "auth-int", then A2 is:

      A2 = Method ":" digest-uri-value ":" H(entity-body)

    (The "Method" value is the HTTP request method as specified in section
    5.1.1 of RFC 2616)
  */
  hashthis = malloc(sizeof(char) * (strlen(http_req) + strlen(uri) +2)  );
  sprintf(hashthis,"%s:%s", http_req, uri);
  if(!hashthis)
    return -1;

  if(digest.qop && strcasecmp(digest.qop, "auth-int") == 0) {
    /* We don't support auth-int for PUT or POST */
    char hashed[65];
    char *hashthis2;

    md5_hash(hashbuf, (uint8_t*)"", 0);
    convert_to_ascii(hashbuf, (unsigned char *)hashed);
    hashthis2 = malloc(sizeof(char) * (strlen(hashthis) + strlen(hashed) +2)  );
    sprintf(hashthis2, "%s:%s", hashthis, hashed);
    free(hashthis);
    hashthis = hashthis2;
  }

  if(!hashthis)
    return -1;

  md5_hash(hashbuf, (unsigned char *) hashthis, strlen(hashthis));
  free(hashthis);
  convert_to_ascii(hashbuf, ha2);

  if(digest.qop) {
    hashthis = malloc(sizeof(char) * (strlen((char *)ha1) + 1 +
                                      strlen(digest.nonce) + 1 +
                                      8 + 1 +
                                      strlen(digest.cnonce) + 1 +
                                      strlen(digest.qop) + 1) +
                                      strlen((char *)ha2) + 1);
    sprintf(hashthis,"%s:%s:%08x:%s:%s:%s", ha1, digest.nonce, digest.nc,
                       digest.cnonce, digest.qop, ha2);
  }
  else {
    hashthis = malloc(sizeof(char) * (strlen((char *)ha1) + 1 +
                                      strlen(digest.nonce) + 1 +
                                      strlen((char *)ha2) + 1));
    sprintf(hashthis,"%s:%s:%s", ha1, digest.nonce, ha2);
  }

  if(!hashthis)
    return -1;

  md5_hash(hashbuf, (unsigned char *) hashthis, strlen(hashthis));
  free(hashthis);
  convert_to_ascii(hashbuf, request_digest);

  userp_quoted = auth_digest_string_quoted(user);
  if(!userp_quoted)
    return -1;
  if(digest.realm)
    realm_quoted = auth_digest_string_quoted(digest.realm);
  else {
    realm_quoted = malloc(1);
    if(realm_quoted)
      realm_quoted[0] = 0;
  }
  if(!realm_quoted) {
    free(userp_quoted);
    return -1;
  }
  nonce_quoted = auth_digest_string_quoted(digest.nonce);
  if(!nonce_quoted) {
    free(realm_quoted);
    free(userp_quoted);
    return -1;
  }

  if(digest.qop) {
    response = malloc(sizeof(char) * (strlen(userp_quoted) + 1 +
                                      strlen(realm_quoted) + 1 +
                                      strlen(nonce_quoted) + 1 +
                                      strlen(uri) + 1 +
                                      strlen(digest.cnonce) + 1 +
                                      8 + 1 +
                                      strlen(digest.qop) + 1 +
                                      strlen((char *)request_digest) + 1 +
                                      256));
    sprintf(response, "Digest username=\"%s\", "
                       "realm=\"%s\", "
                       "nonce=\"%s\", "
                       "uri=\"%s\", "
                       "cnonce=\"%s\", "
                       "nc=%08x, "
                       "qop=%s, "
                       "response=\"%s\"",
                       userp_quoted,
                       realm_quoted,
                       nonce_quoted,
                       uri,
                       digest.cnonce,
                       digest.nc,
                       digest.qop,
                       request_digest);

    /* Increment nonce-count to use another nc value for the next request */
    digest.nc++;
  }
  else {
    response = malloc(sizeof(char) * (strlen(userp_quoted) + 1 +
                                      strlen(realm_quoted) + 1 +
                                      strlen(nonce_quoted) + 1 +
                                      strlen(uri) + 1 +
                                      strlen((char *)request_digest) + 1 +
                                      128));
    sprintf(response,"Digest username=\"%s\", "
                       "realm=\"%s\", "
                       "nonce=\"%s\", "
                       "uri=\"%s\", "
                       "response=\"%s\"",
                       userp_quoted,
                       realm_quoted,
                       nonce_quoted,
                       uri,
                       request_digest);
  }
  free(nonce_quoted);
  free(realm_quoted);
  free(userp_quoted);
  if(!response)
    return -1;

  /* Add the optional fields */
  if(digest.opaque) {
    char *opaque_quoted;
    /* Append the opaque */
    opaque_quoted = auth_digest_string_quoted(digest.opaque);
    if(!opaque_quoted) {
      free(response);
      return -1;
    }
    tmp = malloc(sizeof(char)*strlen(response)+strlen(opaque_quoted)+16);
    sprintf(tmp,"%s, opaque=\"%s\"", response, opaque_quoted);
    free(response);
    free(opaque_quoted);
    if(!tmp)
      return -1;

    response = tmp;
  }

  if(digest.algorithm) {
    /* Append the algorithm */
    tmp = malloc(sizeof(char)*strlen(response)+strlen(digest.algorithm)+16);
    sprintf(tmp,"%s, algorithm=%s", response, digest.algorithm);
    free(response);
    if(!tmp)
      return -1;

    response = tmp;
  }


  /* Return the output */
  *outptr = response;
  *outlen = strlen(response);
  digest_cleanup(&digest);
  return 0;

}

static void
lws_try_client_connection(struct lws_client_connect_info *ii)
{

    ii->pwsi = &client_wsi;
    i.ssl_connection |= LCCSCF_PIPELINE;
    if (!lws_client_connect_via_info(ii)) {
        lwsl_user("%s: failed: conn\n", __func__);
    } else
        lwsl_user("started connection %s:\r\n",
              lws_wsi_tag(client_wsi));
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
          void *user, void *in, size_t len)
{

    switch (reason) {

    /* because we are protocols[0] ... */
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
             in ? (char *)in : "(null)");
        interrupted = 1;
        bad = 3; /* connection failed before we could make connection */
        lws_cancel_service(lws_get_context(wsi));

        break;

    case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
        {
            char buf[128];

            lws_get_peer_simple(wsi, buf, sizeof(buf));
            status = (int)lws_http_client_http_response(wsi);
            lwsl_user("Connected to %s, http response: %d\n",
                    buf, status);

          if(status == 401 && lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE) > 0){
              www_authenticate_buffer = malloc((size_t) lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE) +1);
              memset(www_authenticate_buffer,0x0,(size_t)lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE) +1);
              lws_hdr_copy(wsi,www_authenticate_buffer,1024,WSI_TOKEN_HTTP_WWW_AUTHENTICATE);
              if(strncmp(www_authenticate_buffer,"Digest",5) == 0){
                auth_type = 2;
              }else if(strncmp(www_authenticate_buffer,"Basic",5) == 0){
                auth_type = 1;
              }
          }
        }
        break;
        /* you only need this if you need to do Basic Auth or Digest auth*/
        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
        {
            unsigned char **p = (unsigned char **)in, *end = (*p) + len;

            if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_USER_AGENT,
                    (unsigned char *)ua, (int)strlen(ua), p, end))
                return -1;

            if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_ACCEPT,
                    (unsigned char *)acc, (int)strlen(acc), p, end))
                return -1;
            if(www_authenticate_buffer != NULL && auth_type == 2){

                lwsl_user("< WWW-Authenticate: %s\r\n",www_authenticate_buffer);
                char *output = NULL;
                size_t output_size = 0;

                output_digest(wsi,"GET", path, (char *)ba_user, (char *)ba_password, www_authenticate_buffer, &output,&output_size);
                lwsl_user("> Authorization: %s\r\n",output);
                if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_AUTHORIZATION,
                          (unsigned char *)output, (int)output_size, p, end))
                      return -1;

              }

            break;
    }

    /* chunks of chunked content, with header removed */
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
        lwsl_user("RECEIVE_CLIENT_HTTP_READ: read %d\n", (int)len);
        if(in != NULL){
          lwsl_user("%s\r\n",(char*)in);
        }

        return 0; /* don't passthru */

    /* uninterpreted http content */
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
        {
            char buffer[1024 + LWS_PRE];
            char *px = buffer + LWS_PRE;
            int lenx = sizeof(buffer) - LWS_PRE;

            if (lws_fi_user_wsi_fi(wsi, "user_reject_at_rx"))
                return -1;

            if (lws_http_client_read(wsi, &px, &lenx) < 0)
                return -1;
        }
        return 0; /* don't passthru */

    case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
        lwsl_user("LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n");
        if(last_try == 0){
          last_try = 1;
          lws_try_client_connection(&i);
        }

        break;
    case LWS_CALLBACK_CLIENT_RECEIVE:
      lwsl_user("receive %lu\r\n",len);
      lwsl_user("receive %s \r\n",(char *)in);
      break;
    case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
        interrupted = 1;
        bad = status != 200;
        lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
        break;
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        break;

    default:
        break;
    }

    return 0;//lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
    {
        "http",
        callback_http,
        0, 0, 0, NULL, 0
    },
    LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
    interrupted = 1;
}

struct args {
    int argc;
    const char **argv;
};

static int
system_notify_cb(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
           int current, int target)
{
    struct lws_context *context = mgr->parent;
    struct args *a = lws_context_user(context);
    const char *p;

    if (current != LWS_SYSTATE_OPERATIONAL || target != LWS_SYSTATE_OPERATIONAL)
        return 0;

    lwsl_info("%s: operational\n", __func__);

    memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */
    i.context = context;
    if (!lws_cmdline_option(a->argc, a->argv, "-n")) {
        i.ssl_connection = LCCSCF_USE_SSL;


    }


    i.port = 80;
    i.address = "localhost";


    i.ssl_connection = 0;

    i.ssl_connection |= LCCSCF_H2_QUIRK_OVERFLOWS_TXCR |
                LCCSCF_ACCEPT_TLS_DOWNGRADE_REDIRECTS |
                LCCSCF_H2_QUIRK_NGHTTP2_END_STREAM;

    i.alpn = "h2,http/1.1";

    if ((p = lws_cmdline_option(a->argc, a->argv, "-p")))
        i.port = atoi(p);

    if ((p = lws_cmdline_option(a->argc, a->argv, "--user")))
        ba_user = p;
    if ((p = lws_cmdline_option(a->argc, a->argv, "--password")))
        ba_password = p;

    i.ssl_connection |= LCCSCF_PIPELINE;
    /* the default validity check is 5m / 5m10s... -v = 3s / 10s */


    if ((p = lws_cmdline_option(a->argc, a->argv, "--server")))
        i.address = p;

    if ((p = lws_cmdline_option(a->argc, a->argv, "--path")))
        i.path = p;
    else
        i.path = "/";

    strcpy(path,p);
    i.host = i.address;
    i.origin = i.address;
    i.method = "GET";

    i.protocol = protocols[0].name;
    i.fi_wsi_name = "user";

    lws_try_client_connection(&i);

    return 0;
}

int main(int argc, const char **argv)
{
    lws_state_notify_link_t notifier = { { NULL, NULL, NULL },
                         system_notify_cb, "app" };
    lws_state_notify_link_t *na[] = { &notifier, NULL };
    struct lws_context_creation_info info;
    struct lws_context *context;
    int n = 0, expected = 0;
    struct args args;
    const char *p;

    args.argc = argc;
    args.argv = argv;

    signal(SIGINT, sigint_handler);

    memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
    lws_cmdline_option_handle_builtin(argc, argv, &info);

    lwsl_user("LWS minimal http client auth digest [-d<verbosity>]\n");

    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
    info.protocols = protocols;
    info.user = &args;
    info.register_notifier_list = na;
    info.connect_timeout_secs = 30;


    /*
     * since we know this lws context is only ever going to be used with
     * one client wsis / fds / sockets at a time, let lws know it doesn't
     * have to use the default allocations for fd tables up to ulimit -n.
     * It will just allocate for 1 internal and 1 (+ 1 http2 nwsi) that we
     * will use.
     */
    info.fd_limit_per_thread = 1 + 1 + 1;


    context = lws_create_context(&info);
    if (!context) {
        lwsl_err("lws init failed\n");
        bad = 5;
        goto bail;
    }

    while (n >= 0 && !interrupted){
        n = lws_service(context, 0);
    }

    if(www_authenticate_buffer){
      free(www_authenticate_buffer);
    }
    lws_context_destroy(context);

bail:
    if ((p = lws_cmdline_option(argc, argv, "--expected-exit")))
        expected = atoi(p);

    if (bad == expected) {
        lwsl_user("Completed: OK (seen expected %d)\n", expected);
        return 0;
    } else
        lwsl_err("Completed: failed: exit %d, expected %d\n", bad, expected);

    return 1;
}
