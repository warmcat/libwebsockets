/*
 * If you are including the plugin into your code using static build, you
 * can simplify it by just including this file, which will include all the
 * related code in one step without you having to get involved in the detail.
 *
 * The includer must have included <libwebsockets.h> first, and the build
 * must provide the ffmpeg dev libraries the plugin needs.
 */

#define LWS_PLUGIN_STATIC

#include "../protocol_lws_hls.c"
#include "../hls-av.c"
#include "../hls-dir.c"
#include "../hls-sub.c"
