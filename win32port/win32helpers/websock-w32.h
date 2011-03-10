#ifndef __WEB_SOCK_W32_H__
#define __WEB_SOCK_W32_H__

// Windows uses _DEBUG and NDEBUG
#ifdef _DEBUG
#undef DEBUG
#define DEBUG 1
#endif

#pragma warning(disable : 4996)

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

#define MSG_NOSIGNAL 0
#define SHUT_RDWR SD_BOTH

#define SOL_TCP IPPROTO_TCP

#define random rand
#define usleep _sleep
#define poll WSAPoll

/* override configure because we are not using Makefiles */

#define LWS_NO_FORK
#define DATADIR "."

#endif
