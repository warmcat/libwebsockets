#ifndef _LWS_VERSION_H_INCLUDED
#define _LWS_VERSION_H_INCLUDED

/* The Libwebsocket version */
#cmakedefine LWS_LIBRARY_VERSION "${LWS_LIBRARY_VERSION}"

/* The Libwebsocket version as an int, for easy comparison */
#cmakedefine LWS_LIBRARY_VERSION_NUMBER ${LWS_LIBRARY_VERSION_NUMBER}

/* The current git commit hash that we're building from */
#cmakedefine LWS_BUILD_HASH "${LWS_BUILD_HASH}"

#endif // _LWS_VERSION_H_INCLUDED
