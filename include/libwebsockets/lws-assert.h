#if !defined(__LWS_ASSERT_H__)
#define __LWS_ASSERT_H__




typedef void (*lws_assert_cb)(const char *file, int line, const char *expression);
void lws_set_assert_cb(lws_assert_cb cb);

#ifdef  LWS_ENABLE_CUSTOM_ASSERT
void lws_assert(const char *file, int line, const char *expression);
#   ifdef assert
#       undef assert
#   endif
#define assert(expression) (void)((expression) || (lws_assert(__FILE__, __LINE__, #expression), 0))
#endif




#endif