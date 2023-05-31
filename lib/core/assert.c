#include "private-lib-core.h"

#ifdef LWS_ENABLE_CUSTOM_ASSERT

typedef void (*lws_assert_cb)(const char *file, int line, const char *expression);
void lws_set_assert_cb(lws_assert_cb cb);
void lws_assert(const char *file, int line, const char *expression);
#define assert(expression) (void)((expression) || (lws_assert(__FILE__, __LINE__, #expression), 0))

#endif

static lws_assert_cb assert_cb = NULL;

void lws_set_assert_cb(lws_assert_cb cb) {
    assert_cb = cb;
}

void lws_assert(const char *file, int line, const char *expression) {
    if (assert_cb != NULL) {
        assert_cb(file, line, expression);
    } else {
        fprintf(stderr, "Assertion failed: %s, file %s, line %d\n", expression, file, line);
        abort();
    }
}
