#include "private-lib-core.h"

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
