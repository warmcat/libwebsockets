#include <stdio.h>
#  include "local.h"
#define LONG_MACRO(a, b) \
	((a) + (b)) /* spliced */
# if defined(X) && !defined(Y)
#error "unterminated
#endif
static const char *s = "esc \" \\ \n end";
static char c = '\'';
int a_very_long_identifier_name_that_exceeds_the_scratch_size_by_a_wide_margin_yes = 0x1p-3;
float f = 1.5e+10f, g = .5, h = 1'000'000;
/* block
 * comment ** with stars *** and a slash / inside
 */
// line comment with a splice \
   continued here
int main(void) { return a / 2 + f; } // trailing
/* unterminated at end
