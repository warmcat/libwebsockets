# lws_fixed3232 Fixed point arithmetic

Lws provides reasonably fast fixed-point 32:32 arithmetic functions so code
can be designed to work without floating-point support.

The underlying type is

```
typedef struct lws_fixed3232 {
        int32_t         whole;  /* signed 32-bit int */
        int32_t         frac;   /* proportion from 0 to (100M - 1) */
} lws_fx_t;
```

Either or both of whole or frac may be negative, indicating that the
combined scalar is negative.  This is to deal with numbers less than
0 but greater than -1 not being able to use whole to indicating
signedness, since it's zero.  This scheme allows .whole to be used
as a signed `int32_t` naturally.

## Fractional representation

The fractional part counts parts per 100M and is restricted to the range
0 .. 99999999.  For convenience a constant `LWS_FX_FRACTION_MSD` is
defined with the value 100M.

It's possible to declare constants naturally, but leading zeroes are not
valid on the fractional part, since C parses a leading 0 as indicating
the number is octal.

For the case of negative values less than 1, the fractional part bears the
sign.

Eg to declare 12.5, 6.0, -6.0, 0.1 and -0.1

```
	static const lws_fx_t x[2] = { { 12,50000000 }, { 6,0 },
			{ -6, 0 }, { 0, 10000000 }, { 0, -10000000 } };
```

There are some helpers

|Helper|Function|
|---|---|
|`lws_neg(a)`|nonzero if a is negative in whole or fractional part|
|`lws_fx_set(a,w,f)`|Convenience to set `lws_fx_t` a in code, notices if w is negative and also marks f the same|

## API style

The APIs are given the storage for the result along with the const args.
The result pointer is also returned from the operation to make operation
chaining more natural.

## Available operations

```
const lws_fx_t *
lws_fx_add(lws_fx_t *r, const lws_fx_t *a, const lws_fx_t *b);

const lws_fx_t *
lws_fx_sub(lws_fx_t *r, const lws_fx_t *a, const lws_fx_t *b);

const lws_fx_t *
lws_fx_mul(lws_fx_t *r, const lws_fx_t *a, const lws_fx_t *b);

const lws_fx_t *
lws_fx_div(lws_fx_t *r, const lws_fx_t *a, const lws_fx_t *b);

const lws_fx_t *
lws_fx_sqrt(lws_fx_t *r, const lws_fx_t *a);

int /* -1 if a < b, 1 if a > b, 0 if exactly equal */
lws_fx_comp(const lws_fx_t *a, const lws_fx_t *b);

int /* return whole, or whole + 1 if frac is nonzero */
lws_fx_roundup(const lws_fx_t *a);

int /* return whole */
lws_fx_rounddown(const lws_fx_t *a);

const char * /* format an lws_fx_t into a buffer */
lws_fx_string(const lws_fx_t *a, char *buf, size_t size
```

div and sqrt operations are iterative, up to 64 loops.  Multiply is relatively cheap
since it devolves to four integer multiply-adds.  Add and Sub are trivially cheap.

## Trigonometric operations

Angles and results are radians, represented as `lws_fx_t` using the same
API style.

```
const lws_fx_t *
lws_fx_sin(lws_fx_t *r, const lws_fx_t *a);

const lws_fx_t *
lws_fx_cos(lws_fx_t *r, const lws_fx_t *a);

const lws_fx_t *
lws_fx_tan(lws_fx_t *r, const lws_fx_t *a);

const lws_fx_t * /* atan2(y, x), result in [-pi, pi] */
lws_fx_atan2(lws_fx_t *r, const lws_fx_t *y, const lws_fx_t *x);
```

These are implemented in pure int64 arithmetic like the rest of the
operators, so there is no libm dependency, they are usable on targets with
no FPU, and the results are identical on every platform.

sin and cos use an odd polynomial in x^2 evaluated by nested Horner after
integer range reduction and quadrant reflection; accuracy is a few
fractional units (around 1e-8) for arguments of modest size, degrading
slowly for very large angle magnitudes because the range reduction is
integer.  atan2 normalizes its argument ratio into the first octant, then
applies the pi/4 addition identity above tan(pi/8) or an odd Taylor
otherwise; it is accurate to around 2e-7 radians over its whole output
range, copes with extreme magnitude differences between the components,
and maps the undefined (0, 0) case to 0.  tan is formed from sin and cos;
near its poles at odd multiples of pi/2 the result is clamped to the
largest representable `lws_fx_t` magnitude rather than overflowing.

The trigonometric operations cost a few dozen integer operations each,
with no loops.

Some useful angle constants:

|Angle|`lws_fx_t`|
|---|---|
|pi / 4|`{ 0, 78539816 }`|
|pi / 2|`{ 1, 57079633 }`|
|pi|`{ 3, 14159265 }`|
|2 pi|`{ 6, 28318531 }`|

Eg to get the unit vector components of a 37.5 degree angle

```
	lws_fx_t ang = { 0, 65449847 }, s, c;

	lws_fx_sin(&s, &ang);
	lws_fx_cos(&c, &ang);
```

The operators are validated against host libm references (quadrants,
antisymmetry, extreme magnitude ratios and a sin^2 + cos^2 sweep) by
`lws-api-test-fx`.

