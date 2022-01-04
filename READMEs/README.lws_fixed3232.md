# lws_fixed3232 Fixed point arithmetic

Lws provides reasonably fast fixed-point 32:32 arithmetic functions so code
can be designed to work without floating-point support.

The underlying type is

```
typedef struct lws_fixed3232 {
        int32_t         whole;  /* signed 32-bit int */
        uint32_t        frac;   /* proportion from 0 to (100M - 1) */
} lws_fixed3232_t;
```

## Fractional representation

The fractional part counts parts per 100M and is restricted to the range
0 .. 99999999.  For convenience a constant `LWS_F3232_FRACTION_MSD` is
defined with the value 100M.

It's possible to declare constants naturally, but leading zeroes are not
valid on the fractional part, since C parses a leading 0 as indicating
the number is octal.

Eg to declare 12.5 and 6.0

```
	static const lws_fixed3232_t x[2] = { { 12,50000000 }, { 6,0 } };
```

## API style

The APIs are given the storage for the result along with the const args.
The result pointer is also returned from the operation to make operation
chaining more natural.

## Available operations

```
const lws_fixed3232_t *
lws_fixed3232_add(lws_fixed3232_t *r, const lws_fixed3232_t *a, const lws_fixed3232_t *b);

const lws_fixed3232_t *
lws_fixed3232_sub(lws_fixed3232_t *r, const lws_fixed3232_t *a, const lws_fixed3232_t *b);

const lws_fixed3232_t *
lws_fixed3232_mul(lws_fixed3232_t *r, const lws_fixed3232_t *a, const lws_fixed3232_t *b);

const lws_fixed3232_t *
lws_fixed3232_div(lws_fixed3232_t *r, const lws_fixed3232_t *a, const lws_fixed3232_t *b);

const lws_fixed3232_t *
lws_fixed3232_sqrt(lws_fixed3232_t *r, const lws_fixed3232_t *a);

int /* -1 if a < b, 1 if a > b, 0 if exactly equal */
lws_fixed3232_comp(const lws_fixed3232_t *a, const lws_fixed3232_t *b);

int /* return whole, or whole + 1 if frac is nonzero */
lws_fixed3232_roundup(const lws_fixed3232_t *a);
```

div and sqrt operations are iterative, up to 64 loops.  Multiply is relatively cheap
since it devolves to four integer multiply-adds.  Add and Sub are trivially cheap.

