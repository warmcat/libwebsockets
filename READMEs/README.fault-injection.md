# `lws_fi` Fault Injection

To provide better quality there's a need to not just test the code paths for
normal operation, but also that it acts correctly under various fault
conditions that may be difficult to arrange at test-time.

Code handling the failures may be anywhere including during early initialization
or in user code before lws intialization.

To help with this lws has `LWS_WITH_SYS_FAULT_INJECTION` build option that
provides a simple but powerful api for fault injection in any lws or user code.

## Fault contexts and faults

`lws_fi_t` objects represent a named fault injection rules, just in terms of
whether and how often to inject the fault.

`lws_fi_ctx_t` objects are linked-lists of `lws_fi_t` objects.  When Fault
Injection is enabled at build-time, the key system objects like the
`lws_context`, `lws_vhost`, `wsi` and Secure Stream handles / SSPC handles
contain their own `lws_fi_ctx_t` lists that may have any number of `lws_fi_t`
added to them.

`lws_fi_ctx_t` objects are hierarchical, if a named rule is not found in, eg,
a wsi Fault injection context, then the vhost and finally the lws_context Fault
Injection contexts are searched for it before giving up.  This allows for both
global and individual overridden Fault Injection rules at each level.

## Integrating fault injection conditionals into code

A simple api `lws_fi(fi_ctx, "name")` is provided that returns 0 if no fault to
be injected, or 1 if the fault should be synthesized.  If there is no rule
matching "name", the answer is always to not inject a fault, ie, returns 0.

By default then just enabling Fault Injection at build does not have any impact
on code operation since the user must first add the fault injection rules he
wants.

The api keeps track of each time the context was asked and uses this information
to drive the decision about when to say yes, according to the type of rule

|Injection rule type|Description|
|---|---|
|`LWSFI_ALWAYS`|Unconditionally inject the fault|
|`LWSFI_DETERMINISTIC`|after `pre` times without the fault, the next `count` times exhibit the fault`|
|`LWSFI_PROBABILISTIC`|exhibit a fault `pre` percentage of the time|
|`LWSFI_PATTERN`|Reference `pre` bits pointed to by `pattern` and fault if the bit set|

## Addings Fault Injection Rules to `lws_fi_ctx_t`

User code should prepare a `lws_fi_ctx_t` cleared down to zero if necessary,
and one of these, eg on the stack

```
typedef struct lws_fi {
	const char	*name;
	uint8_t		*pattern;
	uint64_t	pre__prob1;
	uint64_t	count__prob2;
	char		type;		/* LWSFI_* */
} lws_fi_t;
```

and call `lws_fi_add(lws_fi_ctx_t *fic, const lws_fi_t *fi);`, this will
allocate and copy the provided `fi` into the allocation, and attach it to
the `lws_fi_ctx_t` list.

The creation info struct associated with the context, vhost, wsi or Secure
Stream has a `*fi` pointer you can set to your `lws_fi_ctx_t`, when creating
the object it will take ownership of any `lws_fi_t` you attached to it.

So the `lws_fi_ctx_t` and the `lws_fi_t` used as a template for adding the
rules may be on the stack and  safely and go out of scope after the object
creation api is called.  The `lws_fi_t` `name` is also copied into the
allocation and does not need to continue to exist after it is added to the
`lws_fi_ctx_t`.  The only exception is the `pattern` member if used, the
array pointed to is not copied and must exist for the lifetime of the rule.

## Passing in fault injection rules

A key requirement is that Fault Injection rules must be availble to the code
creating an object before the object has been created.  This is why the user
code prepares a temporary context listing his rules, and offers it as part of
the creation info struct, rather than waiting for the object to be created and
then attach Fault Injection rules... it's too late to test faults during the
creation by then otherwise.

## Using the namespace to target specific instances

Wsi client connection can directly have fault injection objects attached to it
at client connection creation time.

