# Secure Streams

## Default Secure Streams policy

Similar to how low-level lws provides a default protocol
suitable for the common case of http processing that is
available is no explicit user protocol is provided, SS
provides a simple default policy that is suitable for
https connections that are trusted by the system trust
store.

This typically requires:

 1) Openssl, which is wired up to a trust store
 2) Http GET type connections on :443

If you need anything more complicated, you will have to
provide your own policy JSON in place of the default one.

The default policy defines a streamtype "__default" that
allows overriding `${endpoint}` with metadata.  What you
put here may be just the endpoint address like `mysite.com`,
or it can be a url like `https://mysite.com:1234/path`,
the elements given here control the stream address, port and
url path.

