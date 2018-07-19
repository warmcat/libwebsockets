## hproxy

Unidirectional proxy plugin

Lws protocol name "lws-hproxy".

## Proxy upstream

The proxy upstream base URL (eg, https://myserver.com/mydir) is set using
a per-vhost option "remote-base".

An api is provided using the plugin lws_protocols "user" pointer.  Other code
on the same vhost, or that has a pointer to the vhost of the lws-hproxy
instantiation wanted, can get this api pointer cleanly like this:

```
typedef int (*mention_t)(const struct lws_protocols *pcol, struct lws_vhost *vh,
			 const char *path);

int
call_hcache_api_func(struct lws_vhost *vh)
{
	struct lws_protocols *hcache = lws_vhost_name_to_protocol(vh, "lws-hproxy");

	if (!hcache)
		return 1;

	return ((mention_t)hcache->user)(hcache, vh, path);
}
```

## Cache location

The cache location is set by a per-vhost option "cache-dir".

## Downstream serving

The cache dir should simply be made available as a mount, using whatever
caching policy is suitable.


## Configuration example for lwsws

The pvos

```
        "lws-hproxy": {
                "status": "ok",
                "remote-base": "https://www.gravatar.com/avatar/",
                "cache-dir": "/var/cache/libjsongit2"
        }
```

The downstream cache dir mount

```
	{
		"mountpoint": "/avatar",
		"origin": "file:///var/cache/libjsongit2",
		"cache-max-age": "60",
		"cache-reuse": "1",
		"cache-revalidate": "1",
		"cache-intermediaries": "0",
		"extra-mimetypes": {
			".zip": "application/zip"
		}
	}
```

