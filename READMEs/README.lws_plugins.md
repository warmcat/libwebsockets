# lws_plugins

Lws now offers apis to manage your own user plugins with `LWS_WITH_PLUGINS_API`.
Lws uses these apis internally for protocol plugins and event loop plugins
if they're selected for build.  But they are also exported for user code to
use them how you like.

## Creating your plugin export

### Specifying your plugin export type

Lws plugins have a single exported struct with a specified header and a user
defined remainder.  The public `lws_plugin_header_t` describes the common
plugin export header, it's defined via libwebsockets.h as

```
typedef struct lws_plugin_header {
	const char *name;
	const char *_class;

	unsigned int api_magic;
	/* set to LWS_PLUGIN_API_MAGIC at plugin build time */

	/* plugin-class specific superclass data follows */
} lws_plugin_header_t;
```

The exported symbol name itself must match the plugin filename, for
example if the symbol name is `my_plugin`, then the filename of the
plugin might be `libmyapp-my_plugin.so` or similar... the matching
part is after the first `-` or `_`, up to the first `.`.  The exact
details differ by platform but these rules cover the supported
platforms.  If lws has the filename of the plugin, it can then
deduce the symbol export it should look for in the plugin.

`name` is a freeform human-readable description for the plugin.

`_class` is shared by your plugins and used to select them from other kinds
of plugin that may be in the same dir.  So choose a unique name like
`"myapp xxx plugin"` or whatever shared by all plugins of that class.

`api_magic` is set to `LWS_PLUGIN_API_MAGIC` to detect if the plugin is
incompatible with the lws plugin apis version.

So for example your plugin type wrapping the header might look like

```
typedef struct myapp_plugin {
        lws_plugin_header_t	hdr; /* must be first */

	/* optional extra data like function pointers from your plugin */
	mytype_t		mymember;
	/* ... */
} myapp_plugin_t;
```

Typically, you will put function pointers to whatever capability your plugin
class offers as the additional members.

## Building your own plugins

Plugins are built standalone, cmake is recommended but you can do what you want.

The only requirement is the single visible export of the plugin name, eg

```
const myapp_plugin_t my_plugin = {
	.hdr = {
		"my_plugin",
		"myapp xxx plugin",
		LWS_PLUGIN_API_MAGIC
	},

	.mymember	= my_plugin_init,
	/*...*/
};
```

## Bringing in plugins at runtime

Lws provides an api to import plugins into the process space and another to
remove and destroy plugins.

You can take two approaches depending on what you're doing, either bring in and
later destroy a whole class of plugins at once, and walk them via a linked-list,
or bring in and later destroy a single specific plugin from the class by filtering
on its specific export name.

See `include/libwebsockets/lws-protocols-plugins.h` for documentation.

```
LWS_VISIBLE LWS_EXTERN int
lws_plugins_init(struct lws_plugin **pplugin, const char * const *d,
		 const char *_class, const char *filter,
		 each_plugin_cb_t each, void *each_user);

LWS_VISIBLE LWS_EXTERN int
lws_plugins_destroy(struct lws_plugin **pplugin, each_plugin_cb_t each,
		    void *each_user);
```

`struct lws_plugin` is a public struct that contains the linked-list of loaded
plugins and a pointer to its exported header object, so you can walk this
after loading.

## Protocol Plugin Best Practices

When writing a protocol plugin that utilizes `LWS_CALLBACK_PROTOCOL_INIT`, you must follow these requirements:

### 1. Ignore NULL `in` Parameters

During context creation or system initialization, `LWS_CALLBACK_PROTOCOL_INIT` may be called with a `NULL` `in` parameter (which normally carries the `lws_protocol_vhost_options`). Your plugin must safely ignore this and exit without error:

```c
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;
```

### 2. Contextual Warning for PVO Errors

When parsing `lws_protocol_vhost_options` (PVOs) during `PROTOCOL_INIT`, if an error occurs (such as a missing or invalid value), you should use `lws_vhost_warn(lws_get_vhost(wsi), ...)` or `lws_vhost_err(...)` instead of generic logging. This ensures the user can understand *which* vhost is misconfigured, especially in multi-vhost setups.

### 3. Stub Process Isolation

Generic stub processes (such as `--lws-stub=dnssec-priv`) inherit the user's config and will attempt to initialize all plugins. To prevent resource contention (like conflicting UDP port bindings or duplicated threads), plugins must explicitly opt-in or opt-out of running inside stubs.

If your plugin **should never run** inside a stub process (which is the case for most application and UI plugins), you must inject this snippet at the top of your `PROTOCOL_INIT` block:

```c
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;

		/* Do not initialize in generic stub processes */
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;
```

If your plugin **is explicitly designed to run** inside a specific stub (e.g. `dnssec-monitor` running inside `dnssec-priv`), you must modify the snippet to ensure it only initializes for *that specific* stub, and ignores any others:

```c
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;

		/* Only initialize if we are running as the dnssec-priv stub */
		const char *stub = lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub");
		if (stub && strcmp(stub, "dnssec-priv"))
			return 0;
```
