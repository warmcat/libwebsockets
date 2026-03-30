# Filtering the Build for Plugins and Minimal Examples

When integrating libwebsockets into constrained environments (like Yocto embedded builds), you may want to strictly control which plugins and minimal examples get built without having to manually patch the library's `CMakeLists.txt` files.

You can explicitly allow or deny specific items using CMake Regular Expressions via the following configuration variables:

* `LWS_WITH_MINIMAL_FILTER_YES`
* `LWS_WITH_MINIMAL_FILTER_NO`
* `LWS_WITH_PLUGIN_FILTER_YES`
* `LWS_WITH_PLUGIN_FILTER_NO`

These variables accept a **comma-separated list** of CMake regular expressions.

## Default Behavior

If none of these filter variables are provided to CMake, libwebsockets will refer to `LWS_WITH_MINIMAL_EXAMPLES` and `LWS_WITH_PLUGINS` to decide whether to build all plugins and minimal examples that satisfy their respective library dependencies, exactly as it traditionally does.

If you enable the `LWS_WITH_MINIMAL_EXAMPLES` or `LWS_WITH_PLUGINS` options, you can either just build all of the examples or plugins, or choose to also use the filter variables to control exactly which items are built.

## How the Filters are Evaluated

1. **NO filters** are evaluated first. If `LWS_WITH_*_FILTER_NO` is provided, and the target matches any regex in the NO list, it will be skipped from the build.
2. **YES filters** are evaluated next. If `LWS_WITH_*_FILTER_YES` is provided, the target *must* match at least one regex in the YES list in order to be built. If it does not match, it will be skipped.
3. If a target is not matched by either rule, it is built as normal.

## Examples

### 1. Build only specific plugins

Suppose you only want to compile `protocol_lws_rtc_camera` and `protocol_lws_webrtc`. You can pass exact string matches (since standard strings are valid regex):

```bash
cmake .. -DLWS_WITH_PLUGIN_FILTER_YES="protocol_lws_rtc_camera,protocol_lws_webrtc"
```

*Note: The plugin name matched is the literal string name inside its `create_plugin(...)` call, e.g., `protocol_lws_webrtc`, without any `lib` prefix or `.so` suffix.*

### 2. Include a broad category, but exclude a specific target

To tell CMake to build all examples matching a prefix (like `minimal-raw-`) but explicitly reject a specific one (`minimal-raw-proxy-fallback`), you can provide both YES and NO lists. Since NO is evaluated first, it overrides YES:

```bash
cmake .. -DLWS_WITH_MINIMAL_FILTER_YES="^minimal-raw-.*" \
         -DLWS_WITH_MINIMAL_FILTER_NO="minimal-raw-proxy-fallback"
```

### 3. Exclude a specific prefix

If you want to build all examples except the ones beginning with `minimal-http-server`:

```bash
cmake .. -DLWS_WITH_MINIMAL_FILTER_NO="^minimal-http-server.*"
```
