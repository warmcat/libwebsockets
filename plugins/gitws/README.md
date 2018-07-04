## gitws plugin

This plugin allows you to use libjsongit2

https://warmcat.com/git/libjsongit2

to format and present a web view on bare git repos.

## Integration with lwsws

### Enabling the lws-gitws protocol

The plugin is integrated using a couple of per-
vhost options in the vhost's ws-protocols section

```
"ws-protocols": [{
...
    "lws-gitws": {
         "status": "ok",
         "html-file": "/usr/local/share/libjsongit2/jg2.html",
         "vpath": "/git",
         "repo-base-dir": "/srv/gitolite/repositories"
       },
...
```

pvo|Function
---|---
vpath|Virtual "mountpoint" for the plugin in the URL space
repo-base-dir|Directory containing the bare repos to present

### Adding the related mounts

You also need to apply two mounts on the vhost

```
    {
       "mountpoint": "/git",
       "origin": "callback://lws-gitws"
    }, {
       "mountpoint": "/jg2",
       "origin": "file:///usr/local/share/libjsongit2",
       "cache-max-age": "60",
       "cache-reuse": "1",
       "cache-revalidate": "1",
       "cache-intermediaries": "0",
       "extra-mimetypes": {
                ".zip": "application/zip",
                ".exe": "application/octet-stream",
                ".map": "application/json"
        }
    }
```

The first `/git` mount creates the virtual URL space mapping for the
plugin's HTML generation.

The second, which can have any mountpoint so long as the html template
matches it, is used to serve static files like the js and css from
libjsongit2.

