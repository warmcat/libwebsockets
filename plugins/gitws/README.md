## gitws plugin

This plugin allows you to use libjsongit2

https://warmcat.com/git/libjsongit2

to format and present a web view on bare git repos.

## Integration with lwsws

### Enabling the lws-gitws protocol

The plugin is integrated using three per-vhost options in the vhost's ws-protocols section

```
"ws-protocols": [{
...
    "lws-gitws": {
         "status": "ok",
         "html-file": "/usr/local/share/libjsongit2/jg2.html",
         "vpath": "/git",
         "acl-user": "v-myvhost",
         "repo-base-dir": "/srv/gitolite/repositories"
       },
...
```

pvo|Function
---|---
html-file|The template html file that will have JSON inserted into it
repo-base-dir|Directory containing the bare repos to present
vpath|Virtual "mountpoint" for the plugin in the URL space
acl-user|Gitolite user that controls access to the repos that can be shown for this vhost

libjsongit2 provides an example `jg2.html` template that can be
modified to suit your vhost's style.

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
                ".map": "application/json"
        }
    }
```

The first `/git` mount creates the virtual URL space mapping for the
plugin's HTML generation.

The second, which can have any mountpoint so long as the html template
references match it, is used to serve static files like the js and css from
libjsongit2.

### Adding access control to gitolite

If you add a virtual user to your gitolite config that represents each
vhost's ability to access repos, libjsongit2 will parse your gitolite config
and restrict the shown repos accordingly.  Set the vhost's `acl-user` to
reflect the vhost's "virtual user name" used in the gitolite config.

