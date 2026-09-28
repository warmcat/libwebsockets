![Sai](./assets/sai.svg)

[![CI status](https://warmcat.com/sai/status/sai)](https://warmcat.com/git/sai)

`Sai` (pronouced like 'sigh': "Trial" in Japanese) is a very lightweight
lws-based network-aware distributed CI builder and coordinating server.
You can run the sai-builder daemon on any number of devices ad-hoc without
central registration or inbound internet access, to offer builds for those
platforms... builders can run:

 - on native boxes,
 - inside systemd-nspawn contexts,
 - inside VMs (eg, via qemu) for native and non-native arches, or
 - cross-build against connected embedded devices which can be flashed and run the build
   results, controlled by gpio and serial.

A sai-server daemon runs on a server to receive wss connections from the builders,
git update hooks POST signed JSON job matrices from configured git servers, and
sai-server coordinates dispatching concurrent jobs to dynamically availabe remote
builders of the correct platforms, collecting logs and results.

A sai-web server daemon is also available usually on :443 or via a proxy to provide
a live web / websockets interface with synamic updates and realtime build logs in
the browser, with JWT-authentication for manual job control.

![sai overview](./READMEs/sai-overview.png)

## General approach

 - Distributed "builders" run the `sai-builder` daemon from inside the build
   platform they want to provide builds for (ie, inside a systemd-nspawn or VM).

 - The `sai-builder` daemons maintain nailed-up outgoing client wss connections
   to a central `sai-server`, which manages the ad-hoc collection of builders
   it finds, and provides a web UI (http/2 and wss2).

![sai git flow](./READMEs/sai-ov2.png)

 - When a git repo that wants sai tests is updated, a push hook performs a POST
   notiftying the Sai server of a new push event which creates an entry in an
   event sqlite3 database.  (The server does not need to access the repo that
   sends the git notification).  The hook sends the server information about the
   push and the revision of `.sai.json` from the new commit in the POST body...
   the server parses that JSON to fill an sqlite3 database with tasks and
   commandline options for the build on platforms mentioned in `.sai.json`.
   Pushes to branches beginning with `_` are ignored by Sai, even if they have
   a valid `.sai.json`; this allows casual sharing of trees via the same git
   repo during intense development without continually triggering CI builds.

 - Builders typically build many variations of the same push, so they use a
   local git mirror only on the builder to reduce the load on the repo that
   was updated.  For large trees, being able to already have previous trees
   as a starting point for git dramatically reduces the time compared to a full
   git fetch.

 - The server hands out waiting tasks on connected idle builders that offer the
   requested platforms, which build them concurrently.  The builders may be
   inside a protected network along with the repos they connect to; both the
   builders and the repo only make outgoing https or wss connections to the
   server.

 - On the builders, result channels (like stdout, stderr, eventually others like
   `/dev/acm0`) with logs and results are streamed back to the server over a wss
   link as the build proceeds, and are stored in an event-specific sqlite3
   database for scalability.

 - Builders can run CTest or other tests after the build and collect the
   results (CTest has the advantages it's lightweight and crossplatform).

 - The server makes human readable current and historical results available
   in realtime over https web interface

 - One `sai-builder` daemon can be configured to offer multiple instances of
   independent platform build, and multiple platform builds (eg, cross
   toolchains).

 - Embedded test devices that need management by external gpios to select
   flash or test modes can be wired to an RPi or similar running sai-jig.
   This listens on a configurable port for requests to perform gpio sequencing
   specified in a configuration file.  One sai-jig instance can separately
   manage external gpio sequencing for multiple test targets.

 - Largely the server is automatic, driven by git hook notifications over
   HTTP and the UI is read-only.  However there are some privileged UI operations
   like deleting a whole event, or redoing whole events or individual tasks.
   For these, if the browser has an authentic JWT signed by the server, it can
   see and operate these privileged controls.

 - sai-power is an optional daemon that runs on a machine on the builder subnet,
   when builders identify they are idle, they can suspend themselves, or ask
   sai-power to turn the builder off (after they have cleanly shutdown themselves)
   at a smartplug.  sai-power also monitors sai-server, and when it sees there
   is a job ready for the platform offered by the builder, either resume the
   builder with WOL, or power the builder up at its smartplug.  Since builders in
   most cases spend most of their time idle, this enables a very good optimization
   of average power down to nearly zero.

## Link authentication ("link-key")

sai-server's listener is expected to be reachable by distributed builders
across the internet, so daemons connecting to it must prove a shared
fleet-wide secret before sai-server treats them as part of the fleet.
Without it, anyone who could reach the listener would count as a builder,
able to register platforms, win real task dispatches (with the repo build
script and artifact upload nonce) and forge task results.

The first ws message on any connection to sai-server's `/sai/builder` or
`/sai/power` endpoints must be

```
{"schema":"com.warmcat.sai.linkauth","secret":"<link-key>"}
```

sai-server compares the secret in constant time and processes nothing else
from the peer until it is proven, dropping the connection on a wrong secret.
The client daemons take care of this themselves and send the auth message
ahead of their first messages on (re)connect: sai-builder (on its main and
artifact links), sai-power and sai-virt.  sai-power also requires the same
secret from builders registering with it over the LAN.

Set up the same key on both sides, generating it as 64 hex chars from 32
random bytes the same way as `notification-key`:

```
$ dd if=/dev/random bs=32 count=1 | sha256sum | cut -d' ' -f1
```

 - on sai-server, in the `vhosts|ws-protocols|com-warmcat-sai` section of
   the config JSON next to `notification-key`... sai-server refuses to start
   without it

```
			"link-key":		"<link-key>",
```

 - on every sai-builder, sai-power and sai-virt host, at the top level of
   the daemon's conf, eg, `/etc/sai/builder/conf`

```
	"link-key":		"<link-key>",
```
## sai-web <-> sai-server control link ("sockpath")

sai-web is the only thing that talks to sai-server on behalf of browsers,
over a unix socket ws link that sai-server serves and sai-web connects to.
Everything the UI can do with admin rights arrives at sai-server over this
link and is trusted (deleting events, resetting and cloning tasks, whose
build scripts the builders then run), so who can connect to the socket is who
has admin on the CI.

Both daemons take the socket path from the optional `sockpath` pvo in the
`vhosts|ws-protocols|com-warmcat-sai` section of their conf, and it must be
the same on both sides:

```
			"sockpath":		"/var/run/sai-websrv",
```

Only one sai-server vhost may carry the com-warmcat-sai protocol: the
builders, the hook intake and this link all belong to that one vhost's
protocol instance.  A second vhost with the protocol (eg, a unix-socket vhost
for a front-end proxy) would bind its own copy of the link on the same path
and sai-web would see a vhd with no builders on it; sai-server now refuses to
initialize the protocol on any vhost after the first.  Hook notifications go
to the same vhost the builders use, eg, `http://127.0.0.1:4444/update-hook`
from a hook on the same host.

sai-server binds it during protocol init, before dropping privileges, and lws
gives the socket sai-server's conf `uid`:`gid` with mode 0660 (the same way it
treats any path-based listen socket).  So only that user and members of that
group can connect: put the user sai-web runs as in sai-server's group, eg,
with the example confs (sai-server runs as `apache`, sai-web as `sai`)

```
# usermod -a -G apache sai
```

If `sockpath` is not set on a side, that side falls back to the
abstract-namespace socket `@com.warmcat.sai-websrv` that older confs used, and
warns at startup: abstract sockets have no filesystem permissions, so any
local user on the host can connect to the link.  Existing deployments keep
working unchanged, but should add the pvo to both confs and restart both
daemons (sai-server first, sai-web reconnects by itself).

## RSS feed of build events

sai-web serves a public RSS 2.0 feed of the latest 10 events at
`/sai/rss.xml`, newest notification first.  The web UI links to it from the
logo area and advertises it for feed autodiscovery.  It can be scoped with `?project=<name>` and / or
`?branch=<branch name or full ref>`, eg,

```
https://mydomain.com/sai/rss.xml?project=libwebsockets&branch=main-dev
```

Each item reflects the event as it is when the feed is fetched.  Besides the
human-readable title, description and categories, it carries the details in
elements in the `https://warmcat.com/sai/ns/rss` namespace:

|element|meaning|
|---|---|
|`sai:received`|unix time the notification that created the event arrived|
|`sai:project`|project (repo) name|
|`sai:branch`|branch being built (the ref, less any `refs/heads/`)|
|`sai:hash`|git commit being built|
|`sai:fetchurl`|the repository fetch url the notification gave|
|`sai:weburl`|the repository web url the notification gave, if any|
|`sai:adhoc`|1 for an ad-hoc event an admin seeded from a task, else 0|
|`sai:state`|event state: `waiting`, `building`, `failing` (still building, but some tasks already failed), `succeeded`, `failed`, `cancelled`, `not-ready` or `paused`; the `code` attribute has the raw state number|
|`sai:tasks`|task counts as attributes: `total`, `ok`, `bad`, `building` and `wait`|

The item `guid` is the event uuid plus its state, so feed readers show an
event again as a new item when its state changes, eg, from `building` to
`failed`, or back to `building` after an admin restarts tasks.  The task
counts change inside an item without changing the guid.

Links in the feed are relative (eg, `index.html?event=<uuid>`), so they
resolve against whatever url the feed was fetched from; no conf is needed to
tell sai-web its public url.

## Build flow and support for embedded

![build flow](READMEs/sai-build-test-flow.png)
 
Testing is based around CTest, it can either run on the build host inside the
container, or run on a separate embedded device.  In the separate case, the flow
can include steps to flash the image that was built and to observe and drive
testing via usually USB tty devices.  IO on these additional ttys is logged
separately than IO from build host subprocess stdout and stderr.

### Sharing embedded devices on the test host

Embedded devices are actually build host-wide assets that may be called upon
and shared by different containers and different build platforms.  For
example, a cross-built flash image on Centos8 and another cross-built on
Ubuntu Bionic for the same platform may want to flash and test on the same
pool of embedded devices.  Even images from different build platforms for the
same kind of device may wish to flash the same embedded device, where the
device can be flashed to completely different OSes.

Devices may be needed by post-build actions, but they are not something
a sai-builder for a platform can "own" or manage by itself.  Instead they are
requested from inside the build action by another tool built with `sai-builder`,
`sai-device`, which reads shared JSON config describing the available devices
and platforms they are appropriate for.

![sai-device overview](READMEs/sai-embedded-test.png)

Rather than reserve the device when the build is spawned, the reservation
needs to happen only when the build inside the build context has completed.
That in turn means that a different sai utility has to run at that time from
inside the build process, in order that it can set things in the already-
existing subprocess environment.

```
"devices": [
        {
                "name":         "esp32-heltec1",
                "type":         "esp32",
                "compatible":   "freertos-esp32",
                "description":  "ESP32 8MByte SPI flash plus display",
                "ttys":         [
                     "/dev/serial/by-path/pci-0000:03:00.3-usb-0:2:1.0-port0"
                ]
        }
]
```

Devices are logically defined inside a separate conf file
`/etc/sai/devices/conf` on the host or vm, and containers should bind a ro
mount of the file at the same place in their /.  This avoids having to maintain
a bunch of different files every time a new device is added.  For platform
builders based in a VM, these have a boolean relationship with IO ports, they
either must wholly own them or are unaware of them: this means they can't
participate in sharing device pools but must be allocated their own with its
own config file inside the VM listing those.

When the build process wants to acquire an embedded device of a particular type
for testing, it runs in the building context, eg, `sai-device esp32 ctest`.

This waits until it can flock() all the ttys of one of the given type of
configured devices ("esp32" in the example), sets up environment vars for each
`SAI_DEVICE_<ttyname>`, eg,
`SAI_DEVICE_TTY0=/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0`,
then executes the given program (`ctest` in the example) as a child process
inside the build context.  Although it has an fd on the tty so it can flock()
it, `sai-device` does not read or write on the fd itself.

Baud rate is not considered an attribute of the tty definition but something set
for each sai-expect.

When the child process or build process ends, the locking is undone and the
device may be acquired by another waiting `sai-device` instance in the same or
different platform build context.

The underlying locking is done hostwide using flock() on bind mounts of
the tty devices, the other containers will observe the locking no matter who
did it.

Availability of the device node via an environment variable means that CTest
or other scripts are able to directly write to the device.

### Logging of device tty activity

The `sai-builder` instance opens three local listening Unix Domain Sockets for
every platform, these accept raw data which is turned into logs on the
respective logging channel and passed up to the `sai-server` for storage and
display like the other logs.

The paths of these "log proxy" Unix Domain Sockets are exported as environment
variables to the child build and test process as follows

Environment Var|Ch#|Meaning|Example
---|---|---|---
SAI_LOGPROXY|3|Build progress logging|`@com.warmcat.com.saib.logproxy.warmcat_com-freertos-esp32.0`
SAI_LOGPROXY_TTY0|4|Device tty0|`@com.warmcat.com.saib.logproxy.warmcat_com-freertos-esp32.0.tty0`
SAI_LOGPROXY_TTY1|5|Optional Device tty1|`@com.warmcat.com.saib.logproxy.warmcat_com-freertos-esp32.0.tty1`

Because some kinds of device share the same tty for flashing the device, at
which time nothing else must be reading from the tty, tty activity is only
captured and proxied during actual user testing by `sai-expect`, which is run at
will be the CTest script.  In this way, device ttys are only monitored while
test are ongoing; however the kernel will buffer traffic that nobody has read
until the next reading consumes it.

### Sai device tty logging

Devices may have multiple ttys defined, for example a device with separate ttys
and log channels for a main cpu and a coprocessor is supported.

The ttys listed on devices have their own log channel index and are timestamped
according to when they were read from the tty.  In the event many channels are
"talking at once", in the web UI the different log channel content appears in
different css colours and in chunks of 100 bytes or so, which tends to keep
isolated lines of logging intact.

## Non-Linux: use /home/sai in the main rootfs

For OSX and other cases that doesn't support overlayfs, the same flow occurs
just in the main rootfs /home/sai instead of the overlayfs /home/sai.

It means things can only be built in the context of the main OS, but since OSX
doesn't have different distros, which is the main use of the Linux overlayfs
feature, it's still okay.

## Builder instances

The config JSON for sai-builder can specify the number of build instances for
each platform.  These instances do not have any relationship about what they
are building, just they run in the same platform context (and are managed by
the one `sai-builder` process).  They each check out their own build tree
independently, so they can be engaged building different versions or different
trees concurrently inside the platform.

Tests have to take care to disambiguate which instance they are running on,
since the network namespace is shared between instances that are running in the
same sai-builder process on the same platform.  An environment var
`SAI_INSTANCE_IDX` is available inside the each build context set to 0, 1, 33 etc
according to the builder instance.  Similar to how fds are allocated in C, the
lowest unused number is reused each time something new is spawned by Sai.

For network related tests, `SAI_INSTANCE_IDX` should be referred to when
choosing, eg, a test server port so it will not conflict with what other
builders may be doing in parallel.

## Builder git caching

For each `<saiserver-project>`, the builder maintains a local git cache.  This is
updated once when the new ref appears and then the related tests check out a
fresh image of their ref from that each time.  This is very fast after the first
update, because it doesn't even involve the network but fetching from the local
filesystem. 

## systemd-nspawn support

On Linux, it's recommended to use systemd-nspawn to provide multiple distro
environments conveniently on one machine.  There are instructions for setting
up individual virtual ethernet devices managed by nmcli on the host.

`sai-builder` also supports running inside a KVM / QEMU VM transparently as well,
eg for windows or emulated architecture VMs.

## `sai` builder user

Builds happen using a user `sai` and on the builder, files are only created
down `/home/sai` or `\Users\sai`.

Note: on redhat type distros like Fedora / Rocky, use `-gnobody`

```
# useradd -u883 -gnogroup sai -d/home/sai -m -r
```

## build filesystem layout

 - /home/sai/
  - git-mirror/
   - `remote git url`_`project name` -- individual git mirrors
  - jobs/
   - `server hostname`-`platform name`-`instance index`/
    - `project_name`/  - checkouts and builds occur in here

## Build steps

Building sai produces two different sets of apps and daemons by default, for
running on a the server that coordinates the builds and for running on machines
that offer the actual builds for particular platforms to one or more servers.

You can use cmake options `-DSAI_SERVER=0` and `-DSAI_BUILDER=0` to disable one
or the other.

Server executables|Function
---|---
sai-server|The server that builders connect to
sai-web|The server that browsers connect to

Builder executables|Function
---|---
sai-builder|The daemon that connects to sai-server and runs builds
sai-device|Helper that coordinates which builds wants and can use specific embedded hardware
sai-expect|Helper run by embedded build flow to capture serial traffic and react to keywords
sai-jig|Helper for embedded devices that lets another device control its buttons, reset etc as part of the embedded build flow

First you must build main branch lws with appropriate options.

For redhat type distros, you probably need to add /usr/local/lib to the
/etc/ld.so.conf before ldconfig can rgister the new libwebsockets.so

```
$ git clone https://libwebsockets.org/repo/libwebsockets
$ cd libwebsockets && mkdir build && cd build && \
  cmake .. -DLWS_LOGS_TIMESTAMP=0 -DLWS_WITH_STRUCT_JSON=1 -DLWS_WITH_JOSE=1 \
   -DLWS_WITH_STRUCT_SQLITE3=1 -DLWS_WITH_GENCRYPTO=1 -DLWS_WITH_SPAWN=1
$ make -j && sudo make -j install && sudo ldconfig
```

The actual cmake options needed depends on if you are building sai-server and / or
sai-builder.

lws cmake option|Meaning
---|---
`-DLWS_LOGS_TIMESTAMP=0` | Avoids duplicating log timestamp in syslog
`-DLWS_WITH_STRUCT_JSON=1` | Support for struct -> JSON -> struct
`-DLWS_WITH_STRUCT_SQLITE3=1` | Support for struct -> sqlite3 -> struct
`-DLWS_WITH_SPAWN=1` | Support for crossplatform process spawning
`-DLWS_WITH_GENCRYPTO=1` | Supoort for cross-tls library crypto
`-DLWS_WITH_JOSE=1` | Support for JOSE web tokens

You can also define `-DLWS_WITH_SYS_METRICS=1` on lws to enable build of
openmetrics pieces in sai when built against lws.

Similarly the two daemons bring in different dependencies

Feature|dependency
---|---
either|libwebsockets
server|libsqlite3
builder|pthreads
jig (linux only)|libgpiod

#### Unix / Linux

```
$ git clone https://warmcat.com/repo/sai
$ cd sai && mkdir build && cd build && cmake .. && make && sudo make install
$ sudo cp ../scripts/sai-builder.service /etc/systemd/system
$ sudo mkdir -p /etc/sai/builder
$ sudo cp ../scripts/builder-conf /etc/sai/builder/conf
$ sudo vim /etc/sai/builder/conf
$ sudo systemctl enable sai-builder
```

#### Windows builder only

Windows is such a steaming pile of crap it has a registry setting to turn off the default-on insane file name limits it turns out.
If you do in an admin powershell:

```
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

you will avoid problems with cmake failing silently towards the end of the main build with a `1` error code.

You have to make git2.dll and some deps visible, in /windows/system32 or similar

```
> sudo cp "\Users\<user>\vcpkg\installed\x64-windows\bin\pcre.dll" "\windows\system32"
```

Build lws the same way as for unix, except with

```
> cmake --build . --config DEBUG
> sudo cmake --install . --config DEBUG
```

For sai it's also very similar to unix, but with

```
> cmake .. -DSAI_SERVER=0 -DSAI_LWS_INC_PATH="\Users\<user>\libwebsockets\build\include" -DSAI_LWS_LIB_PATH="\Users\<user>\libwebsockets\build\lib\Debug\websockets.lib" -DSAI_EXT_PTHREAD_INCLUDE_DIR="C:\Program Files (x86)\pthreads\include" -DSAI_EXT_PTHREAD_LIBRARIES="C:\Program Files (x86)\pthreads\lib\x64\libpthreadGC2.a"
> cmake --build . --config DEBUG
> sudo cmake --install . --config DEBUG 
```

On Windows, the config exists in `C:\ProgramData\sai\builder\conf` rather than \etc.

#### Additional steps for freebsd

Freebsd presents a few differences from Linux.

1) `pkg install bash` and other prerequisites like git, cmake etc

2) Create the sai user via `adduser` and set the uid to 883.

3) Create the builder logproxy socket dir one time as root

```
# mkdir -p /var/run/com.warmcat.com.saib.logproxy
# chown sai /var/run/com.warmcat.com.saib.logproxy
```

4) For script portability, `ln -sf /usr/local/bin/bash /bin/bash`

5) As root copy `scripts/etc-rc.d-sai_builder-FreeBSD` to `/etc/rc.d`.

6) As root, edit `/etc/rc.conf` and add a line `sai_builder_enable="YES"`, then,
`sudo /etc/rc.d/sai_builder start`

7) Create and prepare `/etc/sai/builder/conf` as for Linux

