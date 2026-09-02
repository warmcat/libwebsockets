# lws-api-test-auth-dns-zonedir

Fence for security-audit finding F-055: the local zone-dir trust policy in
the authoritative-DNS plugin (`protocol-lws-auth-dns`).

Everything the plugin loads from its zone dir is served as **authoritative**
DNS data, and expired / evicted entries are unlinked from that dir by
filename.  Pre-fix, a missing `zone-dir` pvo silently defaulted to shared
`/tmp/lws-auth-dns` and the init dir-scan trusted any `*.zone` file on
syntax alone — no ownership, permission, or name-shape check — so any local
user who pre-created or owned the directory could inject zones and have
victim zone files unlinked.

The test builds the plugin in statically and runs sequential phases, each
with its own context and port, planting the attack arrangements on disk
first (all fixture modes are chmod'd explicitly so they do not depend on
the process umask):

| phase | arrangement | pre-fix behavior | post-fix behavior |
|-------|-------------|------------------|-------------------|
| 1 | service-owned dir + properly decorated `origin_ttl_sig_serial.zone` file | served | served (control that the happy path still works) |
| 2 | no `zone-dir` pvo at all | defaulted to `/tmp/lws-auth-dns` and started (listener up) | protocol init refused: queries stay unanswered and the UDP port is bindable by the test itself |
| 3 | world-writable (0777) zone dir with a planted zone | planted zone served | init refused, no listener |
| 4 | `zone-dir` that is a symlink to a valid dir | followed for the dir checks; started anyway (listener up, answering) | init refused, no listener |
| 5 | good dir, but undecorated-name / two-field-suffix / group-writable (0666) / symlinked zone files | all loaded and served | only the properly shaped file loads; the rest answer REFUSED (rcode 5) while the control zone still answers |
| 6 | *(root only)* zone file owned by another uid | loaded and served | file ignored (REFUSED) while the service-owned control file in the same dir still answers |
| 7 | *(root only)* zone dir owned by another uid | started | init refused, no listener |

"No listener" is asserted both by silence (no response within the window)
and by the test binding the UDP port itself afterwards — the plugin only
creates its UDP listeners once its protocol init succeeded.

Phases 6-7 need to create files/dirs owned by another uid and are skipped
when the test is not running as root.

## Commandline

| option | meaning |
|--------|---------|
| `-p PORT` | first auth dns port (from `lws_get_free_port()`) |
| `-b PORT` | second auth dns port (phases alternate between the ports) |

The planted fixtures are (re)created under a per-run scratch dir
`zones-f055/<pid>` in the working directory (so runs under different uids
cannot trip over each other's leftovers) and removed again at exit; the
whole test takes a few seconds.
