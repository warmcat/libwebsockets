# sai-push

## Overview

sai-push is an optional daemon, usually run on the git server host, that
promotes commits once Sai says they're good: eg, when an event on
`main-dev` succeeds, it pushes that commit to `main`, and optionally to the
same branch on mirrors such as github.

It follows sai-web's public feed of events (see "RSS feed of build events"
in the top level README), as JSON, using the feed's long poll: after the
first fetch, it holds a request open with sai-web and only hears back when
an event joins the feed or changes state, eg, from `building` to
`succeeded`.  So it reacts within moments of a build finishing, without
polling.

## How it decides what to push

Each watch in the conf covers one repository, identified by the fetch url
its sai notifications give, and has rules mapping source branches to target
branches:

 - The first rule matching a branch decides: the branch must match the rule's
   wildcard `match` (default `*`) and end in its `branch-suffix`.  The suffix
   is removed to name the target branch, eg, `main-dev` -> `main`.  Branches
   no rule matches are left alone.

 - For each target branch, the newest successful event on a source branch
   mapping to it is the one promoted.  That's the latest known-good commit,
   even if newer events are still building or failed.  Ad-hoc events (admin
   scratch builds from the web UI) are never promoted.

 - An event whose notification arrived before the one last promoted to that
   target is never promoted over it.  This is remembered across restarts,
   see "State" below.

Before pushing, sai-push fetches the primary remote into a bare repo in its
cache dir and checks:

 - the commit is still on the source branch: if the source branch was
   rewritten since, the commit isn't what the branch says is good any more,
   and it's skipped

 - the target branch doesn't already have the commit: if it does, there's
   nothing to do.  So an older success coming back to the top, eg, because a
   newer event's tasks were restarted, can't rewind the target, even where
   force pushing is allowed.

Then it pushes the commit to the target branch on the primary remote,
forced if the rule says so, and then to each mirror in turn, each checked
first for already having it.  A target branch that doesn't exist yet is
created.

If anything fails on the primary, the mirrors are not touched.  If a mirror
fails, the other mirrors are still pushed.  Failures are logged with git's
own output, and the same commit is tried again no sooner than 10 minutes
later, when the feed next changes or the long poll's 10 minute wait
expires.

## Setting it up

1) Build and install sai with the `SAI_PUSH` cmake option (on by default on
   non-Windows), which installs `/usr/local/bin/sai-push`.  It needs lws
   built with `LWS_WITH_CLIENT`, `LWS_WITH_STRUCT_JSON` and `LWS_WITH_SPAWN`,
   and recent enough to have

    - `864f9da72` "lejp: pop an array's element parser when the array ends,
      at any depth": without it, a watch that has both `rules` and `mirrors`
      silently loses whichever of them comes second in the conf

   and, in the lws front-end web server that proxies sai-web,

    - `fbedb4001` "proxy: a response still flowing keeps the parent's content
      timeout off": without it, the front-end drops each held long poll
      request after its `timeout_secs`, and sai-push goes round a fetch /
      wait cycle that often instead of waiting quietly.

2) Create a user just for sai-push, eg, `sai-push`, with a home dir and no
   password.  sai-push is started as root, and becomes this user before it
   does anything on the network; git and ssh run as it.

3) As that user, create an ssh key, and give it write access to the repos it
   should manage on the git server, eg, in gitolite.

4) Put the git server's host key in that user's `~/.ssh/known_hosts`, under
   exactly the host name (and port, if not 22) the `remote` url uses.  ssh
   runs in BatchMode, so it will not ask, and an unknown host fails with
   `Host key verification failed.`  If the git server is this host, you can
   take the key straight from its own host key file, rather than trusting
   what comes over the network the first time, eg,

   ```
   # sudo -u sai-push sh -c 'awk "{print \"libwebsockets.org \" \$1 \" \" \$2}" /etc/ssh/ssh_host_ed25519_key.pub >> ~/.ssh/known_hosts'
   ```

   or log in once as that user with the same name as the `remote` url:
   `sudo -u sai-push ssh git@libwebsockets.org`.

5) For a github mirror, use a deploy key: an ssh key github accepts for just
   the one repository it's added to.  It doesn't expire, and it's revoked
   from the repository's settings if the host is ever compromised.

   github refuses a key that's already in use anywhere else on github, so
   **each mirrored repo needs its own key**.  But every mirror url is on
   the same host, `github.com`, so ssh can't choose the key by host name.
   Instead, give each repo its own made-up host name, an alias, in the ssh
   config, and use that alias in the repo's mirror url.  ssh matches the
   `Host` block by the name in the url, then connects to the real
   `HostName`.

   For each repo, eg, `libwebsockets`:

    a) Make its key, as the sai-push user:

       ```
       # sudo -u sai-push ssh-keygen -t ed25519 -N "" -C "sai-push github libwebsockets" -f /home/sai-push/.ssh/github_libwebsockets
       ```

    b) Add it on github, as an admin of the repository: **Settings**, then
       **Deploy keys** (eg,
       `https://github.com/warmcat/libwebsockets/settings/keys`), then **Add
       deploy key**.  Give it a title, eg, `sai-push on libwebsockets.org`,
       paste in the **public** key,
       `/home/sai-push/.ssh/github_libwebsockets.pub`, tick **Allow write
       access**, and **Add key**.

    c) Add an alias for it to `/home/sai-push/.ssh/config` (owned by
       sai-push, mode 0600):

       ```
       Host github-libwebsockets
       	HostName github.com
       	HostKeyAlias github.com
       	IdentityFile ~/.ssh/github_libwebsockets
       	IdentitiesOnly yes
       ```

        - `HostKeyAlias github.com`: every alias checks github's host key
          under the one `github.com` entry in `known_hosts`
        - `IdentitiesOnly yes`: offer only this key, else github may accept
          another repo's deploy key first and say `Repository not found`

       Don't add a plain `Host github.com` block with a key in it: it would
       quietly apply to every github url that isn't an alias.

    d) Check it, as the sai-push user.  The first time, ssh shows github's
       host key fingerprint: check it against
       https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
       before accepting it.  Because of `HostKeyAlias`, that's only needed
       once, for the first alias.

       ```
       # sudo -u sai-push ssh -T git@github-libwebsockets
       ```

       It should answer `Hi warmcat/libwebsockets! You've successfully
       authenticated, but GitHub does not provide shell access.`: the
       repository named there confirms it's the right deploy key.

    e) Use the alias as the host in that repo's watch's mirror url:
       `{ "url": "ssh://git@github-libwebsockets/warmcat/" }`.

   Each watch covers one repo, so each watch's mirror names its own alias,
   eg, the watch for `otherproject` mirrors to
   `ssh://git@github-otherproject/warmcat/`, after doing a) to e) again with
   `otherproject` in place of `libwebsockets`.

   If the target branch is protected on github by a branch protection rule
   or a ruleset, the deploy key must be allowed to push to it, and to force
   push to it if the rule forces: rulesets can list "Deploy keys" as a
   bypass actor.

   Alternatively, an https mirror can use a token, see `token-file` below,
   eg, a github fine-grained personal access token restricted to just the
   mirror repositories with "Contents: Read and write".  But those expire:
   when it does, the mirror pushes start failing, with git's message in the
   log, until you make a new one and replace the file.

6) Write the conf, `/etc/sai/push/conf`, see below.

7) Install and start the systemd unit, `scripts/sai-push.service`:

   ```
   # cp scripts/sai-push.service /etc/systemd/system/
   # systemctl daemon-reload
   # systemctl enable --now sai-push
   ```

   It orders itself after `sai-web.service`, for when sai-web is on the same
   host, without depending on it: sai-push is often on the git server with
   sai-web elsewhere, and retries the feed with backoff anyway.  If the feed
   url goes through a front-end web server on this host, add its unit to the
   `After=` line too.

## Command line

|option|meaning|
|---|---|
|`-c <file>`|conf file to use, default `/etc/sai/push/conf`|
|`-d <loglevel>`|lws log level bitmap, eg, `-d 1039` adds info logging|

## Configuration

The conf is JSON, read from `/etc/sai/push/conf` unless `-c` says otherwise.
`#` comments to the end of the line are allowed.

sai-push checks the whole conf before starting, and refuses to start if
anything in it isn't usable, logging each problem with its line number:

 - a member it doesn't know, eg, a misspelling, or one that's in the wrong
   place, eg, `mirrors` outside the watch it belongs to: it says where a
   misplaced member should go
 - a value of the wrong kind, eg, `"force": "true"` (a string, rather than
   `true`), or a single `{ }` where a list `[ { } ]` is needed
 - a missing or wrong `schema`, or a file that isn't valid JSON

It also warns, without refusing to start, about an http(s) `remote`, or an
http(s) mirror without a `token-file`, since git has no way to authenticate
pushes there unless the `user`'s own git config gives it credentials.  At
startup it logs, for each watch, its rules, the remote it pushes to, and its
mirrors, or "no mirrors".

### Example

```
# sai-push conf: /etc/sai/push/conf
{
	"schema": "sai-push",

	"user": "sai-push",
	"repo-cache": "/var/cache/sai-push",

	"watches": [{
		"feed": "https://libwebsockets.org/sai/rss.xml",
		"fetchurl": "https://libwebsockets.org/repo/libwebsockets",
		"remote": "ssh://git@libwebsockets.org/",

		"rules": [
			# eg, v5.0-stable-dev -> v5.0-stable, fast-forward only
			{ "match": "*-stable-dev", "branch-suffix": "-dev",
			  "force": false },
			# anything else, eg, main-dev -> main, forced
			{ "branch-suffix": "-dev", "force": true }
		],

		"mirrors": [
			# github, via this repo's deploy key alias, see setup step 5
			{ "url": "ssh://git@github-libwebsockets/warmcat/" }
		]
	}]
}
```

With this, when an event for libwebsockets succeeds on `main-dev`, its commit
is force-pushed to `main` on `ssh://git@libwebsockets.org/libwebsockets` and
then on github's `warmcat/libwebsockets`, using the deploy key for the
`github-libwebsockets` alias; when one succeeds on
`v5.0-stable-dev`, its commit is pushed to `v5.0-stable` on both, but only
if that's a fast-forward.

The same example, commented, is in `etc-sai-EXAMPLE/push/conf`.

### Top level

|member|required|meaning|
|---|---|---|
|`schema`|yes|must be `"sai-push"`|
|`user`|when started as root|the user sai-push becomes before going on the network.  It must exist and not be root.  git and ssh run as it, with its home dir as `HOME`, so its ssh keys, `known_hosts` and git config are the ones used.  If sai-push is started as someone else, eg, to test it by hand, it stays as them and warns that it's ignoring this|
|`repo-cache`|yes|absolute path of a dir sai-push keeps a bare repo per project in, eg, `libwebsockets.git`, so each promotion only has to fetch what's new, plus its state file.  It's created mode 0700 if needed, and given to `user` at startup|
|`watches`|yes|array of one or more watches, see below|

### Watch

Each watch covers one repository.

|member|required|meaning|
|---|---|---|
|`feed`|yes|the sai-web feed url, eg, `https://libwebsockets.org/sai/rss.xml`.  sai-push reads the same feed as JSON, so a url ending `rss.xml` has that changed to `rss.json`; it must end in one or the other.  sai-push adds `?fetchurl=` for the watch itself, so the feed is scoped to the repository.  It must be https, since sai-push acts on what the feed says, except that plain http is allowed from `localhost`, `127.0.0.1` or `::1`|
|`fetchurl`|yes|the repository's fetch url exactly as its sai notifications give it (`repository.fetchurl` in the notification JSON, shown as `sai:fetchurl` in the RSS feed).  Only events with this fetch url are considered|
|`remote`|yes|the primary remote: a url prefix, the event's project name (eg, `libwebsockets`) is appended to it.  It's where the source branches, eg, `main-dev`, are fetched from and checked, and the first place the target branches are pushed to.  Usually ssh, using the `user`'s keys.  It must not contain credentials|
|`rules`|yes|array of one or more rules, see below, tried in order|
|`mirrors`|no|array of mirrors, see below, which get the same pushes as `remote`, in order, after it|

### Rule

|member|required|meaning|
|---|---|---|
|`branch-suffix`|yes|the source branch must end with this, eg, `-dev`.  It's removed to name the target branch.  A branch that is only the suffix doesn't match|
|`match`|no|a pattern the whole source branch name (without `refs/heads/`) must match, with up to three `*` wildcards, eg, `*-stable-dev` or `v5.*-dev`.  Default `*`, any branch|
|`force`|no|`true` if the push to the target branch may be a force push, eg, for a `main` that follows a rebased `main-dev`.  Default `false`: the push must be a fast-forward, and is refused and logged otherwise.  Mirrors are pushed with the same setting|

### Mirror

|member|required|meaning|
|---|---|---|
|`url`|yes|a url prefix, the event's project name is appended to it, eg, `ssh://git@github-libwebsockets/warmcat/` for `ssh://git@github-libwebsockets/warmcat/libwebsockets`.  For github, ssh with a per-repo deploy key and host alias is recommended, see setup step 5; ssh uses the `user`'s ssh config and keys.  It must not contain credentials: sai-push refuses to start if an https url has any|
|`token-file`|no|absolute path (`~` is not expanded) of a file holding a token git gives as the password when the (https) mirror asks, eg, a github fine-grained personal access token.  Whitespace around the token in the file is ignored.  Keep it with the `user`'s other credentials, eg, `/home/sai-push/.github-token`, owned by `user` and mode 0600.  It must be readable by `user`, and must not be readable by everyone: sai-push refuses to start otherwise.  git gets it by running sai-push itself as its `GIT_ASKPASS`, so the token is never in a url, an argv or the logs, and git's own credential helpers are not used for that mirror|

## State

`sai-push-state.json` in the `repo-cache` dir holds, for each target
branch, the last event promoted to it on the primary remote: its uuid, its
commit and the unix time its notification arrived.  It's what stops an
older event being promoted over a newer one, including across restarts.
It's rewritten, by writing a new file and renaming it over the old one,
each time a promotion reaches the primary.

If it's damaged, sai-push refuses to start rather than carry on without
it; removing it starts over, with only the git checks protecting the target
branches until the next promotion.

## Logs

sai-push logs to stderr, so under systemd, to the journal.  Among other
things it logs

 - the rules and mirrors it understood from the conf, at startup

 - each feed update it acts on: `saip_feed_process: <fetchurl>: index ...,
   N events`

 - each promotion started, and how each step ended, eg, `promoting to main
   (force)`, `pushed <hash> to main on <remote>`, `main on <remote> already
   has <hash>`, `<hash> is no longer on main-dev, not promoting it`, or `not
   promoting <hash> ... it's older than event <uuid>, already promoted`

 - anything git says while doing it, a line at a time

## Troubleshooting

|symptom|cause|
|---|---|
|`git: Host key verification failed.`|the `user`'s `known_hosts` has no entry for the exact host name (and port) in the `remote` url.  See step 4 above|
|`git: Permission denied (publickey)` or gitolite refusing access|the `user`'s ssh key isn't allowed write access to the repo on the git server|
|`git: ERROR: The key you are authenticating with has been marked as read only.`|the github deploy key was added without **Allow write access**: delete it and add it again with that ticked|
|`git: ERROR: Repository not found.` from github over ssh|ssh offered a key github doesn't have as a deploy key for that repo, eg, the gitolite key: check the mirror url's host is that repo's alias, that the alias has the right `IdentityFile` and `IdentitiesOnly yes`, and that `sudo -u sai-push ssh -T git@<alias>` greets the right repo|
|`git: ssh: Could not resolve hostname github-...`|the alias in the mirror url has no matching `Host` block in the `user`'s ssh config, or it's misspelled, see setup step 5|
|a github push is refused by a protected branch rule|allow the deploy key (or the token's account) to push, and force push for a forced rule, or add it as a bypass actor, see setup step 5|
|a github https mirror push fails with an authentication error|the token is wrong or expired, or lacks "Contents: Read and write" on that repo|
|`! [rejected] ... (non-fast-forward)`|the rule doesn't allow a force push, and the target branch has moved on in a way the commit doesn't extend.  Retried every 10 minutes while it's the newest success|
|`incomplete feed, retrying` roughly every `timeout_secs` of the front-end web server|the lws front-end proxying sai-web lacks `fbedb4001`, see step 1|
|`... doesn't belong there (...), it goes in ...`, `unknown member ...` or `... should be ...`, and sai-push won't start|the conf has a member in the wrong place, misspelled, or with the wrong kind of value, at the line given: see "Configuration"|
|a github or other mirror never gets pushed, with nothing logged about it|check the startup log has `mirrored to <url>` for it.  If it says `no mirrors`, the `mirrors` list isn't inside the watch.  If the conf is right, lws may lack `864f9da72`, see step 1|
|nothing is promoted although builds succeed|check the watch's `fetchurl` matches `sai:fetchurl` in the RSS feed exactly, and that a rule matches the branch|
