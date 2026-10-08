# Setting up a builder for Rust projects (eg, npro)

This goes from a fresh machine, VM image or container to a sai builder that
can run a Rust project's jobs, using npro as the example.  npro needs
**rustc 1.85 or later**, the first release that knows edition 2024, which
is newer than most distros package.

What each of npro's configurations needs on top of the basics here (the
MSRV toolchain, nightly for Miri and cargo-fuzz, the no_std targets,
cargo-hack / deny / audit, and so on) is in npro's own `docs/sai.md`,
together with its `.sai.json`.  This README covers what every builder
needs before that.

## 1. The `sai` user

Jobs run as the user named in the builder conf's `"perms"`, with `HOME`
set to the conf's `"home"`.  Rust is installed per user, so it has to be
installed **for that user, in that home**.

```
# useradd -u883 -gnogroup sai -d/home/sai -m -r
```

(`-gnobody` on Fedora / Rocky; `useradd -u883 -g32766 -d/home/sai -m sai` on
the BSDs.)

## 2. sai-builder itself

As root, the build dependencies, eg, Debian / Ubuntu

```
# apt install git cmake make gcc g++ pkg-config libssl-dev libsqlite3-dev curl ca-certificates
```

or Fedora / Rocky

```
# dnf install git cmake make gcc gcc-c++ pkgconf openssl-devel sqlite-devel curl
```

(on Fedora / Rocky also add `/usr/local/lib` to `/etc/ld.so.conf` so ldconfig
finds the installed libwebsockets).  Then lws from its main branch, and sai:

```
$ git clone https://libwebsockets.org/repo/libwebsockets
$ cd libwebsockets && mkdir build && cd build && \
  cmake .. -DLWS_LOGS_TIMESTAMP=0 -DLWS_UNIX_SOCK=1 -DLWS_WITH_STRUCT_JSON=1 \
   -DLWS_WITH_JOSE=1 -DLWS_WITH_STRUCT_SQLITE3=1 -DLWS_WITH_GENCRYPTO=1 \
   -DLWS_WITH_SPAWN=1 -DLWS_WITH_SECURE_STREAMS=1
$ make -j && sudo make install && sudo ldconfig
$ cd ../..
$ git clone https://warmcat.com/repo/sai
$ cd sai && mkdir build && cd build && cmake .. -DSAI_SERVER=0 && make -j && sudo make install
$ sudo cp ../scripts/sai-builder.service /etc/systemd/system
$ sudo mkdir -p /etc/sai/builder
$ sudo cp ../scripts/builder-conf /etc/sai/builder/conf
```

The BSDs, macOS and Windows have their own service files and notes, see
[README-build-bsds.md](README-build-bsds.md),
[README-build-windows.md](README-build-windows.md) and the main README.

## 3. Installing Rust with rustup

Use rustup, not the distro's `rustc` / `cargo` packages.  Those are usually
too old: Ubuntu 24.04's is 1.75, and with that cargo can't even parse npro's
`Cargo.toml` (`` `resolver` setting `3` is not valid ``).

As root, run rustup's installer as `sai`, with `sai`'s `HOME`:

```
# sudo -u sai -H sh -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default --no-modify-path"
```

 - `-y` takes the defaults without asking: the stable toolchain for this
   machine's host triple, installed as the default.
 - `--profile default` includes rustfmt and clippy as well as rustc and
   cargo.  `--profile minimal` is enough if no job lints or formats.
 - `--no-modify-path` stops rustup editing `sai`'s `.profile` and similar
   files.  Jobs don't run a login shell, so those edits never reach them
   anyway.  The builder conf puts cargo on the jobs' `PATH` instead (step 4).

The toolchains go in `/home/sai/.rustup`, and cargo, rustc and the rest in
`/home/sai/.cargo/bin`.  Downloaded crates and anything you `cargo install`
also go under `/home/sai/.cargo`.  These are rustup's defaults under
`HOME`, and sai sets each job's `HOME` to the same `/home/sai`, so the jobs
find them without `RUSTUP_HOME` or `CARGO_HOME` being set.

Check it worked:

```
# sudo -u sai -H /home/sai/.cargo/bin/rustc --version
rustc 1.9x.y (...)
```

### Particular rustc versions

Stable is always newer than npro's `rust-version`, so stable alone is enough
for npro's `test` configuration.  If a job also has to build with the MSRV
itself (npro's `gate` does), install that version alongside stable:

```
# sudo -u sai -H /home/sai/.cargo/bin/rustup toolchain install 1.85 --profile minimal
```

Jobs pick it with `cargo +1.85 ...`.  The default stays stable.  For
nightly, use `rustup toolchain install nightly`, with `--component miri,rust-src`
for Miri.

### Hosts rustup doesn't support

rustup has no FreeBSD aarch64 host, so there use `pkg install rust` instead,
and check it is 1.85 or later.  The package's cargo is in `/usr/local/bin`,
which is already on the jobs' base `PATH`.

## 4. The builder conf

Edit `/etc/sai/builder/conf`.  The parts that matter for Rust are `"perms"`,
`"home"` and the platform's `"env"`:

```
{
	"perms":	"sai:nogroup",
	"home":		"/home/sai",
	"host":		"my-builder",
	"link-key":	"<the fleet's link-key, see the main README>",

	"platforms": [
		{
			"name":		"linux-ubuntu-2404/aarch64-a72-bcm2711-rpi4/gcc",
			"instances":	2,
			"env": [
				"PATH=/home/sai/.cargo/bin:$PATH"
			],
			"servers": [ "wss://libwebsockets.org:4444/sai/builder" ]
		}
	]
}
```

Jobs don't inherit sai-builder's environment.  They start with a fixed
`PATH=/usr/local/bin:/usr/bin:/bin` (see
[README-builder-env.md](README-builder-env.md)), so cargo has to be added to
it here.  Spell the path out: `HOME` is not set yet when `env` is expanded,
so `$HOME/.cargo/bin` would expand to `/.cargo/bin`.

npro's `scripts/sai.sh` also puts `$HOME/.cargo/bin` first on `PATH` itself,
so npro's unix jobs work without the `env` line.  Add it anyway: any other
Rust project's job, or a bare `cargo` step, needs it.

The platform name has to be one the project's `.sai.json` asks for.  npro
uses the same platform names as libwebsockets, so a builder that already
builds libwebsockets only needs Rust installed (step 3).

Then start it:

```
# systemctl enable --now sai-builder
```

## 5. Checking it from the job's point of view

This runs rustc with the same user, `HOME` and `PATH` a job gets:

```
# sudo -u sai env -i HOME=/home/sai LANG=en_US.UTF-8 \
    PATH=/home/sai/.cargo/bin:/usr/local/bin:/usr/bin:/bin \
    sh -c 'cd && rustc --version && cargo --version && rustup toolchain list'
```

`rustc` should be 1.85 or later, and not `/usr/bin/rustc` (`command -v
rustc` shows which one is found).  An admin can also open a sai-shell on a
task in the web UI, which runs with the job's real environment.

On a builder with no rustc, or one older than npro's `rust-version`, npro's
`sai.sh` stops before cargo starts and prints the rustup install line above.

## Builders in VMs and containers

 - **sai-virt**: jobs run in throwaway overlays of a base image.  Install
   rustup, toolchains and `cargo install`s in the **base image**: boot the
   base itself while no overlay of it is in use, do steps 1 - 5 there, then
   shut it down cleanly.  Anything installed from inside a job's overlay is
   lost when the overlay goes.  Rust also takes a lot of disk: a toolchain is
   around a gigabyte, and every extra toolchain or target adds more.  If you grow the
   base image, raise `"overlay_size"` to match (see
   [README-sai-virt.md](README-sai-virt.md)).

 - **systemd-nspawn**: install inside the container, as its `sai` user, as
   above.

 - **macOS**: install the Xcode command line tools (`xcode-select --install`)
   first, since rustc links with the system linker.  Then do step 3 as the
   `sai` user.  The base `PATH` there doesn't include `~/.cargo/bin` either,
   so the `env` line is still needed.

 - **Windows**: rustup has to go in a fixed location outside any user
   profile, with `RUSTUP_HOME`, `CARGO_HOME`, `PATH`, `SystemRoot`, `TEMP` and
   `TMP` set in the platform's `env`.  npro's `docs/sai.md` has the exact
   commands and the conf that works with its w11 builder.

## Keeping Rust up to date

Update between jobs, and in the base image for sai-virt:

```
# sudo -u sai -H /home/sai/.cargo/bin/rustup update
```

Pinned versions like `1.85` stay as they are.  Tools installed with `cargo
install` are not updated by this; reinstall them with `cargo install --locked
<name>` to get newer versions.

## When a job fails on setup

|What the job log shows|Why|Fix|
|---|---|---|
|`` `resolver` setting `3` is not valid ``, or ``feature `edition2024` is required``|the job found a distro cargo older than 1.85|install rustup as `sai` (step 3) and check `env` (step 4)|
|`cargo: not found`|cargo is not on the jobs' `PATH`|the `env` line in step 4|
|`no default toolchain configured`|rustup was installed but no toolchain was, or it went in another user's home|`rustup default stable`, as `sai`|
|something you installed earlier has gone|it was installed in a sai-virt overlay|install it in the base image|
|`toolchain '1.85-...' is not installed`|the job asked for a version that isn't installed|`rustup toolchain install 1.85`, as `sai`|
