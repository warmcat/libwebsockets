/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Mount and unmount overlayfs mountpoints (linux only)
 */

#include "private-lib-core.h"
#include <unistd.h>

#include <libmount/libmount.h>

#include <string.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

static int
rm_rf_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	char path[384];

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);

	if (lde->type == LDOT_DIR) {
		lws_dir(path, NULL, rm_rf_cb);
		rmdir(path);
	} else
		unlink(path);

	return 0;
}

/*
 * ovname, distro and the layer names are pasted both into the overlayfs mount
 * option string (where ':' separates lowerdirs and ',' separates options) and
 * into a path we then recursively delete.  Confine them to a conservative
 * alphabet, so that neither the option string can be extended with attacker-
 * chosen lowerdir / upperdir / workdir options, nor the deletion walked out of
 * the overlay base by a '/' or a ".." component.
 */

static int
fsmount_name_ok(const char *name)
{
	const char *p = name;

	if (!name || !*name || !strcmp(name, "..") || !strcmp(name, "."))
		return 0;

	while (*p) {
		if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
		    !(*p >= '0' && *p <= '9') &&
		    *p != '.' && *p != '_' && *p != '-')
			return 0;
		p++;
	}

	return 1;
}

int
lws_fsmount_mount(struct lws_fsmount *fsm)
{
	struct libmnt_context *ctx;
	char opts[512], c;
	int n, m;

	/*
	 * These come from the caller's config or, typically, from a job
	 * description that arrived over the network... validate them before
	 * they are pasted into a mount option string or into a path we rm -rf.
	 * They are fixed-size arrays, so also confirm they are terminated.
	 */

	if (!memchr(fsm->ovname, '\0', sizeof(fsm->ovname)) ||
	    !memchr(fsm->distro, '\0', sizeof(fsm->distro)) ||
	    !fsmount_name_ok(fsm->ovname) || !fsmount_name_ok(fsm->distro)) {
		lwsl_err("%s: bad ovname or distro\n", __func__);

		return 1;
	}

	for (m = 0; m < (int)LWS_ARRAY_SIZE(fsm->layers); m++)
		if (fsm->layers[m] && !fsmount_name_ok(fsm->layers[m])) {
			lwsl_err("%s: bad layer name\n", __func__);

			return 1;
		}

	/*
	 * For robustness, there are a couple of sticky situations caused by
	 * previous mounts not cleaning up... 1) still mounted on the mountpoint
	 * and 2) junk in the session dir from the dead session.
	 *
	 * For 1), do a gratuitous umount attempts until it feels nothing to
	 * umount...
	 */

	c = fsm->mp[0];
	while (!lws_fsmount_unmount(fsm))
		fsm->mp[0] = c;
	fsm->mp[0] = c;

	/*
	 * ... for 2), generate the session dir basepath and destroy everything
	 * in it... it's less dangerous than it sounds because there are
	 * hardcoded unusual dir names in the base path, so it can't go wild
	 * even if the overlay path is empty or /
	 */

	lws_snprintf(opts, sizeof(opts), "%s/overlays/%s/session",
		     fsm->overlay_path, fsm->ovname);
	lwsl_info("%s: emptying session dir %s\n", __func__, opts);
	lws_dir(opts, NULL, rm_rf_cb);

	/*
	 * Piece together the options for the overlay mount...
	 */

	/*
	 * lws_snprintf() returns the given size on truncation, so after any
	 * append n may be exactly sizeof(opts)... check after each one, since
	 * continuing would write opts[sizeof(opts)] with the ':' below and then
	 * underflow the remaining-length arg to (size_t)-1.  A truncated mount
	 * option string is unusable anyway, since it would name the wrong dirs.
	 */

	n = lws_snprintf(opts, sizeof(opts), "lowerdir=");
	for (m = LWS_ARRAY_SIZE(fsm->layers) - 1; m >= 0; m--)
		if (fsm->layers[m]) {
			if (n >= (int)sizeof(opts) - 1)
				goto too_long;

			if (n != 9)
				opts[n++] = ':';

			n += lws_snprintf(&opts[n], sizeof(opts) - (size_t)n,
					  "%s/%s/%s", fsm->layers_path,
					  fsm->distro, fsm->layers[m]);
			if (n >= (int)sizeof(opts))
				goto too_long;
		}

	n += lws_snprintf(&opts[n], sizeof(opts) - (size_t)n,
			  ",upperdir=%s/overlays/%s/session",
			  fsm->overlay_path, fsm->ovname);
	if (n >= (int)sizeof(opts))
		goto too_long;

	n += lws_snprintf(&opts[n], sizeof(opts) - (size_t)n,
			  ",workdir=%s/overlays/%s/work",
			  fsm->overlay_path, fsm->ovname);
	if (n >= (int)sizeof(opts))
		goto too_long;

	ctx = mnt_new_context();
	if (!ctx)
		return 1;

	mnt_context_set_fstype(ctx, "overlay");
	mnt_context_set_options(ctx, opts);
	mnt_context_set_mflags(ctx, MS_NOATIME /* |MS_NOEXEC */);
	mnt_context_set_target(ctx, fsm->mp);
	mnt_context_set_source(ctx, "none");

	lwsl_notice("%s: mount opts %s\n", __func__, opts);
	puts(opts);

	m = mnt_context_mount(ctx);
	lwsl_notice("%s: mountpoint %s: %d\n", __func__, fsm->mp, m);

	mnt_free_context(ctx);

	return m;

too_long:
	lwsl_err("%s: overlay paths too long\n", __func__);

	return 1;
}

int
lws_fsmount_unmount(struct lws_fsmount *fsm)
{
	struct libmnt_context *ctx;
	int m;

	lwsl_notice("%s: %s\n", __func__, fsm->mp);

	ctx = mnt_new_context();
	if (!ctx)
		return 1;

	mnt_context_set_target(ctx, fsm->mp);

	m = mnt_context_umount(ctx);
	mnt_free_context(ctx);

	fsm->mp[0] = '\0';

	return m;
}
