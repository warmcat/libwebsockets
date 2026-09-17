/*
 * lws-hls media directory listing
 *
 * Loaded by the listing the plugin composes at hls/ (see hls-dir.c).  The
 * page's CSP has no 'unsafe-inline', so everything the listing needs a
 * script for is bound from here:
 *
 *  - the delete buttons the plugin adds for an admin (button.del-btn with
 *    the plain filename in data-file): confirm, POST to hls/delete/<name>,
 *    and take the item out of the page on success.  The server decides
 *    who gets the buttons and enforces it again on the POST, so this only
 *    has to drive the UI
 *
 *  - a resume badge over the thumbnail of anything the player left a
 *    resume position for in localStorage, keyed the same way player.js
 *    keys it (sha-256 of "<?v=>_<?t=>" under "lws_hls_"); the thumbnail
 *    itself is then re-requested at that position (preview/<name>/<secs>,
 *    bucketed so the server's cache is not asked for every second), so
 *    the viewer sees the frame they will resume at
 *
 *  - the order: the server lists newest file first; here each item's date
 *    becomes the later of the file's date and when this viewer last
 *    watched it, so what they were watching recently sits at the top
 *    alongside what was recently added
 */

document.addEventListener('DOMContentLoaded', function() {
    if (typeof window.renderLwsLoginStatus === 'function')
        window.renderLwsLoginStatus('auth-status');

    var btns = document.querySelectorAll('button.del-btn');
    for (var i = 0; i < btns.length; i++)
        btns[i].addEventListener('click', delFile);

    function delFile(event) {
        var btn = event.currentTarget;
        var name = btn.getAttribute('data-file');

        event.preventDefault();
        event.stopPropagation();

        /* the listing only ever names plain files in media-dir */
        if (!name || !name.length || name === '.' || name === '..' ||
            name.indexOf('/') !== -1 || name.indexOf('\\') !== -1)
            return;

        if (!confirm('Delete "' + name + '"?'))
            return;

        btn.disabled = true;

        fetch('delete/' + encodeURIComponent(name), {
            method: 'POST',
            credentials: 'same-origin'
        }).then(function(res) {
            if (!res.ok)
                /* the status page body carries the reason */
                return res.text().then(function(t) {
                    t = t.replace(/<h1>.*?<\/h1>/, '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
                    throw new Error('HTTP ' + res.status + (t ? ': ' + t : ''));
                });
            var item = btn.closest('.item');
            if (item)
                item.remove();
        }).catch(function(e) {
            btn.disabled = false;
            alert('Failed to delete "' + name + '": ' + e.message);
        });
    }

    /* resume badges */

    function getHash(str) {
        if (window.crypto && crypto.subtle) {
            return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(function(buf) {
                return Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
            });
        }
        return new Promise(function(resolve) {
            var hash = 0;
            for (var i = 0; i < str.length; i++) hash = ((hash << 5) - hash) + str.codePointAt(i) | 0;
            resolve(hash.toString(36));
        });
    }

    function fmtTime(s) {
        s = Math.floor(s);
        var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
        var mm = (h ? String(m).padStart(2, '0') : m) + ':' + String(sec).padStart(2, '0');
        return h ? h + ':' + mm : mm;
    }

    /* preview/<name>/<secs> is cached per (name, secs) on the server:
     * ask in buckets so a resume point drifting by a few seconds between
     * visits does not mean a fresh decode each time */
    var THUMB_T_BUCKET = 5;

    var items = document.querySelectorAll('.item');
    var order = [];     /* { el, date } for the sort once all are known */
    var pending = items.length;

    function placed(el, date) {
        order.push({ el: el, date: date });
        if (--pending)
            return;

        /* stable: equal dates keep the server's (newest file first) order */
        order.forEach(function(o, i) { o.i = i; });
        order.sort(function(x, y) {
            return (y.date - x.date) || (x.i - y.i);
        });
        var parent = order[0].el.parentNode;
        order.forEach(function(o) { parent.appendChild(o.el); });
    }

    for (var j = 0; j < items.length; j++) (function(item) {
        var a = item.querySelector('a[href]');
        var img = item.querySelector('img.thumb');
        var q, fileDate = 0;

        try {
            q = new URL(a.getAttribute('href'), window.location.href).searchParams;
        } catch (e) {
            placed(item, 0);
            return;
        }
        var v = q.get('v'), t = q.get('t') || '0';
        if (!v) {
            placed(item, 0);
            return;
        }
        /* ?t= is the file's mtime in seconds, from the listing */
        fileDate = (parseInt(t, 10) || 0) * 1000;

        getHash(v + '_' + t).then(function(hk) {
            var saved, parsed;
            try {
                saved = localStorage.getItem('lws_hls_' + hk);
                if (saved)
                    parsed = JSON.parse(saved);
            } catch (e) {
                parsed = null;
            }
            if (!parsed || typeof parsed.pos !== 'number' || !parsed.pos ||
                typeof parsed.ts !== 'number' ||
                Date.now() - parsed.ts >= 604800000 /* 1 week, as the player */) {
                placed(item, fileDate);
                return;
            }

            var badge = document.createElement('span');
            badge.className = 'resume-badge';
            /* escaped, so it survives whatever charset we are decoded as */
            badge.textContent = '\u25B6 ' + fmtTime(parsed.pos) +
                (parsed.dur ? ' / ' + fmtTime(parsed.dur) : '');
            a.appendChild(badge);

            /* the frame at the resume point, for this viewer only */
            if (img) {
                var secs = Math.floor(parsed.pos / THUMB_T_BUCKET) * THUMB_T_BUCKET;
                img.setAttribute('src', img.getAttribute('src') + '/' + secs);
            }

            placed(item, Math.max(fileDate, parsed.ts));
        }).catch(function() {
            placed(item, fileDate);
        });
    })(items[j]);
});
