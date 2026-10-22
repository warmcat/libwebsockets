# lws minimal http server form POST file

## build

```
 $ cmake . && make
```

## Commandline Options

Option|Meaning
---|---
-d|Set logging verbosity
--port <port>|Port to listen on (default 7681)
--upload-dir <dir>|Directory uploads are saved in, created if missing (default ./uploads)
--max-size <bytes>|Largest file accepted (default 10485760, 10MiB)
--max-files <count>|Most files stored per run of the server (default 100)
--help|Show the options

## usage

```
 $ ./lws-minimal-http-server-form-post-file --port 7681
[2026/10/22 09:58:30:8800] U: LWS minimal http server POST file | visit http://localhost:7681
[2026/10/22 09:58:30:8800] U: Saving uploads in ./uploads, max 10485760 bytes each, max 100 files
[2026/10/22 09:58:45:3284] U: file_upload_cb: upload done, written 2729 to ./uploads/wss-over-h2.png
[2026/10/22 09:58:45:3284] U: text1: (len 3) 'xxx'
[2026/10/22 09:58:45:3284] U: send: (len 6) 'Submit'
```

Visit http://localhost:7681, select a file to upload and submit the form.

The file is uploaded and saved in the upload directory, the form parameters are
dumped to the log and you are redirected (303) to a different page.

## Handling untrusted uploads

Anyone who can reach the server can upload, so the example treats everything
about an upload as hostile:

 - The filename the client sends is only used as a single path component
   inside the upload directory.  `lws_filename_purify_inplace()` replaces
   path separators, "..", a leading '.', control characters and the like, so
   `/etc/passwd` is stored as `uploads/_etc_passwd` and `../x` as
   `uploads/___x`.

 - Files are created with `O_CREAT | O_EXCL | O_NOFOLLOW`: a name that
   already exists in the upload directory, including a symlink, is refused
   with `409 Conflict`, never followed or overwritten.

 - A file bigger than `--max-size` is refused with `413`, and whatever was
   written of it is removed.  lws itself refuses a request whose declared
   body is more than 16KiB bigger than that, before any of it is read.

 - At most `--max-files` files are stored per run of the server; after that
   uploads are refused with `503`.  An upload that is refused or abandoned
   does not count.

 - An upload that doesn't complete, because the client went away or the
   form ended mid-file, is removed: nothing is left behind, neither a partial
   file nor an open fd.

The spa that parses the form is freed when the request body completes, and
when the connection closes, since lws gives no callback when the per-request
user data of a default (unbound) protocol is freed.

A real server must also authenticate who may upload at all, and would usually
store uploads under names it generates itself, keeping the client's filename
only as metadata.

## Testing

`api-test-form-post-file` runs this example as a ctest fixture and uploads to
it hostile filenames (absolute paths, `../`, an existing name and a symlink
planted in the upload dir), oversize files, an abandoned upload and more files
than the budget allows, checking nothing is written outside the upload
directory and nothing partial is left in it.
