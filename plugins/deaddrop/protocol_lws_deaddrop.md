# lws-deaddrop

## Introduction

The `lws-deaddrop` plugin implements an authenticated file upload server feature (a "deaddrop") over WebSocket and HTTP POST. Authorized users can securely upload files using multipart/form-data. The server also monitors the configured upload directory (using `inotify` on Linux platforms) to present an active browser listing of shared files between authenticated users directly over a WebSockets portal connection.

## Per-Vhost Options (PVOs)

This plugin accepts the following configuring Per-Vhost Options (PVOs):

| PVO Name | Description |
|---|---|
| `upload-dir` | **Required.** An absolute file path pointing to the directory where uploaded files should be stored by the server. |
| `max-size` | Optional integer expressing the maximum permitted file upload size in bytes. Any file POSTs over this size will be aborted with an HTTP 413 "Payload Too Large". Defaults to `20971520` (20MB). |
