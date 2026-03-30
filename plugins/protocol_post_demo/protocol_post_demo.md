# protocol-post-demo

## Introduction

The `protocol-post-demo` plugin provides an example implementation of parsing `POST` body data natively inside a libwebsockets vhost. Specifically, it uses `lws_spa` (the stateful post argument parser) to accept multipart form uploads, extracting fields named `text` and `send`, parsing uploaded file contents natively under the field name `file`. Form completion results in a generated HTML summary page reflecting what the server successfully extracted.

## Per-Vhost Options (PVOs)

This plugin operates natively on its mount URL entirely without the need for Per-Vhost Options (PVOs) at instantiation.
