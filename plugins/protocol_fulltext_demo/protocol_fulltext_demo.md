# lws-test-fts

## Introduction

The `lws-test-fts` plugin provides a full-text search (FTS) index lookup handler over HTTP. Acting as a basic endpoint for search queries and autocompletion routines, it accesses an underlying trie-structured search index built using the LWS FTS APIs. It resolves the requested parameters natively, providing autocomplete suggestions (`/a/`) or the associated list of matching indexed file hits (`/r/`) based on the requested needle.

## Per-Vhost Options (PVOs)

This plugin handles the following Per-Vhost Options (PVOs):

| PVO Name | Description |
|---|---|
| `indexpath` | **Required.** An absolute file path where the pre-generated FTS index file to be searched against is stored. |
