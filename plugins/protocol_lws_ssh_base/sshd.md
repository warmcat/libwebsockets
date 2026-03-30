# lws-ssh-base

## Introduction

The `lws-ssh-base` plugin implements a foundational SSH server protocol natively integrated within the libwebsockets event loop handling. It manages the low-level asymmetric cryptographic handshakes (e.g., KEX initialization, Elliptic Curve Diffie-Hellman), cipher negotiations, packet decryptions (like `chacha20-poly1305`), and user authorization mechanisms (like `ssh-rsa`). Other plugins, like `lws-sshd-demo`, build upon this abstract protocol by defining the interactive PTY/Shell `lws_ssh_ops` logic.

## Per-Vhost Options (PVOs)

This plugin requires operations callbacks passed through Per-Vhost Options (PVOs) during instantiation to dictate the business logic for the SSH sessions:

| PVO Name | Description |
|---|---|
| `ops` | Raw pointer to a `const struct lws_ssh_ops` structure. Passed natively by the instantiation code when setting up the listening vhost in C. |
| `ops-from` | Alternative to `ops`: String name of another loaded protocol whose `.user` data pointer points directly to the `const struct lws_ssh_ops` structure to be used. |
