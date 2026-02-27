# lws-sshd-demo

## Introduction

The `lws-sshd-demo` plugin uses the `lws-ssh-base` abstraction protocol to serve as a lightweight demo SSH server. It loads an SSH server private key at startup (creating one natively if missing), natively handles logging in via `ssh-rsa` user public keys, and simply spins up an echo loop to interact with connected clients once the SSH shell executes.

## Per-Vhost Options (PVOs)

This plugin doesn't look for any specific customization Per-Vhost Options (PVOs). It simply inherits operations associated with handling SSH server endpoints.
