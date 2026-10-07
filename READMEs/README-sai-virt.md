# Sai Virtualization Daemon (`sai-virt`)

`sai-virt` is a lightweight daemon that connects to `sai-server` as a power controller/agent. Instead of managing physical power outlets or static builders, it coordinates and spawns **ephemeral Virtual Machines (VMs)** on demand.

When `sai-virt` detects a pending job queue for a platform it supports, it spawns a transient instance of a VM template corresponding to that platform. Once the VM finishes the build or stays idle, it is destroyed, resetting the environment to a pristine state.

---

## 1. Installation & Service Setup

To run `sai-virt` as a persistent background daemon managed by systemd:

1. Build `sai-virt` by compiling the project (ensure `LWS_WITH_CLIENT`, `LWS_WITH_STRUCT_JSON`, and `LWS_WITH_SECURE_STREAMS` are enabled in `libwebsockets`).
2. Copy the systemd service template to the system directory:
   ```bash
   sudo cp scripts/sai-virt.service /etc/systemd/system/
   ```
3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now sai-virt
   ```

---

## 2. Configuration (`/etc/sai/virt/conf`)

`sai-virt` reads its configuration from `/etc/sai/virt/conf` (or custom path passed via `-c`). The config is a JSON file matching the schema below:

```json
{
        "perms":        "sai:nobody",
        "home":         "/home/sai",
        "hostname":     "virt-host-1",
        "max_vms":      4,

        "servers": [
                {
                        "url": "wss://libwebsockets.org:4444/sai/builder"
                }
        ],

        "platforms": [
                {
                        "name": "windows-x86_64"
                },
                {
                        "name": "mac-m1"
                },
                {
                        "name": "linux-fedora-x86_64"
                }
        ]
}
```

### Configuration Parameters
* **perms**: The `user:group` that the daemon drops privileges to after binding ports.
* **home**: The home directory for the daemon process.
* **hostname**: Hostname reported to the `sai-server` (masquerading as the power controller node).
* **max_vms**: The maximum number of concurrent VM instances allowed to run on this host.
* **servers**: Array of `sai-server` WebSocket endpoints to connect to.
* **platforms**: Array of platform strings representing the VM environments this host is capable of instantiating.

---

## 3. VM Creation & Registration

To make virtual machines available to `sai-virt`:

1. **Create a VM Template**: Using tools like `virt-install` or `virt-manager`, install your guest OS and configure it to run `sai-builder` automatically on boot (configured to connect to the local UDS/TCP ports, or directly to `sai-server`).
2. **Platform Mapping**: The VM's name or metadata in libvirt must associate it with the corresponding platform defined in `/etc/sai/virt/conf`. 
3. **Pristine State**: When `sai-virt` receives a command to spin up a builder for a platform, it looks for the defined template (e.g. `template-linux-fedora-x86_64`), clones/instantiates it, and boots it.

### Power settings in the template's sai-builder conf

`sai-virt` owns the lifetime of the VMs it spawns, and the power of the host they run on.  In the template, `sai-builder` should run with `-O` (one task per VM) or `-E` (one event per VM), and its `sai-power` url should point at `sai-virt`'s http listener: when the builder is idle, it asks there for `/auto-power-off/<host>` and `sai-virt` destroys the VM.

The template's builder conf should **not** carry `power_controller`, `power-on` or `power-off` settings, such as `"power-off": { "type": "suspend" }` or the virt host's MAC for WOL.  Those would only be copies of the virt host's details repeated in every template.  A builder started with `-O` or `-E` ignores them (and warns that it is doing so): it never suspends, and it doesn't register with `sai-power`.  If you boot a template by hand to maintain it, without `-O` / `-E`, its builder acts on whatever is in its conf, so remove those settings from the image.

Whether the virt host itself may sleep is not something `sai` decides; disable suspend on the host OS, eg, `systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target`, or GNOME's login screen may suspend it while it's idle at the console.

---

## 4. Multi-Use Read-Only OS & Dynamic Overlays

In a scalable build cluster, maintaining a separate copy of the OS disk image for every parallel VM consumes significant storage and creates maintenance overhead. Instead, we use a single **Read-Only (RO) OS Base Image** shared across multiple running instances, with a **Dynamic VM-specific copy-on-write (CoW) overlay** that stores writes and is discarded when the VM stops.

There are two primary methods to implement this in QEMU/libvirt:

### Method A: Libvirt Native `<transient/>` Disks (Recommended)

Libvirt natively supports transient disks for domains. When `<transient/>` is placed under a disk's XML specification, libvirt intercepts disk writes by creating a temporary copy-on-write overlay file overlaying the base image when the domain starts. When the VM is shut down or destroyed, libvirt automatically deletes the temporary overlay.

#### QEMU XML Configuration:
```xml
<disk type='file' device='disk'>
  <driver name='qemu' type='qcow2' discard='unmap'/>
  <!-- Point source to the shared read-only base OS image -->
  <source file='/var/lib/libvirt/images/fedora-base.qcow2'/>
  <target dev='vda' bus='virtio'/>
  <!-- Instruct libvirt to treat this disk as ephemeral/transient -->
  <transient/>
</disk>
```

#### How it works:
* Libvirt boots the VM using `/var/lib/libvirt/images/fedora-base.qcow2` as the backing store.
* An overlay file (e.g., `/var/lib/libvirt/images/fedora-base.qcow2.TRANSIENT`) is created on startup.
* Multiple VM instances can run concurrently using the same base file because the base image is opened in read-only mode by QEMU.
* Discard and deletion of the transient overlay are handled natively by libvirt upon domain destruction.

---

### Method B: Manual `qemu-img` Backing Chains

If your libvirt version or storage driver does not support the `<transient/>` tag natively, you can arrange for the overlay manually.

#### 1. Create a VM-specific overlay file prior to booting:
Before starting a VM instance, run `qemu-img` to create a new QCOW2 overlay image using the read-only OS layer as the backing file:
```bash
qemu-img create -f qcow2 -F qcow2 -b /var/lib/libvirt/images/fedora-base.qcow2 /var/lib/libvirt/images/sai-vm-fedora-instance1.qcow2
```

#### 2. QEMU XML Configuration:
In the domain XML for the ephemeral VM instance, define the disk source to point to the newly created overlay file:
```xml
<disk type='file' device='disk'>
  <driver name='qemu' type='qcow2' discard='unmap'/>
  <!-- Point source to the instance-specific overlay -->
  <source file='/var/lib/libvirt/images/sai-vm-fedora-instance1.qcow2'/>
  <target dev='vda' bus='virtio'/>
</disk>
```

#### 3. Orchestration in `sai-virt`:
* On **Spawn**: `sai-virt` generates a temporary XML file, runs `qemu-img create` to generate the unique overlay, updates the `<source>` tag in the XML, and runs `virsh create <temp-xml>`.
* On **Destroy**: `sai-virt` runs `virsh destroy <vm-name>` and then deletes the instance-specific overlay file from `/var/lib/libvirt/images/`.
