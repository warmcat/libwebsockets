# Sai Virtualization Daemon (`sai-virt`)

`sai-virt` is a lightweight daemon that connects to `sai-server` as a power controller/agent. Instead of managing physical power outlets or static builders, it coordinates and spawns **ephemeral Virtual Machines (VMs)** on demand.

When `sai-virt` detects a pending job queue for a platform it supports, it spawns a transient clone of a "basis" VM for that platform. Once the VM finishes the build or stays idle, it is destroyed, and the next one starts again from the pristine basis image.

---

## 1. Installation & Service Setup

To run `sai-virt` as a persistent background daemon managed by systemd:

1. Build `sai-virt` by compiling the project (ensure `LWS_WITH_CLIENT`, `LWS_WITH_STRUCT_JSON`, and `LWS_WITH_SECURE_STREAMS` are enabled in `libwebsockets`).  It needs libvirt and its development headers on the virt host.
2. Copy the systemd service template to the system directory:
   ```bash
   sudo cp scripts/sai-virt.service /etc/systemd/system/
   ```
3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now sai-virt
   ```

`sai-virt` talks to libvirt at `qemu:///system`, and listens on port 8000 for http requests from the builders in its VMs (`/stay/<vm>` and `/auto-power-off/<vm>`).  Those requests are not authenticated, so the port must only be reachable from the VMs' network.  On a firewalld host (Fedora, Rocky, RHEL...) the libvirt `default` network is in the `libvirt` zone, which doesn't allow it by default:

```bash
sudo firewall-cmd --permanent --zone=libvirt --add-port=8000/tcp
sudo firewall-cmd --reload
```

Whether the virt host itself may sleep is not something `sai` decides; disable suspend on the host OS, or eg, GNOME's login screen may suspend it while it's idle at the console:

```bash
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
```

---

## 2. Configuration

### Global: `/etc/sai/virt/conf`

```json
{
        "link-key":     "<the fleet link secret, as configured on sai-server>",
        "max_vms":      4,

        "servers": [
                {
                        "url": "wss://libwebsockets.org:4444/sai/builder"
                }
        ]
}
```

* **link-key**: The fleet link secret; `sai-server` refuses the connection without it.  It's a secret, keep the conf readable only by root.
* **max_vms**: The maximum number of concurrent VM instances allowed to run on this host.
* **servers**: Array of `sai-server` WebSocket endpoints to connect to.

The name `sai-virt` reports to `sai-server` as its power controller is the host's hostname.

### Platforms: `/etc/sai/virt/conf.d/*`

Each file in `/etc/sai/virt/conf.d/` describes one platform `sai-virt` can spawn VMs for, eg `/etc/sai/virt/conf.d/rocky10`:

```json
{
        "name":         "linux-rocky10-x86_64",
        "platform":     "linux-rocky-10/x86_64-amd/gcc",
        "base_image":   "/var/lib/libvirt/images/rocky10-sai.qcow2",
        "overlay_size": "40G"
}
```

* **name**: The name of the basis VM's libvirt domain (see below).  The VMs spawned from it are named `sai-vm-<name>-<n>`.
* **platform**: The sai platform string the VMs build for; it must match the platform `name` in the basis VM's sai-builder conf.  If not given, `name` is used.
* **base_image**: The basis VM's disk image.  This must be *exactly* the path in the `<source file='...'/>` of the basis domain's disk, see section 4.
* **overlay_size**: The size of the disk the spawned VMs see, eg `40G` (default `20G`).  It should be at least the virtual size of `base_image`.

---

## 3. Preparing a basis VM from a cloud image

Distros publish "cloud" qcow2 images (eg Rocky / Alma / Fedora "GenericCloud", Debian "genericcloud", Ubuntu "cloudimg") that boot straight into an installed system, so they make a good starting point.  Out of the box they have no user you can log in as and no password: they expect `cloud-init`, inside the image, to set those up at first boot from data the cloud provides.  `virt-install` can provide that data itself, so we let `cloud-init` create our user on the basis VM's first boot, and then switch it off for good.

Everything is done by the guest itself, so it works the same whether the image is for the virt host's CPU architecture or another one (eg an aarch64 image on an x86_64 host).  (Editing the image offline with `virt-customize` can't run commands like `useradd` in an image for a different architecture.)

The examples use Rocky 10 on a Rocky / Fedora virt host; adjust names and paths for other distros.

### 3.1 Get the image and give it room

On the virt host, install `virt-install` and fetch the image:

```bash
sudo dnf install virt-install          # Debian / Ubuntu: apt install virtinst
cd /var/lib/libvirt/images
sudo curl -LO https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2
sudo mv Rocky-10-GenericCloud-Base.latest.x86_64.qcow2 rocky10-sai.qcow2
```

Cloud images are small (typically ~10GB virtual).  Builds need more space, so grow the image's virtual disk now; `cloud-init` grows the root partition and filesystem into it on first boot.

```bash
sudo qemu-img resize rocky10-sai.qcow2 40G
```

### 3.2 Write the first-boot user-data

This `cloud-init` user-data creates your own admin user, with a password (for `virsh console`, when networking is broken), passwordless sudo and your ssh public key, and has `cloud-init` disable itself once it has done that:

```bash
U=andy
HASH=$(openssl passwd -6)       # prompts for the password, so it doesn't land in your shell history

cat > /tmp/sai-user-data <<EOF
#cloud-config
users:
  - name: $U
    shell: /bin/bash
    lock_passwd: false
    passwd: '$HASH'
    sudo: 'ALL=(ALL) NOPASSWD:ALL'
    ssh_authorized_keys:
      - $(cat ~/.ssh/id_ed25519.pub)
runcmd:
  - touch /etc/cloud/cloud-init.disabled
EOF
unset HASH
```

* **users**: Listing our user, without `default`, means the distro's usual cloud user (eg `rocky`) isn't created.  Only the password's hash is in the file.  Use `lock_passwd: true` and no `passwd` instead if you only want key-based ssh, but a password is what lets you in on `virsh console` when the network isn't working.
* **sudo**: works the same whatever the distro calls its admin group (`wheel`, `sudo`).  Root's password stays locked; you use sudo.
* **cloud-init.disabled**: after this first boot there's no cloud data any more, and `cloud-init` would spend time at every boot looking for some.  Our clones boot many times a day and should do the same thing every time.

### 3.3 Define the basis VM

The basis VM is an ordinary libvirt domain, named as in the platform's conf.d `name`.  Its CPU, RAM and devices are what every VM spawned from it gets.

```bash
sudo virt-install --name linux-rocky10-x86_64 --import \
        --disk path=/var/lib/libvirt/images/rocky10-sai.qcow2,format=qcow2,bus=virtio \
        --cloud-init user-data=/tmp/sai-user-data \
        --osinfo detect=on,require=off \
        --memory 8192 --vcpus 4 \
        --network network=default \
        --graphics none --noautoconsole
rm /tmp/sai-user-data
```

`virt-install` attaches the user-data on a small CD-ROM image for the first boot only, so the basis domain, and the VMs spawned from it, don't have it.

For an image of a different architecture, add eg `--arch aarch64`.  The virt host needs QEMU's emulator for that architecture (eg `qemu-system-aarch64`, which RHEL-family hosts don't ship), and with no hardware virtualization it runs much slower, as will the VMs spawned from it.

It boots the VM for the first time straight away.  Once `cloud-init` is done, find its address and log in with your key:

```bash
sudo virsh domifaddr linux-rocky10-x86_64
ssh andy@192.168.122.x
```

(or `sudo virsh console linux-rocky10-x86_64` with your password; `Ctrl-]` leaves it.)

### 3.4 First boot: check the image, install sai-builder

Check `cloud-init` finished cleanly and grew the root filesystem into the space added in 3.1:

```bash
cloud-init status --long
df -h /
```

#### Networking on Debian / Ubuntu images

Rocky / Alma / Fedora images use NetworkManager, which brings up DHCP on any wired interface without needing configuration, so nothing more is needed there.

On Debian and Ubuntu cloud images, `cloud-init` generated the network config on first boot, and it matches the NIC's MAC address.  Since each spawned VM gets a new MAC, replace it with a config that doesn't care about the MAC, eg for netplan-based images:

```bash
echo 'network: {version: 2, ethernets: {wired: {match: {name: "en*"}, dhcp4: true}}}' | \
        sudo tee /etc/netplan/90-sai.yaml
sudo chmod 600 /etc/netplan/90-sai.yaml
sudo rm /etc/netplan/50-cloud-init.yaml
```

#### sai-builder

Bring the image up to date and install your build dependencies, then build and install libwebsockets and `sai-builder` in the usual way.  Then create the `sai` user the builder runs as:

```bash
sudo useradd -m sai
```

The builder conf, `/etc/sai/builder/conf`, points the builder at `sai-virt` on the virt host's address on the libvirt network (192.168.122.1 for libvirt's `default` network) as its `sai-power`:

```json
{
        "perms":        "sai:nobody",
        "home":         "/home/sai",
        "host":         "rocky10-basis",
        "link-key":     "<the fleet link secret>",
        "sai-power":    "http://192.168.122.1:8000",

        "platforms": [
                {
                        "name":         "linux-rocky-10/x86_64-amd/gcc",
                        "instances":    1,
                        "servers": [ "wss://libwebsockets.org:4444/sai/builder" ]
                }
        ]
}
```

* **host**: Each spawned VM replaces this with its own name, `sai-vm-<name>-<n>`, which `sai-virt` passes in through QEMU's fw_cfg, so this is only a placeholder.
* **link-key**: Since the image now contains the fleet secret, don't share the image, and keep the conf root-only (`sudo chmod 600 /etc/sai/builder/conf`).
* Don't add `power_controller`, `power-on` or `power-off` settings, see 3.6.

Linux reads its identity from `/sys/firmware/qemu_fw_cfg`; make sure the driver for it is always loaded:

```bash
echo qemu_fw_cfg | sudo tee /etc/modules-load.d/qemu_fw_cfg.conf
```

Install `/etc/systemd/system/sai-builder.service` like this.  `-O` makes it build one task and then have the VM destroyed (`-E` instead keeps it for further tasks from the same event).  The `ConditionPathExists` means the builder only starts in VMs `sai-virt` spawned, not when you boot the basis VM yourself to maintain it, when it would otherwise take real tasks and build them into the basis image.

```ini
[Unit]
Description=Sai Builder
After=network-online.target
Wants=network-online.target
ConditionPathExists=/sys/firmware/qemu_fw_cfg/by_name/opt/sai_builder_id/raw

[Service]
ExecStart=/usr/local/bin/sai-builder -O

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable sai-builder
```

### 3.5 Shut it down, and leave it down

Booting the basis VM gave it a machine-id.  Empty it as the last thing before shutting down, so each spawned VM generates its own at boot.  Otherwise every clone has the same one, and things derived from it, like the DHCP client id `systemd-networkd` sends, collide, so concurrent clones fight over one IP address.  Do this again whenever you shut the basis VM down after maintenance.

```bash
sudo truncate -s 0 /etc/machine-id && sudo poweroff
```

The basis VM must stay defined, and shut off.  Its disk is the read-only backing file of every running VM spawned from it; **booting the basis VM while any of those exist corrupts them**.  `sai-virt` won't spawn new VMs while the basis VM is running, but it can't protect ones that are already running.  To maintain the basis image, stop `sai-virt` first (it destroys its VMs as it exits), then boot the basis VM, make your changes, shut it down and start `sai-virt` again.

Then add the platform's file in `/etc/sai/virt/conf.d/` and restart `sai-virt`.  To debug a spawned VM, it's on the same network and has your key, so you can find it with `sudo virsh list` and `sudo virsh domifaddr sai-vm-...` and ssh in, or use its console.

### 3.6 Power settings in the basis VM's sai-builder conf

`sai-virt` owns the lifetime of the VMs it spawns, and the power of the host they run on.  When the builder in a spawned VM is idle, it asks `sai-virt`, at its `sai-power` url, for `/auto-power-off/<vm>`, and `sai-virt` destroys the VM.

So the basis VM's builder conf should **not** carry `power_controller`, `power-on` or `power-off` settings, such as `"power-off": { "type": "suspend" }` or the virt host's MAC for WOL.  Those would only be copies of the virt host's details repeated in every basis image.  A builder started with `-O` or `-E` ignores them (and warns that it is doing so): it never suspends, and it doesn't register with `sai-power`.

---

## 4. How a VM is spawned

When `sai-virt` decides to spawn a VM for a platform:

1. It creates a qcow2 overlay, `/dev/shm/sai-vm-<name>-<n>.qcow2`, of `overlay_size`, with `base_image` as its read-only backing file, in a libvirt storage pool `sai_shm` it creates on `/dev/shm`.
2. It takes the basis domain's XML and changes the name to `sai-vm-<name>-<n>` and the disk source from `base_image` to the overlay.  The disk source is replaced by matching `file='<base_image>'` literally, so `base_image` in the conf must be the same path the basis domain uses.  If it isn't, eg because of a typo, `sai-virt` refuses to spawn the VM, which would otherwise boot writing to the basis image itself, and logs the disk paths the basis domain does have.  It also refuses while the basis domain is running.
3. It removes the UUID and NIC MAC addresses so libvirt generates new ones, and adds the VM's name as the SMBIOS serial (`sai_builder_id:<vm>`) and the QEMU fw_cfg entry `opt/sai_builder_id`, for the builder inside to use as its identity.
4. It boots the result as a transient domain.

The VM is destroyed, and its overlay deleted, when its builder asks for `/auto-power-off`, if it never contacts `sai-virt` within 5 minutes of starting, or if its builder stops polling `/stay` for 90s.  `sai-virt` also destroys any `sai-vm-*` domains left over from a previous run when it starts.

Since the overlays are on `/dev/shm`, everything the VMs write to disk is held in the virt host's RAM until the VM is destroyed.  `/dev/shm` is normally limited to half the RAM, and that's shared by all the running VMs, along with the RAM given to the VMs themselves, so size `max_vms`, the basis VM's memory and `overlay_size` together for what the host has.
