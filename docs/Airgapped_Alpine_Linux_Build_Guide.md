# 🛡️ Airgapped Alpine Linux Build Guide

**Hardened RAM-Only OS for Raspberry Pi 4/5**

This guide provides a workflow for creating a bootable drive or image that only loads the `entropylab.html` application using Alpine Linux and Chromium. This build is optimized for creation on an M-Series Apple Mac.

> [!CAUTION]
> **Hardware Requirement:** This diskless build requires a Raspberry Pi 4 or 5 with **at least 2GB of RAM**. Because the entire operating system and package set are loaded into a RAM disk (`tmpfs`) during boot, 1GB models will likely encounter Out-of-Memory (OOM) errors and fail to boot.

## 🎯 Project Goal

To create a "zero-trust" RAM-only runtime environment where the attack surface is minimized.

### The Hardening Strategy:

1. **Hardware Layer:** WiFi and Bluetooth radios disabled at the firmware level (`usercfg.txt`).
2. **Kernel Layer:** Network stack initialization disabled via `ip=off` in `cmdline.txt` and all network drivers physically deleted from the root filesystem.
3. **Privilege Layer:** Chromium runs as a low-privileged user (`entropylab`), NOT root. This enables the **Chromium Sandbox**, the primary defense against OS-level attacks.
4. **Browser Layer:** Hardened flags (Incognito, No-Sync, No-Extensions) to prevent data persistence. The UI is served via a local, read-only internal web server rather than using permissive local file flags.

---

## 🛠️ Build Instructions (macOS M-Series)

This workflow is optimized for Apple Silicon (M1/M2/M3/M4) to utilize native ARM64 containerization.

### 1. System Bootstrap

This verifies your hardware and installs **OrbStack** (the lightweight container engine) and the necessary GNU tools.

```zsh
# Check for Apple Silicon
if [ "$(uname -m)" != "arm64" ]; then
    echo "❌ This workflow requires an Apple Silicon Mac."
    exit 1
fi

# Install Homebrew if missing
if ! command -v brew &> /dev/null; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

brew update
echo "Installing OrbStack and GNU tools..."
brew install --cask orbstack
brew install coreutils gnu-sed

# Ensure Homebrew paths are recognized in the current session
export PATH="/opt/homebrew/bin:$PATH"

echo "✅ System Bootstrap Complete."
```

### 2. Workspace & Asset Setup

This creates the project folder in the **root level of your User folder** (e.g., `/Users/yourname/entropylab`).

```zsh
mkdir -p ~/entropylab/{boot,cache,ovl_root,app_assets}
cd ~/entropylab
```

> [!CAUTION]
> **STOP: Asset Placement Required**
> The build automation expects the entropylab.html file to reside in ~/entropylab/app_assets.
> You must rename your main HTML file to entropylab.html before moving it into that folder.

### 3. Minimal Package Fetching

This fetches the packages needed to build the image.

**IMPORTANT:** You must open the **OrbStack** application from your Applications folder and ensure the engine is "Running" before executing this step.

```zsh
docker run --rm -v $(pwd):/work -w /work --platform linux/arm64 alpine:latest sh -c "
  apk update && \
  apk fetch --recursive -o /work/cache \
    alpine-base \
    cage \
    chromium \
    font-dejavu \
    mesa-dri-gallium \
    wayland-protocols \
    eudev \
    eudev-openrc
"
```

### 4. The Hardened Overlay (apkovl)

**4.1 Privilege Separation Setup**
This prepares the home directory structure. The user `entropylab` will be created dynamically by a service script upon boot.

```zsh
mkdir -p ovl_root/home/entropylab
```

**4.2 Media Mount Logic (Udev & Shell Script)**
This detects whether an inserted device is a USB drive or an SD card. 
- SD cards are always mounted to `/mnt/sdcard`.
- USB drives are mounted to `/mnt/usb_[LABEL]`, where [LABEL] is the name of the drive.
This allows for multiple USB drives to be used simultaneously.

```zsh
# Create the udev rule to trigger on ANY partition addition
mkdir -p ovl_root/etc/udev/rules.d
cat << 'EOF' > ovl_root/etc/udev/rules.d/99-automount.rules
ACTION=="add", SUBSYSTEM=="block", ENV{DEVTYPE}=="partition", RUN+="/usr/local/bin/auto-mount.sh %N"
EOF

# Create the smart mount script
mkdir -p ovl_root/usr/local/bin
cat << 'EOF' > ovl_root/usr/local/bin/auto-mount.sh
#!/bin/sh
DEVNAME=$1

# Identify the bus type (usb or mmc)
BUS=$(udevadm info --query=property --name="$DEVNAME" | grep "ID_BUS=" | cut -d'=' -f2)

# 1. Safety Check: If the device is already mounted (the boot device), skip it.
if mount | grep -q "$DEVNAME"; then
    exit 0
fi

# 2. Handle SD Cards
if [ "$BUS" = "mmc" ]; then
    mkdir -p /mnt/sdcard
    mount -o uid=1000,gid=1000,umask=000 "$DEVNAME" /mnt/sdcard

# 3. Handle USB Drives (Dynamic Naming)
elif [ "$BUS" = "usb" ]; then
    # Attempt to get the drive label using blkid
    LABEL=$(blkid -s LABEL -o value "$DEVNAME")
    
    # If no label exists, use the device name (e.g., sda1) as a fallback
    if [ -z "$LABEL" ]; then
        LABEL=$(basename "$DEVNAME")
    fi

    # Create a unique mount point (e.g., /mnt/usb_MYDATA)
    MNT_DIR="/mnt/usb_$LABEL"
    mkdir -p "$MNT_DIR"
    mount -o uid=1000,gid=1000,umask=000 "$DEVNAME" "$MNT_DIR"
fi
EOF
chmod +x ovl_root/usr/local/bin/auto-mount.sh
```

**4.3 Assets & Service Config**
This creates a read-only local website to load local assets.

```zsh
# Copy assets and set permissions so 'nobody' user can serve them
mkdir -p ovl_root/var/www/entropylab
cp -R app_assets/* ovl_root/var/www/entropylab/
chmod -R 755 ovl_root/var/www/entropylab

# Create the startup script
mkdir -p ovl_root/etc/init.d
cat << 'EOF' > ovl_root/etc/init.d/entropylab
#!/sbin/openrc-run
name="EntropyLab App"

depend() {
    after localmount eudev
    keyword -jail
}

start_pre() {
    # Dynamically create the unprivileged user with a valid shell
    if ! id -u entropylab > /dev/null 2>&1; then
        adduser -D -u 1000 -s /bin/ash entropylab
    fi
    # Ensure home directory is owned by the new user
    chown -R entropylab:entropylab /home/entropylab
}

start() {
    ebegin "Starting Hardened EntropyLab App"
    
    # Setup Wayland runtime dir
    export XDG_RUNTIME_DIR=/tmp/runtime-root
    mkdir -p $XDG_RUNTIME_DIR
    chown -R entropylab:entropylab $XDG_RUNTIME_DIR
    chmod 0700 $XDG_RUNTIME_DIR
    
    # Start local web server as unprivileged 'nobody' user
    # This creates a secure sandbox via the Same-Origin Policy (SOP)
    httpd -p 127.0.0.1:8080 -h /var/www/entropylab -u nobody:nobody
    
    # Launch Cage (Wayland Compositor) with Chromium
    su - entropylab -c "
      export XDG_RUNTIME_DIR=/tmp/runtime-root
      cage -d -- chromium-browser \
        --incognito \
        --no-first-run \
        --disable-sync \
        --disable-extensions \
        --disable-component-update \
        --disable-notifications \
        --user-data-dir=/tmp/chrome \
        http://127.0.0.1:8080/entropylab.html &
    "
    eend $?
}

stop() {
    ebegin "Stopping EntropyLab App"
    killall chromium-browser cage httpd
    eend $?
}
EOF
chmod +x ovl_root/etc/init.d/entropylab
```

**4.4 Finalize Overlay and Enable Services**

```zsh
mkdir -p ovl_root/etc/runlevels/{sysinit,default}
echo "entropylab" > ovl_root/etc/hostname

# Enable hotplugging daemon and EntropyLab App at boot
ln -s /etc/init.d/udev ovl_root/etc/runlevels/sysinit/udev
ln -s /etc/init.d/udev-trigger ovl_root/etc/runlevels/sysinit/udev-trigger
ln -s /etc/init.d/entropylab ovl_root/etc/runlevels/default/entropylab

# Package the overlay
tar -czf boot/localhost.apkovl.tar.gz -C ovl_root .
```

### 5. Kernel & Firmware Lockdown

This removes and disables network drivers, devices, and the kernel IP stack.

**5.1 Kernel Download & Physical Driver Scrubbing**

```zsh
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/alpine-rpi-3.20.0-aarch64.tar.gz
tar -xzf alpine-rpi-3.20.0-aarch64.tar.gz -C boot/
rm alpine-rpi-3.20.0-aarch64.tar.gz

# Hardening: Physically delete network drivers from the ROOT filesystem (the overlay)
# This ensures they are never loaded into RAM during the boot process.
rm -rf ovl_root/lib/modules/*/kernel/drivers/net
```

**5.2 Firmware Radios Disable**

```zsh
cat << 'EOF' >> boot/usercfg.txt
dtoverlay=disable-wifi
dtoverlay=disable-bt
gpu_mem=128
EOF
```

**5.3 Kernel IP Stack Disable**

```zsh
gsed -i 's/$/ ip=off/' boot/cmdline.txt
```

### 6. Distribution

**Option A: Flash Directly to microSD/USB**

```zsh
diskutil list
# Replace <disk_id> with your actual disk identifier (e.g., disk4)
diskutil partitionDisk /dev/<disk_id> MBR "MS-DOS FAT32" ENTROPYLAB 0b
cp -R boot/* /Volumes/ENTROPYLAB/
mkdir -p /Volumes/ENTROPYLAB/cache
cp -R cache/* /Volumes/ENTROPYLAB/cache/
sync
diskutil eject /Volumes/ENTROPYLAB
```

**Option B: Generate Distributable .img File**

```zsh
docker run --rm -v $(pwd):/work -w /work --platform linux/arm64 alpine:latest sh -c "
  apk add dosfstools mtools && \
  dd if=/dev/zero of=entropylab_rpi.img bs=1M count=256 && \
  mkfs.vfat -F 32 entropylab_rpi.img && \
  mcopy -i entropylab_rpi.img -s boot/* ::/ && \
  mcopy -i entropylab_rpi.img -s cache ::/
"
echo "✅ Distributable image created: entropylab_rpi.img"
```
