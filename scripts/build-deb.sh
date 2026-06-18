#!/usr/bin/env bash
#
# Build a reproducible Debian package (.deb) for zecd from a pre-built binary.
#
# The binary itself is expected to already be a *reproducible* artifact - in CI it is
# extracted from the `export` stage of the StageX (amd64) / pinned-Debian (arm64)
# Dockerfiles, which carry all the determinism flags (SOURCE_DATE_EPOCH, codegen-units=1,
# --build-id=none, static musl on amd64). This script only wraps that binary, so it must
# not reintroduce nondeterminism: every file gets a fixed mtime (SOURCE_DATE_EPOCH),
# `dpkg-deb --root-owner-group` pins uid/gid to root:root, and gzip is invoked with `-n`
# so the changelog has no embedded name/timestamp. dpkg-deb (>= 1.18.11) then honors
# SOURCE_DATE_EPOCH for the ar member timestamps, yielding a bit-for-bit identical .deb.
#
# Usage:
#   scripts/build-deb.sh <binary-path> <version> <deb-arch> <output-dir>
#
#   <binary-path>  path to the compiled `zecd` binary
#   <version>      package version, e.g. 0.1.0 (no leading "v")
#   <deb-arch>     Debian architecture: amd64 | arm64
#   <output-dir>   directory the .deb is written to (created if missing)

set -euo pipefail

BINARY_PATH="${1:?usage: build-deb.sh <binary-path> <version> <deb-arch> <output-dir>}"
VERSION="${2:?missing version}"
DEB_ARCH="${3:?missing deb-arch}"
OUTPUT_DIR="${4:?missing output-dir}"

# Determinism anchor - keep in lockstep with the Dockerfiles' SOURCE_DATE_EPOCH.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 0755 "$STAGE"   # mktemp -d is 0700; the package root (./) should be world-readable

# --- Filesystem layout -----------------------------------------------------------------
install -D -m 0755 "$BINARY_PATH"                       "$STAGE/usr/bin/zecd"
install -D -m 0644 "$REPO_ROOT/zecd.example.toml"       "$STAGE/usr/share/doc/zecd/zecd.example.toml"
install -D -m 0644 "$REPO_ROOT/README.md"               "$STAGE/usr/share/doc/zecd/README.md"

# systemd unit (installed, not enabled - the admin opts in with `systemctl enable zecd`).
install -D -m 0644 /dev/stdin "$STAGE/lib/systemd/system/zecd.service" <<'UNIT'
[Unit]
Description=zecd - Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash
Documentation=https://github.com/zecrocks/zecd
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=zecd
Group=zecd
ExecStart=/usr/bin/zecd --datadir /var/lib/zecd
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/zecd

[Install]
WantedBy=multi-user.target
UNIT

# Debian copyright file (dual MIT / Apache-2.0).
install -D -m 0644 /dev/stdin "$STAGE/usr/share/doc/zecd/copyright" <<'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: zecd
Source: https://github.com/zecrocks/zecd

Files: *
Copyright: The zecd authors
License: MIT or Apache-2.0
 zecd is dual-licensed under the MIT and Apache-2.0 licenses. The full texts are
 distributed with the source at https://github.com/zecrocks/zecd
 (LICENSE-MIT and LICENSE-APACHE).
COPYRIGHT

# Debian changelog (gzip -n keeps it timestamp/name free for reproducibility).
CHANGELOG_TMP="$(mktemp)"
cat > "$CHANGELOG_TMP" <<CHANGELOG
zecd (${VERSION}) unstable; urgency=medium

  * Release ${VERSION}. See https://github.com/zecrocks/zecd/releases for notes.

 -- zecd <noreply@users.noreply.github.com>  Thu, 01 Jan 1970 00:00:00 +0000
CHANGELOG
gzip -9nc "$CHANGELOG_TMP" > "$STAGE/usr/share/doc/zecd/changelog.Debian.gz"
chmod 0644 "$STAGE/usr/share/doc/zecd/changelog.Debian.gz"
rm -f "$CHANGELOG_TMP"

# --- Control archive -------------------------------------------------------------------
INSTALLED_SIZE="$(du -k -s "$STAGE/usr" | cut -f1)"
install -D -m 0644 /dev/stdin "$STAGE/DEBIAN/control" <<CONTROL
Package: zecd
Version: ${VERSION}
Architecture: ${DEB_ARCH}
Maintainer: zecd <noreply@users.noreply.github.com>
Installed-Size: ${INSTALLED_SIZE}
Section: net
Priority: optional
Homepage: https://github.com/zecrocks/zecd
Description: Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash
 zecd speaks bitcoind's JSON-RPC dialect (method names, response shapes, error
 codes, HTTP auth) and maps it onto Orchard-shielded Zcash operations, built on
 librustzcash. It runs against a local zebrad or a lightwalletd backend.
CONTROL

# conffiles: none under /etc - the example config ships read-only under /usr/share/doc.

# Maintainer scripts: create the service user/datadir and refresh systemd.
install -D -m 0755 /dev/stdin "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if ! getent group zecd >/dev/null; then
        addgroup --system zecd
    fi
    if ! getent passwd zecd >/dev/null; then
        adduser --system --ingroup zecd --home /var/lib/zecd \
            --no-create-home --gecos "zecd daemon" zecd
    fi
    install -d -o zecd -g zecd -m 0750 /var/lib/zecd
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
fi
exit 0
POSTINST

install -D -m 0755 /dev/stdin "$STAGE/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop zecd.service >/dev/null 2>&1 || true
    fi
fi
exit 0
PRERM

install -D -m 0755 /dev/stdin "$STAGE/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
POSTRM

# --- Normalize mtimes, then build -------------------------------------------------------
# Clamp every path to SOURCE_DATE_EPOCH so the data/control tarballs are byte-stable.
find "$STAGE" -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +

mkdir -p "$OUTPUT_DIR"
DEB_PATH="${OUTPUT_DIR}/zecd_${VERSION}_${DEB_ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB_PATH"

echo "$DEB_PATH"
