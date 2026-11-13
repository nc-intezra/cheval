#!/bin/sh
# Build a .deb from an already compiled cheval binary.
#   packaging/build-deb.sh BINARY VERSION SOURCE_DIR OUT_DIR [ARCH]
# SOURCE_DIR supplies README, changelog, example config and systemd units.
set -eu
BIN=$1; VERSION=${2#v}; SRC=$3; OUT=$4; ARCH=${5:-amd64}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

install -Dm755 "$BIN" "$STAGE/usr/bin/cheval"
install -Dm644 "$SRC/README.md" "$STAGE/usr/share/doc/cheval/README.md"
install -Dm644 "$SRC/LICENSE" "$STAGE/usr/share/doc/cheval/copyright"
install -Dm644 "$SRC/examples/cheval.toml" "$STAGE/usr/share/doc/cheval/examples/cheval.toml"
if [ -f "$SRC/CHANGELOG.md" ]; then
    gzip -9nc "$SRC/CHANGELOG.md" > "$STAGE/usr/share/doc/cheval/changelog.gz"
    chmod 644 "$STAGE/usr/share/doc/cheval/changelog.gz"
fi
# systemd units: shipped but not enabled. The package installs to /usr/bin.
for unit in "$SRC"/contrib/*.service "$SRC"/contrib/*.timer; do
    [ -f "$unit" ] || continue
    install -d "$STAGE/usr/lib/systemd/system"
    sed 's#/usr/local/bin/cheval#/usr/bin/cheval#g' "$unit" > "$STAGE/usr/lib/systemd/system/$(basename "$unit")"
    chmod 644 "$STAGE/usr/lib/systemd/system/$(basename "$unit")"
done
install -d -m755 "$STAGE/etc/cheval"

SIZE=$(du -sk "$STAGE" | cut -f1)
install -d "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<CTL
Package: cheval
Version: $VERSION
Architecture: $ARCH
Maintainer: nc-intezra <nc-intezra@users.noreply.github.com>
Installed-Size: $SIZE
Recommends: ca-certificates
Section: admin
Priority: optional
Homepage: https://github.com/nc-intezra/cheval
Description: consistent, verified APT repository mirroring with a TUI
 cheval mirrors APT repositories to local disk. Indices are published only
 after every package they reference has been downloaded and verified, so the
 mirror is consistent at every moment. Includes OpenPGP verification, resume,
 flat and authenticated repositories, snapshots and offline bundles.
 .
 The binary is statically linked. Copy
 /usr/share/doc/cheval/examples/cheval.toml to /etc/cheval/cheval.toml to start.
CTL
cat > "$STAGE/DEBIAN/postinst" <<'PI'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    # Unprivileged account used by the shipped systemd unit.
    if ! getent passwd cheval >/dev/null; then
        useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin cheval || true
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
fi
PI
cat > "$STAGE/DEBIAN/postrm" <<'PR'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
PR
chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/postrm"

mkdir -p "$OUT"
DEB="$OUT/cheval_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$DEB" >/dev/null
echo "$DEB"
