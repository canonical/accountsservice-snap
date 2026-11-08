#!/bin/bash
# Build the accountsservice snap for CI
# (canonical/accountsservice-snap, main).
#
# Mirrors the local go-build recipe minus the local-dev build-user/proxy
# wrappers (none of which apply on a GitHub-hosted runner): swap the
# core26-desktop base for a core26 placeholder for every snapcraft call,
# pack, restore the tracked yaml, then patch the packed snap's declared
# base back to core26-desktop.
#
# The snap's base is core26-desktop on purpose (see snap/snapcraft.yaml):
# the confined daemon execs its helpers at compiled-in absolute paths, so
# its /usr must be the desktop variant rootfs, not the stock core26 base.
# snapcraft's schema validation rejects 'core26-desktop' as a base name,
# so the placeholder swap is required (same recipe as
# plasma-desktop-session's build-github.sh).
#
# SUFFIX (set by the workflow matrix) is appended to the published asset
# name ("" on amd64, "-arm64" on the arm64 leg).
set -euo pipefail

rm -f ./*.snap

sed -i 's/^base: core26-desktop$/base: core26/' snap/snapcraft.yaml
restore_base() {
    sed -i -e 's/^base: core26$/base: core26-desktop/' \
           -e '/^build-base: core26$/d' snap/snapcraft.yaml
}
trap restore_base EXIT

# The version is stamped in the 'accountsservice' part's override-build
# from the staged .deb's version. snapcraft caches that scriptlet whenever
# the part definition is unchanged, so clean the part every run: it is a
# nil part, re-running it costs seconds.
snapcraft clean accountsservice |& tee build.log

snapcraft pack |& tee -a build.log

trap - EXIT
restore_base

# Patch the packed snap's declared base back to the real value, keeping a
# copy under a fixed name: the image workflow downloads this repo's
# release asset by a fixed name.
built="$(ls -t accountsservice_*.snap 2>/dev/null | head -1)"
if [ -z "$built" ]; then
    echo "no packed accountsservice snap found" >&2
    exit 1
fi
tmp="$(mktemp -d ./snap-patch-tmp.XXXXXX)"
unsquashfs -d "$tmp/squashfs-root" -f "$built" >/dev/null
sed -i 's/^base: core26$/base: core26-desktop/' "$tmp/squashfs-root/meta/snap.yaml"
mksquashfs "$tmp/squashfs-root" "$built" -noappend -comp xz -no-progress -xattrs
rm -rf "$tmp"

cp -f "$built" "accountsservice${SUFFIX:-}.snap"
