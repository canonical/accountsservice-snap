# accountsservice snap

AccountsService (org.freedesktop.Accounts) system D-Bus daemon as a
provider snap for Ubuntu Core Desktop. Staged from the resolute
`accountsservice` deb; base core26-desktop. Companion to the snapd fork's
`accountsservice` interface (slot policy) and the gnome gadget's static
connections. Build with `./go-build` (runs snapcraft pack as the copilot
build user).

## CreateUser helpers: adduser + perl-base (staged here, not in the base)

The daemon execs its compiled-in `/usr/sbin/adduser` for CreateUser — a
perl script — plus `/usr/sbin/usermod` for group membership. The base
(core26-desktop) does not carry adduser/perl: the base must not ship perl;
dependencies belong to the consumer and are staged as proper archive debs:

- `adduser` + `perl-base` via stage-packages (adduser needs nothing beyond
  perl-base: Fcntl/Getopt::Long/parent/Exporter ship in perl-base, and the
  `Debian::Adduser*.pm` modules ship inside the adduser deb itself).
- `patches/adduser-extrausers-usermod.patch` is applied at build time to
  the staged archive adduser. This is exactly the patch the fat base
  carried (byte-checked: the patched result must md5-match the fat-chain
  script `430f8d1d23c460e795eb7181c4503365`); it comes from the Ubuntu
  Core Desktop adduser work (the local ucd-ppa repo's
  adduser 3.153ubuntu1+ucd1 build took a different, stricter approach —
  not what the fat base shipped). The archive deb needs it in
  USE_EXTRAUSERS mode:
  1. AddUserToGroup would exec `usermod --extrausers`, but usermod has no
     such flag (usage text, exit 2); plain usermod is correct because the
     archive shadow build is extrausers-aware on its own.
  2. `ch_comment` would `log_fatal` in extrausers mode — and the daemon
     always passes `--gecos <fullname>`, so this runs on EVERY CreateUser;
     refusing silently dropped the real name set by the first-boot wizard.
- `conf/adduser.conf` (the live-validated fat-base config) ships at
  `etc/adduser.conf` in the snap: the daemon execs adduser WITHOUT
  `--extrausers` (compiled-in argv: `adduser --quiet --disabled-password
  --gecos <fullname> <name>`), so `USE_EXTRAUSERS=1` in the config is what
  routes accounts into `/var/lib/extrausers`. The deb's stock config (no
  USE_EXTRAUSERS) is excluded from staging.
- Layouts serve all of it at the daemon's compiled-in absolute paths
  inside its mount namespace (`/usr/sbin/adduser`, `/usr/bin/perl`,
  `/usr/lib/<triplet>/perl-base` (via `$CRAFT_ARCH_TRIPLET_BUILD_FOR`,
  expanded at pack time), `/usr/share/perl5`,
  `/etc/adduser.conf` — bind-file/bind layouts; snap-update-ns creates
  missing mountpoints, including files, over the read-only base).
  Paths stay identical to what the fork's slot policy grants, so no
  snapd policy change was needed.
- `usermod` and `chpasswd` still resolve from the variant base: the base
  bakes the 1017 extrausers-fallback chpasswd (also mirrored in-snap as
  the guarded `chpasswd.real`), and the archive usermod is
  extrausers-aware (it edits `/var/lib/extrausers/{passwd,group}` for
  extrausers users).

## SetPassword chpasswd guard

The staged daemon execs its compiled-in `/usr/sbin/chpasswd -e` and pipes
exactly one `"user:crypt\n"` record to it, taking the crypt string verbatim
from the D-Bus caller. It performs no separator validation, so a caller
supplying `"hash\notheruser:otherhash"` made chpasswd process a second
record and change another extrausers account (SetPassword record injection,
final review security finding). The daemon binary cannot be patched, so the
snap ships a validating shim:

- `chpasswd/chpasswd-guard.c` is compiled to `usr/sbin/chpasswd` inside the
  snap, and a layout (`/usr/sbin/chpasswd: bind-file: $SNAP/usr/sbin/chpasswd`)
  puts it at the daemon's compiled-in helper path in its mount namespace.
- The guard accepts ONLY `chpasswd -e` (the daemon's sole invocation shape)
  and exactly one `username:$<scheme>$salt$hash` record (any modular-crypt
  scheme — the real wizard caller uses glibc yescrypt `$y$`; single line, newline
  terminated, no CR, valid SHA-512 crypt shape). Anything else is rejected
  with exit 2 and a message on stderr; the daemon surfaces chpasswd
  failures to the D-Bus caller. Valid input is re-fed to the real chpasswd
  unchanged with the original argv and the child's exit status propagated.
- The real chpasswd ships as `usr/sbin/chpasswd.real`: a copy of the
  1017 extrausers-fallback build (the same file the variant rootfs bakes;
  per-arch md5 checked at build time). This preserves the proven SetPassword
  chain (`chpasswd -e` → /etc lock failure on the RO base → 1017 fallback →
  writes `/var/lib/extrausers/shadow`), because the layout shadows the base's
  `/usr/sbin/chpasswd` inside the namespace. Per-arch builds of the same
  patched source:
  - amd64: the ucd-ppa `passwd_4.17.4-2ubuntu3+ucd1` deb output
    (`chpasswd/chpasswd.real`).
  - arm64: cross-built from the same ucd-ppa source tree (resolute shadow
    4.17.4 + debian patch series + `1017_extrausers_chpasswd.patch`) with
    `aarch64-linux-gnu-gcc` against resolute arm64 debs, configured with the
    deb's own flags and LTO/hardening; symbol resolution matches the deb
    (arc4random_buf/reallocarray from glibc, libbsd dropped) so the runtime
    closure is identical (`libpam/libaudit/libselinux/libcrypt/libc`).
    Verified end-to-end under qemu-user: RO-base lock failure → fallback →
    hash written to `/var/lib/extrausers/shadow`, `/etc/shadow` untouched.
    (`chpasswd/chpasswd.real-arm64`.)
- No snapd policy change was needed: the fork's slot rule
  `/{,usr/}sbin/chpasswd ixr` matches the guard's namespace exec path, and
  the base template's exec grant on the snap's own install directory
  (`@{INSTALL_DIR}/<snap>/<rev>/** mrklix`) covers `chpasswd.real`.
