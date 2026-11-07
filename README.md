# accountsservice snap

AccountsService (org.freedesktop.Accounts) system D-Bus daemon as a
provider snap for Ubuntu Core Desktop. Staged from the resolute
`accountsservice` deb; base core26. Companion to the snapd fork's
`accountsservice` interface (slot policy) and the gnome gadget's static
connections. Build with `./go-build` (runs snapcraft pack as the copilot
build user).

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
  and exactly one `username:$6$salt$hash` record (single line, newline
  terminated, no CR, valid SHA-512 crypt shape). Anything else is rejected
  with exit 2 and a message on stderr; the daemon surfaces chpasswd
  failures to the D-Bus caller. Valid input is re-fed to the real chpasswd
  unchanged with the original argv and the child's exit status propagated.
- The real chpasswd ships as `usr/sbin/chpasswd.real`: a byte-identical
  copy of the fat base's 1017 extrausers-fallback binary (the same file the
  variant rootfs bakes; md5 checked at build time). This preserves the
  proven SetPassword chain (`chpasswd -e` → 1017 fallback → writes
  `/var/lib/extrausers/shadow`), because the layout shadows the base's
  `/usr/sbin/chpasswd` inside the namespace.
- No snapd policy change was needed: the fork's slot rule
  `/{,usr/}sbin/chpasswd ixr` matches the guard's namespace exec path, and
  the base template's exec grant on the snap's own install directory
  (`@{INSTALL_DIR}/<snap>/<rev>/** mrklix`) covers `chpasswd.real`.
