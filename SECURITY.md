# Security Policy

## The important warning: untrusted cheat tables run code

This tool inspects and modifies other processes' memory. It is frequently run
with elevated privileges (`ptrace`, often under `sudo`), and its cheat-table
format is scriptable.

**Do not execute scripts from `.CT` / `.CETRAINER` files you do not trust.** A
cheat table can embed Lua and Auto Assembler payloads. The legacy Qt frontend
asks before table-level Lua runs. The GTK migration frontend imports every
script inactive, requires explicit table-scoped trust before an Auto Assembler
record can be enabled, and uses an independent consent state for Lua. Its
script-review dialog is read-only and paged: summary requests are capped,
payload requests are capped at 64 KiB, and text is sanitized before crossing
into GTK. Opening or paging that dialog never executes a payload and never
grants trust. Lua never auto-runs: after table-scoped Lua trust, every selected
payload still needs a separate Run confirmation. Payload input is capped at
1 MiB, pure Lua execution at 2 million VM instructions, and captured output at
64 KiB. Native functions may still block beyond that VM limit.

Revoking GTK Lua trust destroys its Lua state, callbacks, timers, and globals,
but cannot reverse arbitrary target writes, file/system actions, injected code,
or other side effects already performed by a trusted payload. Treat a shared
table like a shared executable even when it initially opens without execution.

The two most dangerous parts of the Lua surface are **denied by default** and
only enabled by an out-of-band opt-in that a table's own script cannot set — the
environment variable `CECORE_LUA_ALLOW_UNSAFE=1`, launched with the process:

- `shellExecute` — runs arbitrary shell commands.
- the `write*Local` functions — write cecore's *own* address space, which a
  malicious table could use to patch cecore's code/GOT and hijack the process.

The `read*Local` functions (host-memory read / info disclosure) and the rest of
the target-memory API stay available. Standard Lua libraries such as `os` and
`io` also remain available after explicit Lua trust, so these two guards do not
turn table Lua into a sandbox. The operational rule still holds: only run tables
you authored or trust. Every native binding is additionally routed through a
central exception firewall, so a C++ exception escaping a binding becomes a Lua
error instead of unwinding through liblua's C frames.

## Running with least privilege

- Prefer running as your normal user with `/proc/sys/kernel/yama/ptrace_scope`
  set appropriately, or `PR_SET_PTRACER`, rather than blanket `sudo`, when the
  target permits it.
- The optional kernel module (`kernel/cecore_kmod.ko`) exposes a privileged
  memory-access device; only load it if you need it, and unload it when done.

## Supported versions

Only the latest release and `main` receive fixes. This is pre-1.0 software.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:
open a GitHub **Security Advisory** on the repository
(`Security → Report a vulnerability`), or email the maintainer. Include a
description, affected version/commit, and a reproduction if possible. We aim to
acknowledge within a few days.
