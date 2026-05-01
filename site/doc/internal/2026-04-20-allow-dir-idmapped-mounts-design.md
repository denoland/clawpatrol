# Design: `--allow-dir` idmapped mounts for `unclaw run`

> **Status: SUPERSEDED** by FUSE passthrough, 2026-04-21.
> See the **Postmortem** at the end of this document for why the
> idmapped-mount approach didn't work unprivileged on Ubuntu 24.04,
> and how the replacement design (`native/napi/src/client_linux/fuse_passthrough.rs`)
> maps `--fs-access` paths through a per-path FUSE daemon instead.
> The sections below describe the original design as historical
> reference. The CLI flag also ended up being renamed to `--fs-access`.

## Context

`unclaw run` on Linux now wraps commands inside a user+net+mount namespace
mapped to a **subordinate uid/gid** from `/etc/subuid` and `/etc/subgid`
(see `native/napi/src/client_linux/netns.rs::run_in_fresh_netns`). The
wrapped command runs as a different host user that owns no files, which
blocks the wrapped command from reading the caller's home directory,
UNCLAW_DATA, etc.

That isolation is the point — but the wrapped command needs access to
at least the project it's working on. We need an opt-in mechanism to
expose specific directories to the subuid without copying files or
changing on-disk ownership.

## Goals

- User can list specific directories to expose via repeatable CLI flags.
- Inside the namespace, those directories behave as if the wrapped
  command had the caller's own uid/gid for permission checks — the same
  rwx the caller has on host.
- No on-disk mutation on the host (no chown, no ACLs, no copy).
- Directories not listed stay inaccessible to the wrapped command.

## Non-goals

- Automatic exposure of CWD or `$HOME`. Every path is explicit.
- Cross-user sharing (exposing paths owned by another host user to the
  wrapped command). The only mapping is *caller → inside*.
- Fallback for hosts without idmapped-mount kernel/fs support: hard
  error with a diagnostic message instead.

## Mechanism: idmapped bind mounts

Linux 5.12+ supports attaching a user namespace to a mount such that
the VFS remaps on-disk uid/gid through that namespace for all operations
on the mount. LXC, podman, and systemd-nspawn use this for exactly this
purpose.

Per exposed directory, the child does:

1. `open_tree(AT_FDCWD, <src>, OPEN_TREE_CLONE | AT_RECURSIVE)` →
   detached mount fd (a recursive bind clone).
2. Acquire a **helper user-ns fd** with the idmap `inside=1 outside=<caller_uid> 1`
   for uid and `inside=1 outside=<caller_gid> 1` for gid. The helper ns is
   created once per `unclaw run` invocation; all `--allow-dir` mounts reuse it.
3. `mount_setattr(tree_fd, "", AT_EMPTY_PATH, MOUNT_ATTR_IDMAP, userns_fd)`
   to attach the idmap to the detached tree.
4. `move_mount(tree_fd, "", AT_FDCWD, <src>, MOVE_MOUNT_F_EMPTY_PATH)` to
   attach the idmapped clone on top of `<src>`. Mount point inside the
   namespace = mount point outside = the same absolute path.

After this, a file on disk owned by `<caller_uid>:<caller_gid>` looks
like it's owned by uid 1 / gid 1 to the wrapped process. The wrapped
process runs as inside uid 1 / gid 1 by construction, so the owner-bits
checks pass. Group- and other-bits checks also pass, since those are
unchanged by the idmap.

## CLI surface

`unclaw run`:

- New repeatable flag: `--allow-dir <path>` (both space- and
  `=`-separated accepted, same as existing flags).
- Each `<path>` is resolved at invocation time:
  - `path.resolve(process.cwd(), arg)` → absolute path.
  - `realpathSync(absPath)` → canonical path (symlinks collapsed).
  - `statSync(canonical).isDirectory()` must be true — else abort with
    `--allow-dir <orig>: not a directory`.
- Duplicates (after canonicalization) are deduped.
- The resolved list is passed through to the NAPI call as
  `allow_dirs: string[]`.

## NAPI/Rust surface

`NetnsParams` / `NapiNetnsParams` gain one field:

```rust
/// Absolute, canonical directories to expose inside the child's mount
/// ns via idmapped bind mount. The caller's uid/gid is mapped to the
/// child's inside uid/gid (1/1) so permission checks pass through.
pub allow_dirs: Vec<String>,
```

## Child flow ordering (netns.rs)

We need to (a) hold CAP_SYS_ADMIN in the mount's owning user ns for
`open_tree` + `mount_setattr` + `move_mount`, and (b) have `/` marked
rprivate so the new bind mounts don't propagate back to the host. This
requires a small reordering of the current flow: move `mount / rprivate`
to run before `setuid(1)`. The existing `ip` subprocesses for TUN/route
setup happen after `setuid`, so only `rprivate` moves — everything else
keeps its current relative order.

```
current:
  1. unshare(USER|NET|NS)
  2. write /proc/self/setgroups "deny"
  3. signal parent "u"
  4. wait for parent "m"           (parent did newuidmap/newgidmap)
  5. setuid(1) / setgid(1)         (caps drop)
  6. raise_ambient_net_admin
  7. mount / rprivate
  8. open TUN, config ip, ...

new:
  1. unshare(USER|NET|NS)
  2. write /proc/self/setgroups "deny"
  3. signal parent "u"
  4. wait for parent "m"
  5. mount / rprivate                                   [moved earlier]
  6. [new] build helper user-ns fd with caller→inside idmap
  7. [new] for each dir in allow_dirs: idmap_bind_mount(dir, ...)
  8. [new] close helper user-ns fd
  9. setuid(1) / setgid(1)         (caps drop)
 10. raise_ambient_net_admin
 11. open TUN, config ip, ...
```

The helper user-ns fd is built via a transient fork:
- Parent-in-child: creates a pipe, forks.
- Grand-child: `unshare(CLONE_NEWUSER)`, writes uid_map/gid_map (no
  `newuidmap`/`newgidmap` — these are self-mappings using the ns-root
  caps we already have), then blocks on the pipe so the ns stays alive.
- Parent-in-child: opens `/proc/<grandchild_pid>/ns/user`, closes pipe,
  waits for grand-child to exit. The user-ns fd keeps the ns alive
  after the grand-child is reaped.

## Error handling

Per the user's decision: if any of `open_tree`, `mount_setattr`, or
`move_mount` fails, bail out of the run with a descriptive error
including the path and the underlying errno. Likely causes:

- `ENOSYS` on `open_tree`/`mount_setattr`/`move_mount` — kernel < 5.12.
  Message: `"kernel too old for --allow-dir (needs Linux 5.12+)"`.
- `EINVAL` on `mount_setattr` with `MOUNT_ATTR_IDMAP` — fs doesn't
  support idmapped mounts. Message names the path and suggests
  checking the filesystem (e.g. ext4 5.12+, btrfs 5.15+, xfs 5.19+).
- `ENOENT`/`ENOTDIR` — path went away or changed between CLI
  validation and child exec; treat as abort.

No per-dir fallback; first failure aborts.

## Test plan

Integration tests (gated on Linux kernel ≥ 5.12 + user-ns support):

1. `unclaw run --allow-dir <tmpdir> touch <tmpdir>/x` — file gets
   created, owned by the caller on host (verified by `stat` after).
2. `unclaw run --allow-dir <tmpdir> cat <tmpdir>/secret` when
   `<tmpdir>/secret` is mode 600 owned by caller — succeeds.
3. `unclaw run cat /home/<caller>/.bashrc` (no allow-dir) — fails with
   permission-denied (isolation still intact for non-allowed paths).
4. `unclaw run --allow-dir /nonexistent ls` — fails at CLI validation
   with a clear error, never enters the namespace.
5. `unclaw run --allow-dir <tmpdir> --allow-dir <tmpdir> ls` — dedup,
   single idmap bind, no error.

Manual verification on a host with an older kernel (e.g. Ubuntu 20.04
generic 5.4) — expect clean error referencing kernel version.

## Files touched

- `native/napi/src/client_linux/netns.rs` — new helper + child-flow
  insertion + NAPI struct field.
- `native/napi/src/client_stubs.rs` — add `allow_dirs: Vec<String>` to
  the non-Linux stub.
- `native/napi/index.d.ts` — regenerated via napi build, adds field.
- `src/cli.ts` — `--allow-dir` parsing in `runLinux`, plumbed through
  the NAPI call site.

No changes to onboarding, dashboard, or plugin surfaces.

---

## Postmortem (2026-04-21)

### Why the idmap approach was abandoned

After implementing the design above, `mount_setattr(MOUNT_ATTR_IDMAP)`
consistently returned EPERM on our Ubuntu 24.04 (kernel 6.8) target,
regardless of how we structured the helper user ns.

The kernel's permission check for attaching `MOUNT_ATTR_IDMAP` to a
mount includes, roughly:

```c
if (!ns_capable(mnt->mnt_sb->s_user_ns, CAP_SYS_ADMIN))
    return -EPERM;
```

For any mount whose superblock was created in init_user_ns — i.e.
everything the host mounted at boot, including the ext4 root that
backs `/home/*` — `s_user_ns == init_user_ns`. An unprivileged user
never holds `CAP_SYS_ADMIN` there, so the check can't pass.

We chased this for several iterations: different helper user ns
nesting positions (child of init vs child of wrapped), different
uid_map contents, a fork-race fix on the helper, even a compute-
elsewhere / move-mount approach. All hit the same invariant. It is
deliberate kernel policy to prevent rootless users from attaching
arbitrary uid/gid translations to host-owned filesystems.

Confirming references: `fs/namespace.c::build_mount_idmapped` +
`can_idmap_mount`, and the kernel Documentation/filesystems/idmappings.rst
notes that rootless `MOUNT_ATTR_IDMAP` requires either the caller
to hold `CAP_SYS_ADMIN` in the superblock's user ns, or the mount
to come from a user-namespace-owned filesystem (e.g. a FUSE mount
the caller itself set up).

### Replacement: per-path FUSE passthrough

Landed in `native/napi/src/client_linux/fuse_passthrough.rs`. Key
points:

- The CLI flag is `--fs-access PATH` (not `--allow-dir`) — files as
  well as directories are accepted.
- For each `--fs-access` path, `child_run` (post-newuidmap,
  pre-setuid) forks a FUSE daemon via `fuse_passthrough::spawn`,
  following the `relay.rs` subprocess pattern (no new binary).
- The daemon runs as the caller's kuid (inherited via fork before
  `setuid(subuid)`), so it has direct access to the underlying
  files.
- It mounts a FUSE filesystem at `/tmp/unclaw-fuse-<pid>-<i>` using
  `fuser::Session::new`. Because this is a user-created FS, its
  `s_user_ns` is the wrapped user ns — so subsequent VFS ops don't
  hit the idmap-mount kernel gate above.
- Immediately after the mount, the daemon `unshare(CLONE_NEWNS)`s
  its own mount namespace and makes it rprivate. This prevents
  the wrapped child's later bind-mount (which puts the FUSE mount
  over the source path) from looping the daemon's own reads of the
  source back through its own FUSE mount.
- The daemon reports the wrapped process's inside uid/gid in every
  `getattr` response (uid/gid rewriting at the FUSE protocol layer).
  That makes the wrapped process see files as its own, so standard
  Unix DAC checks pass; writes land on disk owned by the caller
  because the daemon does the I/O as the caller's kuid.
- Wrapped child's `newuidmap` writes two extents under
  `--fs-access`: `1 <caller_uid> 1` + `2 <subuid> 1`. Inside uid 1
  lets the daemon pass the FUSE kernel's `user_id` sanity check
  (`libc::getuid()` in the daemon must produce a uid that maps to
  its own kuid); inside uid 2 is where the wrapped command runs
  after `setuid(2)` for isolation. `newuidmap`'s `verify_range`
  accepts the caller-uid extent as the own-uid special case that
  doesn't require an `/etc/subuid` entry.

### Trade-offs vs. the original design

- **Worked**: the FUSE approach works rootless on Ubuntu 24.04
  without any policy toggles.
- **Cost**: per-syscall FUSE userspace roundtrip (~20-50µs) on
  `--fs-access` paths. Acceptable for the AI-agent use case;
  painful for heavy build/test workloads inside those paths.
- **State**: no host-state mutation (unlike the rejected ACL
  alternative). Cleanup is implicit — daemon exits when wrapped
  process dies (`PR_SET_PDEATHSIG`), mount goes away with the
  wrapped ns.
- **Security**: equivalent isolation to the idmap design; wrapped
  process runs as a distinct host kuid (the subuid), gets owner-bit
  access only to paths we explicitly FUSE-mount.
