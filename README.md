# ABKCG Parallel Layer Module

This module patches an AOSP 6.1 kernel tree to add an ABK shadow cgroup layer
with:

- ABK shadow `pids.*` accounting and enforcement.
- ABK shadow `devices.*` filtering.
- a mountable `abkcg2fs` cgroup2 view filesystem.
- a sysfs control plane under `/sys/kernel/abkcg/`.

Design constraints:

- the real cgroup2 tree remains authoritative;
- native `pids` / `devices` controllers stay disabled;
- ABK state is keyed to the real cgroup hierarchy;
- userspace explicitly mounts `abkcg2fs` inside the target mount namespace.

This module only changes the module directory itself. The kernel tree is
modified later by running `setup.sh` with `KERNEL_ROOT` pointing at the AOSP
kernel source.

Testing notes:

- `abkcg2fs` should be mounted on top of a real cgroup2 tree such as
  `/sys/fs/cgroup`.
- when SELinux is enabled, `/sys/kernel/abkcg/sepolicy` accepts minimal live
  test commands inspired by KernelSU's policy patch flow:
  - `ksu-abkcg`
  - `permissive <domain>`
  - `allow <src> <tgt> <class> <perm|*>`
- this interface is intended only to unblock ABKCG test flows that would
  otherwise hit AVC denials during cgroup directory or control-file access.
