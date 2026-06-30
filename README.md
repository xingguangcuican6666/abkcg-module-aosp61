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
