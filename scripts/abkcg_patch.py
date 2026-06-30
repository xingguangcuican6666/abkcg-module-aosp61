#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"{label}: anchor not found in {path}")
    path.write_text(text.replace(old, new, 1))


def ensure_after(path: Path, anchor: str, snippet: str, label: str) -> None:
    text = path.read_text()
    if snippet in text:
        return
    if anchor not in text:
        raise SystemExit(f"{label}: anchor not found in {path}")
    path.write_text(text.replace(anchor, anchor + snippet, 1))


def patch_fs_makefile(path: Path) -> None:
    replace_once(
        path,
        "\t\tkernel_read_file.o remap_range.o\n",
        "\t\tkernel_read_file.o remap_range.o\n\nobj-$(CONFIG_ABK_CGROUP)\t+= abkcg2fs.o\n",
        "fs_makefile",
    )


def patch_kernel_makefile(path: Path) -> None:
    ensure_after(
        path,
        "obj-$(CONFIG_CGROUPS) += cgroup/\n",
        "obj-$(CONFIG_ABK_CGROUP) += abkcg_core.o\n",
        "kernel_makefile",
    )

def patch_init_kconfig(path: Path) -> None:
    replace_once(
        path,
        "config CGROUP_RDMA\n",
        'config ABK_CGROUP\n\tbool "ABK cgroup2 shadow pids/devices view"\n\tdepends on CGROUPS && SYSFS\n\tdefault n\n\thelp\n\t  Build the ABK shadow cgroup layer and the abkcg2fs cgroup2 view\n\t  filesystem. This keeps native pids/devices controllers disabled while\n\t  exposing ABK-backed pids.* and devices.* files in a separate view.\n\nconfig CGROUP_RDMA\n',
        "init_kconfig",
    )


def patch_device_cgroup(path: Path) -> None:
    ensure_after(
        path,
        "#include <linux/device_cgroup.h>\n",
        "#include <linux/abkcg.h>\n",
        "device_cgroup_include_abkcg",
    )

    replace_once(
        path,
        "int devcgroup_check_permission(short type, u32 major, u32 minor, short access)\n{\n\tint rc = BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type, major, minor, access);\n\n\tif (rc)\n\t\treturn rc;\n",
        "int devcgroup_check_permission(short type, u32 major, u32 minor, short access)\n{\n\tint rc;\n\n\trc = abkcg_dev_check_permission(type, major, minor, access);\n\tif (rc)\n\t\treturn rc;\n\n\trc = BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type, major, minor, access);\n\n\tif (rc)\n\t\treturn rc;\n",
        "device_cgroup_hook",
    )


def patch_fork(path: Path) -> None:
    ensure_after(
        path,
        "#include <linux/io_uring.h>\n",
        "#include <linux/abkcg.h>\n",
        "fork_include_abkcg",
    )
    ensure_after(
        path,
        "\tcgroup_fork(p);\n",
        "\tretval = abkcg_fork(p);\n\tif (retval)\n\t\tgoto bad_fork_cleanup_delayacct;\n",
        "fork_call_abkcg",
    )
    ensure_after(
        path,
        "bad_fork_cleanup_delayacct:\n",
        "\tabkcg_fork_failed(p);\n",
        "fork_failed_abkcg",
    )


def patch_exit(path: Path) -> None:
    ensure_after(
        path,
        "#include <linux/profile.h>\n",
        "#include <linux/abkcg.h>\n",
        "exit_include_abkcg",
    )
    ensure_after(
        path,
        "\tsched_autogroup_exit_task(tsk);\n",
        "\tabkcg_exit(tsk);\n",
        "exit_call_abkcg",
    )


def patch_cgroup_core(path: Path) -> None:
    ensure_after(
        path,
        "#include <linux/bpf-cgroup.h>\n",
        "#include <linux/abkcg.h>\n",
        "cgroup_core_include_abkcg",
    )
    ensure_after(
        path,
        "\tret = cgroup_attach_task(dst_cgrp, task, threadgroup);\n",
        "\tif (!ret)\n\t\tabkcg_migrate(task, src_cgrp, dst_cgrp, threadgroup);\n",
        "cgroup_core_migrate_abkcg",
    )


def copy_kernel_files(module_dir: Path, kernel_root: Path) -> None:
    files_root = module_dir / "files" / "common"
    targets = {
        files_root / "include/linux/abkcg.h": kernel_root / "common/include/linux/abkcg.h",
        files_root / "kernel/abkcg_core.c": kernel_root / "common/kernel/abkcg_core.c",
        files_root / "fs/abkcg2fs.c": kernel_root / "common/fs/abkcg2fs.c",
    }

    for source, target in targets.items():
        if not source.is_file():
            raise SystemExit(f"template file not found: {source}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def patch_kernel_tree(module_dir: Path, kernel_root: Path) -> None:
    common = kernel_root / "common"
    patch_fs_makefile(common / "fs/Makefile")
    patch_kernel_makefile(common / "kernel/Makefile")
    patch_init_kconfig(common / "init/Kconfig")
    patch_fork(common / "kernel/fork.c")
    patch_exit(common / "kernel/exit.c")
    patch_cgroup_core(common / "kernel/cgroup/cgroup.c")
    patch_device_cgroup(common / "security/device_cgroup.c")
    copy_kernel_files(module_dir, kernel_root)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise SystemExit(f"usage: {argv[0]} <kernel-root>")

    module_dir = Path(os.environ.get("MODULE_DIR", "")).resolve()
    if not module_dir.is_dir():
        raise SystemExit("MODULE_DIR environment variable is missing or invalid")

    kernel_root = Path(argv[1])
    if not kernel_root.is_dir():
        raise SystemExit(f"kernel root not found: {kernel_root}")

    patch_kernel_tree(module_dir, kernel_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
