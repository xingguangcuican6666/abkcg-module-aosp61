#!/usr/bin/env bash

abkcg_patch_script() {
  printf '%s/scripts/abkcg_patch.py\n' "$MODULE_DIR"
}

abkcg_apply_kernel_patch() {
  local patch_script

  patch_script="$(abkcg_patch_script)"
  abk_require_file "$patch_script"
  abk_require_dir "$KERNEL_ROOT"

  abk_log "patching kernel for ABKCG parallel layer"
  MODULE_DIR="$MODULE_DIR" python3 "$patch_script" "$KERNEL_ROOT"
}

abkcg_enable_config() {
  abk_enable_config CONFIG_ABK_CGROUP
  abk_disable_config CONFIG_CGROUP_PIDS
  abk_disable_config CONFIG_CGROUP_DEVICE
}
