#!/usr/bin/env bash

abk_log() {
  printf '[ABK module] %s\n' "$*"
}

abk_warn() {
  printf '[ABK module][warn] %s\n' "$*" >&2
}

abk_die() {
  printf '[ABK module][error] %s\n' "$*" >&2
  exit 1
}

abk_require_env() {
  local name
  for name in "$@"; do
    if [ -z "${!name:-}" ]; then
      abk_die "required environment variable is empty: $name"
    fi
  done
}

abk_require_file() {
  local path="$1"
  [ -f "$path" ] || abk_die "required file not found: $path"
}

abk_require_dir() {
  local path="$1"
  [ -d "$path" ] || abk_die "required directory not found: $path"
}

abk_config_line() {
  local symbol="$1"
  local value="$2"
  symbol="${symbol#CONFIG_}"

  case "$value" in
    n)
      printf '# CONFIG_%s is not set\n' "$symbol"
      ;;
    y|m)
      printf 'CONFIG_%s=%s\n' "$symbol" "$value"
      ;;
    \"*\")
      printf 'CONFIG_%s=%s\n' "$symbol" "$value"
      ;;
    *)
      printf 'CONFIG_%s=%s\n' "$symbol" "$value"
      ;;
  esac
}

abk_set_config() {
  local symbol="$1"
  local value="$2"
  local file="${3:-${DEFCONFIG:-}}"
  local clean_symbol
  local tmp

  [ -n "$file" ] || abk_die "DEFCONFIG is empty and no config file was provided"
  abk_require_file "$file"

  clean_symbol="${symbol#CONFIG_}"
  tmp="$(mktemp)"
  grep -v -E "^(CONFIG_${clean_symbol}=|# CONFIG_${clean_symbol} is not set$)" "$file" > "$tmp" || true
  abk_config_line "$clean_symbol" "$value" >> "$tmp"
  mv "$tmp" "$file"
  abk_log "set CONFIG_${clean_symbol}=$value in $file"
}

abk_enable_config() {
  abk_set_config "$1" y "${2:-${DEFCONFIG:-}}"
}

abk_disable_config() {
  abk_set_config "$1" n "${2:-${DEFCONFIG:-}}"
}
