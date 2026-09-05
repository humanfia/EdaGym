#!/usr/bin/env bash

set -euo pipefail

readonly sail_version="0.20.2"
readonly sail_revision="3b7af38d66466ecadad563158b07ce2f82fe05da"
readonly release_tag="0.20.2-binary"

case "$(uname -m)" in
  x86_64)
    readonly archive_name="sail-Linux-x86_64.tar.gz"
    readonly archive_sha256="26b59bcab2d66e9f220d317dfe45f8b09170ed70e59a824553d6f525134d1ff6"
    ;;
  aarch64)
    readonly archive_name="sail-Linux-aarch64.tar.gz"
    readonly archive_sha256="10428d1be9a2945a71f9855c81027c22d6a2895dbbcf2ce9a4f9640203d5067f"
    ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 2
    ;;
esac

readonly release_url="https://github.com/rems-project/sail/releases/download/${release_tag}/${archive_name}"
account_home=$(getent passwd "$(id -u)" | cut -d: -f6)
readonly account_home
readonly scratch_parent="${account_home}/.cache/edagym/sail-bootstrap"
readonly install_parent="${account_home}/.local/opt/sail"
readonly install_root="${install_parent}/${sail_version}"
readonly command_parent="${account_home}/.local/bin"

mkdir -p "$scratch_parent" "$install_parent" "$command_parent"
exec 9>"${install_parent}/.bootstrap.lock"
flock 9

if [[ (-e "$install_root" || -L "$install_root") && (! -d "$install_root" || -L "$install_root") ]]; then
  echo "Refusing non-directory installation target: ${install_root}" >&2
  exit 1
fi

if [[ ! -d "$install_root" ]]; then
  scratch_dir=$(mktemp -d "${scratch_parent}/install.XXXXXX")
  readonly scratch_dir
  trap 'rm -rf -- "$scratch_dir"' EXIT
  archive_path="${scratch_dir}/${archive_name}"

  curl --fail --show-error --location --proto '=https' --tlsv1.2 \
    --output "$archive_path" "$release_url"
  printf '%s  %s\n' "$archive_sha256" "$archive_path" | sha256sum --check --status

  if ! tar -tzf "$archive_path" | awk '
    $0 !~ /^sail\// || $0 ~ /(^|\/)\.\.($|\/)/ { invalid = 1 }
    END { exit invalid }
  '; then
    echo "Release archive contains an invalid path" >&2
    exit 1
  fi
  if ! LC_ALL=C tar -tvzf "$archive_path" | awk '
    substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { invalid = 1 }
    END { exit invalid }
  '; then
    echo "Release archive contains a link or special file" >&2
    exit 1
  fi

  tar --no-same-owner --no-same-permissions -xzf "$archive_path" -C "$scratch_dir"
  mv -T -- "$scratch_dir/sail" "$install_root"
fi

for command_name in sail z3; do
  command_target="${install_root}/bin/${command_name}"
  command_link="${command_parent}/${command_name}"
  if [[ ! -x "$command_target" ]]; then
    echo "Installed command is missing or not executable: ${command_target}" >&2
    exit 1
  fi
  if [[ -e "$command_link" || -L "$command_link" ]]; then
    if [[ "$(readlink -f -- "$command_link")" != "$command_target" ]]; then
      echo "Refusing to replace existing command: ${command_link}" >&2
      exit 1
    fi
  else
    ln -s -- "$command_target" "$command_link"
  fi
done

actual_version=$(PATH="${command_parent}:${install_root}/bin:${PATH}" \
  "${command_parent}/sail" --version)
readonly actual_version
readonly expected_version="Sail ${sail_version} (sail2 @ ${sail_revision})"
if [[ "$actual_version" != "$expected_version" ]]; then
  echo "Unexpected Sail version: ${actual_version}" >&2
  exit 1
fi

printf '%s\n' "$actual_version"
