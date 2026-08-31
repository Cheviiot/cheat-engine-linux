#!/usr/bin/env bash
set -euo pipefail

readonly CONTAINER_NAME="lch-rust-gtk-dev"
readonly CARGO_HOME_IN_CONTAINER="/opt/lch-rust/cargo"
readonly RUSTUP_HOME_IN_CONTAINER="/opt/lch-rust/rustup"
readonly CONTAINER_PATH="${CARGO_HOME_IN_CONTAINER}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if ! command -v distrobox >/dev/null 2>&1; then
    echo "distrobox is required on the host" >&2
    exit 1
fi

if ! distrobox list | awk 'NR > 1 { print $3 }' | grep -qx "${CONTAINER_NAME}"; then
    echo "Distrobox '${CONTAINER_NAME}' does not exist; see docs/DEVELOPMENT.md" >&2
    exit 1
fi

exec distrobox enter "${CONTAINER_NAME}" -- env \
    CARGO_HOME="${CARGO_HOME_IN_CONTAINER}" \
    RUSTUP_HOME="${RUSTUP_HOME_IN_CONTAINER}" \
    PATH="${CONTAINER_PATH}" \
    "$@"
