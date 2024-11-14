#!/bin/bash

verify_snp_host() {
local AMDSEV_URL="https://github.com/LakshmiSaiHarika/AMDSEV.git"
local AMDSEV_DEFAULT_BRANCH="fedora-build-install-upstream-kernel"

if ! sudo dmesg | grep -i "SEV-SNP enabled" 2>&1 >/dev/null; then
  echo -e "SEV-SNP not enabled on the host. Please follow these steps to enable:\n\
  $(echo "${AMDSEV_URL}" | sed 's|\.git$||g')/tree/${AMDSEV_DEFAULT_BRANCH}#prepare-host"
  return 1
fi
}

check_rust_on_host() {
  # Install Rust on the host
  source "${HOME}/.cargo/env" 2>/dev/null || true
  if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -sSf | sh -s -- -y
    source "${HOME}/.cargo/env" 2>/dev/null
  fi
}

