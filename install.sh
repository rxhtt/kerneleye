#!/usr/bin/env bash
set -eo pipefail

BOLD='\033[1m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
RESET='\033[0m'

echo -e "${BOLD}================================================================${RESET}"
echo -e "${BOLD}   KERNELEYE: ZERO-CONTAINER eBPF LSM AGENT SECURITY INSTALLER  ${RESET}"
echo -e "${BOLD}================================================================${RESET}"

# 1. Check OS
if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${RED}[-] Error: KernelEye requires Linux kernel 5.8+ with eBPF LSM support.${RESET}"
    exit 1
fi

# 2. Check eBPF LSM kernel support
if [ -f "/sys/kernel/security/lsm" ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if [[ "$LSM_LIST" =~ "bpf" ]]; then
        echo -e "${GREEN}[+] eBPF LSM support verified in kernel:${RESET} $LSM_LIST"
    else
        echo -e "${YELLOW}[!] Warning: 'bpf' not detected in active LSM list ($LSM_LIST).${RESET}"
        echo -e "${YELLOW}    To enable, append 'lsm=...,bpf' to your kernel boot parameters.${RESET}"
    fi
else
    echo -e "${YELLOW}[!] Notice: /sys/kernel/security/lsm not available. Assuming compatible kernel.${RESET}"
fi

# 3. Locate compiled binary or build artifact
INSTALL_TARGET="/usr/local/bin/kerneleye"
SRC_BIN=""

if [ -f "target/release/kerneleye" ]; then
    SRC_BIN="target/release/kerneleye"
elif [ -f "../target/release/kerneleye" ]; then
    SRC_BIN="../target/release/kerneleye"
elif [ -f "releases/kerneleye" ]; then
    SRC_BIN="releases/kerneleye"
fi

if [ -n "$SRC_BIN" ]; then
    echo -e "[*] Installing local release binary ($SRC_BIN) to $INSTALL_TARGET..."
    sudo cp "$SRC_BIN" "$INSTALL_TARGET"
    sudo chmod 755 "$INSTALL_TARGET"
else
    echo -e "[*] Building kerneleye release binary from source via cargo xtask..."
    cargo xtask build --release -j 2
    sudo cp target/release/kerneleye "$INSTALL_TARGET"
    sudo chmod 755 "$INSTALL_TARGET"
fi

echo -e "${GREEN}[+] Successfully installed KernelEye to $INSTALL_TARGET${RESET}"
"$INSTALL_TARGET" --version
echo -e "\n${BOLD}Quick Start:${RESET}"
echo "  sudo kerneleye run -- <COMMAND> [ARGS...]"
echo "  sudo kerneleye top"
echo ""
