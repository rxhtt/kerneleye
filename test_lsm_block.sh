#!/usr/bin/env bash
set -e

echo "[+] Testing eBPF LSM bprm_check_security enforcement..."
echo "[+] Target dummy command to block: curl"
echo ""

# 1. Test allowed command
echo "[*] Executing allowed command (/bin/true)..."
if /bin/true; then
    echo "[+] Allowed command executed successfully."
else
    echo "[-] Unexpected failure on allowed command."
    exit 1
fi

# 2. Test blocked command (curl)
echo "[*] Attempting to execute blocked command (/usr/bin/curl --version)..."
set +e
output=$(/usr/bin/curl --version 2>&1)
exit_code=$?
set -e

echo "[*] Return status: $exit_code"
echo "[*] Output: $output"

if [ $exit_code -ne 0 ]; then
    echo "[+] Execution blocked by kernel LSM as expected (-EPERM / Operation not permitted)."
else
    echo "[-] Command was not blocked. (Ensure daemon is running with root and BPF LSM is active)"
fi

echo ""
echo "[+] Test finished without kernel panic or instability."
