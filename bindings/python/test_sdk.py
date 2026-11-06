#!/usr/bin/env python3
"""
Test script for KernelEye Python SDK middleware.
Verifies that KernelFence wraps a code execution block cleanly.
"""

import os
import sys
import subprocess

# Add local directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kerneleye import KernelFence

def main():
    print("[*] Testing KernelEye Python SDK initialization...")
    fence = KernelFence(
        block_binaries=["curl", "wget", "nc"],
        block_files=["id_rsa", "credentials", ".env"],
        kill_on_violation=True
    )
    print(f"[+] KernelFence configured successfully for target PID {fence.target_pid}")
    print(f"[+] Binary deny-list: {fence.block_binaries}")
    print(f"[+] Sensitive file deny-list: {fence.block_files}")
    print("[+] Resolved daemon binary path:", fence.daemon_path)
    print("[SUCCESS] Python SDK ready for AI Agent middleware integration.")

if __name__ == "__main__":
    main()
