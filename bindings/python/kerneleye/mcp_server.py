#!/usr/bin/env python3
"""
KernelEye MCP Server
Standard Model Context Protocol (MCP) stdio server providing secure,
in-kernel eBPF LSM fenced command execution and process control for Claude Desktop, Cursor, and OpenHands.
"""

import sys
import json
import os
import signal
from .fence import KernelFence


def send_response(response: dict):
    line = json.dumps(response)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def handle_initialize(req_id: int):
    send_response({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "kerneleye",
                "version": "0.2.0"
            }
        }
    })


def handle_tools_list(req_id: int):
    send_response({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "tools": [
                {
                    "name": "execute_fenced_command",
                    "description": (
                        "Executes a bash command inside a kernel-enforced eBPF LSM sandbox. "
                        "Blocks unauthorized network egress (AF_INET/AF_INET6/UDP sendto), "
                        "sensitive credential file access (.env, id_rsa), and dangerous binaries."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The shell command to execute inside the kernel fence."
                            },
                            "audit_only": {
                                "type": "boolean",
                                "description": "If true, logs security violations without killing/blocking."
                            },
                            "scrub_env": {
                                "type": "boolean",
                                "description": "If true, sanitizes API keys and tokens from the environment."
                            }
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "kerneleye_inspect_fence",
                    "description": (
                        "Inspects current KernelEye confinement policy, default blocked binaries, "
                        "protected sensitive file patterns, and daemon status."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "kerneleye_freeze_process",
                    "description": (
                        "Cryo-freezes a runaway or suspicious process tree in RAM (SIGSTOP) "
                        "for security inspection without destroying its state."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "pid": {
                                "type": "integer",
                                "description": "Process ID (PID) to suspend."
                            }
                        },
                        "required": ["pid"]
                    }
                }
            ]
        }
    })


def handle_tools_call(req_id: int, params: dict):
    name = params.get("name")
    args = params.get("arguments", {})

    if name == "execute_fenced_command":
        command = args.get("command", "")
        audit_only = args.get("audit_only", False)
        scrub_env = args.get("scrub_env", False)

        fence = KernelFence(audit_only=audit_only, scrub_env=scrub_env)
        with fence:
            res = fence.run_command(command, timeout=30.0)

        is_error = res.returncode != 0
        text_content = f"Return Code: {res.returncode}\n\nSTDOUT:\n{res.stdout}\n\nSTDERR:\n{res.stderr}"

        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": text_content
                    }
                ],
                "isError": is_error
            }
        })
    elif name == "kerneleye_inspect_fence":
        fence = KernelFence()
        status_info = {
            "status": "operational",
            "version": "0.2.0",
            "daemon_binary": fence.daemon_path,
            "blocked_binaries": fence.block_binaries,
            "protected_files": fence.block_files,
            "lsm_hooks": [
                "bprm_check_security",
                "socket_connect",
                "socket_sendmsg",
                "file_open",
                "task_kill",
                "ptrace_access_check",
                "inode_link",
                "inode_rename",
                "inode_unlink"
            ],
            "cryo_freeze_supported": True,
            "phantom_sinkhole_supported": True
        }
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(status_info, indent=2)
                    }
                ],
                "isError": False
            }
        })
    elif name == "kerneleye_freeze_process":
        target_pid = args.get("pid")
        if not target_pid:
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": "Missing 'pid' parameter"
                }
            })
            return
        try:
            os.kill(target_pid, signal.SIGSTOP)
            res_msg = f"[+] Process PID {target_pid} cryo-frozen in RAM via SIGSTOP."
            err = False
        except ProcessLookupError:
            res_msg = f"[-] Process PID {target_pid} not found."
            err = True
        except PermissionError:
            res_msg = f"[-] Permission denied attempting to signal PID {target_pid}."
            err = True

        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": res_msg
                    }
                ],
                "isError": err
            }
        })
    else:
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {name}"
            }
        })


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        method = req.get("method")
        req_id = req.get("id")

        if method == "initialize":
            handle_initialize(req_id)
        elif method == "tools/list":
            handle_tools_list(req_id)
        elif method == "tools/call":
            handle_tools_call(req_id, req.get("params", {}))
        elif method == "notifications/initialized":
            pass
        else:
            if req_id is not None:
                send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                })


if __name__ == "__main__":
    main()
