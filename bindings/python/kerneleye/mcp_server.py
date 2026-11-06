#!/usr/bin/env python3
"""
KernelEye MCP Server
Standard Model Context Protocol (MCP) stdio server providing secure,
in-kernel eBPF LSM fenced command execution for Claude Desktop, Cursor, and OpenHands.
"""

import sys
import json
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
                "version": "0.1.0"
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
                            }
                        },
                        "required": ["command"]
                    }
                }
            ]
        }
    })


def handle_tools_call(req_id: int, params: dict):
    name = params.get("name")
    args = params.get("arguments", {})

    if name != "execute_fenced_command":
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {name}"
            }
        })
        return

    command = args.get("command", "")
    audit_only = args.get("audit_only", False)

    fence = KernelFence(audit_only=audit_only)
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


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        req_id = req.get("id")

        if method == "initialize":
            handle_initialize(req_id)
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            handle_tools_list(req_id)
        elif method == "tools/call":
            handle_tools_call(req_id, req.get("params", {}))
        elif req_id is not None:
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Unhandled method: {method}"
                }
            })


if __name__ == "__main__":
    main()
