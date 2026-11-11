#!/usr/bin/env python3
"""
Unit and integration test suite for KernelEye Python SDK and MCP server.
Compatible with pytest and standard python3 execution.
"""

import os
import sys
import json
import pytest

# Add package directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kerneleye import KernelFence, fence_agent
from kerneleye import mcp_server


def test_kernel_fence_init():
    """Verify default initialization parameters."""
    fence = KernelFence()
    assert fence.target_pid is None
    assert "curl" in fence.block_binaries
    assert "wget" in fence.block_binaries
    assert "nc" in fence.block_binaries
    assert "id_rsa" in fence.block_files
    assert ".env" in fence.block_files
    assert fence.audit_only is False
    assert fence.cryo_freeze is False
    assert fence.scrub_env is False
    assert fence.daemon_path is not None


def test_kernel_fence_custom_policies():
    """Verify custom security policies and scrub options."""
    fence = KernelFence(
        pid=1337,
        block_binaries=["custom_bin", "bash"],
        block_files=[".aws_keys", "secret.json"],
        audit_only=True,
        cryo_freeze=True,
        scrub_env=True,
        allow_env=["PATH", "LANG"],
        audit_log="audit.jsonl",
    )
    assert fence.target_pid == 1337
    assert fence.block_binaries == ["custom_bin", "bash"]
    assert fence.block_files == [".aws_keys", "secret.json"]
    assert fence.audit_only is True
    assert fence.cryo_freeze is True
    assert fence.scrub_env is True
    assert fence.allow_env == ["PATH", "LANG"]
    assert fence.audit_log == "audit.jsonl"


def test_fence_agent_decorator():
    """Verify @fence_agent decorator signature, wrapping, and return value."""
    @fence_agent(block_binaries=["curl"], protect_files=[".env"])
    def dummy_task(x: int, y: int) -> int:
        """Adds two numbers."""
        return x + y

    assert dummy_task(3, 4) == 7
    assert dummy_task.__name__ == "dummy_task"
    assert dummy_task.__doc__ == "Adds two numbers."


def test_honeypot_canary_lifecycle(tmp_path, monkeypatch):
    """Verify honeypot canary credential creation on enter and cleanup on exit."""
    monkeypatch.chdir(tmp_path)
    fence = KernelFence(honeypot_canary=True)
    canary_path = os.path.join(str(tmp_path), ".env.canary")

    with fence:
        assert os.path.exists(canary_path)
        with open(canary_path, "r") as f:
            content = f.read()
        assert "AWS_SECRET_ACCESS_KEY=" in content
        assert "AKIA_CANARY" in content

    # On context exit, honeypot canary should be deleted
    assert not os.path.exists(canary_path)


def test_mcp_server_initialize():
    """Verify MCP protocol initialization handshake."""
    responses = []
    def mock_send(resp):
        responses.append(resp)

    original_send = mcp_server.send_response
    mcp_server.send_response = mock_send
    try:
        mcp_server.handle_initialize(1)
        assert len(responses) == 1
        res = responses[0]
        assert res["id"] == 1
        assert res["result"]["serverInfo"]["name"] == "kerneleye"
        assert res["result"]["serverInfo"]["version"] == "0.2.0"
    finally:
        mcp_server.send_response = original_send


def test_mcp_server_tools_list():
    """Verify MCP tools discovery includes execute, inspect, and freeze tools."""
    responses = []
    def mock_send(resp):
        responses.append(resp)

    original_send = mcp_server.send_response
    mcp_server.send_response = mock_send
    try:
        mcp_server.handle_tools_list(2)
        assert len(responses) == 1
        tools = responses[0]["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert "execute_fenced_command" in tool_names
        assert "kerneleye_inspect_fence" in tool_names
        assert "kerneleye_freeze_process" in tool_names
    finally:
        mcp_server.send_response = original_send


def test_mcp_server_inspect_tool():
    """Verify kerneleye_inspect_fence tool execution."""
    responses = []
    def mock_send(resp):
        responses.append(resp)

    original_send = mcp_server.send_response
    mcp_server.send_response = mock_send
    try:
        mcp_server.handle_tools_call(3, {"name": "kerneleye_inspect_fence", "arguments": {}})
        assert len(responses) == 1
        content_text = responses[0]["result"]["content"][0]["text"]
        data = json.loads(content_text)
        assert data["status"] == "operational"
        assert len(data["lsm_hooks"]) == 9
        assert "socket_connect" in data["lsm_hooks"]
    finally:
        mcp_server.send_response = original_send


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
