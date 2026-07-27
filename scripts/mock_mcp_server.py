#!/usr/bin/env python3
"""Minimal MCP stdio server for oscar integration tests (no deps)."""
import json
import sys


def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        if b":" in line:
            k, v = line.decode().split(":", 1)
            headers[k.strip().lower()] = v.strip()
    n = int(headers.get("content-length", "0"))
    body = sys.stdin.buffer.read(n)
    return json.loads(body.decode())


def write_message(msg):
    body = json.dumps(msg).encode()
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode())
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def main():
    while True:
        msg = read_message()
        if msg is None:
            break
        mid = msg.get("id")
        method = msg.get("method")
        if method == "initialize":
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock", "version": "0.0.1"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "Echo a message (mock MCP tool)",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "text": {"type": "string"}
                                    },
                                    "required": ["text"],
                                },
                            }
                        ]
                    },
                }
            )
        elif method == "tools/call":
            params = msg.get("params") or {}
            args = params.get("arguments") or {}
            text = args.get("text", "")
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "content": [{"type": "text", "text": f"echo:{text}"}],
                        "isError": False,
                    },
                }
            )
        else:
            if mid is not None:
                write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32601, "message": f"unknown {method}"},
                    }
                )


if __name__ == "__main__":
    main()
