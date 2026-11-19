"""
Demo & Self-Test Script for MCP-Sentry Circuit Breaker
Simulates JSON-RPC traffic between Client (Claude/Cursor) and a mock MCP Server.
"""

import json
import subprocess
import sys
import os

def test_circuit_breaker():
    print("=== Testing MCP-Sentry Circuit Breaker ===")
    
    # We run mcp_sentry wrapping a simple echo/mock server
    sentry_script = os.path.join(os.path.dirname(__file__), "mcp_sentry.py")
    
    # Simple inline python mock server that accepts JSON-RPC and replies
    mock_server_code = (
        "import sys, json\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    resp = {'jsonrpc': '2.0', 'id': msg.get('id'), 'result': {'content': [{'type': 'text', 'text': 'ok'}]}}\n"
        "    sys.stdout.write(json.dumps(resp) + '\\n')\n"
        "    sys.stdout.flush()\n"
    )
    
    cmd = [sys.executable, sentry_script, "--max-loop", "2", "--window", "10", "--", sys.executable, "-c", mock_server_code]
    
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    def send_rpc(msg_dict):
        proc.stdin.write(json.dumps(msg_dict) + "\n")
        proc.stdin.flush()
        res_line = proc.stdout.readline()
        return json.loads(res_line) if res_line else None

    # Step 1: Normal call
    req1 = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "query_db", "arguments": {"sql": "SELECT 1"}}}
    res1 = send_rpc(req1)
    print(f"Call 1 Status: {'ALLOWED' if not res1.get('result', {}).get('isError') else 'TRIPPED'}")
    assert not res1.get('result', {}).get('isError'), "First call should pass"

    # Step 2: Identical call (attempt 2)
    req2 = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "query_db", "arguments": {"sql": "SELECT 1"}}}
    res2 = send_rpc(req2)
    print(f"Call 2 Status: {'ALLOWED' if not res2.get('result', {}).get('isError') else 'TRIPPED'}")
    assert not res2.get('result', {}).get('isError'), "Second call within threshold should pass"

    # Step 3: Identical call (attempt 3 -> Should TRIP circuit breaker!)
    req3 = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "query_db", "arguments": {"sql": "SELECT 1"}}}
    res3 = send_rpc(req3)
    is_tripped = res3.get('result', {}).get('isError') is True
    print(f"Call 3 Status: {'CIRCUIT TRIPPED (PASS)' if is_tripped else 'FAILED TO TRIP'}")
    print(f"Intercept Message: {res3['result']['content'][0]['text']}")
    assert is_tripped, "Third identical call must trigger circuit breaker"

    # Step 4: Security DLP test (.env leak)
    req4 = {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/app/.env"}}}
    res4 = send_rpc(req4)
    is_blocked = res4.get('result', {}).get('isError') is True
    print(f"Security Test (.env): {'BLOCKED (PASS)' if is_blocked else 'FAILED TO BLOCK'}")
    print(f"Security Message: {res4['result']['content'][0]['text']}")
    assert is_blocked, ".env access must be blocked"

    proc.terminate()
    print("\n🎉 ALL TESTS PASSED! MCP-Sentry works flawlessly out of the box.")

if __name__ == "__main__":
    test_circuit_breaker()
