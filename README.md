# Guardian-AI
Guardian AI is a multi-agent cybersecurity system that detects &amp; responds to threats in real-time.It combines AI-driven agents,a secure MCP server, &amp; encrypted communication to automate incident detection, blocking responsive-reducing response time from hours to seconds.
"""
guardianai_demo.py

Single-file prototype of GuardianAI (for local demo):

- MCP Server: exposes /tools/block_ip and /tools/quarantine_device (token-protected)
- Response Agent: Flask app with /inbound that validates incoming agent messages and calls MCP
- Threat Analyst: simulated scanner that posts a high-severity event to the Response Agent

Run:
    pip install Flask requests
    python guardianai_demo.py

Watch stdout: you'll see the full flow and an audit log at ./mcp_audit.log
This is a prototype; replace shared secrets with proper auth (Descope/Cequence) for production.
"""
import threading
import time
import os
import json
from datetime import datetime
from flask import Flask, request, jsonify
import requests
from werkzeug.serving import make_server

# -------------------------
# Config (change if needed)
# -------------------------
MCP_API_TOKEN = os.environ.get("MCP_API_TOKEN", "supersecrettoken")
AGENT_SHARED_SECRET = os.environ.get("AGENT_SHARED_SECRET", "agentssecret")
MCP_HOST = "127.0.0.1"
MCP_PORT = 5000
RESP_HOST = "127.0.0.1"
RESP_PORT = 9000
AUDIT_FILE = "mcp_audit.log"

# -------------------------
# Utility: Audit logger
# -------------------------
def audit(action, payload):
    ts = datetime.utcnow().isoformat() + "Z"
    entry = f"{ts} | {action} | {payload}\n"
    with open(AUDIT_FILE, "a") as f:
        f.write(entry)

# -------------------------
# MCP Server (Flask app)
# -------------------------
mcp_app = Flask("mcp_server")

def _valid_token(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return False
    token = auth_header.split(" ", 1)[1].strip()
    return token == MCP_API_TOKEN

@mcp_app.route("/health", methods=["GET"])
def mcp_health():
    return jsonify({"status": "ok"})

@mcp_app.route("/tools/block_ip", methods=["POST"])
def mcp_block_ip():
    auth = request.headers.get("Authorization", "")
    if not _valid_token(auth):
        return jsonify({"error": "invalid_token"}), 403
    data = request.json or {}
    ip = data.get("ip_address")
    if not ip:
        return jsonify({"error": "missing_ip"}), 400
    # Demo behavior: write audit and return success
    audit("block_ip", ip)
    print(f"[MCP] blocked ip: {ip}")
    return jsonify({"result": "blocked", "ip": ip})

@mcp_app.route("/tools/quarantine_device", methods=["POST"])
def mcp_quarantine():
    auth = request.headers.get("Authorization", "")
    if not _valid_token(auth):
        return jsonify({"error": "invalid_token"}), 403
    data = request.json or {}
    dev = data.get("device_id")
    if not dev:
        return jsonify({"error": "missing_device_id"}), 400
    audit("quarantine_device", dev)
    print(f"[MCP] quarantined device: {dev}")
    return jsonify({"result": "quarantined", "device_id": dev})

# -------------------------
# Response Agent (Flask app)
# -------------------------
resp_app = Flask("response_agent")

def create_ticket(payload):
    # Demo: print a ticket JSON (replace with Jira/Asana integration)
    ticket = {
        "title": f"Security Incident: {payload.get('type')} ({payload.get('repo')})",
        "description": payload,
        "assignee": "on-call-analyst",
        "priority": payload.get('severity', 'low'),
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    print("[ResponseAgent] Created ticket:")
    print(json.dumps(ticket, indent=2))
    return ticket

def call_mcp_block_ip(ip):
    url = f"http://{MCP_HOST}:{MCP_PORT}/tools/block_ip"
    headers = {"Authorization": f"Bearer {MCP_API_TOKEN}"}
    try:
        r = requests.post(url, json={"ip_address": ip}, headers=headers, timeout=8)
        print("[ResponseAgent] MCP response:", r.status_code, r.text)
        return r
    except Exception as e:
        print("[ResponseAgent] Error calling MCP:", e)
        return None

@resp_app.route("/inbound", methods=["POST"])
def inbound():
    signature = request.headers.get("X-Agent-Sign", "")
    if signature != AGENT_SHARED_SECRET:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.json or {}
    print("[ResponseAgent] Received payload:", payload)
    # Simple decision logic
    sev = payload.get("severity", "low")
    if sev == "high" and payload.get("malicious_ip"):
        ip = payload["malicious_ip"]
        create_ticket(payload)
        call_mcp_block_ip(ip)
        return jsonify({"status": "action_taken"})
    else:
        return jsonify({"status": "no_action_needed"})

# -------------------------
# Thread wrappers to run Flask apps without blocking
# -------------------------
class ServerThread(threading.Thread):
    def __init__(self, app, host, port):
        threading.Thread.__init__(self)
        self.srv = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()
        self.host = host
        self.port = port

    def run(self):
        print(f"[ServerThread] Starting server on http://{self.host}:{self.port}")
        self.srv.serve_forever()

    def shutdown(self):
        print(f"[ServerThread] Shutting down server on http://{self.host}:{self.port}")
        self.srv.shutdown()

# -------------------------
# Threat Analyst (simulated)
# -------------------------
def threat_analyst_simulate_and_send():
    # Simulate delay for real scanning
    time.sleep(1.0)
    event = {
        "type": "leaked_secret",
        "repo": "acme/internal-service",
        "commit_id": "abc123",
        "severity": "high",
        "details": "Simulated AWS key leaked in commit message",
        "malicious_ip": "203.0.113.45"
    }
    print("[ThreatAnalyst] Detected event:", event["type"], "severity:", event["severity"])
    # Send to Response Agent
    resp_url = f"http://{RESP_HOST}:{RESP_PORT}/inbound"
    headers = {"Content-Type": "application/json", "X-Agent-Sign": AGENT_SHARED_SECRET}
    try:
        r = requests.post(resp_url, json=event, headers=headers, timeout=8)
        print("[ThreatAnalyst] Sent to Response Agent:", r.status_code, r.text)
    except Exception as e:
        print("[ThreatAnalyst] Error posting to Response Agent:", e)

# -------------------------
# Main: start servers and run simulation
# -------------------------
def main():
    # Clean previous audit file (for demo clarity)
    try:
        if os.path.exists(AUDIT_FILE):
            os.remove(AUDIT_FILE)
    except Exception:
        pass

    # Start MCP server thread
    mcp_thread = ServerThread(mcp_app, MCP_HOST, MCP_PORT)
    mcp_thread.start()
    time.sleep(0.5)

    # Start Response Agent server thread
    resp_thread = ServerThread(resp_app, RESP_HOST, RESP_PORT)
    resp_thread.start()
    time.sleep(0.5)

    try:
        # Run Threat Analyst simulation (single-shot)
        print("\n--- Running Threat Analyst simulation in 2s ---\n")
        time.sleep(2.0)
        threat_analyst_simulate_and_send()

        # Give some time for actions to complete
        time.sleep(2.0)

        # Show audit file content (if any)
        if os.path.exists(AUDIT_FILE):
            print("\n[MCP Audit Log]")
            with open(AUDIT_FILE, "r") as f:
                print(f.read())
        else:
            print("\nNo audit entries found.")

        print("\nDemo finished. Servers will shut down now.\n")
    finally:
        # Shutdown servers cleanly
        resp_thread.shutdown()
        mcp_thread.shutdown()
        # join threads
        resp_thread.join(timeout=2.0)
        mcp_thread.join(timeout=2.0)

if __name__ == "__main__":
    main()
