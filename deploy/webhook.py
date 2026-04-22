#!/usr/bin/env python3
"""
Minimal GitHub webhook receiver for authere deployments.

Listens for GitHub release events, verifies the HMAC-SHA256 signature,
and triggers the deploy script when a new release is published.

Configuration via environment variables:
  WEBHOOK_SECRET  - GitHub webhook secret (required)
  WEBHOOK_PORT    - Port to listen on (default: 9000)
  DEPLOY_SCRIPT   - Path to deploy script (default: /opt/authere/deploy.sh)
"""

import hashlib
import hmac
import json
import os
import subprocess
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
DEPLOY_SCRIPT = os.environ.get("DEPLOY_SCRIPT", "/opt/authere/deploy.sh")
PORT = int(os.environ.get("WEBHOOK_PORT", "9000"))

if not WEBHOOK_SECRET:
    print("ERROR: WEBHOOK_SECRET environment variable is required", file=sys.stderr)
    sys.exit(1)


def verify_signature(payload: bytes, signature: str) -> bool:
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(
        WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/webhook":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 1_000_000:
            self.send_error(413)
            return

        payload = self.rfile.read(content_length)

        signature = self.headers.get("X-Hub-Signature-256", "")
        if not verify_signature(payload, signature):
            print("Rejected: invalid signature", file=sys.stderr)
            self.send_error(403)
            return

        event = self.headers.get("X-GitHub-Event", "")
        if event != "release":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ignored event\n")
            return

        body = json.loads(payload)
        action = body.get("action", "")
        tag = body.get("release", {}).get("tag_name", "")

        if action != "published" or tag != "latest":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ignored release\n")
            return

        print(f"Deploying release {tag}", file=sys.stderr)
        self.send_response(202)
        self.end_headers()
        self.wfile.write(b"deploying\n")

        subprocess.Popen(
            ["/bin/bash", DEPLOY_SCRIPT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        self.send_error(404)

    def log_message(self, format, *args):
        print(f"[webhook] {args[0]}", file=sys.stderr)


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), WebhookHandler)
    print(f"Webhook listener on 127.0.0.1:{PORT}", file=sys.stderr)
    server.serve_forever()
