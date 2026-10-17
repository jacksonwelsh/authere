#!/usr/bin/env python3
"""Regression tests for webhook request validation and request isolation."""

import hashlib
import hmac
import http.client
import json
import os
import socket
import threading
import unittest
from unittest.mock import patch

os.environ["WEBHOOK_SECRET"] = "test-webhook-secret"
import webhook


class WebhookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = webhook.WebhookServer(("127.0.0.1", 0), webhook.WebhookHandler)
        cls.address = cls.server.server_address
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def post(self, payload, signature=None):
        signature = signature or "sha256=" + hmac.new(
            b"test-webhook-secret", payload, hashlib.sha256
        ).hexdigest()
        connection = http.client.HTTPConnection(*self.address, timeout=2)
        try:
            connection.request("POST", "/webhook", payload, {
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "release",
            })
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def test_signed_release_deploys_once(self):
        payload = json.dumps({"action": "published", "release": {"tag_name": "latest"}}).encode()
        with patch.object(webhook.subprocess, "Popen") as spawn:
            self.assertEqual(self.post(payload), 202)
            # Wait for the handler to finish its accepted request.
            for _ in range(100):
                if spawn.called:
                    break
                threading.Event().wait(0.01)
            spawn.assert_called_once()

    def test_invalid_signature_never_deploys(self):
        with patch.object(webhook.subprocess, "Popen") as spawn:
            self.assertEqual(self.post(b"{}", "sha256=wrong"), 403)
            spawn.assert_not_called()
        self.assertFalse(webhook.verify_signature(b"{}", "sha256=\u00e9"))

    def test_malformed_signed_json_returns_bad_request(self):
        for payload in [b"{", b"[]", b'{"release":null}']:
            self.assertEqual(self.post(payload), 400)

    def test_invalid_content_length_is_rejected_before_reading(self):
        for headers in [
            b"Content-Length: -1\r\n",
            b"Content-Length: invalid\r\n",
            b"Content-Length: 1\r\nContent-Length: 2\r\n",
            b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        ]:
            with socket.create_connection(self.address, timeout=2) as connection:
                connection.sendall(b"POST /webhook HTTP/1.0\r\n" + headers + b"\r\n")
                response = connection.recv(4096)
                self.assertIn(b" 400 ", response)

    def test_incomplete_body_does_not_block_health_checks(self):
        with socket.create_connection(self.address, timeout=2) as stalled:
            stalled.sendall(b"POST /webhook HTTP/1.0\r\nContent-Length: 100\r\n\r\n")
            connection = http.client.HTTPConnection(*self.address, timeout=2)
            try:
                connection.request("GET", "/health")
                self.assertEqual(connection.getresponse().status, 200)
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
