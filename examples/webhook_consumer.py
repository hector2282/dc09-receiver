"""Minimal webhook consumer that verifies the HMAC signature.

    DC09_WEBHOOK_SECRET=change-me python examples/webhook_consumer.py

Then point a ``webhook`` sink at http://127.0.0.1:8080/dc09.
"""

import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ.get("DC09_WEBHOOK_SECRET", "change-me").encode()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        expected = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, self.headers.get("X-DC09-Signature", "")):
            self.send_response(401)
            self.end_headers()
            return
        event = json.loads(body)
        if event["category"] == "alarm":
            print(
                f"ALARM  {event['account_name'] or event['account']}: {event['description']}"
                f" (zone {event['zone_name'] or event['zone']})"
            )
        else:
            print(f"{event['category']:<11} {event['account']}: {event['description']}")
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
