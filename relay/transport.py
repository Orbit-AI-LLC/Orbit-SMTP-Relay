"""The HTTP client for the Orbit Mail server.

Standard library only, so the relay needs no third-party Python packages here.
On a node whose job is to stay up, every dependency is something that can break
an update.

The important distinction is between two kinds of failure, because the queue
treats them differently:

* **Retryable**: timeout, connection refused, 5xx, 429, and 401 (the API key
  may have been rotated and the node not yet updated; the mail must wait).
* **Permanent**: other 4xx, or a response that says ``retryable: false``,
  such as ``413`` for a message over the server's limit. Retrying forever
  would fill the disk with mail that can never be delivered; the agent parks
  the message and bounces it to the sender (``relay/bounce.py``).
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

USER_AGENT = "OrbitMailRelay/3.0"


class TransportError(Exception):
    """Base class for anything that went wrong talking to the server."""


class RetryableError(TransportError):
    """The request may succeed later. Keep the message queued."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class PermanentError(TransportError):
    """The request will never succeed. Stop retrying."""

    def __init__(self, message, status=None, code=None):
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass
class Response:
    status: int
    body: str
    headers: dict

    def json(self):
        if not self.body:
            return {}
        try:
            return json.loads(self.body)
        except json.JSONDecodeError:
            return {}


class HttpClient:
    """A small JSON-over-HTTP client with explicit retry semantics."""

    def __init__(self, timeout=20.0, verify_tls=True):
        self.timeout = timeout
        self._ssl_context = None
        if not verify_tls:
            # Only reachable through an explicit configuration choice.
            self._ssl_context = ssl._create_unverified_context()

    def request(self, url, *, method="POST", payload=None, headers=None, timeout=None):
        data = None
        request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request_headers.update(headers or {})
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)

        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout, context=self._ssl_context) as response:
                body = response.read().decode("utf-8", errors="replace")
                return Response(response.status, body, dict(response.headers))
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            status = error.code
            detail = ""
            retryable = None
            code = None
            try:
                parsed = json.loads(body)
                detail = parsed.get("error", "")
                retryable = parsed.get("retryable")
                code = parsed.get("code")
            except (json.JSONDecodeError, AttributeError):
                detail = body[:200]
            message = f"HTTP {status}: {detail or error.reason}"
            if retryable is True or status in (401, 429) or status >= 500:
                raise RetryableError(message, status=status) from error
            raise PermanentError(message, status=status, code=code) from error
        except urllib.error.URLError as error:
            raise RetryableError(f"Connection failed: {error.reason}") from error
        except (socket.timeout, TimeoutError) as error:
            raise RetryableError(f"Timed out: {error}") from error
        except ssl.SSLError as error:
            # The connection broke while the answer was being read. A
            # certificate problem fails the handshake instead, and urllib
            # reports that as the URLError above.
            raise RetryableError(f"TLS error: {error}") from error
        except OSError as error:
            raise RetryableError(f"Network error: {error}") from error


class MailServerClient:
    """Everything the relay says to the Orbit Mail server."""

    def __init__(self, config):
        self.config = config
        self.base = config.server_url.rstrip("/")
        self.http = HttpClient(timeout=config.request_timeout, verify_tls=config.verify_tls)

    def _url(self, path, **fmt):
        return f"{self.base}/{path.lstrip('/')}".format(**fmt)

    def _headers(self):
        headers = {"X-Orbit-Relay-Node": self.config.node_name}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def deliver(self, message):
        """Post one inbound message. Raises RetryableError or PermanentError.

        Only ciphertext ever leaves the node. ``raw`` is the base64 ciphertext
        the receive hook produced; the server stores it as it is and files the
        message from the readable header block beside it.
        """
        if not getattr(message, "is_encrypted", False):
            # Cannot happen through the receive hook, which seals every
            # message. A queue file edited by hand, or one written by a
            # release before 3.0, is parked rather than posted readable.
            raise PermanentError("Refusing to post a readable message; the relay only delivers sealed mail.", code="not_encrypted")
        payload = {
            "message_id": message.id,
            "recipient": message.recipient,
            "envelope_from": message.envelope_from,
            "encoding": "base64",
            "received_at": message.received_at,
            "relay_node": self.config.node_name,
            "raw": message.raw,
            "encrypted": dict(message.encryption),
            "headers": message.headers,
            "has_attachments": bool(message.has_attachments),
            "size": int(message.plain_size or 0),
        }
        response = self.http.request(self._url(self.config.inbound_path), payload=payload, headers=self._headers())
        body = response.json()
        if body.get("retryable") is False:
            raise PermanentError(body.get("error", "Rejected as permanently undeliverable."), status=response.status, code=body.get("code"))
        return body

    def heartbeat(self, status, config_digest=""):
        """Report liveness and fetch the fleet configuration."""
        payload = dict(status)
        payload["config_digest"] = config_digest
        return self.http.request(self._url(self.config.heartbeat_path), payload=payload, headers=self._headers()).json()

    def claim_outbound(self, limit=10, encryption_kid=""):
        """Take a batch of outgoing messages to send.

        Sealed mail goes only to a node it was sealed to. Naming this node's
        key id keeps that right when another node (another owner's, say)
        reports under the same name.
        """
        payload = {"node": self.config.node_name, "limit": limit}
        if encryption_kid:
            payload["encryption_kid"] = encryption_kid
        return self.http.request(self._url(self.config.outbound_claim_path), payload=payload, headers=self._headers()).json()

    def report_outbound(self, outbound_id, status, error=""):
        payload = {"node": self.config.node_name, "status": status, "error": error[:2000]}
        return self.http.request(self._url(self.config.outbound_result_path, id=outbound_id), payload=payload, headers=self._headers()).json()

    def health(self):
        """A cheap liveness probe used by the status endpoint."""
        return self.http.request(self._url(self.config.health_path), method="GET", timeout=5.0)

    def fetch_public_key(self, address):
        """The readers' public keys for ``address``: ``{address, kid, public_key, readers}``.

        Returns None when the mailbox exists but nobody who reads it has set
        a key yet. Raises PermanentError when this node's API key may not deliver
        to that mailbox or there is no such mailbox, RetryableError when the
        server cannot be reached.
        """
        from urllib.parse import urlencode

        url = self._url(self.config.keys_path) + "?" + urlencode({"address": address})
        try:
            response = self.http.request(url, method="GET", headers=self._headers())
        except (RetryableError, PermanentError) as error:
            # The server answers 404 with code no_key, marked retryable, until
            # a reader sets a key, and 404 with code no_mailbox for good.
            if error.status == 404 and getattr(error, "code", None) != "no_mailbox":
                return None
            raise
        body = response.json()
        if not body.get("public_key") and not body.get("readers"):
            return None
        return body
