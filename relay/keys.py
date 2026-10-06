"""Looking up readers' public keys on the Orbit Mail server.

Before a message is queued, the receive hook needs the public key of the
mailbox it is for. The server answers ``GET /api/relay/keys/?address=`` with
the key and its id for any mailbox the node's API key may deliver to: a
user-scoped key sees only its owner's mailboxes, an admin key sees them all.

Keys are cached on disk for a short while so a burst of mail for one address
costs one request, and so a brief server outage does not hold up mail for a
reader whose key was seen recently. A mailbox that has no key yet is cached
for a shorter time; the hook defers such mail at Postfix, which retries, and
the message is sealed as soon as the reader has set a key.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time

from .crypto import EncryptionError, key_id, parse_public_key
from .transport import PermanentError, RetryableError

logger = logging.getLogger("orbit.relay.keys")


class KeyUnavailable(Exception):
    """No usable public key for an address right now.

    ``retryable`` is True when waiting may help (server unreachable, or the
    reader has not set a key yet) and False when it cannot (this node's API
    key may not deliver to that mailbox).
    """

    def __init__(self, message, retryable=True):
        super().__init__(message)
        self.retryable = retryable


class PublicKeyDirectory:
    """Fetches and caches public keys, by address."""

    def __init__(self, client, cache_dir, ttl=600.0, missing_ttl=60.0):
        self.client = client
        self.cache_dir = os.path.abspath(cache_dir)
        self.ttl = ttl
        self.missing_ttl = missing_ttl

    def lookup(self, address):
        """Return ``(kid, raw_public)`` for ``address`` or raise KeyUnavailable."""
        address = (address or "").strip().lower()
        if not address or "@" not in address:
            raise KeyUnavailable(f"{address!r} is not an address.", retryable=False)
        cached = self._read(address)
        now = time.time()
        if cached is not None:
            age = now - float(cached.get("fetched_at") or 0)
            if cached.get("public_key") and age < self.ttl:
                return self._entry(cached)
            if not cached.get("public_key") and age < self.missing_ttl:
                raise KeyUnavailable(f"{address} has not set an encryption key yet.")
        try:
            found = self.client.fetch_public_key(address)
        except RetryableError as error:
            if cached is not None and cached.get("public_key"):
                # The server is away; a key seen recently is still the right key.
                logger.warning("Using the cached key for %s; the server is unreachable: %s", address, error)
                return self._entry(cached)
            raise KeyUnavailable(f"Could not fetch the key for {address}: {error}") from error
        except PermanentError as error:
            raise KeyUnavailable(f"The server refused the key for {address}: {error}", retryable=False) from error
        if not found:
            self._write(address, {"address": address, "fetched_at": now})
            raise KeyUnavailable(f"{address} has not set an encryption key yet.")
        try:
            raw_public = parse_public_key(found.get("public_key"))
        except EncryptionError as error:
            raise KeyUnavailable(f"The server sent a malformed key for {address}: {error}", retryable=False) from error
        kid = key_id(raw_public)
        if found.get("kid") and found["kid"] != kid:
            raise KeyUnavailable(f"The server's key id for {address} does not match its key.", retryable=False)
        record = {"address": address, "kid": kid, "public_key": found["public_key"], "fetched_at": now}
        self._write(address, record)
        return self._entry(record)

    def forget(self, address):
        try:
            os.remove(self._path(address))
        except OSError:
            pass

    @staticmethod
    def _entry(record):
        return record["kid"], parse_public_key(record["public_key"])

    def _path(self, address):
        return os.path.join(self.cache_dir, hashlib.sha256(address.encode("utf-8")).hexdigest()[:32] + ".json")

    def _read(self, address):
        try:
            with open(self._path(address), encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _write(self, address, record):
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            path = self._path(address)
            tmp = f"{path}.tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(record, handle)
            os.replace(tmp, path)
        except OSError as error:
            # A cache miss is only a slower path; it must never stop mail.
            logger.warning("Could not cache the key for %s: %s", address, error)
