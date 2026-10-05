"""Relay configuration, read from the environment.

Everything is an environment variable so the same image runs unchanged on every
node; a node differs only by its name and the API key. The install script
served by Orbit Mail writes these into ``/etc/orbit-mail/relay.env``.

There are exactly two things a node must know: where the Orbit Mail server is
and the relay API key issued in its admin area. Everything else, including the
domains and addresses it should accept mail for, is downloaded from the server
on every heartbeat. A third, optional setting turns on encryption: see
``relay/crypto.py``.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field


def _env(name, default=""):
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _env_int(name, default):
    try:
        return int(_env(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(name, default):
    try:
        return float(_env(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(name, default=False):
    raw = _env(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


@dataclass
class Config:
    """The relay agent's runtime settings."""

    # --- Identity ---------------------------------------------------------
    node_name: str = field(default_factory=lambda: _env("ORBIT_RELAY_NAME", socket.gethostname() or "relay-1"))
    #: The hostname Postfix announces in EHLO. Should match the MX record.
    hostname: str = field(default_factory=lambda: _env("ORBIT_RELAY_HOSTNAME", socket.getfqdn() or "relay"))

    # --- Orbit Mail server ------------------------------------------------
    server_url: str = field(default_factory=lambda: _env("ORBIT_MAIL_SERVER_URL", "http://localhost:8100").rstrip("/"))
    #: Issued in the Orbit Mail admin area. Without it the node cannot talk to
    #: the server; the agent still runs so the queue keeps accepting mail.
    api_key: str = field(default_factory=lambda: _env("ORBIT_RELAY_API_KEY", ""))
    heartbeat_path: str = field(default_factory=lambda: _env("ORBIT_HEARTBEAT_PATH", "/api/relay/heartbeat/"))
    inbound_path: str = field(default_factory=lambda: _env("ORBIT_INBOUND_PATH", "/api/relay/inbound/"))
    outbound_claim_path: str = field(default_factory=lambda: _env("ORBIT_OUTBOUND_CLAIM_PATH", "/api/relay/outbound/claim/"))
    outbound_result_path: str = field(default_factory=lambda: _env("ORBIT_OUTBOUND_RESULT_PATH", "/api/relay/outbound/{id}/result/"))
    health_path: str = field(default_factory=lambda: _env("ORBIT_HEALTH_PATH", "/api/relay/health/"))
    #: Set to 0 only for a local http server with a self-signed certificate.
    verify_tls: bool = field(default_factory=lambda: _env_bool("ORBIT_VERIFY_TLS", True))

    # --- Encryption -------------------------------------------------------
    #: Optional. When set, mail is encrypted on this node before it reaches
    #: the server and decrypted in the reader's browser. Either the key
    #: itself (``orbe_...``) or a file holding it; the file is preferred so
    #: the key never appears in a process listing or a compose file.
    encryption_key: str = field(default_factory=lambda: _env("ORBIT_RELAY_ENCRYPTION_KEY", ""))
    encryption_key_file: str = field(default_factory=lambda: _env("ORBIT_RELAY_ENCRYPTION_KEY_FILE", ""))

    #: How often to check in; the server may ask for a different interval.
    heartbeat_interval: int = field(default_factory=lambda: _env_int("ORBIT_HEARTBEAT_INTERVAL", 60))
    #: How often to ask for outgoing mail when the last poll came back empty.
    outbound_poll_interval: int = field(default_factory=lambda: _env_int("ORBIT_OUTBOUND_POLL_INTERVAL", 5))
    outbound_batch: int = field(default_factory=lambda: _env_int("ORBIT_OUTBOUND_BATCH", 10))

    # --- Local paths ------------------------------------------------------
    maildrop_dir: str = field(default_factory=lambda: _env("ORBIT_MAILDROP_DIR", "/var/spool/orbit-mail/incoming"))
    queue_dir: str = field(default_factory=lambda: _env("ORBIT_QUEUE_DIR", "/var/lib/orbit-mail/queue"))
    state_dir: str = field(default_factory=lambda: _env("ORBIT_STATE_DIR", "/var/lib/orbit-mail/state"))
    #: Where the Postfix lookup tables are written. Blank disables Postfix
    #: integration (tests, or running the agent beside a hand-managed Postfix).
    postfix_dir: str = field(default_factory=lambda: _env("ORBIT_POSTFIX_DIR", "/etc/postfix/orbit"))
    sendmail_path: str = field(default_factory=lambda: _env("ORBIT_SENDMAIL", "/usr/sbin/sendmail"))

    # --- Retry policy -----------------------------------------------------
    max_retry_hours: int = field(default_factory=lambda: _env_int("ORBIT_MAX_RETRY_HOURS", 72))
    max_attempts: int = field(default_factory=lambda: _env_int("ORBIT_MAX_ATTEMPTS", 0))
    backoff_base: float = field(default_factory=lambda: _env_float("ORBIT_BACKOFF_BASE", 5.0))
    backoff_max: float = field(default_factory=lambda: _env_float("ORBIT_BACKOFF_MAX", 300.0))
    backoff_jitter: float = field(default_factory=lambda: _env_float("ORBIT_BACKOFF_JITTER", 0.25))
    request_timeout: float = field(default_factory=lambda: _env_float("ORBIT_REQUEST_TIMEOUT", 20.0))

    # --- Logging ----------------------------------------------------------
    log_level: str = field(default_factory=lambda: _env("ORBIT_LOG_LEVEL", "INFO"))
    log_backend: str = field(default_factory=lambda: _env("ORBIT_LOG_BACKEND", "memory"))
    log_max_entries: int = field(default_factory=lambda: _env_int("ORBIT_LOG_MAX_ENTRIES", 500))
    log_path: str = field(default_factory=lambda: _env("ORBIT_LOG_PATH", ""))

    #: When false the agent drains its queue but never accepts new mail; the
    #: graceful way to take a node out before maintenance.
    accepting_mail: bool = field(default_factory=lambda: _env_bool("ORBIT_ACCEPTING_MAIL", True))

    def validate(self):
        """Return a list of configuration problems, empty when usable."""
        problems = []
        if not self.node_name:
            problems.append("ORBIT_RELAY_NAME is required.")
        if not self.server_url:
            problems.append("ORBIT_MAIL_SERVER_URL is required.")
        elif not self.server_url.startswith(("http://", "https://")):
            problems.append("ORBIT_MAIL_SERVER_URL must be an http(s) URL.")
        if self.backoff_base <= 0:
            problems.append("ORBIT_BACKOFF_BASE must be greater than zero.")
        if self.backoff_max < self.backoff_base:
            problems.append("ORBIT_BACKOFF_MAX must be at least ORBIT_BACKOFF_BASE.")
        if self.encryption_key or self.encryption_key_file:
            from .crypto import EncryptionError, load_cipher

            try:
                load_cipher(self)
            except EncryptionError as error:
                problems.append(f"Encryption: {error}")
        return problems

    @property
    def encryption_enabled(self):
        return bool(self.encryption_key or self.encryption_key_file)

    @property
    def has_api_key(self):
        return bool(self.api_key)

    @property
    def is_enrolled(self):
        """Kept for callers that predate the API-key design."""
        return self.has_api_key


def load_config():
    return Config()
