"""Relay configuration, read from the environment.

Everything is an environment variable so the same code runs unchanged on every
node; a node differs only by its name and the API key. The install script
served by Orbit Mail writes these into ``/etc/orbit-mail/relay.env``, which
every entry point reads (see :func:`load_env_file`).

There are exactly three things a node must know: where the Orbit Mail server
is, the relay API key issued there, and its own encryption key, which opens
the outgoing mail people seal to it (see ``relay/crypto.py``). Everything
else, including the domains and addresses it should accept mail for and the
public keys it seals inbound mail to, is downloaded from the server. A node
without a key of its own refuses to start: the relay never hands the server
readable mail.
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


#: Where the installer writes the node's encryption key.
DEFAULT_KEY_FILE = "/etc/orbit-mail/relay.key"

#: Where the installer writes the node's settings.
DEFAULT_CONFIG_FILE = "/etc/orbit-mail/relay.env"


def load_env_file(path):
    """Copy ``NAME=value`` lines from ``path`` into the environment.

    Postfix starts the receive hook with an almost empty environment, and an
    operator's shell has none of the node's settings, so every entry point
    reads the installer's file itself rather than relying on whoever started
    it. A variable already set wins, so one command can still override a
    value. A missing or unreadable file is not an error: validation reports
    whatever is then missing.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name and not os.environ.get(name):
            os.environ[name] = value


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
    keys_path: str = field(default_factory=lambda: _env("ORBIT_KEYS_PATH", "/api/relay/keys/"))
    #: Set to 0 only for a local http server with a self-signed certificate.
    verify_tls: bool = field(default_factory=lambda: _env_bool("ORBIT_VERIFY_TLS", True))

    # --- Encryption -------------------------------------------------------
    #: Required. This node's private key (``orbp_...``), which opens the
    #: outgoing mail browsers seal to its public key. Either the key itself
    #: or a file holding it; the file is preferred so the key never appears
    #: in a process listing or a compose file. The file defaults to where the
    #: installer writes it.
    encryption_key: str = field(default_factory=lambda: _env("ORBIT_RELAY_ENCRYPTION_KEY", ""))
    encryption_key_file: str = field(default_factory=lambda: _env("ORBIT_RELAY_ENCRYPTION_KEY_FILE", DEFAULT_KEY_FILE))
    #: How long a reader's public key, fetched from the server, is trusted
    #: before it is fetched again; and how long "no key yet" is remembered.
    key_cache_seconds: int = field(default_factory=lambda: _env_int("ORBIT_KEY_CACHE_SECONDS", 600))
    missing_key_cache_seconds: int = field(default_factory=lambda: _env_int("ORBIT_MISSING_KEY_CACHE_SECONDS", 60))

    #: How often to check in; the server may ask for a different interval.
    heartbeat_interval: int = field(default_factory=lambda: _env_int("ORBIT_HEARTBEAT_INTERVAL", 60))
    #: How often to ask for outgoing mail when the last poll came back empty.
    outbound_poll_interval: int = field(default_factory=lambda: _env_int("ORBIT_OUTBOUND_POLL_INTERVAL", 5))
    outbound_batch: int = field(default_factory=lambda: _env_int("ORBIT_OUTBOUND_BATCH", 10))

    # --- Local paths ------------------------------------------------------
    maildrop_dir: str = field(default_factory=lambda: _env("ORBIT_MAILDROP_DIR", "/var/spool/orbit-mail/incoming"))
    queue_dir: str = field(default_factory=lambda: _env("ORBIT_QUEUE_DIR", "/var/lib/orbit-mail/queue"))
    state_dir: str = field(default_factory=lambda: _env("ORBIT_STATE_DIR", "/var/lib/orbit-mail/state"))
    #: Where the Postfix lookup tables are written. ``Config(postfix_dir="")``
    #: disables Postfix integration, for tests; a blank variable means the
    #: default, like every other setting here.
    postfix_dir: str = field(default_factory=lambda: _env("ORBIT_POSTFIX_DIR", "/etc/postfix/orbit"))
    #: The lookup table type in ``main.cf``. The installer sets it to the
    #: host Postfix's ``default_database_type``.
    postfix_db_type: str = field(default_factory=lambda: _env("ORBIT_POSTFIX_DB_TYPE", "hash"))
    sendmail_path: str = field(default_factory=lambda: _env("ORBIT_SENDMAIL", "/usr/sbin/sendmail"))

    # --- Status endpoint --------------------------------------------------
    #: Unauthenticated, so it listens on loopback unless told otherwise.
    status_address: str = field(default_factory=lambda: _env("ORBIT_STATUS_ADDRESS", "127.0.0.1"))
    #: 0 turns the endpoint off.
    status_port: int = field(default_factory=lambda: _env_int("ORBIT_STATUS_PORT", 8080))

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
        from .crypto import EncryptionError, load_cipher

        try:
            load_cipher(self)
        except EncryptionError as error:
            problems.append(f"Encryption: {error}")
        return problems

    @property
    def has_api_key(self):
        return bool(self.api_key)

    @property
    def is_enrolled(self):
        """Kept for callers that predate the API-key design."""
        return self.has_api_key


def load_config():
    load_env_file(os.environ.get("ORBIT_CONFIG_FILE", DEFAULT_CONFIG_FILE))
    return Config()
