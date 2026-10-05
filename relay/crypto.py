"""Encrypting mail on the relay so the Orbit Mail server never sees it.

This is the optional end-to-end mode for people who host their own relay.
When a key is configured, every inbound message is encrypted here, on the host
you control, before it is posted to the Orbit Mail server; the server stores
the ciphertext and your browser decrypts it with the same key. Outgoing mail
written in the browser arrives here encrypted and is decrypted only to hand it
to Postfix.

The key is a 256-bit secret shared by the relay and the people who read the
mailbox. It is written as ``orbe_`` followed by the key in URL-safe base64, so
it is easy to recognise and to paste into the Orbit Mail settings page. The
key id is the first twelve hex characters of its SHA-256 digest; it is sent to
the server so the browser can tell which key a message needs, and it reveals
nothing about the key itself.

The cipher is AES-256-GCM with a fresh 96-bit nonce per message and a fixed
associated-data string that names the format, so a ciphertext made for one
purpose cannot be replayed as another. The browser uses WebCrypto's AES-GCM
with the same parameters, which is why there is nothing custom here: the
format is exactly what both standard libraries produce.

The ``cryptography`` package is imported lazily so a relay that does not
encrypt never needs it installed.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets

KEY_PREFIX = "orbe_"
KEY_BYTES = 32
NONCE_BYTES = 12
ALGORITHM = "A256GCM"
FORMAT_VERSION = 1
#: Authenticated but unencrypted context bound to every ciphertext.
ASSOCIATED_DATA = b"orbit-mail/e2ee/v1"


class EncryptionError(Exception):
    """A key could not be loaded or a message could not be transformed."""


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text):
    text = text.strip()
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def generate_key():
    """A new random key in its textual form."""
    return KEY_PREFIX + _b64url_encode(secrets.token_bytes(KEY_BYTES))


def parse_key(text):
    """Turn the textual key into its 32 raw bytes, or raise EncryptionError."""
    text = (text or "").strip()
    if not text.startswith(KEY_PREFIX):
        raise EncryptionError(f"Encryption keys start with {KEY_PREFIX!r}.")
    try:
        raw = _b64url_decode(text[len(KEY_PREFIX):])
    except (ValueError, TypeError) as error:
        raise EncryptionError("The encryption key is not valid base64.") from error
    if len(raw) != KEY_BYTES:
        raise EncryptionError(f"The encryption key must decode to {KEY_BYTES} bytes, not {len(raw)}.")
    return raw


def key_id(raw_key):
    """The short, non-secret identifier of a key."""
    return hashlib.sha256(raw_key).hexdigest()[:12]


def read_key_file(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as error:
        raise EncryptionError(f"Could not read the encryption key file {path}: {error}") from error


def write_key_file(path, key_text, overwrite=False):
    """Write a key with owner-only permissions. Refuses to clobber by default."""
    if os.path.exists(path) and not overwrite:
        raise EncryptionError(f"{path} already exists; pass --force to replace it.")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(key_text.strip() + "\n")
    os.chmod(path, 0o600)


def load_key_text(config):
    """The configured key as text, or an empty string when encryption is off."""
    if config.encryption_key:
        return config.encryption_key.strip()
    if config.encryption_key_file:
        return read_key_file(config.encryption_key_file)
    return ""


class Cipher:
    """AES-256-GCM with one shared key."""

    def __init__(self, raw_key):
        if len(raw_key) != KEY_BYTES:
            raise EncryptionError("Wrong key length.")
        self._key = bytes(raw_key)
        self.kid = key_id(self._key)

    @classmethod
    def from_text(cls, key_text):
        return cls(parse_key(key_text))

    def _aead(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as error:  # pragma: no cover - depends on the environment
            raise EncryptionError(
                "The 'cryptography' package is required for relay encryption. "
                "Install python3-cryptography or pip install cryptography."
            ) from error
        return AESGCM(self._key)

    def encrypt(self, plaintext):
        """Return ``(nonce, ciphertext)``; the ciphertext ends with the GCM tag."""
        nonce = secrets.token_bytes(NONCE_BYTES)
        return nonce, self._aead().encrypt(nonce, bytes(plaintext), ASSOCIATED_DATA)

    def decrypt(self, nonce, ciphertext):
        try:
            return self._aead().decrypt(bytes(nonce), bytes(ciphertext), ASSOCIATED_DATA)
        except Exception as error:
            raise EncryptionError("The message could not be decrypted with this key.") from error

    def envelope(self, nonce):
        """The non-secret parameters stored beside a ciphertext."""
        return {
            "v": FORMAT_VERSION,
            "alg": ALGORITHM,
            "kid": self.kid,
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }

    def seal(self, plaintext):
        """Encrypt and return ``(envelope, ciphertext_base64)``."""
        nonce, ciphertext = self.encrypt(plaintext)
        return self.envelope(nonce), base64.b64encode(ciphertext).decode("ascii")

    def open(self, envelope, ciphertext_base64):
        """The inverse of :meth:`seal`. Raises EncryptionError on any mismatch."""
        envelope = envelope or {}
        if envelope.get("alg", ALGORITHM) != ALGORITHM:
            raise EncryptionError(f"Unsupported encryption algorithm {envelope.get('alg')!r}.")
        if envelope.get("kid") and envelope["kid"] != self.kid:
            raise EncryptionError(f"This node holds key {self.kid}, not {envelope['kid']}.")
        try:
            nonce = base64.b64decode(envelope.get("nonce") or "", validate=True)
            ciphertext = base64.b64decode(ciphertext_base64 or "", validate=True)
        except (ValueError, TypeError) as error:
            raise EncryptionError("The encrypted message is not valid base64.") from error
        if len(nonce) != NONCE_BYTES:
            raise EncryptionError("The encrypted message has a malformed nonce.")
        return self.decrypt(nonce, ciphertext)


def load_cipher(config):
    """The configured cipher, or None when encryption is not enabled."""
    key_text = load_key_text(config)
    if not key_text:
        return None
    return Cipher.from_text(key_text)
