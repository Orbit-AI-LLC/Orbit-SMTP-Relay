"""Sealing mail to the reader's public key so the server never sees it.

Every relay node seals mail. When Postfix hands over a message, the agent asks
the Orbit Mail server for the recipient's public key, encrypts the whole
message to it on this host, and only then queues and posts the ciphertext.
The server stores what it cannot open; the reader's browser holds the private
key and decrypts there. Outgoing mail is sealed in the browser to this node's
public key and opened here only to hand it to Postfix. There is no readable
mode: a node without a key of its own does not start, and the receive hook
defers a message whose reader has no key yet rather than queue plaintext.

Keys are ECDH P-256, the same identity Orbit Chat uses. A public key is its
SubjectPublicKeyInfo (91 bytes) in base64; the key id is the first twelve hex
characters of that DER's SHA-256 and reveals nothing secret. A private key is
written as ``orbp_`` followed by a 32-byte seed in URL-safe base64; the scalar
is ``seed mod (n - 1) + 1``, which is how the browser turns a seed into a key
too. The reader's seed is derived in the browser from the person's Orbit
password and never written anywhere on a server; this node's lives in
``/etc/orbit-mail/relay.key``.

A message is sealed with a fresh random content key under AES-256-GCM (12-byte
nonce, 128-bit tag, the associated data ``orbit-mail/e2ee/v2``). For each
reader, an ephemeral P-256 key agrees a shared secret with the reader's
public key; HKDF-SHA256 (no salt, info ``orbit-mail/e2ee/v2/wrap`` followed
by the ephemeral and the reader's SPKI bytes) turns it into a key-wrapping
key that encrypts the content key, again with AES-256-GCM and the reader's
key id as associated data. One ciphertext can therefore have several readers,
which is how a sent message is readable by both its author and the relay that
sends it. The browser uses WebCrypto's ECDH, HKDF and AES-GCM with the same
parameters, so there is nothing custom on either side.

The ``cryptography`` package is imported lazily so the CLI can report a
missing package plainly before anything else runs.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets

PRIVATE_KEY_PREFIX = "orbp_"
SEED_BYTES = 32
#: A P-256 SubjectPublicKeyInfo with an uncompressed point.
PUBLIC_KEY_BYTES = 91
NONCE_BYTES = 12
ALGORITHM = "ECDH-P256-A256GCM"
FORMAT_VERSION = 2
#: Authenticated but unencrypted context bound to every message ciphertext.
ASSOCIATED_DATA = b"orbit-mail/e2ee/v2"
#: HKDF context for the per-reader key-wrapping key.
WRAP_INFO = b"orbit-mail/e2ee/v2/wrap"
#: The order of the P-256 group.
CURVE_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

#: Shown wherever a node is found without a key of its own.
NO_KEY_HINT = (
    "No encryption key is configured. Every relay node seals mail, so a key is required: set "
    "ORBIT_RELAY_ENCRYPTION_KEY_FILE to a file holding one (the installer writes "
    "/etc/orbit-mail/relay.key), or generate one with 'orbit-relay key generate'."
)


class EncryptionError(Exception):
    """A key could not be loaded or a message could not be transformed."""


def _primitives():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise EncryptionError(
            "The 'cryptography' package is required. Install python3-cryptography or pip install cryptography."
        ) from error
    return hashes, serialization, ec, AESGCM, HKDF


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text):
    text = text.strip()
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _b64(data):
    return base64.b64encode(bytes(data)).decode("ascii")


def _unb64(text, what):
    try:
        return base64.b64decode(text or "", validate=True)
    except (ValueError, TypeError) as error:
        raise EncryptionError(f"The {what} is not valid base64.") from error


# --- Keys ---------------------------------------------------------------------


def generate_key():
    """A new random private key (seed) in its textual form."""
    return PRIVATE_KEY_PREFIX + _b64url_encode(secrets.token_bytes(SEED_BYTES))


def parse_private_key(text):
    """The 32-byte seed of an ``orbp_`` key, or raise EncryptionError."""
    text = (text or "").strip()
    if not text.startswith(PRIVATE_KEY_PREFIX):
        raise EncryptionError(f"Relay encryption keys start with {PRIVATE_KEY_PREFIX!r}.")
    try:
        raw = _b64url_decode(text[len(PRIVATE_KEY_PREFIX):])
    except (ValueError, TypeError) as error:
        raise EncryptionError("The encryption key is not valid base64.") from error
    if len(raw) != SEED_BYTES:
        raise EncryptionError(f"The encryption key must decode to {SEED_BYTES} bytes, not {len(raw)}.")
    return raw


def scalar_from_seed(seed):
    """The P-256 private scalar a 32-byte seed stands for: ``seed mod (n - 1) + 1``."""
    return int.from_bytes(bytes(seed), "big") % (CURVE_ORDER - 1) + 1


def private_key_from_seed(seed):
    _hashes, _ser, ec, _aesgcm, _hkdf = _primitives()
    return ec.derive_private_key(scalar_from_seed(seed), ec.SECP256R1())


def public_bytes(public_key):
    """The SubjectPublicKeyInfo DER of a P-256 public key."""
    _hashes, serialization, _ec, _aesgcm, _hkdf = _primitives()
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_key(spki):
    _hashes, serialization, ec, _aesgcm, _hkdf = _primitives()
    try:
        key = serialization.load_der_public_key(bytes(spki))
    except (ValueError, TypeError) as error:
        raise EncryptionError("The public key is not a valid P-256 key.") from error
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise EncryptionError("The public key is not a P-256 key.")
    return key


def parse_public_key(text):
    """The SPKI bytes of a public key given in base64 (either alphabet)."""
    text = (text or "").strip()
    if not text:
        raise EncryptionError("The public key is empty.")
    try:
        raw = _b64url_decode(text.replace("+", "-").replace("/", "_"))
    except (ValueError, TypeError) as error:
        raise EncryptionError("The public key is not valid base64.") from error
    if len(raw) != PUBLIC_KEY_BYTES:
        raise EncryptionError(f"The public key must decode to {PUBLIC_KEY_BYTES} bytes, not {len(raw)}.")
    load_public_key(raw)
    return raw


def public_key_text(raw_public):
    return _b64(raw_public)


def key_id(raw_public):
    """The short, non-secret identifier of a key: derived from its SPKI bytes."""
    return hashlib.sha256(bytes(raw_public)).hexdigest()[:12]


def public_key_of(seed):
    return public_bytes(private_key_from_seed(seed).public_key())


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
    """The node's private key as text. Raises EncryptionError when there is none."""
    if config.encryption_key:
        return config.encryption_key.strip()
    if config.encryption_key_file:
        if not os.path.exists(config.encryption_key_file):
            raise EncryptionError(f"{config.encryption_key_file} does not exist. {NO_KEY_HINT}")
        text = read_key_file(config.encryption_key_file)
        if not text:
            raise EncryptionError(f"{config.encryption_key_file} is empty. {NO_KEY_HINT}")
        return text
    raise EncryptionError(NO_KEY_HINT)


# --- Sealing and opening ------------------------------------------------------


def _kek(shared, ephemeral_spki, reader_spki):
    hashes, _ser, _ec, _aesgcm, HKDF = _primitives()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=WRAP_INFO + bytes(ephemeral_spki) + bytes(reader_spki)).derive(shared)


def _wrap_key(content_key, kid, raw_public):
    _hashes, _ser, ec, AESGCM, _hkdf = _primitives()
    reader = load_public_key(raw_public)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    ephemeral_spki = public_bytes(ephemeral.public_key())
    shared = ephemeral.exchange(ec.ECDH(), reader)
    kek = _kek(shared, ephemeral_spki, raw_public)
    iv = secrets.token_bytes(NONCE_BYTES)
    wrapped = AESGCM(kek).encrypt(iv, content_key, kid.encode("ascii"))
    return {"kid": kid, "epk": _b64(ephemeral_spki), "iv": _b64(iv), "wk": _b64(wrapped)}


def seal(plaintext, readers):
    """Encrypt ``plaintext`` for every ``(kid, raw_public)`` in ``readers``.

    Returns ``(envelope, ciphertext_base64)``. The envelope holds the
    non-secret parameters the server stores beside the ciphertext; its ``kid``
    names the first reader, the one the message is filed for.
    """
    readers = list(readers)
    if not readers:
        raise EncryptionError("A message needs at least one reader to be sealed for.")
    _hashes, _ser, _ec, AESGCM, _hkdf = _primitives()
    content_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(content_key).encrypt(nonce, bytes(plaintext), ASSOCIATED_DATA)
    envelope = {
        "v": FORMAT_VERSION,
        "alg": ALGORITHM,
        "kid": readers[0][0],
        "nonce": _b64(nonce),
        "keys": [_wrap_key(content_key, kid, raw_public) for kid, raw_public in readers],
    }
    return envelope, _b64(ciphertext)


class Cipher:
    """This node's P-256 key: opens mail sealed to it, and names itself to the server."""

    def __init__(self, seed):
        if len(seed) != SEED_BYTES:
            raise EncryptionError("Wrong key length.")
        self._seed = bytes(seed)
        self._private = private_key_from_seed(self._seed)
        self.public_key = public_bytes(self._private.public_key())
        self.kid = key_id(self.public_key)

    @classmethod
    def from_text(cls, key_text):
        return cls(parse_private_key(key_text))

    @property
    def public_key_text(self):
        return public_key_text(self.public_key)

    def open(self, envelope, ciphertext_base64):
        """Decrypt a message sealed for this key. Raises EncryptionError on any mismatch."""
        envelope = envelope or {}
        if envelope.get("alg", ALGORITHM) != ALGORITHM:
            raise EncryptionError(f"Unsupported encryption algorithm {envelope.get('alg')!r}.")
        entry = next((k for k in envelope.get("keys") or [] if isinstance(k, dict) and k.get("kid") == self.kid), None)
        if entry is None:
            raise EncryptionError(f"This node holds key {self.kid}, which this message was not sealed for.")
        _hashes, _ser, ec, AESGCM, _hkdf = _primitives()
        ephemeral_spki = _unb64(entry.get("epk"), "ephemeral key")
        iv = _unb64(entry.get("iv"), "wrapping nonce")
        wrapped = _unb64(entry.get("wk"), "wrapped key")
        nonce = _unb64(envelope.get("nonce"), "nonce")
        ciphertext = _unb64(ciphertext_base64, "message")
        if len(ephemeral_spki) != PUBLIC_KEY_BYTES or len(iv) != NONCE_BYTES or len(nonce) != NONCE_BYTES:
            raise EncryptionError("The encrypted message has malformed parameters.")
        try:
            shared = self._private.exchange(ec.ECDH(), load_public_key(ephemeral_spki))
            content_key = AESGCM(_kek(shared, ephemeral_spki, self.public_key)).decrypt(iv, wrapped, self.kid.encode("ascii"))
            return AESGCM(content_key).decrypt(nonce, ciphertext, ASSOCIATED_DATA)
        except Exception as error:
            raise EncryptionError("The message could not be decrypted with this node's key.") from error


def load_cipher(config):
    """The node's cipher. Raises EncryptionError when the node has no key."""
    return Cipher.from_text(load_key_text(config))
