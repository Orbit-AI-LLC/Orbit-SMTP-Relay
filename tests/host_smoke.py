"""Smoke test of a node installed by install.sh, run by CI as root on the host.

Not part of the unit suite (its name keeps it out of discovery): it needs a
real Postfix, the orbit-relay service and root. It checks what only a real
install can show:

* the status endpoint answers on loopback and nowhere else;
* Postfix answers as the relay and refuses domains it was not given;
* tables rebuilt by orbitmail are picked up without a reload, as the agent's
  heartbeat relies on;
* a message for a served address goes through the receive hook, is sealed
  to the reader's key and reaches the queue, with no plaintext at rest.

The server at mail.example.com does not exist, so the reader's key is put in
the node's key cache by hand and the message stays queued.
"""

import email
import email.policy
import hashlib
import json
import os
import pwd
import smtplib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "/opt/orbit-relay")
from relay.crypto import Cipher, generate_key  # noqa: E402

# Domains with real MX records: reject_unknown_recipient_domain and
# reject_unknown_sender_domain look them up.
READER = "orbit-ci-reader@outlook.com"
SENDER = "orbit-ci-sender@gmail.com"
MARKER = "orbit-ci-plaintext-marker"
POSTFIX_DIR = "/etc/postfix/orbit"
STATE_DIR = "/var/lib/orbit-mail/state"
QUEUE_DIR = "/var/lib/orbit-mail/queue"


def step(text):
    print(f"--- {text}", flush=True)


def settings():
    values = {}
    with open("/etc/orbit-mail/relay.env", encoding="utf-8") as handle:
        for line in handle:
            name, sep, value = line.strip().partition("=")
            if sep and not name.startswith("#"):
                values[name] = value
    return values


def host_address():
    """This host's own non-loopback address, which is outside mynetworks."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))
        return probe.getsockname()[0]


def as_orbitmail(*command):
    subprocess.run(["runuser", "-u", "orbitmail", "--", *command], check=True)


def wait_for(description, attempt, timeout=90):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            result = attempt()
        except Exception as error:  # noqa: BLE001
            result, last = None, error
        if result:
            return result
        time.sleep(2)
    raise AssertionError(f"Timed out waiting for {description}; last error: {last}")


def main():
    config = settings()
    port = int(config.get("ORBIT_STATUS_PORT", "8080"))
    db_type = config.get("ORBIT_POSTFIX_DB_TYPE", "hash")
    address = host_address()

    step("status endpoint answers on loopback only")
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=5) as response:
        status = json.load(response)
    assert status.get("node"), status
    try:
        urllib.request.urlopen(f"http://{address}:{port}/status", timeout=5)
    except (urllib.error.URLError, OSError):
        pass
    else:
        raise AssertionError(f"the status endpoint answers on {address}")

    step(f"Postfix on {address} answers as the relay and refuses unknown domains")
    with smtplib.SMTP(address, 25, timeout=30) as smtp:
        code, banner = smtp.ehlo()
        assert code == 250, (code, banner)
        smtp.mail(SENDER)
        code, reply = smtp.rcpt("someone@unlisted.invalid")
        assert code >= 400 and b"Relay access denied" in reply, (code, reply)

    step("serve the reader's address and cache the reader's key")
    for table, line in (("relay_domains", READER.split("@")[1]), ("relay_recipients", READER)):
        path = os.path.join(POSTFIX_DIR, table)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f"{line}\tOK\n")
        os.chown(path, pwd.getpwnam("orbitmail").pw_uid, pwd.getpwnam("orbitmail").pw_gid)
        as_orbitmail("postmap", f"{db_type}:{path}")
    reader = Cipher.from_text(generate_key())
    cache_dir = os.path.join(STATE_DIR, "keys")
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, hashlib.sha256(READER.encode()).hexdigest()[:32] + ".json")
    with open(cache_file, "w", encoding="utf-8") as handle:
        json.dump({"address": READER, "kid": reader.kid, "public_key": reader.public_key_text, "fetched_at": time.time()}, handle)
    for path in (cache_dir, cache_file):
        os.chown(path, pwd.getpwnam("orbitmail").pw_uid, pwd.getpwnam("orbitmail").pw_gid)

    step("Postfix picks up the rebuilt tables without a reload")

    def accepted():
        with smtplib.SMTP(address, 25, timeout=30) as smtp:
            smtp.ehlo()
            smtp.mail(SENDER)
            code, reply = smtp.rcpt(READER)
            if code != 250:
                raise AssertionError(f"RCPT {code} {reply!r}")
            return True

    wait_for("Postfix to accept the reader's address", accepted)

    step("a message for the reader is sealed and queued")
    body = (
        f"From: CI <{SENDER}>\r\nTo: <{READER}>\r\nSubject: Orbit relay CI\r\n"
        f"Message-ID: <{int(time.time())}@orbit-ci>\r\n\r\n{MARKER}\r\n"
    )
    with smtplib.SMTP(address, 25, timeout=30) as smtp:
        smtp.sendmail(SENDER, [READER], body.encode())

    def queued():
        for state in ("pending", "inflight", "dead"):
            directory = os.path.join(QUEUE_DIR, state)
            for name in os.listdir(directory) if os.path.isdir(directory) else []:
                if name.endswith(".json"):
                    with open(os.path.join(directory, name), encoding="utf-8") as handle:
                        message = json.load(handle)
                    if message.get("recipient") == READER:
                        return message
        return None

    message = wait_for("the message to reach the queue", queued)
    opened = email.message_from_bytes(reader.open(message["encryption"], message["raw"]), policy=email.policy.default)
    assert MARKER in opened.get_content(), "the sealed message does not open to what was sent"

    step("no plaintext at rest under /var/lib/orbit-mail")
    for root, _dirs, files in os.walk("/var/lib/orbit-mail"):
        for name in files:
            with open(os.path.join(root, name), "rb") as handle:
                assert MARKER.encode() not in handle.read(), os.path.join(root, name)

    print("Host smoke test passed.")


if __name__ == "__main__":
    main()
