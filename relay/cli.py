"""Command-line entry points for the relay.

The ``orbit-relay`` service runs ``orbit-relay run``. The same command is the
piece Postfix needs (``orbit-relay receive``) and the operator's tool, so one
program on the host covers running, feeding and diagnosing the node.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .agent import RelayAgent
from .config import load_config
from .crypto import EncryptionError, generate_key, load_cipher, load_key_text, write_key_file
from .keys import KeyUnavailable, PublicKeyDirectory
from .logging_setup import recent_events, setup_logging
from .queue import Queue


def _build_parser():
    parser = argparse.ArgumentParser(prog="orbit-relay", description="Orbit Mail relay agent.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="Run the relay (what the orbit-relay service runs).")
    run.add_argument("--status-port", type=int, default=None, help="Status endpoint port; 0 turns it off (default: ORBIT_STATUS_PORT, 8080).")

    receive = subparsers.add_parser("receive", help="Accept one message from Postfix. Invoked by Postfix, not by humans.")
    receive.add_argument("filename", help="The dropped file's name, relative to the maildrop directory.")

    subparsers.add_parser("status", help="Print queue and agent status as JSON.")
    subparsers.add_parser("check", help="Validate configuration and exit non-zero if unusable.")
    subparsers.add_parser("ping", help="Contact the Orbit Mail server once and print its answer.")
    subparsers.add_parser("logs", help="Print recent in-memory events.")

    dead = subparsers.add_parser("dead", help="List messages parked after exhausting retries.")
    dead.add_argument("--limit", type=int, default=20)

    key = subparsers.add_parser("key", help="Manage the node's encryption key.")
    key_commands = key.add_subparsers(dest="key_command", required=True)
    generate = key_commands.add_parser("generate", help="Print a new encryption key, or write it to a file.")
    generate.add_argument("--write", metavar="PATH", help="Write the key to this file (mode 0600) instead of printing it.")
    generate.add_argument("--force", action="store_true", help="Replace an existing key file.")
    show = key_commands.add_parser("show", help="Print this node's public key and key id.")
    show.add_argument("--id-only", action="store_true", help="Print only the key id.")
    show.add_argument("--private", action="store_true", help="Print the private key instead, for copying to another node.")

    return parser


def main(argv=None):
    args = _build_parser().parse_args(argv)
    handlers = {
        "run": cmd_run,
        "receive": cmd_receive,
        "status": cmd_status,
        "check": cmd_check,
        "ping": cmd_ping,
        "logs": cmd_logs,
        "dead": cmd_dead,
        "key": cmd_key,
    }
    return handlers[args.command](args)


def cmd_run(args):
    agent = RelayAgent()
    port = agent.config.status_port if args.status_port is None else args.status_port
    if port:
        _start_status_server(agent, agent.config.status_address, port)
    return agent.run()


def cmd_receive(args):
    """Accept one message from Postfix.

    The exit code is the verdict Postfix reads. Zero means the message is safely
    on the durable queue; 75 asks Postfix to try again later; 67 rejects it.
    """
    config = load_config()
    setup_logging(level=config.log_level, backend=config.log_backend, max_entries=config.log_max_entries, path=config.log_path)
    logger = logging.getLogger("orbit.relay")

    queue = Queue(
        config.queue_dir,
        max_attempts=config.max_attempts,
        max_age_hours=config.max_retry_hours,
        backoff_base=config.backoff_base,
        backoff_max=config.backoff_max,
        backoff_jitter=config.backoff_jitter,
    )
    from .postfix import Maildrop
    from .transport import MailServerClient

    client = MailServerClient(config)
    keys = PublicKeyDirectory(
        client, os.path.join(config.state_dir, "keys"),
        ttl=config.key_cache_seconds, missing_ttl=config.missing_key_cache_seconds,
    )
    maildrop = Maildrop(config.maildrop_dir, queue, config.node_name, keys=keys)

    path = maildrop.claim(args.filename)
    if path is None:
        logger.info("Drop file %s was already claimed.", args.filename)
        return 0

    try:
        message = maildrop.process_file(path)
    except ValueError as error:
        logger.error("Rejecting %s: %s", args.filename, error)
        maildrop.discard(path)
        return 67  # EX_NOUSER
    except KeyUnavailable as error:
        # There is no readable mode. Without the reader's key the message
        # waits in Postfix's queue (deferred) until the reader sets one, or
        # bounces (rejected) when this node may never deliver to that mailbox.
        # Either way Postfix keeps its own copy and pipes it again on a retry,
        # so the drop file is removed rather than left readable on disk.
        maildrop.discard(path)
        if error.retryable:
            logger.warning("Deferring %s: %s", args.filename, error)
            return 75  # EX_TEMPFAIL
        logger.error("Rejecting %s: %s", args.filename, error)
        return 67
    except Exception:
        logger.exception("Failed to accept %s", args.filename)
        maildrop.discard(path)
        return 75  # EX_TEMPFAIL

    maildrop.discard(path)
    logger.info("Accepted %s for %s (queued as %s)", args.filename, message.recipient, message.id)
    return 0


def _queue_for(config):
    return Queue(config.queue_dir, max_attempts=config.max_attempts, max_age_hours=config.max_retry_hours)


def cmd_status(args):
    config = load_config()
    queue = _queue_for(config)
    print(json.dumps({"node": config.node_name, "server": config.server_url, "has_api_key": config.has_api_key,
                      "encryption": _encryption_summary(config),
                      "queue": queue.stats(), "queue_bytes": queue.total_bytes()}, indent=2))
    return 0


def _encryption_summary(config):
    try:
        cipher = load_cipher(config)
    except EncryptionError as error:
        return {"enabled": True, "kid": "", "public_key": "", "error": str(error)}
    return {"enabled": True, "kid": cipher.kid, "public_key": cipher.public_key_text}


def cmd_check(args):
    config = load_config()
    problems = config.validate()
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if not config.has_api_key:
        print("WARNING: ORBIT_RELAY_API_KEY is not set; the node cannot reach the server.")
    if problems:
        return 1
    print(f"This node's key id is {_encryption_summary(config)['kid']}; inbound mail is sealed to each reader's key.")
    print("Configuration is usable.")
    return 0


def cmd_ping(args):
    from .transport import MailServerClient, TransportError

    config = load_config()
    setup_logging(level="WARNING", backend="memory")
    client = MailServerClient(config)
    # The server records the key a heartbeat names; one without it would stop
    # browsers sealing to this node until the agent's next heartbeat.
    encryption = _encryption_summary(config)
    try:
        health = client.health().json()
        payload = client.heartbeat({"node": config.node_name, "hostname": config.hostname, "version": "ping",
                                    "encryption_kid": encryption["kid"], "encryption_public_key": encryption["public_key"]})
    except TransportError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"health": health, "domains": payload.get("domains"), "recipients": len(payload.get("recipients") or []),
                      "relay_hostname": payload.get("relay_hostname")}, indent=2))
    return 0


def cmd_logs(args):
    setup_logging(level=load_config().log_level, backend="memory")
    print(json.dumps(recent_events(limit=100), indent=2))
    return 0


def cmd_dead(args):
    queue = _queue_for(load_config())
    messages = queue.list_dead(limit=args.limit)
    print(json.dumps([{"id": m.id, "recipient": m.recipient, "attempts": m.attempts, "first_seen_at": m.first_seen_at,
                       "last_error": m.last_error, "size": m.size} for m in messages], indent=2))
    return 0


def cmd_key(args):
    if args.key_command == "generate":
        key_text = generate_key()
        if args.write:
            try:
                write_key_file(args.write, key_text, overwrite=args.force)
            except EncryptionError as error:
                print(f"ERROR: {error}", file=sys.stderr)
                return 1
            from .crypto import Cipher

            print(f"Wrote a new encryption key to {args.write} (key id {Cipher.from_text(key_text).kid}).")
            print("Keep a copy somewhere safe: outgoing mail sealed to this node needs it to be sent.")
            return 0
        print(key_text)
        return 0

    config = load_config()
    try:
        key_text = load_key_text(config)
        from .crypto import Cipher

        cipher = Cipher.from_text(key_text)
    except EncryptionError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.id_only:
        print(cipher.kid)
    elif args.private:
        print(key_text)
    else:
        print(f"key id     {cipher.kid}")
        print(f"public key {cipher.public_key_text}")
    return 0


def _start_status_server(agent, address, port):
    """Expose queue depth and recent errors over HTTP, for monitoring.

    Read-only and unauthenticated by design: it reports how much mail is
    waiting, never any of it. It listens on loopback unless
    ORBIT_STATUS_ADDRESS says otherwise.
    """

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.startswith("/health"):
                self._send(200, {"status": "ok"})
            elif self.path.startswith("/status"):
                self._send(200, agent.status())
            elif self.path.startswith("/logs"):
                self._send(200, {"events": recent_events(limit=100)})
            else:
                self._send(404, {"error": "not found"})

        def _send(self, status, payload):
            body = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *a):
            return

    server = ThreadingHTTPServer((address, port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="orbit-relay-status", daemon=True)
    thread.start()


if __name__ == "__main__":
    raise SystemExit(main())
