"""Orbit Mail relay agent.

Runs on a host you control, next to Postfix. Postfix does what it is good at (TLS,
rate limiting) and hands accepted messages to this agent, which is responsible
for exactly one thing: getting each message back to the Orbit Mail server,
reliably, and holding onto anything it cannot deliver yet. On the way it notes
who sent each message (SPF, DKIM, DMARC; ``sender_auth``) for the server.

The design assumption throughout is that the web server will be down more often
than the relay is. Nothing here treats delivery back to Orbit Mail as a
synchronous step that can fail and be forgotten: every message enters a durable
queue on disk first, and the queue is drained independently.
"""

__version__ = "3.3.0"
