"""Logging that does not fill a node's disk.

The relay's job is to move mail, and it stores mail only while the web server
is refusing it. Keeping an archive of every event is the same mistake one
level up: the message body already exists on the web server, and a second copy
on the relay is a liability rather than a record.

``memory`` keeps a bounded ring in RAM and writes nothing. That is the default
because it makes unbounded disk growth structurally impossible rather than
merely unlikely.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import time
from collections import deque


class MemoryHandler(logging.Handler):
    """A bounded in-memory ring of recent events.

    Bounded by count rather than size because log lines here are short and a
    cap on lines is one fewer thing to get wrong.
    """

    def __init__(self, max_entries=500):
        super().__init__()
        self.records = deque(maxlen=max_entries)

    def emit(self, record):
        try:
            self.records.append({
                "at": time.time(),
                "level": record.levelname,
                "message": record.getMessage(),
            })
        except Exception:
            self.handleError(record)

    def recent(self, limit=100, level=None):
        items = list(self.records)
        if level:
            wanted = level.upper()
            items = [r for r in items if r["level"] == wanted]
        return items[-limit:]


#: The single shared instance, so the status endpoint can read recent events
#: without the logging calls having to pass an object around.
_memory_handler = MemoryHandler()


def setup_logging(level="INFO", backend="memory", max_entries=500, path=""):
    """Configure the root logger from configuration values.

    Always adds a stderr handler: a container's logs have to go somewhere even
    when on-disk logging is off, and `docker logs` is the transport rather than
    a stored archive.
    """
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    root.addHandler(stderr_handler)

    _memory_handler.records.clear()
    _memory_handler.setFormatter(formatter)
    _memory_handler.max_entries = max_entries
    try:
        # deque(maxlen=...) is fixed at construction, so rebuild rather than
        # pretend a later configuration change took effect.
        _memory_handler.records = deque(maxlen=max_entries, iterable=())
    except Exception:
        pass
    root.addHandler(_memory_handler)

    backend = (backend or "memory").lower()
    if backend == "file" and path:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=10 * 1024 * 1024, backupCount=3
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    return _memory_handler


def get_memory_handler():
    return _memory_handler


def recent_events(limit=100, level=None):
    return _memory_handler.recent(limit=limit, level=level)
