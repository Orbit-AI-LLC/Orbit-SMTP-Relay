"""Writing the Postfix lookup tables from the server's configuration.

Postfix decides at SMTP time which domains and addresses to accept. Rather than
asking the server on every connection, the agent writes two lookup tables each
time the fleet configuration changes:

``relay_domains``     one line per active domain
``relay_recipients``  one line per deliverable address, plus ``@domain`` for
                      catch-all domains

Both are referenced from ``main.cf`` as indexed maps (``hash:`` unless the
host's Postfix defaults to another type), so after writing them the agent runs
``postmap``. Postfix notices a rebuilt indexed table by itself; the reload the
agent asks for when it runs as root only makes that immediate. Mail for
anything not in the tables is rejected at the door with a 550, which is what
stops a relay from becoming a backscatter source.

Beside them the agent keeps ``accepting``: ``yes``, or ``no`` while the
server's fleet switch (``accepting_mail``) or the operator's
``ORBIT_ACCEPTING_MAIL=0`` says the node takes no new mail. Postfix does not
read it; the receive hook does (:func:`accepting_mail`), and defers every
message while it says ``no``.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile

logger = logging.getLogger("orbit.relay.postfix")


class PostfixTables:
    def __init__(self, directory, postmap_path="postmap", postfix_path="postfix", db_type="hash"):
        self.directory = directory
        self.db_type = db_type or "hash"
        self.postmap_path = postmap_path
        self.postfix_path = postfix_path
        self.last_digest = ""

    @property
    def enabled(self):
        return bool(self.directory)

    def paths(self):
        return {
            "domains": os.path.join(self.directory, "relay_domains"),
            "recipients": os.path.join(self.directory, "relay_recipients"),
            "accepting": os.path.join(self.directory, "accepting"),
        }

    def apply(self, config, accepting=None):
        """Write the tables from a heartbeat payload. Returns True if they changed.

        ``accepting`` is whether the node takes new mail, the server's
        ``accepting_mail`` and the operator's own switch together; without it,
        the server's alone. It is recorded on every heartbeat, apart from the
        lists: the server leaves those out of an unchanged answer, and its
        ``config_digest`` does not cover the switch.
        """
        if not self.enabled:
            return False
        if accepting is None:
            accepting = bool(config.get("accepting_mail", True))
        self.set_accepting(accepting)
        digest = config.get("config_digest", "")
        if digest and digest == self.last_digest:
            return False
        if "domains" not in config:
            # The server said "unchanged" but we have nothing on disk yet; the
            # next heartbeat without a digest will send the full lists.
            return False

        os.makedirs(self.directory, exist_ok=True)
        paths = self.paths()
        domains = sorted(set(config.get("domains") or []))
        recipients = sorted(set(config.get("recipients") or []))
        catch_all = sorted(set(config.get("catch_all_domains") or []))

        domain_lines = [f"{d}\tOK" for d in domains]
        recipient_lines = [f"{r}\tOK" for r in recipients] + [f"@{d}\tOK" for d in catch_all]
        self._write(paths["domains"], domain_lines)
        self._write(paths["recipients"], recipient_lines)

        for path in (paths["domains"], paths["recipients"]):
            self._postmap(path)
        self._reload()
        self.last_digest = digest
        logger.info("Postfix tables updated: %d domain(s), %d address(es), accepting=%s", len(domains), len(recipient_lines), accepting)
        return True

    def set_accepting(self, accepting):
        """Record whether the node takes new mail. Returns True if that changed."""
        if not self.enabled:
            return False
        path = self.paths()["accepting"]
        if os.path.exists(path) and self.accepting_flag() == accepting:
            return False
        os.makedirs(self.directory, exist_ok=True)
        self._write(path, ["yes" if accepting else "no"])
        if accepting:
            logger.info("Accepting inbound mail.")
        else:
            logger.warning("Not accepting inbound mail: it is deferred, and senders try again later.")
        return True

    def accepting_flag(self):
        """What ``accepting`` says. Only an explicit ``no`` stops mail: a node
        whose agent has not written the file yet accepts, as it always has."""
        try:
            with open(self.paths()["accepting"], encoding="utf-8") as handle:
                return handle.read().strip() != "no"
        except OSError:
            return True

    @staticmethod
    def _write(path, lines):
        """Write atomically so Postfix never reads a half-written table."""
        directory = os.path.dirname(path)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + ("\n" if lines else ""))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _postmap(self, path):
        if not shutil.which(self.postmap_path):
            return
        try:
            subprocess.run([self.postmap_path, f"{self.db_type}:{path}"], check=False, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            logger.warning("postmap failed for %s: %s", path, error)

    def _reload(self):
        # The service runs as orbitmail, which Postfix will not take a reload
        # from; the rebuilt tables are picked up without one.
        if os.geteuid() != 0 or not shutil.which(self.postfix_path):
            return
        try:
            subprocess.run([self.postfix_path, "reload"], check=False, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            logger.warning("postfix reload failed: %s", error)


def accepting_mail(config):
    """Whether the node takes new inbound mail right now, for the receive hook.

    No when the operator set ``ORBIT_ACCEPTING_MAIL=0`` (read from the
    settings file by the hook itself, so it holds before the agent's next
    heartbeat, or with the server unreachable), or when the agent last wrote
    ``no`` to ``accepting`` because the server's fleet switch is off.
    """
    if not config.accepting_mail:
        return False
    if not config.postfix_dir:
        return True
    return PostfixTables(config.postfix_dir).accepting_flag()
