"""Writing the Postfix lookup tables from the server's configuration.

Postfix decides at SMTP time which domains and addresses to accept. Rather than
asking the server on every connection, the agent writes two lookup tables each
time the fleet configuration changes:

``relay_domains``     one line per active domain
``relay_recipients``  one line per deliverable address, plus ``@domain`` for
                      catch-all domains

Both are referenced from ``main.cf`` as ``hash:`` maps, so after writing them
the agent runs ``postmap`` and asks Postfix to reload. Mail for anything not in
the tables is rejected at the door with a 550, which is what stops a relay from
becoming a backscatter source.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile

logger = logging.getLogger("orbit.relay.postfix")


class PostfixTables:
    def __init__(self, directory, postmap_path="postmap", postfix_path="postfix"):
        self.directory = directory
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

    def apply(self, config):
        """Write the tables from a heartbeat payload. Returns True if changed."""
        if not self.enabled:
            return False
        digest = config.get("config_digest", "")
        accepting = bool(config.get("accepting_mail", True))
        if digest and digest == self.last_digest and self._accepting_flag() == accepting:
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
        self._write(paths["accepting"], ["yes" if accepting else "no"])

        for path in (paths["domains"], paths["recipients"]):
            self._postmap(path)
        self._reload()
        self.last_digest = digest
        logger.info("Postfix tables updated: %d domain(s), %d address(es), accepting=%s", len(domains), len(recipient_lines), accepting)
        return True

    def _accepting_flag(self):
        try:
            with open(self.paths()["accepting"], encoding="utf-8") as handle:
                return handle.read().strip() == "yes"
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
            subprocess.run([self.postmap_path, f"hash:{path}"], check=False, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            logger.warning("postmap failed for %s: %s", path, error)

    def _reload(self):
        if not shutil.which(self.postfix_path):
            return
        try:
            subprocess.run([self.postfix_path, "reload"], check=False, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            logger.warning("postfix reload failed: %s", error)
