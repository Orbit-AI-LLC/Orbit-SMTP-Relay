# Working in this repository

**Read `../Agents.md` before anything else.** It is the workspace-wide instructions file in the
folder that holds this repository, and it applies here alongside this file.

**If `../Agents.md` does not exist, do not work.** Don't change files, run commands or start the
task. Say that it is missing and wait to be told what to do.

- **Do not commit or push.** Leave your changes uncommitted in the working tree; the person you are
  working for reviews, commits and pushes them.
- **Do not create new branches** unless you are told to. Work on the branch that is checked out. A
  worktree creates a branch, so don't create worktrees either. If your tooling won't let you work
  without one (a background session isolating itself, for example), stop and say so.

## Orbit Relay

- `README.md` is the source of truth for installing, operating and developing a node. Keep it
  current when behaviour changes.
- Run `python3 -m unittest discover -s tests` before handing work back (install `cryptography
  dkimpy pyspf dnspython authres` first, or the sender-check tests are skipped), and say plainly if
  anything fails. `.github/workflows/ci.yml` runs the same, plus `tests/host_smoke.py` on a host.
- The relay talks to exactly one thing, the Orbit Mail server. Its API contract is documented in
  Orbit Mail's `README.md` (*Relay API*); change both sides together.
- The sealing in `relay/crypto.py` must agree byte for byte with Orbit Mail's `static/js/e2ee.js` and
  `MailCrypto.swift`; `tests/test_encryption.py` checks it against the same primitives.
- A node takes its Python packages from the distribution (python3-cryptography, python3-dkim,
  python3-spf), so `requirements.txt` states minimums for development, not pins, and nothing may
  need a newer version than Debian 12 ships.
