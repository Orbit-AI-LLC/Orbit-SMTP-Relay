# Contributing

Thanks for helping make the relay better. A few things that keep the project
easy to work on:

- **Open an issue first** for anything bigger than a bug fix, so the design
  can be discussed before the code is written.
- **No new runtime dependencies.** The agent runs on the Python standard
  library plus `cryptography`, which seals every message. A relay node has to
  be rebuildable years from now. The sender checks (`sender_auth.py`) use the
  distribution's `python3-dkim`, `python3-spf` and `publicsuffix` too, and
  only report: without them mail flows exactly as before.
- **No readable mode.** Every message is encrypted on the node before it is
  queued or posted. A change that lets plaintext reach the server, even as an
  option, will not be merged.
- **Tests run with one command** and need no Postfix or network:

  ```bash
  python3 -m pip install cryptography dkimpy pyspf dnspython authres   # once
  python3 -m unittest discover -s tests
  ```

- **Keep the README current.** It is the source of truth for setup,
  behaviour and configuration; a change in behaviour is a change there too.
- **Shell scripts pass `bash -n` and ShellCheck** at warning level. CI runs
  both, plus a real install on a fresh Ubuntu host (`tests/host_smoke.py`).
- **Write plainly.** Comments explain why, not what. Keep sentences short and
  avoid em-dashes in prose.

By contributing you agree that your contributions are licensed under the MIT
licence in `LICENSE`.
