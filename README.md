# Orbit SMTP Relay

The SMTP relay for [Orbit Mail](https://orbit.com.ai/docs/relay/). It runs on
a host you control, accepts inbound mail for your domains, forwards it to your
Orbit Mail server, and sends the mail people write in Orbit Mail. Postfix does
the SMTP; a small Python agent does everything that touches the server.

The relay talks to exactly one thing: the Orbit Mail server, over HTTPS, with
one API key. It makes outbound requests only, so it can sit behind NAT with
nothing but port 25 open.

Optionally, the relay **encrypts mail before it reaches the server**. Message
bodies and attachments are sealed on your host with a key the server never
sees, stored as ciphertext, and decrypted in your browser. This is the same
relay Orbit runs for hosted mailboxes; the hosted fleet simply runs it with
encryption off.

Supported hosts: **Ubuntu 22.04, 24.04 and newer; Debian 12 (bookworm), 13
(trixie) and newer.** Only Docker runs on the host; the relay itself is one
container.

## Install a node

Open the Orbit Mail admin area, go to **Relay**, issue the API key, and run the
printed command on a fresh host. It is the same as:

```bash
curl -fsSL https://raw.githubusercontent.com/Oribt-AI/Orbit-SMTP-Relay/main/install.sh \
    | sudo bash -s -- --server https://mail.example.com --key orbk_...
```

The installer carries no secrets. It installs Docker, stops a host MTA that
would hold port 25, clones this repository to `/opt/orbit-relay`, writes
`/etc/orbit-mail/relay.env` (mode 0600) with the server URL, node name and
key, builds the image and starts the `orbit-relay` container with port 25
published. Re-running it updates the node in place; the keys are remembered.

Then, back in the admin area, set the **relay hostname** to this host's name
and point each domain's MX record at it.

| Option | Purpose |
|---|---|
| `--encrypt` | Seal mail on this host before it reaches the server. See below. |
| `--name relay-2` | Name a second node. |
| `--hostname mx1.example.com` | The EHLO name; should match the MX record and the host's PTR record. |
| `--ref v2.1.0` | Pin a release instead of `main`. |
| `--no-encrypt` | Start without encryption even though a key file exists. |

The host needs port 25 reachable from the internet. Many cloud providers block
it by default and will open it on request.

## Encryption

Run the installer with `--encrypt` and the node generates a 256-bit key in
`/etc/orbit-mail/relay.key`. From then on:

- **Inbound.** The moment Postfix hands a message to the agent, the agent
  encrypts it with AES-256-GCM and only then writes it to its queue and posts
  it to the server. The plaintext never rests on disk and never leaves the
  host. The server stores the ciphertext and files the message using the
  header block, which stays readable.
- **Reading.** In Orbit Mail, open **Settings, Encryption** and paste the key
  (`sudo cat /etc/orbit-mail/relay.key` on the relay). The key stays in your
  browser; it is never sent to the server. Encrypted messages are decrypted
  on your screen.
- **Sending.** Mail you write in Orbit Mail is encrypted in the browser with
  the same key before it is saved. The relay decrypts it, assembles the
  message and hands it to Postfix. The server only ever holds the ciphertext
  and the readable headers.

What the server can see with encryption on: who wrote to whom, when, the
subject, and the message size. What it cannot see: the body, the HTML and
every attachment. This is the boundary PGP and S/MIME draw too; SMTP
metadata is visible to every relay on the internet regardless.

Things to know:

- **Back the key up.** Mail sealed with a lost key cannot be recovered by
  anyone, including Orbit. Copy `/etc/orbit-mail/relay.key` somewhere safe.
- **Search covers headers only** for encrypted mail; the server cannot index
  what it cannot read. Drafts are not saved while encryption is active; send
  or discard.
- **The junk filter still works** on headers, authentication results and
  sender lists, but not on body content.
- **Several nodes** can share one key: copy the file to each host before
  running the installer. A node without the key defers outgoing encrypted
  mail so a node that has it picks it up. Each node reports its key id (the
  first twelve hex characters of the key's SHA-256) on every heartbeat; the
  admin area shows it, and it reveals nothing about the key.
- **Turning it off** later: `sudo rm /etc/orbit-mail/relay.key`, re-run the
  installer with `--no-encrypt`. Mail already stored encrypted stays
  encrypted and still opens in the browser while the key is pasted there.

Useful commands on the node:

```bash
docker exec orbit-relay orbit-relay key show            # the key, for pasting into Orbit Mail
docker exec orbit-relay orbit-relay key show --id-only  # just the key id
docker exec orbit-relay orbit-relay key generate        # print a fresh key without installing it
```

## What the agent does

```
          Postfix (:25)                      Orbit Mail server
               |                                    ^
   inbound     | pipe: orbit-relay receive          | POST /api/relay/inbound/
               v                                    |
      [encrypt] -> durable queue -- delivery worker -+
                                                    |
        control loop <-- POST /api/relay/heartbeat/ (domains, addresses, settings)
               |
               v
        Postfix tables (relay_domains, relay_recipients) + reload

        outbound worker <-- POST /api/relay/outbound/claim/
               |
               v [decrypt, assemble] sendmail
          Postfix ---> the internet, then POST .../result/
```

**Inbound.** Postfix accepts a message only if its domain and address are in
the tables the agent downloaded, hands it to `orbit-relay receive`, which
writes it to the durable queue before answering Postfix. The delivery worker
posts queued messages to the server and retries with exponential, jittered
backoff. A message the server rejects for good (no such mailbox) is parked in
`dead/`; nothing is ever discarded silently.

**Configuration.** Every heartbeat sends the node's status (queue depth,
version, encryption key id, last error) and receives the active domains,
deliverable addresses, catch-all domains and fleet settings. The agent writes
them as Postfix lookup tables and reloads Postfix only when the server's
`config_digest` changes.

**Outbound.** The agent claims batches of queued messages, hands each to
Postfix through `sendmail -f <sender> <recipients>`, and reports `sent`,
`deferred` or `failed`. Postfix then owns delivery to the remote server.

**Storage.** One JSON file per inbound message, written atomically:

```
/var/lib/orbit-mail/queue/pending/     ready to send to the server
/var/lib/orbit-mail/queue/inflight/    being sent right now
/var/lib/orbit-mail/queue/dead/        gave up; kept for inspection
```

Logs default to a bounded in-memory ring (`ORBIT_LOG_BACKEND=memory`); the
container's stdout still carries everything for `docker logs`.

## Operating a node

```bash
curl -s http://127.0.0.1:8080/status | python3 -m json.tool   # queue, server reachability, encryption, counters
docker exec orbit-relay orbit-relay ping     # contact the server once
docker exec orbit-relay orbit-relay status   # queue depth
docker exec orbit-relay orbit-relay logs     # recent events
docker exec orbit-relay orbit-relay dead     # parked messages
docker logs -f orbit-relay                   # everything, including Postfix
```

A growing `pending` count means the server is unreachable or refusing
messages. A growing `dead` count means something is permanently wrong; look at
`last_error` there before assuming a transient outage.

**Updating.** Re-run the install command. It pulls the latest source, rebuilds
the image and restarts the container; the queue lives in a Docker volume and
survives.

**Rotating the API key.** Rotate it in the admin area, then re-run the install
command with the new key on each node. Until then, the node keeps accepting and
queueing mail; it just cannot deliver it.

**More than one node.** Nothing needs to know about the others. Each node
downloads the same configuration and claims outbound mail from the same queue;
claims expire after ten minutes so a crashed node's work is picked up by the
next one. Point each domain's MX at the node(s) you want, with equal preference
for round-robin.

**TLS.** Postfix offers STARTTLS with a self-signed certificate out of the box.
To present a real one, set `ORBIT_TLS_CERT` and `ORBIT_TLS_KEY` in
`/etc/orbit-mail/relay.env` to paths inside the container and add the files
to the `volumes` list in `/opt/orbit-relay/docker-compose.yml`.

**DKIM.** Mount a signing key into `/etc/orbit-mail/dkim` and configure a DKIM
milter in Postfix if you need signed outbound mail; paste the public key into
the domain's page in the admin area so it appears in the DNS records.

## Configuration

Everything is an environment variable, written by the installer to
`/etc/orbit-mail/relay.env`.

| Variable | Default | Purpose |
|---|---|---|
| `ORBIT_MAIL_SERVER_URL` | `http://localhost:8100` | The Orbit Mail server. |
| `ORBIT_RELAY_API_KEY` | (none) | Issued in the admin area. Without it mail queues locally. |
| `ORBIT_RELAY_NAME` | hostname | Node name shown in the admin area. |
| `ORBIT_RELAY_HOSTNAME` | FQDN | EHLO name; should match the MX record. |
| `ORBIT_RELAY_ENCRYPTION_KEY_FILE` | (none) | Path to the `orbe_...` key. Turns encryption on. |
| `ORBIT_RELAY_ENCRYPTION_KEY` | (none) | The key itself, for environments without a file. The file is preferred. |
| `ORBIT_HEARTBEAT_INTERVAL` | `60` | Seconds; the server may override. |
| `ORBIT_OUTBOUND_POLL_INTERVAL` | `5` | Seconds between empty outbound polls. |
| `ORBIT_QUEUE_DIR` | `/var/lib/orbit-mail/queue` | Durable queue. |
| `ORBIT_POSTFIX_DIR` | `/etc/postfix/orbit` | Where the lookup tables are written; blank disables. |
| `ORBIT_MAX_RETRY_HOURS` | `72` | Before an inbound message is parked. |
| `ORBIT_BACKOFF_BASE` / `_MAX` | `5` / `300` | Retry backoff, seconds. |
| `ORBIT_LOG_BACKEND` | `memory` | `memory` or `file`. |
| `ORBIT_VERIFY_TLS` | `1` | Set `0` only against a local self-signed server. |
| `ORBIT_TLS_CERT` / `ORBIT_TLS_KEY` | snakeoil | Certificate and key Postfix presents for STARTTLS. |

## Running it by hand

Without the installer, on any host with Docker:

```bash
git clone https://github.com/Oribt-AI/Orbit-SMTP-Relay.git /opt/orbit-relay
cd /opt/orbit-relay
docker build -t orbit-relay .
docker run -d --name orbit-relay --restart unless-stopped \
    -p 25:25 -p 127.0.0.1:8080:8080 \
    -e ORBIT_MAIL_SERVER_URL=https://mail.example.com \
    -e ORBIT_RELAY_API_KEY=orbk_... \
    -e ORBIT_RELAY_HOSTNAME=mx1.example.com \
    -v orbit-relay-queue:/var/lib/orbit-mail \
    -v orbit-relay-spool:/var/spool/orbit-mail \
    orbit-relay
```

Add `-v /etc/orbit-mail/relay.key:/etc/orbit-mail/relay.key:ro` and
`-e ORBIT_RELAY_ENCRYPTION_KEY_FILE=/etc/orbit-mail/relay.key` for the
encryption mode.

## Development

The agent has no third-party dependencies; `cryptography` is the one optional
package, used only when encryption is on.

```bash
python3 -m pip install cryptography
python3 -m unittest discover -s tests
```

The tests cover the queue's crash-safety and retry policy, the
retryable/permanent classification of server responses, the Postfix to queue
to server path, the heartbeat's table writing, the outbound claim to sendmail
to report path, and the encryption format against the primitive the browser
uses.

To run a node against a local Orbit Mail server:

```bash
docker compose -f deploy/docker-compose.dev.yml up --build
```

with Orbit Mail on the host at port 8100 and a key from its admin area in
`ORBIT_RELAY_API_KEY`. SMTP is on port 2525, status on 127.0.0.1:8080.

## Licence

MIT. See [LICENSE](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).
