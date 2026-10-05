# Security

## Reporting a vulnerability

Email **hello@orbit.com.ai** with a description and, where you can, steps to
reproduce. Please do not open a public issue for anything that could expose
mail. We acknowledge reports within two working days.

## What a relay node holds

- **The relay API key.** In `/etc/orbit-mail/relay.env`, mode 0600, root only.
  It authorises the node to post inbound mail to one Orbit Mail server and to
  claim outgoing mail from it. Rotate it from the Orbit Mail admin area; the
  old key stops working at once.
- **Mail in transit.** Messages Postfix has accepted but the server has not
  yet stored live on disk under `/var/lib/orbit-mail/queue`. With encryption
  on, the queue holds ciphertext only.
- **The encryption key** (optional). In `/etc/orbit-mail/relay.key`, mode
  0600. Anyone who holds it can read every message this node sealed, so back
  it up somewhere safe and treat it like a password.

The node never holds an account password, a session or a database connection
to the server. It makes outbound HTTPS requests only.

## What the server can and cannot see

Without encryption, the Orbit Mail server stores mail readable, exactly like
any hosted mail service.

With encryption on, the server stores the message body and attachments as
AES-256-GCM ciphertext made on your relay with a key the server never
receives. The header block (sender, recipients, subject, date and the
threading headers) is stored readable so the server can file, list and thread
messages. SMTP metadata is visible to every relay on the internet anyway; the
subject is the one piece of content this design deliberately leaves readable.
Outgoing mail written in Orbit Mail is encrypted in the browser and decrypted
only on your relay to hand it to Postfix.

## Hardening the host

- Keep port 25 open and nothing else inbound; the relay needs no other port.
  The status endpoint binds to localhost.
- Mount a real TLS certificate for the relay hostname (see the README) so
  other mail servers can use STARTTLS with a verified chain.
- Keep the host patched. The installer is idempotent, so re-running it after
  `apt-get upgrade` is the normal update path.
