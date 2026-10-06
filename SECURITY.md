# Security

## Reporting a vulnerability

Email **hello@orbit.com.ai** with a description and, where you can, steps to
reproduce. Please do not open a public issue for anything that could expose
mail. We acknowledge reports within two working days.

## What a relay node holds

- **The relay API key.** In `/etc/orbit-mail/relay.env`, mode 0640, readable
  by root and the relay's `orbitmail` user only.
  It authorises the node to fetch readers' public keys from, post inbound
  mail to, and claim outgoing mail from one Orbit Mail server, for the
  mailboxes the key covers (yours, for a key issued under Settings,
  Encryption; every mailbox, for the admin key). Rotate it where it was
  issued; the old key stops working at once.
- **Mail in transit.** Messages Postfix has accepted but the server has not
  yet stored live on disk under `/var/lib/orbit-mail/queue`, as ciphertext
  only. The plaintext exists on the node for the moment between Postfix
  handing a message over and the agent sealing it.
- **The node's own key.** In `/etc/orbit-mail/relay.key`, mode 0640, for
  root and `orbitmail` only. It
  opens outgoing mail that browsers sealed to this node, nothing else:
  inbound mail is sealed to each reader's key, which this node never holds.
  Back the node key up and treat it like a password; the node does not
  start without one.
- **Readers' public keys**, cached under the state directory. Public, by
  definition.

The node never holds an account password, a session or a database connection
to the server. It makes outbound HTTPS requests only.

## What the server can and cannot see

The Orbit Mail server stores the message body and attachments as
AES-256-GCM ciphertext, sealed on the relay to the reader's ECDH P-256 public
key. The matching private key is derived in the reader's browser from their
Orbit password and never exists on any server. There is no unencrypted
mode. The header block (sender, recipients, subject, date and the
threading headers) is stored readable so the server can file, list and thread
messages. SMTP metadata is visible to every relay on the internet anyway; the
subject is the one piece of content this design deliberately leaves readable.
Outgoing mail written in Orbit Mail is encrypted in the browser, to the
author and to the relay nodes online, and decrypted only on a relay to hand
it to Postfix.

The relay host sees a message for the instant between Postfix accepting it
and the agent sealing it, as every mail server on a message's path does. On
a relay you run, that instant is on your machine; on a relay Orbit runs, it
is on Orbit's, and the stored mail is sealed to your key either way.

## Hardening the host

- Keep port 25 open and nothing else inbound; the relay needs no other port.
  The status endpoint listens on loopback unless `ORBIT_STATUS_ADDRESS`
  says otherwise.
- The agent and the receive hook run as the unprivileged `orbitmail` user;
  only Postfix's master process runs as root.
- Give Postfix a real TLS certificate for the relay hostname (`--tls-cert`
  and `--tls-key`, see the README) so other mail servers can use STARTTLS
  with a verified chain.
- Run the relay on a host of its own. It takes over the host's Postfix, and
  isolating it in a VM or container is yours to choose.
- Keep the host patched. The installer is idempotent, so re-running it after
  `apt-get upgrade` is the normal update path.
