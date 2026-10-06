# Orbit SMTP Relay node: Postfix plus the relay agent.
#
# Postfix lives in the same container rather than beside it so that the two move
# as one unit. A relay node is deployed as a single unit with a single
# lifecycle: splitting them means a Postfix restart without an agent restart
# leaves mail on disk with nothing draining the queue.
#
# The image is the same on every host. The host only needs Docker, which is
# why the installer works on both Ubuntu and Debian.

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ORBIT_QUEUE_DIR=/var/lib/orbit-mail/queue \
    ORBIT_MAILDROP_DIR=/var/spool/orbit-mail/incoming \
    ORBIT_STATE_DIR=/var/lib/orbit-mail/state

# postfix: the SMTP server that actually receives mail
# python3-minimal: the agent itself
# python3-cryptography: AES-GCM for sealing mail, from the distribution so
#   the image builds without reaching PyPI
# ca-certificates: TLS for posting back to the web server
# curl, jq: used by the entrypoint for health checks and Postfix TLS setup
# --error-on=any: an unreachable mirror fails here, naming the mirror, rather
#   than surfacing as "Unable to locate package postfix" on the next command
RUN apt-get update --error-on=any && apt-get install -y --no-install-recommends \
        postfix \
        postfix-pcre \
        ca-certificates \
        python3-minimal \
        python3-venv \
        python3-cryptography \
        curl \
        jq \
        postfix-lmdb \
        ssl-cert \
        rsyslog \
        supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/orbit-mail --shell /usr/sbin/nologin orbitmail

COPY requirements.txt /app/requirements.txt
COPY pyproject.toml /app/pyproject.toml
COPY relay /app/relay
COPY deploy/entrypoint.sh /usr/local/bin/orbit-relay-entrypoint
COPY deploy/orbit-relay-receive /usr/local/bin/orbit-relay-receive
COPY deploy/supervisord.conf /app/deploy/supervisord.conf

RUN chmod +x /usr/local/bin/orbit-relay-entrypoint /usr/local/bin/orbit-relay-receive \
    && mkdir -p "$ORBIT_QUEUE_DIR" "$ORBIT_MAILDROP_DIR" "$ORBIT_STATE_DIR" /etc/postfix/orbit /etc/orbit-mail/dkim \
    && chown -R orbitmail:orbitmail /var/lib/orbit-mail /var/spool/orbit-mail /etc/postfix/orbit

# --system-site-packages lets the venv see the distribution's cryptography
# package, the agent's one dependency, so pip never reaches PyPI for it.
RUN python3 -m venv --system-site-packages /opt/orbit-relay \
    && /opt/orbit-relay/bin/pip install --no-cache-dir --no-deps /app

ENV PATH="/opt/orbit-relay/bin:$PATH"

WORKDIR /app
# supervisord and Postfix need root; the agent's receive hook runs as orbitmail
# via Postfix's pipe transport, and the agent itself drops nothing it does not need.

# SMTP in, and the local status endpoint.
EXPOSE 25 8080

ENTRYPOINT ["/usr/local/bin/orbit-relay-entrypoint"]
CMD ["run"]
