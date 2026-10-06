#!/usr/bin/env bash
# Orbit SMTP Relay installer for Ubuntu and Debian.
#
# Installs or updates one relay node on the host it runs on:
#
#   curl -fsSL https://raw.githubusercontent.com/Oribt-AI/Orbit-SMTP-Relay/main/install.sh \
#       | sudo bash -s -- --server https://mail.example.com --key orbk_...
#
# The same command is printed, with the server filled in, by the Orbit Mail
# admin area under Relay. Re-running it on the same host updates the node in
# place: the API key and the encryption key are remembered.
#
# What it does: installs Docker if it is missing, stops a host Postfix that
# would hold port 25, clones this repository to /opt/orbit-relay, generates
# the node's encryption key once, writes a root-only environment file with the
# server URL and API key, builds the image and starts the orbit-relay
# container with port 25 published. Mail is sealed on this host with that key
# before it reaches the server; the relay has no readable mode.
#
# The script carries no secrets. The keys are written straight to
# /etc/orbit-mail (mode 0600) and nowhere else.
#
# Supported: Ubuntu 22.04, 24.04 and newer; Debian 12 (bookworm), 13 (trixie)
# and newer. Anything with apt, systemd and a Docker-supported release works.

set -euo pipefail

SERVER_URL="${ORBIT_MAIL_SERVER_URL:-}"
API_KEY=""
NODE_NAME="$(hostname -s 2>/dev/null || echo relay-1)"
RELAY_HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
REPO_URL="${ORBIT_RELAY_REPO_URL:-https://github.com/Oribt-AI/Orbit-SMTP-Relay.git}"
REPO_REF="main"
INSTALL_DIR=/opt/orbit-relay
ENV_DIR=/etc/orbit-mail
ENV_FILE="$ENV_DIR/relay.env"
KEY_FILE="$ENV_DIR/relay.key"
CONTAINER=orbit-relay
STATUS_PORT=8080

usage() {
    cat <<'USAGE'
Install or update an Orbit SMTP Relay node.

  --server <url>       Orbit Mail server URL (required on first install)
  --key <api-key>      Relay API key from the Orbit Mail admin area (required on first install)
  --name <name>        Node name shown in the admin area (default: short hostname)
  --hostname <fqdn>    Hostname Postfix announces in EHLO (default: this host's FQDN)
  --repo <git-url>     Relay source repository
  --ref <branch|tag>   Git ref to build (default: main)
  --status-port <n>    Local port for the relay's status endpoint (default: 8080)
  -h, --help           Show this help

Mail is always sealed on this host before it reaches the server. The key is
generated once in /etc/orbit-mail/relay.key and remembered on re-runs; copy
that file to another host first to have several nodes share one key.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server) SERVER_URL="$2"; shift 2 ;;
        --key) API_KEY="$2"; shift 2 ;;
        --name) NODE_NAME="$2"; shift 2 ;;
        --hostname) RELAY_HOSTNAME="$2"; shift 2 ;;
        --encrypt) shift ;;  # accepted for commands printed by older servers; it is the only mode
        --no-encrypt) echo "The relay always seals mail; --no-encrypt is not supported." >&2; exit 2 ;;
        --repo) REPO_URL="$2"; shift 2 ;;
        --ref) REPO_REF="$2"; shift 2 ;;
        --status-port) STATUS_PORT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

log()  { printf '\033[0;36m[orbit-relay]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[orbit-relay]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[0;31m[orbit-relay]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run this script as root (prefix it with sudo)."

# --- Operating system ---------------------------------------------------------

check_os() {
    [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release; only Ubuntu and Debian are supported."
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_CODENAME="${VERSION_CODENAME:-}"
    case "$OS_ID" in
        ubuntu)
            if [[ -n "${VERSION_ID:-}" ]] && [[ "${VERSION_ID%%.*}" -lt 22 ]]; then
                die "Ubuntu ${VERSION_ID} is too old; use 22.04 or newer."
            fi
            ;;
        debian)
            if [[ -n "${VERSION_ID:-}" ]] && [[ "${VERSION_ID%%.*}" -lt 12 ]]; then
                die "Debian ${VERSION_ID} is too old; use 12 (bookworm) or newer."
            fi
            ;;
        *)
            die "This installer supports Ubuntu and Debian; detected '${OS_ID:-unknown}'."
            ;;
    esac
    [[ -n "$OS_CODENAME" ]] || die "Cannot determine the release codename from /etc/os-release."
    command -v systemctl >/dev/null 2>&1 || die "systemd is required to run Docker."
    log "Detected ${PRETTY_NAME:-$OS_ID $OS_CODENAME}"
}

# --- Settings -----------------------------------------------------------------

read_env_value() {
    [[ -f "$ENV_FILE" ]] || return 0
    grep -E "^$1=" "$ENV_FILE" | head -n1 | cut -d= -f2- || true
}

resolve_settings() {
    if [[ -z "$SERVER_URL" ]]; then
        SERVER_URL="$(read_env_value ORBIT_MAIL_SERVER_URL)"
    fi
    [[ -n "$SERVER_URL" ]] || die "--server is required on first install (the Orbit Mail server URL)."
    [[ "$SERVER_URL" =~ ^https?:// ]] || die "--server must be an http(s) URL."
    SERVER_URL="${SERVER_URL%/}"

    if [[ -z "$API_KEY" ]]; then
        API_KEY="$(read_env_value ORBIT_RELAY_API_KEY)"
    fi
    [[ -n "$API_KEY" ]] || die "--key is required on first install. Issue one in the Orbit Mail admin area under Relay."
    if [[ "$SERVER_URL" =~ ^http:// ]]; then
        warn "The server URL is plain http. The API key will travel unencrypted; use https in production."
    fi
}

# --- Packages -----------------------------------------------------------------

export DEBIAN_FRONTEND=noninteractive

install_packages() {
    log "Installing base packages"
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl git gnupg >/dev/null
}

install_docker() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        log "Docker already present: $(docker --version)"
        return
    fi
    log "Installing Docker for ${OS_ID} ${OS_CODENAME}"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID} ${OS_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
    systemctl enable --now docker
}

stop_host_postfix() {
    # A Postfix (or Exim, Debian's default) installed on the host would hold
    # port 25 and the container could not bind it.
    for unit in postfix exim4; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            log "Stopping the host's ${unit} so the relay can own port 25"
            systemctl disable --now "$unit"
        fi
    done
}

# --- Source and configuration -------------------------------------------------

fetch_source() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        log "Updating relay source in $INSTALL_DIR"
        git -C "$INSTALL_DIR" fetch -q origin
        git -C "$INSTALL_DIR" checkout -q "$REPO_REF"
        git -C "$INSTALL_DIR" pull -q --ff-only origin "$REPO_REF" || true
    else
        log "Cloning relay source from $REPO_URL"
        git clone -q --branch "$REPO_REF" "$REPO_URL" "$INSTALL_DIR"
    fi
}

# --- Container network --------------------------------------------------------

# The image build runs apt in a container on Docker's bridge network, not on
# the host's. A host whose own apt works can still have its containers cut off
# (IP forwarding off, a firewall that dropped Docker's NAT rules, a proxy only
# the host's apt knows about), and the build then spends ten minutes timing out
# before failing with "Unable to locate package". Fetching one small file the
# way the build will turns that into a few seconds and says where the fault is.

probe_mirror() {
    docker run --rm -i "$@" "$BASE_IMAGE" bash -s <<'PROBE'
. /etc/os-release
mirror="$(sed -n 's/^URIs: *\([^ ]*\).*/\1/p' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null | head -n1)"
mirror="${mirror:-http://archive.ubuntu.com/ubuntu/}"
timeout 60 /usr/lib/apt/apt-helper -o Acquire::Retries=0 -o Acquire::http::Timeout=10 \
    download-file "${mirror%/}/dists/${VERSION_CODENAME}/InRelease" /tmp/InRelease
PROBE
}

check_container_network() {
    BASE_IMAGE="$(awk '$1 == "FROM" { print $2; exit }' "$INSTALL_DIR/Dockerfile")"
    log "Checking that containers can reach the package mirror"
    docker pull -q "$BASE_IMAGE" >/dev/null \
        || die "Cannot pull ${BASE_IMAGE} from Docker Hub. Check this host's internet access."

    local output
    if output="$(probe_mirror 2>&1)"; then
        return
    fi
    warn "A container cannot reach the Ubuntu package mirror, so the image cannot be built:"
    grep -v '^W:' <<<"$output" | tail -n 3 | sed 's/^/    /' >&2 || true

    if probe_mirror --network host >/dev/null 2>&1; then
        die "This host reaches the mirror but its containers do not: Docker's bridge network has
no route out. net.ipv4.ip_forward is $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown) (Docker needs 1); a firewall or
sysctl reload after Docker started is the usual cause. Restart Docker to restore its
rules, then re-run this installer:
    systemctl restart docker"
    fi

    local HOST_APT_PROXY=""
    eval "$(apt-config shell HOST_APT_PROXY Acquire::http::Proxy)"
    if [[ -n "$HOST_APT_PROXY" ]]; then
        die "This host's apt goes through the proxy ${HOST_APT_PROXY}; containers do not. Give Docker
the proxy in /root/.docker/config.json, then re-run this installer:
    {\"proxies\": {\"default\": {\"httpProxy\": \"${HOST_APT_PROXY}\", \"httpsProxy\": \"${HOST_APT_PROXY}\"}}}"
    fi
    die "Containers cannot reach the mirror even on the host's network. Check this host's
outbound firewall for HTTP (port 80)."
}

ensure_encryption_key() {
    if [[ -s "$KEY_FILE" ]]; then
        log "Using the existing encryption key in $KEY_FILE"
        return
    fi
    log "Generating an encryption key in $KEY_FILE"
    install -d -m 0750 "$ENV_DIR"
    umask 077
    printf 'orbp_%s\n' "$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')" > "$KEY_FILE"
    chmod 0600 "$KEY_FILE"
}

write_env() {
    log "Writing $ENV_FILE"
    install -d -m 0750 "$ENV_DIR"
    umask 077
    cat > "$ENV_FILE" <<EOF
# Orbit SMTP Relay configuration for ${NODE_NAME}.
# Written by install.sh. Mode 0600: this file holds the relay API key.

ORBIT_MAIL_SERVER_URL=${SERVER_URL}
ORBIT_RELAY_API_KEY=${API_KEY}
ORBIT_RELAY_NAME=${NODE_NAME}
ORBIT_RELAY_HOSTNAME=${RELAY_HOSTNAME}

# Retry policy: a message is retried for three days before being parked.
ORBIT_MAX_RETRY_HOURS=72
ORBIT_BACKOFF_BASE=5
ORBIT_BACKOFF_MAX=300

# Logs stay in a bounded in-memory ring; docker logs still shows everything.
ORBIT_LOG_BACKEND=memory

# This node's own key. Mail people write in Orbit Mail is sealed to it in
# their browser and opened here to be sent; inbound mail is sealed to each
# reader's key, fetched from the server.
ORBIT_RELAY_ENCRYPTION_KEY_FILE=/etc/orbit-mail/relay.key
EOF
    chmod 0600 "$ENV_FILE"
}

write_compose() {
    cat > "$INSTALL_DIR/docker-compose.yml" <<EOF
services:
  relay:
    build: .
    image: orbit-relay:local
    container_name: ${CONTAINER}
    restart: unless-stopped
    hostname: ${RELAY_HOSTNAME}
    env_file:
      - ${ENV_FILE}
    ports:
      - "25:25"
      - "127.0.0.1:${STATUS_PORT}:8080"
    volumes:
      # The queue must outlive the container: it is the only copy of mail the
      # server has not yet accepted.
      - orbit-relay-queue:/var/lib/orbit-mail
      - orbit-relay-spool:/var/spool/orbit-mail
      - orbit-relay-dkim:/etc/orbit-mail/dkim
      # The encryption key, read-only. The relay does not start without it.
      - ${KEY_FILE}:/etc/orbit-mail/relay.key:ro
    cap_add:
      - NET_BIND_SERVICE
      - SETGID
      - SETUID
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  orbit-relay-queue:
  orbit-relay-spool:
  orbit-relay-dkim:
EOF
}

start() {
    log "Building and starting the relay container (this takes a minute the first time)"
    docker compose -f "$INSTALL_DIR/docker-compose.yml" up -d --build
}

open_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q active; then
        log "Opening SMTP in ufw"
        ufw allow 25/tcp comment 'Orbit SMTP Relay' >/dev/null || true
    fi
}

verify() {
    log "Waiting for the relay to report in"
    for _ in $(seq 1 20); do
        if curl -fsS "http://127.0.0.1:${STATUS_PORT}/status" 2>/dev/null | grep -q '"server_reachable": true'; then
            log "Relay is up and talking to ${SERVER_URL}"
            return
        fi
        sleep 3
    done
    warn "The relay has not confirmed contact with the server yet. Check: docker logs ${CONTAINER}"
}

check_os
resolve_settings
install_packages
install_docker
fetch_source
check_container_network
stop_host_postfix
ensure_encryption_key
write_env
write_compose
start
open_firewall
verify

cat <<SUMMARY

$(log "Relay node ${NODE_NAME} is installed.")

  Status        : curl -s http://127.0.0.1:${STATUS_PORT}/status | python3 -m json.tool
  Queue / logs  : docker exec ${CONTAINER} orbit-relay status
                  docker exec ${CONTAINER} orbit-relay logs
  Container log : docker logs -f ${CONTAINER}
  Configuration : ${ENV_FILE}
  Update        : re-run this install command (the keys are remembered)
  Encryption    : inbound mail is sealed to each reader's key before it reaches
                  the server. This node's own key is ${KEY_FILE}; back it up,
                  and show its id with: docker exec ${CONTAINER} orbit-relay key show

Next: in the Orbit Mail admin area, set the relay hostname to ${RELAY_HOSTNAME}
and point each domain's MX record at it.
SUMMARY
