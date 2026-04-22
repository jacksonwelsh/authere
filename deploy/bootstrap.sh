#!/usr/bin/env bash
set -euo pipefail

# Bootstrap script for Authere on Debian 13 (Trixie) LXC
# Run as root: bash bootstrap.sh

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run this script as root"
  exit 1
fi

echo "==> Configuring unattended security upgrades"
apt-get update
apt-get install -y unattended-upgrades apt-listchanges

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'APTEOF'
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
APTEOF

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'APTEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APTEOF

systemctl enable --now unattended-upgrades

echo "==> Installing runtime dependencies"
apt-get install -y sqlite3 ca-certificates curl python3

echo "==> Creating authere user and directories"
useradd --system --shell /usr/sbin/nologin --home-dir /opt/authere authere || true
mkdir -p /opt/authere/data

echo "==> Generating production key secret"
if [[ ! -f /opt/authere/.env ]]; then
  KEY_SECRET=$(openssl rand -hex 32)
  cat > /opt/authere/.env <<EOF
AUTHERE_KEY_SECRET=${KEY_SECRET}
DATABASE_URL=sqlite:/opt/authere/data/authere.db
RUST_LOG=info
EOF
  chmod 600 /opt/authere/.env
  echo "    Generated new AUTHERE_KEY_SECRET (stored in /opt/authere/.env)"
else
  echo "    /opt/authere/.env already exists, skipping"
fi

echo "==> Setting up webhook receiver"
if [[ ! -f /opt/authere/webhook.env ]]; then
  WEBHOOK_SECRET=$(openssl rand -hex 32)
  cat > /opt/authere/webhook.env <<EOF
WEBHOOK_SECRET=${WEBHOOK_SECRET}
WEBHOOK_PORT=9000
DEPLOY_SCRIPT=/opt/authere/deploy.sh
EOF
  chmod 600 /opt/authere/webhook.env
  echo "    Generated WEBHOOK_SECRET: ${WEBHOOK_SECRET}"
  echo "    Save this — you'll need it when configuring the GitHub webhook"
else
  echo "    /opt/authere/webhook.env already exists, skipping"
fi

echo "==> Installing systemd services"
cp /opt/authere/authere.service /etc/systemd/system/authere.service 2>/dev/null \
  || echo "    NOTE: Copy deploy/authere.service to /etc/systemd/system/"
cp /opt/authere/authere-webhook.service /etc/systemd/system/authere-webhook.service 2>/dev/null \
  || echo "    NOTE: Copy deploy/authere-webhook.service to /etc/systemd/system/"
systemctl daemon-reload
systemctl enable authere authere-webhook

echo "==> Allowing authere user to restart its own service"
apt-get install -y sudo
mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/authere <<'SUDOEOF'
authere ALL=(root) NOPASSWD: /usr/bin/systemctl restart authere, /usr/bin/systemctl stop authere, /usr/bin/systemctl start authere
SUDOEOF
chmod 440 /etc/sudoers.d/authere

echo "==> Setting permissions"
chown -R authere:authere /opt/authere

echo ""
echo "=== Bootstrap complete ==="
echo ""
echo "Next steps:"
echo "  1. Copy deploy files to the LXC:"
echo "       scp deploy/authere.service deploy/authere-webhook.service root@<lxc>:/etc/systemd/system/"
echo "       scp deploy/webhook.py deploy/deploy.sh root@<lxc>:/opt/authere/"
echo "       ssh root@<lxc> 'chmod +x /opt/authere/deploy.sh && chown -R authere:authere /opt/authere'"
echo ""
echo "  2. Do the first deploy manually (download binary from a GitHub release or build locally):"
echo "       scp server/target/release/authere_server root@<lxc>:/opt/authere/"
echo ""
echo "  3. Initialize admin user:"
echo "       ssh root@<lxc> 'sudo -u authere /opt/authere/authere_server init-admin --username admin --password <pw> --name Admin'"
echo ""
echo "  4. Configure GitHub webhook:"
echo "       Repo → Settings → Webhooks → Add webhook"
echo "       Payload URL: https://<your-domain>/webhook  (proxy port 9000 via Caddy)"
echo "       Content type: application/json"
echo "       Secret: (from /opt/authere/webhook.env on the LXC)"
echo "       Events: select only 'Releases'"
echo ""
echo "  5. Start services:"
echo "       systemctl start authere authere-webhook"
echo ""
echo "  6. Configure Caddy to reverse proxy /webhook to 127.0.0.1:9000"
echo "       Example Caddyfile snippet:"
echo "         auth.example.com {"
echo "           handle /webhook {"
echo "             reverse_proxy 127.0.0.1:9000"
echo "           }"
echo "           handle {"
echo "             reverse_proxy 127.0.0.1:3000"
echo "           }"
echo "         }"
echo ""
