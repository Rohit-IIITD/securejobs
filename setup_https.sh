#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  setup_https.sh — SecureJobs
#  Run this script ONCE on your Ubuntu VM to set up HTTPS.
#
#  Usage:
#    chmod +x setup_https.sh
#    sudo bash setup_https.sh
#
#  What it does (in order):
#    1. Installs Nginx
#    2. Generates a self-signed RSA-4096 TLS certificate
#    3. Copies nginx.conf to the right location
#    4. Enables the site and tests the config
#    5. Opens firewall ports 80 and 443, blocks direct port 8000
#    6. Starts / reloads Nginx
#    7. Prints a summary
# ─────────────────────────────────────────────────────────────

set -e   # Exit immediately if any command fails

# ── Colour helpers ────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'   # No colour

info()    { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Must run as root ──────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo bash setup_https.sh"
fi

info "=== SecureJobs HTTPS Setup ==="
echo ""

# ── Step 1: Install Nginx ─────────────────────────────────────
info "Step 1/6 — Installing Nginx..."
apt-get update -qq
apt-get install -y nginx > /dev/null
info "Nginx installed."

# ── Step 2: Generate self-signed TLS certificate ─────────────
info "Step 2/6 — Generating self-signed TLS certificate (RSA-4096)..."
mkdir -p /etc/nginx/ssl

openssl req -x509 \
    -newkey rsa:4096 \
    -keyout /etc/nginx/ssl/securejobs.key \
    -out    /etc/nginx/ssl/securejobs.crt \
    -days   365 \
    -nodes \
    -subj "/C=IN/ST=Delhi/L=Delhi/O=SecureJobs/OU=Dev/CN=localhost"

chmod 600 /etc/nginx/ssl/securejobs.key   # private key readable by root only
chmod 644 /etc/nginx/ssl/securejobs.crt

info "Certificate written to /etc/nginx/ssl/securejobs.crt"
info "Private key  written to /etc/nginx/ssl/securejobs.key"

# ── Step 3: Generate DH parameters (for perfect forward secrecy) ──
info "Step 3/6 — Generating DH parameters (this may take a minute)..."
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048 2>/dev/null
info "DH parameters written to /etc/nginx/ssl/dhparam.pem"

# ── Step 4: Install Nginx config ─────────────────────────────
info "Step 4/6 — Installing Nginx site configuration..."

# nginx.conf is expected to be in the same directory as this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_SRC="$SCRIPT_DIR/nginx.conf"

if [ ! -f "$CONF_SRC" ]; then
    error "nginx.conf not found at $CONF_SRC — place it next to this script."
fi

# Enable the dhparam line in nginx.conf now that the file exists
sed -i 's|# ssl_dhparam|ssl_dhparam|' "$CONF_SRC"

cp "$CONF_SRC" /etc/nginx/sites-available/securejobs
ln -sf /etc/nginx/sites-available/securejobs \
       /etc/nginx/sites-enabled/securejobs

# Disable the default site to avoid conflicts
rm -f /etc/nginx/sites-enabled/default

# Test config before reloading
nginx -t || error "Nginx config test failed — check /etc/nginx/sites-available/securejobs"
info "Nginx config test passed."

# ── Step 5: Firewall rules ────────────────────────────────────
info "Step 5/6 — Configuring UFW firewall..."

if command -v ufw &> /dev/null; then
    ufw allow 80/tcp   comment 'HTTP → redirects to HTTPS'
    ufw allow 443/tcp  comment 'HTTPS'
    ufw deny  8000/tcp comment 'Block direct Uvicorn access'
    ufw --force enable
    info "UFW rules applied: 80 and 443 open, 8000 blocked."
else
    warn "UFW not found — skipping firewall setup. Install with: apt install ufw"
fi

# ── Step 6: Start / reload Nginx ─────────────────────────────
info "Step 6/6 — Starting Nginx..."
systemctl enable nginx
systemctl reload nginx || systemctl start nginx
info "Nginx is running."

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  HTTPS setup complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Certificate : /etc/nginx/ssl/securejobs.crt"
echo "  Private key : /etc/nginx/ssl/securejobs.key"
echo "  Nginx config: /etc/nginx/sites-enabled/securejobs"
echo ""
echo "  Next steps:"
echo "  1. Start Uvicorn (in your project directory):"
echo "       uvicorn main:app --host 127.0.0.1 --port 8000"
echo ""
echo "  2. Open in browser:"
echo "       https://localhost"
echo "       (Click 'Advanced → Proceed' to accept self-signed cert)"
echo ""
echo "  3. Verify HTTP → HTTPS redirect works:"
echo "       curl -I http://localhost"
echo "       (should show: Location: https://localhost/)"
echo ""
warn "Self-signed cert will show a browser warning — this is expected."
warn "For production, replace with a Let's Encrypt certificate:"
warn "  sudo apt install certbot python3-certbot-nginx"
warn "  sudo certbot --nginx -d yourdomain.com"
echo ""
