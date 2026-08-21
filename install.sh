#!/bin/bash
set -e  # exit immediately if any command fails, rather than plowing ahead
 
echo "=== Seclog Installer ==="
 
# --- Check prerequisites ---
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Install Docker first: https://docs.docker.com/engine/install/"
    exit 1
fi
 
if ! docker compose version &> /dev/null; then
    echo "Docker Compose plugin is not available. Install it before continuing."
    exit 1
fi
 
# --- Generate .env if it doesn't exist ---
if [ -f .env ]; then
    echo ".env already exists -- skipping secret generation (existing install detected)."
else
    echo "Generating secrets..."
    DB_ROOT_PASS=$(openssl rand -hex 24)
    DB_PASS=$(openssl rand -hex 24)
 
    cat > .env << EOF
DB_ROOT_PASS=${DB_ROOT_PASS}
DB_NAME=seclog
DB_USER=seclog_user
DB_PASS=${DB_PASS}
DATABASE_URL=mysql://seclog_user:${DB_PASS}@mariadb:3306/seclog
EOF
 
    chmod 600 .env  # restrict readability to the owning user only
    echo ".env generated with strong random secrets."
fi

# --- Frontend origin (used to lock down CORS) ---
# Checked independently of the block above -- this needs to run on
# upgrades of an existing .env too, not just fresh installs, since older
# installs won't have this value and the server now refuses to start
# without it.
if grep -q "^FRONTEND_ORIGIN=" .env 2>/dev/null; then
    echo "FRONTEND_ORIGIN already recorded in .env -- skipping prompt."
else
    echo ""
    echo "What URL will people use in their browser to reach Seclog?"
    echo "(the full https:// address -- used to restrict which origins"
    echo "are allowed to talk to the API)"
    read -rp "Frontend URL (e.g. https://seclog.example.com): " frontend_origin

    if [ -z "$frontend_origin" ]; then
        echo "A frontend URL is required -- Seclog won't start without it."
        exit 1
    fi

    echo "FRONTEND_ORIGIN=${frontend_origin}" >> .env
    echo "FRONTEND_ORIGIN set to '${frontend_origin}'."
fi
 
# --- Reverse proxy setup ---
# Seclog's session cookie uses the browser-enforced __Host- prefix, which
# only works over HTTPS. Something has to terminate TLS in front of it.
if grep -q "^COMPOSE_PROFILES=" .env 2>/dev/null; then
    echo "Reverse proxy choice already recorded in .env -- skipping prompt."
else
    echo ""
    echo "Seclog requires HTTPS on the browser-facing side (its session"
    echo "cookie won't work over plain HTTP)."
    echo ""
    echo "Do you already have a reverse proxy in front of this host"
    echo "(NGINX Proxy Manager, Traefik, etc.)?"
    echo "  1) Yes -- I'll point my own proxy at it"
    echo "  2) No -- set one up for me (Caddy, automatic TLS)"
    read -rp "Choice [1/2]: " proxy_choice
 
    if [ "$proxy_choice" = "2" ]; then
        echo ""
        read -rp "Domain name pointing at this server (leave blank if none / using a bare IP): " domain
 
        if [ -n "$domain" ]; then
            cat > Caddyfile << EOF
${domain} {
    reverse_proxy app:3000
}
EOF
            echo "Caddyfile written for domain '${domain}' -- Caddy will obtain a real cert automatically via Let's Encrypt."
        else
            cat > Caddyfile << EOF
:443 {
    tls internal
    reverse_proxy app:3000
}
EOF
            echo "Caddyfile written for IP-only access -- Caddy will use a self-signed cert."
            echo "Your browser will show a certificate warning the first time; that's expected without a domain."
        fi
 
        echo "COMPOSE_PROFILES=caddy" >> .env
    else
        echo "COMPOSE_PROFILES=" >> .env
        echo ""
        echo "Skipping Caddy. Point your existing reverse proxy's upstream at:"
        echo "  http://<this-host-ip>:3000"
        echo "and make sure it terminates HTTPS on the browser-facing side --"
        echo "the app itself must still be reached over HTTPS from the browser"
        echo "for login to work."
    fi
fi

# --- Optional: dev environment variables ---
# Same idempotent pattern as FRONTEND_ORIGIN/COMPOSE_PROFILES above --
# safe to run on a fresh .env or one that already has these. Only needed
# if you're running docker-compose.dev.yml alongside the main stack.
if grep -q "^DEV_DB_ROOT_PASS=" .env 2>/dev/null; then
    echo "Dev environment variables already recorded in .env -- skipping prompt."
else
    echo ""
    echo "Set up a separate dev environment too? This adds DEV_ variables"
    echo "to .env for use with docker-compose.dev.yml -- a second app +"
    echo "database stack, isolated from your main install."
    read -rp "Set up dev environment variables? [y/N]: " setup_dev

    if [ "$setup_dev" = "y" ] || [ "$setup_dev" = "Y" ]; then
        echo "Generating dev secrets..."
        DEV_DB_ROOT_PASS=$(openssl rand -hex 24)
        DEV_DB_PASS=$(openssl rand -hex 24)

        echo ""
        read -rp "Frontend URL for the dev instance (e.g. https://seclog-dev.example.com): " dev_frontend_origin

        if [ -z "$dev_frontend_origin" ]; then
            echo "No URL given -- skipping dev environment setup. You can add"
            echo "the DEV_ variables to .env manually later if you change your mind."
        else
            cat >> .env << EOF
DEV_DB_ROOT_PASS=${DEV_DB_ROOT_PASS}
DEV_DB_NAME=seclog_dev
DEV_DB_USER=seclog_dev_user
DEV_DB_PASS=${DEV_DB_PASS}
DEV_FRONTEND_ORIGIN=${dev_frontend_origin}
EOF
            echo "Dev environment variables added to .env."
            echo "Start it with: docker compose -f docker-compose.dev.yml up -d --build"
        fi
    else
        echo "Skipping dev environment setup."
    fi
fi
 
# --- Build and start ---
echo ""
echo "Building and starting containers..."
docker compose up -d --build
 
echo ""
echo "=== Done ==="
if grep -q "^COMPOSE_PROFILES=caddy" .env 2>/dev/null; then
    echo "Seclog is starting up behind Caddy. Give it a few seconds, then visit:"
    echo "  https://<this-host-ip-or-domain>"
else
    echo "Seclog is starting up. Give it a few seconds, then visit it through"
    echo "your reverse proxy's HTTPS URL."
fi
echo ""
echo "The first account you create there will automatically become the admin."
