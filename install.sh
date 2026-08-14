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

# --- Build and start ---
echo "Building and starting containers..."
docker compose up -d --build

echo ""
echo "=== Done ==="
echo "Seclog is starting up. Give it a few seconds, then visit:"
echo "  http://localhost:3000"
echo ""
echo "The first account you create there will automatically become the admin."
