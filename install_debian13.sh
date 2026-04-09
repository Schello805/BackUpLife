#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/aeterna"
SERVICE_FILE="/etc/systemd/system/aeterna.service"
NGINX_FILE="/etc/nginx/sites-available/aeterna"
DOMAIN="${1:-_}"

apt-get update
apt-get install -y python3 python3-venv python3-pip nginx sqlite3 rsync

mkdir -p "$APP_DIR"
rsync -a --delete ./ "$APP_DIR"/

cd "$APP_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

mkdir -p instance/uploads
if [ ! -f .env ]; then
  cp .env.example .env
fi

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Aeterna Nachlassverwaltung
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$APP_DIR/.venv/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 app:create_app_instance
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

cat > "$NGINX_FILE" <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    client_max_body_size 25M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

ln -sf "$NGINX_FILE" /etc/nginx/sites-enabled/aeterna
rm -f /etc/nginx/sites-enabled/default

systemctl daemon-reload
systemctl enable --now aeterna
nginx -t
systemctl restart nginx

echo "Aeterna wurde installiert."
echo "Bitte .env in $APP_DIR anpassen und den Dienst mit 'systemctl restart aeterna' neu starten."
