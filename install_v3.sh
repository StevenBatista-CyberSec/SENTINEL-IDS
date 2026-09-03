#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/sentinel-ids"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta: sudo bash install_v3.sh"
  exit 1
fi

apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv libpcap-dev build-essential iptables
mkdir -p "$APP_DIR" "$APP_DIR/config" "$APP_DIR/reports" "$APP_DIR/logs" "$APP_DIR/tests" "$APP_DIR/sentinel_soc/core" "$APP_DIR/sentinel_soc/integrations"

cp "$SCRIPT_DIR/sentinel_ids_pro_v3.py" "$APP_DIR/"
cp "$SCRIPT_DIR/config.example.json" "$APP_DIR/config/"
cp "$SCRIPT_DIR/README_SENTINEL_IDS_v3.md" "$APP_DIR/"
cp "$SCRIPT_DIR/tests/test_v3.py" "$APP_DIR/tests/"
cp "$SCRIPT_DIR/tests/test_integrations.py" "$APP_DIR/tests/"
cp "$SCRIPT_DIR/soc_ingest.py" "$APP_DIR/"
cp "$SCRIPT_DIR/sentinel_soc/__init__.py" "$APP_DIR/sentinel_soc/"
cp "$SCRIPT_DIR/sentinel_soc/core/__init__.py" "$APP_DIR/sentinel_soc/core/"
cp "$SCRIPT_DIR/sentinel_soc/core/risk.py" "$APP_DIR/sentinel_soc/core/"
cp "$SCRIPT_DIR/sentinel_soc/integrations/__init__.py" "$APP_DIR/sentinel_soc/integrations/"
cp "$SCRIPT_DIR/sentinel_soc/integrations/"*.py "$APP_DIR/sentinel_soc/integrations/"

python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip
"$APP_DIR/.venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" pytest

if [[ ! -f "$APP_DIR/config.json" ]]; then
  cp "$SCRIPT_DIR/config.example.json" "$APP_DIR/config.json"
fi

cat > /usr/local/bin/sentinel-ids <<EOF
#!/usr/bin/env bash
exec "$APP_DIR/.venv/bin/python" "$APP_DIR/sentinel_ids_pro_v3.py" "\$@"
EOF
chmod +x /usr/local/bin/sentinel-ids

python3 -m py_compile "$APP_DIR/sentinel_ids_pro_v3.py"
echo "SENTINEL IDS PRO v3.1 instalado en $APP_DIR"
echo "Ejemplo: sudo sentinel-ids"
