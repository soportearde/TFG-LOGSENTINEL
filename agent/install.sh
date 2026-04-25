#!/bin/bash
# ─────────────────────────────────────────────────────────────
# LogSentinel Agent — Script de instalación para Ubuntu
#
# Uso (generado desde el dashboard de LogSentinel):
#   curl -sSL http://TU_SERVIDOR/agent/install.sh | sudo bash -s -- \
#     --url http://TU_SERVIDOR/api/log \
#     --api-key TU_API_KEY \
#     --name "mi-servidor-web"
# ─────────────────────────────────────────────────────────────

set -e

# Colores para la terminal
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════╗"
echo "║       LogSentinel Agent — Instalador         ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ─────────────────────────────────────────────────────────────
# PARSEAR ARGUMENTOS
# ─────────────────────────────────────────────────────────────
LOGSENTINEL_URL=""
API_KEY=""
SYSTEM_NAME=$(hostname)
INTERVAL=5

while [[ $# -gt 0 ]]; do
    case $1 in
        --url)
            LOGSENTINEL_URL="$2"
            shift 2
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        --name)
            SYSTEM_NAME="$2"
            shift 2
            ;;
        --interval)
            INTERVAL="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Argumento desconocido: $1${NC}"
            exit 1
            ;;
    esac
done

# Validar que tenemos URL y API key
if [ -z "$LOGSENTINEL_URL" ]; then
    echo -e "${RED}Error: falta --url (URL del LogCollector)${NC}"
    echo "Ejemplo: --url http://192.168.1.100:5000/log"
    exit 1
fi

if [ -z "$API_KEY" ]; then
    echo -e "${RED}Error: falta --api-key${NC}"
    exit 1
fi

echo -e "${YELLOW}Configuración:${NC}"
echo "  URL:      $LOGSENTINEL_URL"
echo "  API Key:  ${API_KEY:0:8}..."
echo "  Sistema:  $SYSTEM_NAME"
echo "  Intervalo: ${INTERVAL}s"
echo ""

# ─────────────────────────────────────────────────────────────
# 1. INSTALAR DEPENDENCIAS
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}[1/5] Instalando dependencias...${NC}"
apt-get update -qq 2>&1 | grep -v "^W:" || true   # ignorar repos rotos de terceros
apt-get install -y -qq python3 python3-pip > /dev/null 2>&1
pip3 install requests --break-system-packages -q 2>/dev/null || pip3 install requests -q

# ─────────────────────────────────────────────────────────────
# 2. CREAR DIRECTORIOS
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}[2/5] Creando directorios...${NC}"
mkdir -p /opt/logsentinel
mkdir -p /etc/logsentinel
mkdir -p /var/lib/logsentinel
mkdir -p /var/log/logsentinel

# ─────────────────────────────────────────────────────────────
# 3. COPIAR EL AGENTE
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}[3/5] Instalando el agente...${NC}"

# Descargar el agente desde el servidor de LogSentinel
# (en producción sería una URL real, aquí usamos el script local)
AGENT_URL="http://20.238.17.71/agent/logsentinel-agent.py"
if curl -sSf "$AGENT_URL" -o /opt/logsentinel/logsentinel-agent.py 2>/dev/null; then
    echo "  Agente descargado desde el servidor"
else
    echo -e "${YELLOW}  No se pudo descargar. Asegúrate de copiar logsentinel-agent.py a /opt/logsentinel/${NC}"
fi

chmod +x /opt/logsentinel/logsentinel-agent.py

# ─────────────────────────────────────────────────────────────
# 4. CREAR FICHERO DE CONFIGURACIÓN
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}[4/5] Configurando el agente...${NC}"

cat > /etc/logsentinel/agent.conf << EOF
{
    "url": "$LOGSENTINEL_URL",
    "api_key": "$API_KEY",
    "system_name": "$SYSTEM_NAME",
    "interval": $INTERVAL
}
EOF

echo "  Config guardada en /etc/logsentinel/agent.conf"

# ─────────────────────────────────────────────────────────────
# 5. CREAR SERVICIO SYSTEMD
# ─────────────────────────────────────────────────────────────
echo -e "${GREEN}[5/5] Creando servicio systemd...${NC}"

cat > /etc/systemd/system/logsentinel-agent.service << EOF
[Unit]
Description=LogSentinel Agent - Monitorización de logs
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/logsentinel/logsentinel-agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Variables de entorno (respaldo, el agente lee de agent.conf)
Environment=LOGSENTINEL_URL=$LOGSENTINEL_URL
Environment=LOGSENTINEL_API_KEY=$API_KEY
Environment=LOGSENTINEL_SYSTEM_NAME=$SYSTEM_NAME
Environment=LOGSENTINEL_INTERVAL=$INTERVAL

[Install]
WantedBy=multi-user.target
EOF

# Recargar systemd y arrancar el servicio
systemctl daemon-reload
systemctl enable logsentinel-agent
systemctl start logsentinel-agent

# ─────────────────────────────────────────────────────────────
# RESULTADO
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗"
echo "║     ✅ LogSentinel Agent instalado!           ║"
echo "╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "Comandos útiles:"
echo "  Ver estado:     systemctl status logsentinel-agent"
echo "  Ver logs:       journalctl -u logsentinel-agent -f"
echo "  Reiniciar:      systemctl restart logsentinel-agent"
echo "  Parar:          systemctl stop logsentinel-agent"
echo "  Desinstalar:    systemctl stop logsentinel-agent && systemctl disable logsentinel-agent"
echo ""
echo -e "${YELLOW}El agente ya está enviando logs a: ${LOGSENTINEL_URL}${NC}"
