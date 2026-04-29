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
apt-get install -y -qq python3 python3-pip auditd fail2ban > /dev/null 2>&1
pip3 install requests --break-system-packages -q 2>/dev/null || pip3 install requests -q

# Activar auditd (File Guardian lo necesita para vigilar rutas restringidas)
systemctl enable auditd > /dev/null 2>&1 || true
systemctl start  auditd > /dev/null 2>&1 || true

# Configurar fail2ban para SSH (bloquea bots de internet a nivel de firewall,
# evitando que el ruido de fuerza bruta inunde el SIEM)
cat > /etc/fail2ban/jail.d/sshd.local << 'F2BCONF'
[DEFAULT]
# Tu IP de casa nunca se banea, evita autobloqueos accidentales
ignoreip = 127.0.0.1/8 ::1
# Resuelve nombres por DNS solo si es necesario
usedns   = warn

[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
# 2 fallos en 30 min ya es ataque (no hay typos legítimos repetidos así)
maxretry = 2
findtime = 1800
# Ban de 24h
bantime  = 86400

# Reincidentes: si una IP se banea 3 veces, se banea 1 semana entera
[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
banaction = iptables-allports
bantime   = 604800
findtime  = 86400
maxretry  = 3
F2BCONF
systemctl enable fail2ban > /dev/null 2>&1 || true
systemctl restart fail2ban > /dev/null 2>&1 || true

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

# Derivar la URL del agente a partir de --url (ej: https://host/api/log -> https://host/agent/logsentinel-agent.py)
AGENT_BASE="${LOGSENTINEL_URL%/api/log}"
AGENT_URL="${AGENT_BASE}/agent/logsentinel-agent.py"

if ! curl -sSfL "$AGENT_URL" -o /opt/logsentinel/logsentinel-agent.py; then
    echo -e "${RED}  Error: no se pudo descargar el agente desde $AGENT_URL${NC}"
    exit 1
fi

# Validar que es un fichero Python (no una página HTML de error)
if ! head -1 /opt/logsentinel/logsentinel-agent.py | grep -q '^#!.*python'; then
    echo -e "${RED}  Error: la descarga de $AGENT_URL no es un script Python válido${NC}"
    head -3 /opt/logsentinel/logsentinel-agent.py
    exit 1
fi
echo "  Agente descargado desde $AGENT_URL"

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
