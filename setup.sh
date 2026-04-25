#!/bin/bash
set -e

POSTGRES_PASSWORD="CHANGE_ME_IN_PRODUCTION"

echo "=== [1/5] Docker ==="
if command -v docker &>/dev/null; then
    echo "  Docker ya instalado, saltando."
else
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"
    echo "  Docker instalado."
fi

echo "=== [2/5] PostgreSQL ==="
if command -v psql &>/dev/null; then
    echo "  PostgreSQL ya instalado, saltando."
else
    sudo apt update -qq
    sudo apt install -y postgresql postgresql-contrib
    echo "  PostgreSQL instalado."
fi

sudo systemctl enable postgresql
sudo systemctl start postgresql

echo "=== [3/5] Configurando PostgreSQL ==="

# Detectar rutas según la versión instalada
PG_VERSION=$(ls /etc/postgresql/ | sort -V | tail -1)
PG_HBA="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"
PG_CONF="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"
echo "  Versión PostgreSQL detectada: ${PG_VERSION}"
echo "  pg_hba.conf: ${PG_HBA}"

sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '${POSTGRES_PASSWORD}';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='log_collector'" | grep -q 1 \
    && echo "  BD log_collector ya existe." \
    || sudo -u postgres psql -c "CREATE DATABASE log_collector;"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='alerts_db'" | grep -q 1 \
    && echo "  BD alerts_db ya existe." \
    || sudo -u postgres psql -c "CREATE DATABASE alerts_db;"

# Cubrir todo el rango de IPs que Docker puede asignar (172.16.0.0/12 cubre 172.16-172.31)
if ! sudo grep -q "172.16.0.0/12" "$PG_HBA"; then
    echo "host    all    all    172.16.0.0/12    md5" | sudo tee -a "$PG_HBA"
    echo "  Regla Docker añadida (172.16.0.0/12)."
else
    echo "  Regla Docker ya existe, saltando."
fi

if ! sudo grep -q "^listen_addresses = '\*'" "$PG_CONF"; then
    sudo sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$PG_CONF"
    echo "  listen_addresses actualizado."
else
    echo "  listen_addresses ya configurado, saltando."
fi

sudo systemctl restart postgresql

echo "=== [4/5] Creando tablas ==="
sudo -u postgres psql -d log_collector -c "
CREATE TABLE IF NOT EXISTS raw_logs (
    id            SERIAL PRIMARY KEY,
    source_system VARCHAR(255),
    source_ip     VARCHAR(45),
    username      VARCHAR(255),
    event_type    VARCHAR(255),
    raw_data      JSONB,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);"

sudo -u postgres psql -d alerts_db -c "
CREATE TABLE IF NOT EXISTS correlation_rules (
    id        SERIAL PRIMARY KEY,
    rule_name VARCHAR(255) UNIQUE NOT NULL,
    enabled   BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS alerts (
    id              SERIAL PRIMARY KEY,
    rule_id         INTEGER REFERENCES correlation_rules(id),
    severity_id     INTEGER DEFAULT 1,
    source_ip       VARCHAR(45),
    username        VARCHAR(255),
    source_system   VARCHAR(255),
    title           VARCHAR(500),
    message         TEXT,
    metadata        JSONB,
    event_timestamp TIMESTAMPTZ DEFAULT NOW(),
    status          VARCHAR(50) DEFAULT 'open',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO correlation_rules (rule_name) VALUES
    ('login_sequence'),
    ('privilege_escalation'),
    ('blacklist_ip'),
    ('dos_detection'),
    ('failed_login_bruteforce'),
    ('tor_exit_node'),
    ('asn_block_rule'),
    ('file_access_ided'),
    ('geoip_restriction'),
    ('ssh_bruteforce_user')
ON CONFLICT (rule_name) DO NOTHING;"

echo "=== [5/5] Levantando contenedores ==="
sudo docker compose up -d --build

echo ""
echo "=== LISTO ==="
echo "Collector:  http://$(curl -s ifconfig.me):5000/log"
echo "Correlator: http://$(curl -s ifconfig.me):7000/event"
