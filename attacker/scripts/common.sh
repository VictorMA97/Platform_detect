#!/bin/bash
# Variables y funciones comunes a los tres scripts de ataque.
# Se sobreescriben por variable de entorno si hace falta apuntar a otro objetivo.

TARGET_HOST="${TARGET_HOST:-victim}"
TARGET_USER="${TARGET_USER:-corpuser}"
TARGET_PASS="${TARGET_PASS:-Lab-Ficticio-2026!}"
TARGET_PORT="${TARGET_PORT:-22}"

RESULTS_DIR="/opt/results"
RESULTS_LOG="${RESULTS_DIR}/timings.log"
mkdir -p "${RESULTS_DIR}"

# Timestamp ISO8601 con milisegundos, en UTC, para poder calcular deltas
# entre el ataque, la alerta de Wazuh y la respuesta automática.
now() { date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"; }

# log_event EVENTO RESULTADO "DETALLE"
log_event() {
    local evento="$1"
    local resultado="$2"
    local detalle="$3"
    echo "[$(now)] EVENTO=${evento} ORIGEN=$(basename "$0") RESULTADO=${resultado} DETALLE=\"${detalle}\"" | tee -a "${RESULTS_LOG}"
}

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR -p ${TARGET_PORT}"