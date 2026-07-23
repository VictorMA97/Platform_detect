#!/bin/bash
# Active Response: bloqueo temporal de IP origen (T1110).
# Reversible: Wazuh invoca este mismo script con 'delete' al expirar el timeout.
set -uo pipefail

LOG="/var/ossec/logs/active-responses.log"
EVIDENCE_DIR="/var/ossec/evidence"
WHITELIST="/var/ossec/active-response/bin/whitelist.conf"
CHAIN="WAZUH_AR"

mkdir -p "${EVIDENCE_DIR}"
now() { date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"; }
log_ev() { echo "[$(now)] block_ip.sh RESULTADO=$1 DETALLE=\"$2\"" | tee -a "${LOG}" >> "${EVIDENCE_DIR}/active_response.log"; }

T_START=$(now)

# Wazuh entrega la alerta como JSON por stdin
read -r INPUT_JSON
ACTION=$(echo "${INPUT_JSON}" | jq -r '.command // "add"')
SRCIP=$(echo "${INPUT_JSON}" | jq -r '.parameters.alert.data.srcip // empty')
RULE_ID=$(echo "${INPUT_JSON}" | jq -r '.parameters.alert.rule.id // "desconocida"')

if [ -z "${SRCIP}" ]; then
    log_ev "FALLO" "No se pudo extraer srcip de la alerta"
    exit 1
fi

# shellcheck disable=SC1090
[ -f "${WHITELIST}" ] && . "${WHITELIST}"

for ip in ${WHITELIST_IPS:-}; do
    if [ "${ip}" = "${SRCIP}" ]; then
        log_ev "OMITIDO_WHITELIST" "IP ${SRCIP} en whitelist, no se bloquea (regla ${RULE_ID})"
        exit 0
    fi
done

# Cadena dedicada: aisla las reglas del AR y facilita la limpieza
iptables -N "${CHAIN}" 2>/dev/null
iptables -C INPUT -j "${CHAIN}" 2>/dev/null || iptables -I INPUT -j "${CHAIN}"

case "${ACTION}" in
    add)
        if iptables -C "${CHAIN}" -s "${SRCIP}" -j DROP 2>/dev/null; then
            log_ev "YA_BLOQUEADA" "IP ${SRCIP} ya estaba bloqueada"
        elif iptables -I "${CHAIN}" -s "${SRCIP}" -j DROP; then
            T_END=$(now)
            log_ev "OK" "IP ${SRCIP} bloqueada por regla ${RULE_ID} | inicio=${T_START} fin=${T_END}"
        else
            log_ev "FALLO" "No se pudo aplicar iptables sobre ${SRCIP} (revisar cap_add NET_ADMIN)"
            exit 1
        fi
        ;;
    delete)
        iptables -D "${CHAIN}" -s "${SRCIP}" -j DROP 2>/dev/null \
            && log_ev "REVERTIDO" "Bloqueo de ${SRCIP} retirado (timeout cumplido)" \
            || log_ev "REVERSION_NO_NECESARIA" "No habia bloqueo activo para ${SRCIP}"
        ;;
esac
exit 0