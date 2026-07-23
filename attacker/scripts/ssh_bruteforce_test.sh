#!/bin/bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

ATTEMPTS="${ATTEMPTS:-10}"
DELAY_SECONDS="${DELAY_SECONDS:-1}"
WRONG_PASS="clave-incorrecta-$$"

log_event "ssh_bruteforce_start" "INFO" "Objetivo=${TARGET_HOST} usuario=${TARGET_USER} intentos=${ATTEMPTS}"

fallos=0
for i in $(seq 1 "${ATTEMPTS}"); do
    salida=$(sshpass -p "${WRONG_PASS}" ssh ${SSH_OPTS} "${TARGET_USER}@${TARGET_HOST}" "echo no-deberia-llegar-aqui" 2>&1)
    if echo "${salida}" | grep -qi "Permission denied"; then
        fallos=$((fallos + 1))
        log_event "ssh_bruteforce_attempt" "FAIL_ESPERADO" "Intento ${i}/${ATTEMPTS} rechazado (autenticacion fallida, comportamiento esperado)"
    else
        log_event "ssh_bruteforce_attempt" "INESPERADO" "Intento ${i}/${ATTEMPTS} no devolvio 'Permission denied': ${salida}"
    fi
    sleep "${DELAY_SECONDS}"
done

log_event "ssh_bruteforce_end" "OK" "Completados ${fallos}/${ATTEMPTS} intentos fallidos de autenticacion SSH"
echo "Fin de la simulacion de fuerza bruta SSH. Revisa las alertas de Wazuh (regla 100010) y el estado de bloqueo de IP en la victima."