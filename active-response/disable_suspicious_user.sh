#!/bin/bash
# Active Response: deshabilitar cuenta local no autorizada (T1136).
# No borra la cuenta: la bloquea, de forma reversible con 'usermod -U'.
set -uo pipefail

LOG="/var/ossec/logs/active-responses.log"
EVIDENCE_DIR="/var/ossec/evidence"
WHITELIST="/var/ossec/active-response/bin/whitelist.conf"

mkdir -p "${EVIDENCE_DIR}"
now() { date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"; }
log_ev() { echo "[$(now)] disable_user.sh RESULTADO=$1 DETALLE=\"$2\"" | tee -a "${LOG}" >> "${EVIDENCE_DIR}/active_response.log"; }

T_START=$(now)
read -r INPUT_JSON
ACTION=$(echo "${INPUT_JSON}" | jq -r '.command // "add"')
RULE_ID=$(echo "${INPUT_JSON}" | jq -r '.parameters.alert.rule.id // "desconocida"')

# El evento FIM no trae el usuario: se extrae del diff de /etc/passwd
DIFF=$(echo "${INPUT_JSON}" | jq -r '.parameters.alert.syscheck.diff // empty')
NEW_USER=$(echo "${DIFF}" | grep -E '^>' | cut -d: -f1 | tr -d '> ' | head -1)

# Respaldo: si el diff no sirve, comparar con el baseline conocido
if [ -z "${NEW_USER}" ] && [ -f "${EVIDENCE_DIR}/passwd.baseline" ]; then
    NEW_USER=$(comm -13 <(sort "${EVIDENCE_DIR}/passwd.baseline") <(cut -d: -f1 /etc/passwd | sort) | head -1)
fi

if [ -z "${NEW_USER}" ]; then
    log_ev "SIN_USUARIO" "No se pudo determinar el usuario nuevo (regla ${RULE_ID})"
    exit 0
fi

# shellcheck disable=SC1090
[ -f "${WHITELIST}" ] && . "${WHITELIST}"

for u in ${WHITELIST_USERS:-}; do
    if [ "${u}" = "${NEW_USER}" ]; then
        log_ev "OMITIDO_WHITELIST" "Usuario ${NEW_USER} protegido, no se deshabilita"
        exit 0
    fi
done

case "${ACTION}" in
    add)
        if usermod -L "${NEW_USER}" && usermod -s /sbin/nologin "${NEW_USER}"; then
            T_END=$(now)
            log_ev "OK" "Usuario ${NEW_USER} deshabilitado por regla ${RULE_ID} | inicio=${T_START} fin=${T_END} | reversion: usermod -U ${NEW_USER}"
        else
            log_ev "FALLO" "No se pudo deshabilitar ${NEW_USER}"
            exit 1
        fi
        ;;
    delete)
        usermod -U "${NEW_USER}" && log_ev "REVERTIDO" "Usuario ${NEW_USER} reactivado"
        ;;
esac
exit 0