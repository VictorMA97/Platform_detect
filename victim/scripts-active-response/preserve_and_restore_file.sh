#!/bin/bash
# Active Response: preservar evidencia y restaurar fichero limpio (T1098.004).
# Nunca destruye evidencia: copia el fichero alterado antes de tocarlo.
set -uo pipefail

LOG="/var/ossec/logs/active-responses.log"
EVIDENCE_DIR="/var/ossec/evidence"
BASELINE_DIR="/opt/baseline"

mkdir -p "${EVIDENCE_DIR}"
now() { date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"; }
log_ev() { echo "[$(now)] preserve_restore.sh RESULTADO=$1 DETALLE=\"$2\"" | tee -a "${LOG}" >> "${EVIDENCE_DIR}/active_response.log"; }

T_START=$(now)
read -r INPUT_JSON
ACTION=$(echo "${INPUT_JSON}" | jq -r '.command // "add"')
RULE_ID=$(echo "${INPUT_JSON}" | jq -r '.parameters.alert.rule.id // "desconocida"')
TARGET=$(echo "${INPUT_JSON}" | jq -r '.parameters.alert.syscheck.path // empty')

[ "${ACTION}" != "add" ] && exit 0

if [ -z "${TARGET}" ] || [ ! -f "${TARGET}" ]; then
    log_ev "SIN_FICHERO" "Ruta no valida o inexistente: '${TARGET}'"
    exit 0
fi

STAMP=$(date -u +"%Y%m%dT%H%M%S%3NZ")
SAFE_NAME=$(echo "${TARGET}" | tr '/' '_' | sed 's/^_//')
CLEAN="${BASELINE_DIR}/$(basename "${TARGET}").clean"

# Corta el bucle de auto-disparo: si ya coincide con el baseline,
# este evento lo ha provocado la propia restauracion anterior.
if [ -f "${CLEAN}" ] && cmp -s "${TARGET}" "${CLEAN}"; then
    log_ev "SIN_CAMBIOS" "${TARGET} ya coincide con el baseline; evento auto-inducido, no se actua"
    exit 0
fi

PRESERVED="${EVIDENCE_DIR}/${STAMP}_${SAFE_NAME}"
# Nunca sobrescribir evidencia previa
n=1
while [ -e "${PRESERVED}" ]; do
    PRESERVED="${EVIDENCE_DIR}/${STAMP}_${SAFE_NAME}.${n}"
    n=$((n + 1))
done

# 1. Preservar SIEMPRE antes de cualquier modificacion
cp -p "${TARGET}" "${PRESERVED}" || { log_ev "FALLO" "No se pudo preservar ${TARGET}"; exit 1; }
HASH=$(sha256sum "${PRESERVED}" | awk '{print $1}')
echo "${HASH}  ${TARGET}  ${STAMP}" >> "${EVIDENCE_DIR}/hashes.txt"
log_ev "PRESERVADO" "Copia en ${PRESERVED} | SHA256=${HASH}"

# 2. Restaurar baseline limpio, si existe
CLEAN="${BASELINE_DIR}/$(basename "${TARGET}").clean"
if [ -f "${CLEAN}" ]; then
    OWNER=$(stat -c '%U:%G' "${TARGET}")
    MODE=$(stat -c '%a' "${TARGET}")
    if cp "${CLEAN}" "${TARGET}" && chown "${OWNER}" "${TARGET}" && chmod "${MODE}" "${TARGET}"; then
        T_END=$(now)
        log_ev "RESTAURADO" "Baseline aplicado a ${TARGET} por regla ${RULE_ID} | inicio=${T_START} fin=${T_END} | original preservado en ${PRESERVED}"
    else
        log_ev "FALLO_RESTAURACION" "Evidencia conservada en ${PRESERVED}"
    fi
else
    log_ev "SIN_BASELINE" "No hay copia limpia para ${TARGET}; evidencia preservada, fichero sin modificar"
fi
exit 0