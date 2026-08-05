#!/bin/bash
# Lanza uno de los tres escenarios y mide, cruzando results/timings.log
# (ataque), alerts.json en wazuh.manager (alerta) y evidence/active_response.log
# (respuesta), las tres metricas definidas en docs/validation_plan.md §5:
# tiempo de deteccion, duracion de la respuesta y tiempo total.
#
# Uso:
#   scripts/measure_timings.sh 1|2|3            # lanza el ataque y mide
#   scripts/measure_timings.sh 1|2|3 --no-launch # mide el ultimo ataque ya lanzado
#
# Debe ejecutarse en el host, desde la raiz del repositorio, con el
# laboratorio ya levantado (docker compose up -d).
#
# Nota: los logs son acumulativos entre ejecuciones (mismas reglas pueden
# haber disparado antes, o el propio escenario 3 genera una segunda alerta
# auto-inducida al restaurar el fichero). Por eso no se toma "la ultima
# linea" sin mas: se filtra por lo que ocurre en o despues del inicio de
# ESTE ataque, y de eso se toma lo mas temprano.
set -euo pipefail

SCENARIO="${1:?Uso: $0 <1|2|3> [--no-launch]}"
LAUNCH=1
[ "${2:-}" = "--no-launch" ] && LAUNCH=0

case "${SCENARIO}" in
    1)
        NOMBRE="Escenario 1 - Fuerza bruta SSH (T1110)"
        ATTACK_SCRIPT="ssh_bruteforce_test.sh"
        START_EVENT="ssh_bruteforce_start"
        RULE_ID="100010"
        AR_PATTERN="block_ip.sh RESULTADO=OK"
        AR_LINES=1
        ;;
    2)
        NOMBRE="Escenario 2 - Creacion de cuenta local (T1136)"
        ATTACK_SCRIPT="create_user_attack.sh"
        START_EVENT="create_user_start"
        RULE_ID="100020"
        AR_PATTERN="disable_user.sh RESULTADO=OK"
        AR_LINES=2
        ;;
    3)
        NOMBRE="Escenario 3 - Clave SSH no autorizada (T1098.004)"
        ATTACK_SCRIPT="add_ssh_key_attack.sh"
        START_EVENT="add_ssh_key_start"
        RULE_ID="100030"
        AR_PATTERN="preserve_restore.sh RESULTADO=RESTAURADO"
        AR_LINES=1
        ;;
    *)
        echo "Escenario invalido: '${SCENARIO}' (usa 1, 2 o 3)" >&2
        exit 1
        ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

to_ms() { date -u -d "$1" +%s%3N; }

fmt_delta() {
    local ms=$1
    printf "%d,%03d s" $((ms / 1000)) $((ms % 1000))
}

# De una lista de timestamps (uno por linea, por stdin), imprime el primero
# que sea >= $1 (umbral en ms desde epoch).
first_after() {
    local threshold_ms=$1 ts ts_ms
    while IFS= read -r ts; do
        [ -z "${ts}" ] && continue
        ts_ms=$(to_ms "${ts}" 2>/dev/null) || continue
        if [ "${ts_ms}" -ge "${threshold_ms}" ]; then
            echo "${ts}"
            return 0
        fi
    done
    return 1
}

if [ "${LAUNCH}" -eq 1 ]; then
    echo "Lanzando ${NOMBRE}..."
    docker compose exec -T attacker "/opt/scripts/${ATTACK_SCRIPT}"
    echo
    echo "Esperando propagacion de alerta y respuesta (10s)..."
    sleep 10
else
    echo "Midiendo el ultimo ataque ya lanzado para: ${NOMBRE}"
fi

# 1. Instante de inicio del ataque (ultima ocurrencia del evento de arranque)
T_ATAQUE_RAW=$(grep "EVENTO=${START_EVENT} " results/timings.log | tail -1 \
    | grep -o '^\[[^]]*\]' | tr -d '[]')

if [ -z "${T_ATAQUE_RAW}" ]; then
    echo "No se encontro ningun evento '${START_EVENT}' en results/timings.log." >&2
    echo "¿Se ha lanzado el escenario al menos una vez?" >&2
    exit 1
fi
T_ATAQUE_MS=$(to_ms "${T_ATAQUE_RAW}")

# 2. Instante de la alerta: la primera con esa regla en o despues del ataque
T_ALERTA_RAW=$(docker compose exec -T wazuh.manager sh -c \
    "grep '\"id\":\"${RULE_ID}\"' /var/ossec/logs/alerts/alerts.json \
     | grep -o '\"timestamp\":\"[^\"]*\"' | cut -d'\"' -f4" \
    | first_after "${T_ATAQUE_MS}") || {
    echo "No se encontro ninguna alerta con regla ${RULE_ID} despues del ataque." >&2
    exit 1
}
T_ALERTA_MS=$(to_ms "${T_ALERTA_RAW}")

# 3. Inicio y fin de la respuesta: las AR_LINES invocaciones que coinciden,
#    en o despues del ataque (para escenario 2 son 2: passwd + group)
AR_CANDIDATES=$(grep "${AR_PATTERN}" evidence/active_response.log \
    | sed -n 's/.*inicio=\([^ ]*\) fin=\([^ "]*\).*/\1 \2/p')

AR_MATCHED=""
while IFS=' ' read -r inicio fin; do
    [ -z "${inicio}" ] && continue
    inicio_ms=$(to_ms "${inicio}" 2>/dev/null) || continue
    if [ "${inicio_ms}" -ge "${T_ATAQUE_MS}" ]; then
        AR_MATCHED="${AR_MATCHED}${inicio} ${fin}"$'\n'
        [ "$(echo -n "${AR_MATCHED}" | grep -c .)" -ge "${AR_LINES}" ] && break
    fi
done <<< "${AR_CANDIDATES}"

if [ -z "${AR_MATCHED}" ]; then
    echo "No se encontro ninguna respuesta '${AR_PATTERN}' despues del ataque." >&2
    exit 1
fi

T_RESP_INICIO_RAW=$(echo "${AR_MATCHED}" | head -1 | awk '{print $1}')
T_RESP_FIN_RAW=$(echo "${AR_MATCHED}" | sed '/^$/d' | tail -1 | awk '{print $2}')

T_RESP_INICIO_MS=$(to_ms "${T_RESP_INICIO_RAW}")
T_RESP_FIN_MS=$(to_ms "${T_RESP_FIN_RAW}")

DETECCION_MS=$((T_ALERTA_MS - T_ATAQUE_MS))
RESPUESTA_MS=$((T_RESP_FIN_MS - T_RESP_INICIO_MS))
DESPACHO_MS=$((T_RESP_INICIO_MS - T_ALERTA_MS))
TOTAL_MS=$((T_RESP_FIN_MS - T_ATAQUE_MS))

echo
echo "=== ${NOMBRE} ==="
printf "%-32s %s\n" "Inicio del ataque:"        "${T_ATAQUE_RAW}"
printf "%-32s %s\n" "Alerta generada (${RULE_ID}):" "${T_ALERTA_RAW}"
printf "%-32s %s -> %s\n" "Respuesta (inicio -> fin):" "${T_RESP_INICIO_RAW}" "${T_RESP_FIN_RAW}"
echo "---"
printf "%-32s %s\n" "Tiempo de deteccion:"       "$(fmt_delta "${DETECCION_MS}")"
printf "%-32s %s\n" "Despacho manager->agente:"  "$(fmt_delta "${DESPACHO_MS}")"
printf "%-32s %s\n" "Duracion de la respuesta:"  "$(fmt_delta "${RESPUESTA_MS}")"
printf "%-32s %s\n" "Tiempo total:"               "$(fmt_delta "${TOTAL_MS}")"
