#!/bin/sh
# Bootstrap de un solo uso: crea en TheHive una organizacion y un usuario
# dedicados a la integracion Wazuh->TheHive, y genera su clave API, dejandola
# en un fichero que el manager de Wazuh monta de solo lectura. El usuario
# administrador del sistema (admin@thehive.local) NO sirve para crear
# alertas: pertenece a la organizacion 'admin' de gestion del sistema, sin
# permiso sobre alertas de casos (comprobado en vivo: HTTP 403
# AuthorizationError). Hace falta una organizacion y un usuario 'org-admin'
# propios, tal como documenta la API v1 de TheHive.
set -eu

THEHIVE_URL="http://thehive:9000"
ADMIN_USER="admin@thehive.local"
ADMIN_PASSWORD="secret"
ORG_NAME="tfm-apt-lab"
WAZUH_USER="wazuh@thehive.local"
OUT_FILE="/shared/wazuh_api_key.txt"

echo "Esperando a que la API de TheHive responda..."
i=0
until curl -sf -o /dev/null "${THEHIVE_URL}/api/status"; do
    i=$((i + 1))
    if [ "${i}" -ge 60 ]; then
        echo "TheHive no respondio tras 5 minutos; no se genera la clave (integracion Wazuh->TheHive quedara inactiva)." >&2
        exit 0
    fi
    sleep 5
done

# metodo path json_body -> imprime "CODE\nBODY"
api_call() {
    method="$1"
    path="$2"
    data="${3:-}"
    if [ -n "${data}" ]; then
        curl -s -o /tmp/resp.$$ -w '%{http_code}' -X "${method}" \
            -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -H "Content-Type: application/json" \
            -d "${data}" "${THEHIVE_URL}${path}" || echo "000"
    else
        curl -s -o /tmp/resp.$$ -w '%{http_code}' -X "${method}" \
            -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${THEHIVE_URL}${path}" || echo "000"
    fi
}

echo "Creando organizacion '${ORG_NAME}' (si no existe ya)..."
CODE=$(api_call POST /api/v1/organisation "{\"name\":\"${ORG_NAME}\",\"description\":\"Laboratorio TFM\"}")
if [ "${CODE}" != "201" ]; then
    echo "  HTTP ${CODE}: $(cat /tmp/resp.$$ 2>/dev/null) (se continua; puede ya existir de una ejecucion anterior)"
fi
rm -f /tmp/resp.$$

echo "Creando usuario '${WAZUH_USER}' en '${ORG_NAME}' (si no existe ya)..."
CODE=$(api_call POST /api/v1/user "{\"login\":\"${WAZUH_USER}\",\"name\":\"Integracion Wazuh\",\"profile\":\"org-admin\",\"organisation\":\"${ORG_NAME}\"}")
if [ "${CODE}" != "201" ]; then
    echo "  HTTP ${CODE}: $(cat /tmp/resp.$$ 2>/dev/null) (se continua; puede ya existir de una ejecucion anterior)"
fi
rm -f /tmp/resp.$$

echo "Generando/renovando clave API para ${WAZUH_USER}..."
RESPONSE=$(curl -s -X POST -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -H "Content-Type: application/json" -d '{}' \
    "${THEHIVE_URL}/api/user/${WAZUH_USER}/key/renew") || RESPONSE=""

# La API devuelve la clave en texto plano (sin comillas ni JSON envolvente).
KEY=$(printf '%s' "${RESPONSE}" | tr -d '\r\n"')

if [ -z "${KEY}" ] || [ "${#KEY}" -lt 10 ]; then
    echo "No se pudo generar la clave (respuesta: '${RESPONSE}')." >&2
    echo "La integracion Wazuh->TheHive quedara inactiva hasta configurarla a mano." >&2
    exit 0
fi

echo "${KEY}" > "${OUT_FILE}"
# Sin chmod aqui a proposito: ver nota en el historial del proyecto
# (docs/validation_plan.md) sobre por que un chmod sobre un fichero que no
# es propio del UID que ejecuta este script aborta el bootstrap con set -e.
echo "Clave API de TheHive para Wazuh generada y guardada en ${OUT_FILE}."
