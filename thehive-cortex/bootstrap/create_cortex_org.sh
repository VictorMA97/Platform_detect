#!/bin/sh
# Bootstrap de un solo uso: automatiza por API el enlace Cortex<->TheHive
# (organizacion, usuario analista, analizador FileInfo, clave API), antes
# manual en la UI de Cortex. Que endpoint hace falta para cada paso y por
# que (codigo fuente de Cortex, no documentacion oficial -- no la publica)
# esta en docs/validation_plan.md §7.15; aqui solo lo no obvio para leer
# el script:
#
# - Cortex acepta un POST /api/user sin autenticar solo mientras no exista
#   NINGUN usuario en toda la instancia (UserSrv.getInitialUser); por eso
#   el superadmin se crea asi, con password en el mismo POST, y todo lo
#   demas necesita sesion.
# - Cortex tiene deshabilitado HTTP Basic pese a que su config por defecto
#   sugiere lo contrario. Hay que autenticar con /api/login (cookie de
#   sesion) y mandar el token CSRF que emite en la cookie
#   CORTEX-XSRF-TOKEN como cabecera X-CORTEX-XSRF-TOKEN en cada
#   POST/PATCH/DELETE, o responde 403 -- y esa cookie no la emite el propio
#   /api/login, hace falta una llamada autenticada mas antes de tenerla.
#
# Idempotente y permisivo, igual que create_wazuh_api_key.sh: si algo ya
# existe o falla, se avisa y se continua en vez de abortar.
set -eu

CORTEX_URL="http://cortex:9001"
ADMIN_USER="${CORTEX_ADMIN_USER:?falta CORTEX_ADMIN_USER en .env}"
ADMIN_PASSWORD="${CORTEX_ADMIN_PASSWORD:?falta CORTEX_ADMIN_PASSWORD en .env}"
ANALYST_USER="${CORTEX_ANALYST_USER:?falta CORTEX_ANALYST_USER en .env}"
ANALYST_PASSWORD="${CORTEX_ANALYST_PASSWORD:?falta CORTEX_ANALYST_PASSWORD en .env}"
ORG_NAME="TFM"
ANALYZER_ID="FileInfo_8_0"
APPLICATION_CONF="/thehive-application-conf/application.conf"
ADMIN_JAR="/tmp/admin_cookies"
ANALYST_JAR="/tmp/analyst_cookies"

echo "Esperando a que la API de Cortex responda..."
i=0
until curl -sf -o /dev/null "${CORTEX_URL}/api/status"; do
    i=$((i + 1))
    if [ "${i}" -ge 60 ]; then
        echo "Cortex no respondio tras 5 minutos; no se hace el bootstrap (el enlace Cortex<->TheHive quedara inactivo)." >&2
        exit 0
    fi
    sleep 5
done

# jarfile -> imprime el valor actual del token CSRF de esa sesion
csrf_of() {
    grep CORTEX-XSRF-TOKEN "$1" 2>/dev/null | awk '{print $NF}'
}

# usuario password jarfile -> inicia sesion y deja lista la cookie CSRF
login() {
    user="$1"
    pass="$2"
    jar="$3"
    rm -f "${jar}"
    curl -s -o /dev/null -c "${jar}" -X POST -H "Content-Type: application/json" \
        -d "{\"user\":\"${user}\",\"password\":\"${pass}\"}" \
        "${CORTEX_URL}/api/login" || true
    # /api/login no emite todavia la cookie CSRF; una llamada autenticada
    # cualquiera despues si lo hace.
    curl -s -o /dev/null -b "${jar}" -c "${jar}" "${CORTEX_URL}/api/user/current" || true
}

# jarfile metodo path json_body -> imprime el codigo HTTP, deja el cuerpo en /tmp/resp.$$
auth_call() {
    jar="$1"
    method="$2"
    path="$3"
    data="${4:-}"
    csrf=$(csrf_of "${jar}")
    if [ -n "${data}" ]; then
        curl -s -o /tmp/resp.$$ -w '%{http_code}' -b "${jar}" -c "${jar}" -X "${method}" \
            -H "Content-Type: application/json" -H "X-CORTEX-XSRF-TOKEN: ${csrf}" \
            -d "${data}" "${CORTEX_URL}${path}" || echo "000"
    else
        curl -s -o /tmp/resp.$$ -w '%{http_code}' -b "${jar}" -c "${jar}" -X "${method}" \
            -H "X-CORTEX-XSRF-TOKEN: ${csrf}" \
            "${CORTEX_URL}${path}" || echo "000"
    fi
}

echo "Inicializando la base de datos de Cortex (si ya lo esta, no hace nada)..."
curl -s -o /dev/null -X POST "${CORTEX_URL}/api/maintenance/migrate" || true

echo "Comprobando si '${ADMIN_USER}' ya existe como superadmin..."
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -d "{\"user\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
    "${CORTEX_URL}/api/login")
if [ "${CODE}" = "200" ]; then
    echo "  Ya existe y las credenciales son validas; no hace falta crearlo."
else
    echo "Creando el superadmin '${ADMIN_USER}' (unico momento en que Cortex acepta esto sin autenticar)..."
    CODE=$(curl -s -o /tmp/resp.$$ -w '%{http_code}' -X POST -H "Content-Type: application/json" \
        -d "{\"login\":\"${ADMIN_USER}\",\"name\":\"Superadmin (bootstrap TFM)\",\"organization\":\"cortex\",\"roles\":[\"superadmin\"],\"password\":\"${ADMIN_PASSWORD}\"}" \
        "${CORTEX_URL}/api/user")
    if [ "${CODE}" != "201" ]; then
        echo "  HTTP ${CODE}: $(cat /tmp/resp.$$ 2>/dev/null)" >&2
        echo "  No se pudo crear el superadmin (probablemente ya existe uno con otras credenciales, creado a mano). Bootstrap abortado; hazlo manualmente (ver README)." >&2
        rm -f /tmp/resp.$$
        exit 0
    fi
    rm -f /tmp/resp.$$
fi

login "${ADMIN_USER}" "${ADMIN_PASSWORD}" "${ADMIN_JAR}"

echo "Creando la organizacion '${ORG_NAME}' (si no existe ya)..."
CODE=$(auth_call "${ADMIN_JAR}" POST /api/organization "{\"name\":\"${ORG_NAME}\",\"description\":\"Laboratorio TFM\"}")
if [ "${CODE}" != "201" ]; then
    echo "  HTTP ${CODE}: $(cat /tmp/resp.$$ 2>/dev/null) (se continua; puede ya existir de una ejecucion anterior)"
fi
rm -f /tmp/resp.$$

echo "Creando el usuario analista '${ANALYST_USER}' en '${ORG_NAME}' (si no existe ya)..."
CODE=$(auth_call "${ADMIN_JAR}" POST /api/user \
    "{\"login\":\"${ANALYST_USER}\",\"name\":\"Analista TFM (bootstrap)\",\"organization\":\"${ORG_NAME}\",\"roles\":[\"read\",\"analyze\",\"orgadmin\"],\"password\":\"${ANALYST_PASSWORD}\"}")
if [ "${CODE}" != "201" ]; then
    echo "  HTTP ${CODE}: $(cat /tmp/resp.$$ 2>/dev/null) (se continua; puede ya existir de una ejecucion anterior)"
fi
rm -f /tmp/resp.$$

login "${ANALYST_USER}" "${ANALYST_PASSWORD}" "${ANALYST_JAR}"

echo "Habilitando el analizador '${ANALYZER_ID}' para '${ORG_NAME}' (si no lo esta ya)..."
CODE=$(auth_call "${ANALYST_JAR}" POST "/api/organization/analyzer/${ANALYZER_ID}" "{\"name\":\"${ANALYZER_ID}\"}")
if [ "${CODE}" != "201" ]; then
    echo "  HTTP ${CODE}: $(cat /tmp/resp.$$ 2>/dev/null) (se continua; puede ya estar habilitado de una ejecucion anterior)"
fi
rm -f /tmp/resp.$$

echo "Obteniendo la clave API de '${ANALYST_USER}' (sin rotarla si ya existe)..."
CODE=$(auth_call "${ANALYST_JAR}" GET "/api/user/${ANALYST_USER}/key")
if [ "${CODE}" = "200" ]; then
    KEY=$(cat /tmp/resp.$$)
else
    echo "  No tenia clave todavia (HTTP ${CODE}); generando una nueva..."
    CODE=$(auth_call "${ANALYST_JAR}" POST "/api/user/${ANALYST_USER}/key/renew")
    if [ "${CODE}" != "200" ]; then
        echo "  HTTP ${CODE}: $(cat /tmp/resp.$$ 2>/dev/null)" >&2
        echo "  No se pudo generar la clave API. El enlace Cortex<->TheHive quedara inactivo hasta configurarlo a mano (ver README)." >&2
        rm -f /tmp/resp.$$
        exit 0
    fi
    KEY=$(cat /tmp/resp.$$)
fi
rm -f /tmp/resp.$$
KEY=$(printf '%s' "${KEY}" | tr -d '\r\n"')

if [ -z "${KEY}" ] || [ "${#KEY}" -lt 10 ]; then
    echo "No se pudo obtener la clave API (respuesta invalida: '${KEY}')." >&2
    echo "El enlace Cortex<->TheHive quedara inactivo hasta configurarlo a mano (ver README)." >&2
    exit 0
fi

echo "Escribiendo la clave en ${APPLICATION_CONF}..."
# Anclado a 'key' como primer token: 'play.http.secret.key = "..."' tambien
# contiene la subcadena 'key = "' y no hay que tocarlo.
awk -v k="${KEY}" '
    $0 ~ /^[[:space:]]*key = "/ {
        match($0, /^[[:space:]]*/)
        print substr($0, RSTART, RLENGTH) "key = \"" k "\""
        next
    }
    { print }
' "${APPLICATION_CONF}" > "${APPLICATION_CONF}.new" && mv "${APPLICATION_CONF}.new" "${APPLICATION_CONF}"

echo "Bootstrap de Cortex completado: organizacion '${ORG_NAME}', usuario '${ANALYST_USER}', analizador '${ANALYZER_ID}' habilitado, clave escrita en application.conf."
