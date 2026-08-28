#!/bin/sh
# Bootstrap de un solo uso: hace en Cortex, por API, exactamente lo que hasta
# ahora habia que hacer a mano en su interfaz (ver README, seccion "Gestion
# de incidentes", version anterior a este script):
#   1. inicializar la base de datos (POST /api/maintenance/migrate)
#   2. crear el primer usuario (superadmin), unico paso que Cortex permite
#      sin autenticar -- pero solo mientras no exista NINGUN usuario en toda
#      la instancia (org.thp.cortex.services.UserSrv.getInitialUser, en el
#      propio codigo fuente de Cortex: cuenta usuarios sin filtrar por
#      organizacion). Password fijado en el mismo POST (UserSrv.create llama
#      a authSrv.setPassword si el campo "password" viene en el body), asi
#      que no hace falta un segundo paso autenticado para el usuario que
#      todavia no tiene credenciales. (El "hasPassword": false que devuelve
#      la respuesta es enganoso: es una foto del objeto tomada ANTES de
#      fijar la contrasena, no significa que no se haya guardado -- probado
#      en vivo iniciando sesion con ella justo despues.)
#   3. crear una organizacion de trabajo (el superadmin vive en la
#      organizacion de sistema 'cortex' y NO puede ejecutar analizadores;
#      confirmado en vivo, ver docs/validation_plan.md §7.12 adenda)
#   4. crear en ella un usuario con roles read+analyze+orgadmin (orgadmin es
#      imprescindible: sin el, nadie puede habilitar analizadores para esa
#      organizacion, ni siquiera el superadmin desde fuera)
#   5. habilitar el analizador FileInfo para esa organizacion
#      (POST /api/organization/analyzer/:id, scopeado a la organizacion del
#      usuario autenticado -- por eso hace falta el usuario del paso 4, no
#      el superadmin; y necesita "name" en el cuerpo, o Cortex responde
#      AttributeCheckingError)
#   6. obtener (o generar si no existe) la clave API de ese usuario
#   7. escribir esa clave dentro de thehive/application.conf, sustituyendo
#      el valor que haya en la linea 'key = "..."' del bloque cortex.servers
#      -- unico paso que sigue siendo necesario porque ese fichero lo lee
#      TheHive una sola vez, al arrancar (HOCON, no hay recarga en caliente)
#
# Autenticacion: Cortex 3.2.1 tiene deshabilitado el transporte HTTP Basic
# pese a que su config por defecto sugiere lo contrario (comprobado en
# vivo: 'curl -u usuario:clave' devuelve 401 en cualquier endpoint). Hay que
# autenticar con /api/login (usuario+password -> cookie de sesion
# CORTEX_SESSION) y, para cualquier POST/PATCH/DELETE, mandar ademas el
# token CSRF que Cortex emite en la cookie CORTEX-XSRF-TOKEN (nombres fijados
# en su reference.conf) como cabecera X-CORTEX-XSRF-TOKEN -- si no, Cortex
# responde 403 Forbidden. La cookie CSRF no la emite el propio /api/login:
# hace falta una llamada GET autenticada despues para que aparezca.
#
# Idempotente y permisivo, igual que create_wazuh_api_key.sh: si algun paso
# falla porque el recurso ya existe (ejecuciones repetidas del bootstrap) se
# registra un aviso y se continua. Si el superadmin ya existe con OTRAS
# credenciales (alguien completo el paso a mano antes de que existiera este
# script), no hay forma de saber su password: se avisa y se sale sin tocar
# nada mas.
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
# Anclado a que 'key' sea el primer token tras la indentacion (no basta con
# contener la subcadena 'key = "': eso tambien encaja con la linea
# 'play.http.secret.key = "..."', el secreto de Play, que no hay que tocar).
# El fichero se escribe dentro del mismo directorio que se monta (no como
# bind mount de un unico fichero) para poder hacer un reemplazo atomico
# (escribir aparte + mover) sin tropezar con el punto de montaje.
awk -v k="${KEY}" '
    $0 ~ /^[[:space:]]*key = "/ {
        match($0, /^[[:space:]]*/)
        print substr($0, RSTART, RLENGTH) "key = \"" k "\""
        next
    }
    { print }
' "${APPLICATION_CONF}" > "${APPLICATION_CONF}.new" && mv "${APPLICATION_CONF}.new" "${APPLICATION_CONF}"

echo "Bootstrap de Cortex completado: organizacion '${ORG_NAME}', usuario '${ANALYST_USER}', analizador '${ANALYZER_ID}' habilitado, clave escrita en application.conf."
