#!/bin/bash
set -Eeuo pipefail

OSSEC_PATH="/var/ossec"
OSSEC_CONF="${OSSEC_PATH}/etc/ossec.conf"
CLIENT_KEYS="${OSSEC_PATH}/etc/client.keys"

log() {
    printf '[agent-entrypoint] %s\n' "$*"
}

stop_services() {
    log "Deteniendo servicios..."

    "${OSSEC_PATH}/bin/wazuh-control" stop >/dev/null 2>&1 || true

    if [[ -f /run/sshd.pid ]]; then
        kill "$(cat /run/sshd.pid)" 2>/dev/null || true
    fi

    if [[ -f /run/rsyslogd.pid ]]; then
        kill "$(cat /run/rsyslogd.pid)" 2>/dev/null || true
    fi

    exit 0
}

trap stop_services SIGTERM SIGINT

# Compatibilidad con la variable utilizada por wazuh/wazuh-agent.
WAZUH_MANAGER="${WAZUH_MANAGER:-${WAZUH_MANAGER_SERVER:-}}"
WAZUH_REGISTRATION_SERVER="${WAZUH_REGISTRATION_SERVER:-${WAZUH_MANAGER}}"

if [[ -z "${WAZUH_MANAGER}" ]]; then
    log "ERROR: WAZUH_MANAGER_SERVER o WAZUH_MANAGER no está definido."
    exit 1
fi

configure_manager() {
    local escaped_manager

    escaped_manager="$(
        printf '%s' "${WAZUH_MANAGER}" |
            sed 's/[\/&]/\\&/g'
    )"

    if grep -q '<address>.*</address>' "${OSSEC_CONF}"; then
        sed -i \
            "0,/<address>.*<\/address>/s//<address>${escaped_manager}<\/address>/" \
            "${OSSEC_CONF}"
    else
        log "ERROR: no se encontró <address> en ${OSSEC_CONF}."
        exit 1
    fi

    log "Manager configurado: ${WAZUH_MANAGER}"
}

wait_for_manager() {
    local attempt
    local max_attempts=60

    log "Esperando al servicio de registro ${WAZUH_REGISTRATION_SERVER}:1515..."

    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        if nc -z "${WAZUH_REGISTRATION_SERVER}" 1515; then
            log "Servicio de registro disponible."
            return 0
        fi

        sleep 2
    done

    log "ERROR: el servicio de registro no está disponible."
    return 1
}

enroll_agent() {
    local -a auth_command

    # El volumen conserva client.keys entre recreaciones.
    if [[ -s "${CLIENT_KEYS}" ]]; then
        log "El agente ya está registrado."
        return 0
    fi

    wait_for_manager

    auth_command=(
        "${OSSEC_PATH}/bin/agent-auth"
        -m "${WAZUH_REGISTRATION_SERVER}"
    )

    if [[ -n "${WAZUH_AGENT_NAME:-}" ]]; then
        auth_command+=(-A "${WAZUH_AGENT_NAME}")
    fi

    if [[ -n "${WAZUH_AGENT_GROUP:-}" ]]; then
        auth_command+=(-G "${WAZUH_AGENT_GROUP}")
    fi

    if [[ -n "${WAZUH_REGISTRATION_PASSWORD:-}" ]]; then
        auth_command+=(-P "${WAZUH_REGISTRATION_PASSWORD}")
    fi

    log "Registrando agente ${WAZUH_AGENT_NAME:-$(hostname)}..."

    local attempt
    for attempt in {1..10}; do
        if "${auth_command[@]}"; then
            log "Registro completado."
            return 0
        fi

        log "Registro fallido; reintentando (${attempt}/10)..."
        sleep 5
    done

    log "ERROR: no fue posible registrar el agente."
    return 1
}

start_services() {
    mkdir -p /run/sshd /var/log
    touch /var/log/auth.log

    log "Generando claves SSH..."
    ssh-keygen -A

    log "Validando configuración SSH..."
    /usr/sbin/sshd -t

    log "Iniciando rsyslog..."
    /usr/sbin/rsyslogd

    log "Iniciando sshd..."
    /usr/sbin/sshd

    log "Limpiando PID antiguos de Wazuh..."
    rm -f /var/ossec/var/run/*.pid
    rm -f /var/ossec/var/run/*.pid-*

    log "Iniciando Wazuh Agent..."
    "${OSSEC_PATH}/bin/wazuh-control" start

    sleep 3

    log "Estado de Wazuh Agent:"
    "${OSSEC_PATH}/bin/wazuh-control" status
}

configure_lab_user() {
    local lab_user="${LAB_USER:-labuser}"
    local lab_password="${LAB_PASSWORD:-labpassword123}"
    local allow_sudo="${LAB_ALLOW_SUDO:-false}"

    if [[ ! "${lab_user}" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
        log "ERROR: LAB_USER contiene caracteres no válidos."
        exit 1
    fi

    if [[ -z "${lab_password}" ]]; then
        log "ERROR: LAB_PASSWORD no puede estar vacío."
        exit 1
    fi

    if id "${lab_user}" >/dev/null 2>&1; then
        log "El usuario ${lab_user} ya existe."
    else
        log "Creando usuario vulnerable ${lab_user}..."
        useradd \
            --create-home \
            --shell /bin/bash \
            "${lab_user}"
    fi

    printf '%s:%s\n' "${lab_user}" "${lab_password}" | chpasswd

    mkdir -p "/home/${lab_user}/.ssh"
    chmod 0700 "/home/${lab_user}/.ssh"
    chown -R "${lab_user}:${lab_user}" "/home/${lab_user}"

    case "${allow_sudo,,}" in
        true | "1" | yes)
            log "Concediendo sudo a ${lab_user}..."

            usermod -aG sudo "${lab_user}"

            printf '%s ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/chpasswd, /usr/sbin/userdel, /usr/sbin/usermod\n' "${lab_user}" \
                > "/etc/sudoers.d/${lab_user}"

            chmod 0440 "/etc/sudoers.d/${lab_user}"
            ;;
        *)
            rm -f "/etc/sudoers.d/${lab_user}"
            ;;
    esac
}

install_ar_scripts() {
    log "Instalando scripts de Active Response..."
    mkdir -p /var/ossec/active-response/bin
    if [ -d /opt/ar-src ]; then
        cp /opt/ar-src/*.sh /var/ossec/active-response/bin/ 2>/dev/null || true
        cp /opt/ar-src/whitelist.conf /var/ossec/active-response/bin/ 2>/dev/null || true
        chown root:wazuh /var/ossec/active-response/bin/* 2>/dev/null || true
        chmod 750 /var/ossec/active-response/bin/*.sh 2>/dev/null || true
    fi
}

configure_manager
enroll_agent
configure_lab_user
sed -i "s|/home/[^/]*/.ssh|/home/${LAB_USER:-corpuser}/.ssh|g" "${OSSEC_CONF}"
install_ar_scripts
start_services

log "Contenedor inicializado correctamente."

tail -F \
    /var/log/auth.log \
    /var/ossec/logs/ossec.log &

TAIL_PID=$!
wait "${TAIL_PID}"