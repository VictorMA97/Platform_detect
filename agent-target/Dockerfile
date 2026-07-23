FROM debian:bookworm-slim

USER root

ARG WAZUH_VERSION=4.14.6-1

ENV DEBIAN_FRONTEND=noninteractive \
    WAZUH_MANAGER_SERVER="" \
    WAZUH_REGISTRATION_SERVER="" \
    WAZUH_AGENT_NAME="" \
    WAZUH_AGENT_GROUP="default" \
    WAZUH_REGISTRATION_PASSWORD="" \
    LAB_USER=labuser \
    LAB_PASSWORD=labpassword123 \
    LAB_ALLOW_SUDO=false

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        openssh-server \
        rsyslog \
        iptables \
        jq \
        sudo \
        procps \
        passwd \
        netcat-openbsd && \
    find /etc/rsyslog.conf /etc/rsyslog.d -type f \
    -exec sed -i \
      -e '/^[[:space:]]*module(load="imklog")/s/^/#/' \
      -e '/^[[:space:]]*\$ModLoad[[:space:]]\+imklog/s/^/#/' \
      {} \; && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor --yes -o /etc/apt/keyrings/wazuh.gpg && \
    chmod 0644 /etc/apt/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        "wazuh-agent=${WAZUH_VERSION}" && \
    mkdir -p /run/sshd /var/log && \
    touch /var/log/auth.log && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# SSH deliberadamente inseguro para el escenario de laboratorio
RUN printf '%s\n' \
        'PasswordAuthentication yes' \
        'PermitRootLogin yes' \
        'UsePAM yes' \
        'LogLevel VERBOSE' \
        > /etc/ssh/sshd_config.d/99-wazuh-lab.conf

# Asegurar que el agente monitoriza los intentos de autenticación SSH
RUN if ! grep -q '<location>/var/log/auth.log</location>' \
        /var/ossec/etc/ossec.conf; then \
      sed -i '/<\/ossec_config>/i\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/auth.log</location>\
  </localfile>' /var/ossec/etc/ossec.conf; \
    fi

COPY entrypoint-wrapper.sh /entrypoint-wrapper.sh

COPY wazuh_agent/ossec.conf /var/ossec/etc/ossec.conf
RUN chown root:wazuh /var/ossec/etc/ossec.conf && chmod 640 /var/ossec/etc/ossec.conf

RUN chmod 0755 /entrypoint-wrapper.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint-wrapper.sh"]