FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    sshpass \
    openssh-client \
    netcat-openbsd \
    iputils-ping \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/scripts
COPY scripts/ /opt/scripts/
RUN chmod +x /opt/scripts/*.sh && mkdir -p /var/log/attack

# PID 1 sigue el log de common.sh en vez de dormir: 'docker compose logs'
# solo captura stdout de PID 1, y los ataques se lanzan aparte via
# 'docker compose exec'. '-F' sigue esperando aunque el fichero no exista
# todavia o se trunque/recree.
CMD ["tail", "-F", "/var/log/attack/timings.log"]
