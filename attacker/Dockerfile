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

# Proceso principal del contenedor: sigue el log local que common.sh va
# escribiendo (ver LOCAL_LOG). Los ataques se lanzan aparte, via
# 'docker compose exec' (un proceso distinto, en el mismo contenedor), pero
# 'docker compose logs' solo captura el stdout del PID 1 -- con 'tail -F'
# como PID 1, cada linea que escriben los scripts de ataque llega tambien
# ahi, en vivo. '-F' (mayuscula) sigue esperando aunque el fichero no exista
# todavia (antes del primer ataque) o se trunque/recree.
CMD ["tail", "-F", "/var/log/attack/timings.log"]
