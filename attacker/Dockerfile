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
RUN chmod +x /opt/scripts/*.sh

CMD ["sleep", "infinity"]
