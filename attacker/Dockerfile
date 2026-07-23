FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    hydra \
    sshpass \
    openssh-client \
    netcat-openbsd \
    iputils-ping \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

# Diccionario básico para hydra en T1110 (fuerza bruta SSH)
RUN echo "labuser\nroot\nadmin\ntest" > users.txt && \
    echo "123456\npassword\nlabpassword123\ntoor\nadmin123\nqwerty" > passwords.txt

WORKDIR /opt/scripts
COPY scripts/ /opt/scripts/
RUN chmod +x /opt/scripts/*.sh

CMD ["sleep", "infinity"]
