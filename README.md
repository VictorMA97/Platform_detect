# TFM — Laboratorio de detección y respuesta automática ante técnicas APT con Wazuh

Prueba de concepto reproducible que demuestra un ciclo completo de detección y respuesta
sobre un servidor Linux corporativo simulado:

```
Ataque simulado → evento en el servidor víctima → alerta en Wazuh
→ respuesta automática → evidencia generada → validación del resultado
```

---

## 1. Objetivo del laboratorio

Validar, sobre un entorno acotado y reproducible, que una organización puede detectar y
responder de forma automática a tres comportamientos asociados a intrusiones avanzadas,
sin necesidad de una plataforma SOAR completa ni de infraestructura dedicada.

El laboratorio cubre tres escenarios mapeados a MITRE ATT&CK:

| # | Escenario | Táctica | Técnica |
|---|-----------|---------|---------|
| 1 | Acceso no autorizado por SSH (fuerza bruta) | Credential Access | T1110 — Brute Force |
| 2 | Creación de cuenta local no autorizada | Persistence | T1136 — Create Account |
| 3 | Inserción de clave SSH no autorizada | Persistence / Defense Evasion | T1098.004 — SSH Authorized Keys |

Cada escenario produce: una alerta con identificador propio, la ejecución de un script de
respuesta, un registro con marcas de tiempo y una evidencia recuperable desde el host.

---

## 2. Arquitectura

```
┌──────────────┐   SSH    ┌──────────────────┐   1514/tcp  ┌──────────────────┐
│  attacker    │─────────▶│  wazuh.agent     │────────────▶│  wazuh.manager   │
│  (Ubuntu)    │          │  sshd + agente   │             │  reglas locales  │
│  3 scripts   │          │  FIM + AR        │◀────────────│  Active Response │
└──────────────┘          └────────┬─────────┘   comando   └────────┬─────────┘
                                   │                                │ 9200/tcp
                                   ▼                                ▼
                          ┌──────────────────┐            ┌──────────────────┐
                          │  ./evidence/     │            │  wazuh.indexer   │
                          │  (volumen host)  │            └────────┬─────────┘
                          └──────────────────┘                     │
                                                                   ▼
                                                          ┌──────────────────┐
                                                          │ wazuh.dashboard  │
                                                          │  (interfaz web)  │
                                                          └──────────────────┘
```

### Componentes

| Servicio | Imagen / origen | Función |
|----------|-----------------|---------|
| `wazuh.manager` | `wazuh/wazuh-manager:4.14.6` | Correlación, reglas locales, orquestación de Active Response |
| `wazuh.indexer` | `wazuh/wazuh-indexer:4.14.6` | Almacenamiento e indexado de alertas (OpenSearch) |
| `wazuh.dashboard` | `wazuh/wazuh-dashboard:4.14.6` | Consulta y visualización de alertas |
| `wazuh.agent` | build `./agent-target` | Servidor víctima: sshd, usuario de prueba, agente Wazuh, scripts de respuesta |
| `attacker` | build `./attacker` | Máquina atacante con los tres scripts de simulación |
| `wazuh-certs-generator` | `wazuh/wazuh-certs-generator` | Bootstrap de un solo uso: genera la CA y los certificados TLS |
| `wazuh-certs-permissions` | `alpine:3.20` | Bootstrap de un solo uso: normaliza permisos del volumen de certificados |

Los dos servicios de bootstrap están bajo el perfil `bootstrap` (`profiles: [bootstrap]`), por
lo que `docker compose up -d` no los levanta: solo se ejecutan explícitamente con
`docker compose run --rm <servicio>`.

Todos los servicios comparten la red `wazuh-network`. El único puerto publicado al host es
el del dashboard.

### Flujo de una detección

1. El contenedor `attacker` ejecuta una acción ofensiva contra `wazuh.agent`.
2. El evento queda registrado en el sistema víctima (`/var/log/auth.log` para SSH,
   File Integrity Monitoring para cambios en ficheros).
3. El agente envía el evento al manager, que lo evalúa contra el ruleset.
4. Una regla local (`100010`, `100020`, `100030`/`100031`) genera la alerta y activa el
   Active Response correspondiente.
5. El script se ejecuta **en el agente** (`location: local`), es decir, donde ocurrió el
   incidente, replicando el modelo de un EDR real.
6. El script registra el resultado con marcas de tiempo y deposita la evidencia en un
   volumen accesible desde el host.

---

## 3. Requisitos previos

- Docker Engine ≥ 24 y Docker Compose v2.
- 6 GB de RAM disponibles para Docker (el indexer reserva 1 GB de heap JVM).
- Salida a Internet **únicamente** durante la construcción de imágenes y la generación
  inicial de certificados.
- `vm.max_map_count` ≥ 262144 en el host que ejecuta el motor de Docker:

```bash
sudo sysctl -w vm.max_map_count=262144
```

> **Windows / WSL2.** Ejecuta el laboratorio desde el sistema de ficheros nativo de la
> distribución WSL (`~/proyectos/...`), **nunca desde `/mnt/c/...`**. Los bind mounts a
> través de `drvfs` provocan problemas de permisos y la creación de directorios fantasma
> cuando el fichero de origen no existe. El ajuste de `vm.max_map_count` se aplica dentro
> de la VM de WSL, no en PowerShell.

---

## 4. Cómo levantar el entorno

La generación de certificados es un **paso previo de un solo uso**, deliberadamente separado
del ciclo de vida habitual: la herramienta oficial de Wazuh no es idempotente y aborta si
detecta certificados de una ejecución anterior.

> `./config/wazuh_indexer_ssl_certs/` es un *bind mount*, no un volumen Docker con nombre:
> `docker compose down -v` **no lo limpia**. Si ya existen certificados de una ejecución
> previa, bórralos a mano antes de regenerarlos (paso 1 de abajo).

```bash
# 0. Solo si ya existen certificados de una ejecución anterior
rm -rf config/wazuh_indexer_ssl_certs/*

# 1. Certificados TLS (solo la primera vez, o tras el paso 0)
docker compose run --rm wazuh-certs-generator

# 2. Normalización de permisos sobre el volumen de certificados
docker compose run --rm wazuh-certs-permissions

# 3. Laboratorio completo
docker compose up -d

# 4. Estado
docker compose ps
```

Todos los servicios deben aparecer como `Up`. El indexer tarda entre 40 y 90 segundos en
quedar operativo. Estos cuatro pasos se han verificado íntegros desde cero (`down -v` +
limpieza de certificados + redespliegue completo + los tres escenarios) el 2026-07-27; el
detalle está en `docs/validation_plan.md`, apartado 9bis.

---

## 5. Cómo comprobar que Wazuh funciona

```bash
# El agente debe figurar como "Active"
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l

# Procesos del manager en ejecución
docker compose exec wazuh.manager /var/ossec/bin/wazuh-control status

# Reglas locales cargadas
docker compose exec wazuh.manager cat /var/ossec/etc/rules/local_rules.xml

# Scripts de respuesta instalados (deben tener permisos 750 root:wazuh)
docker compose exec wazuh.agent ls -la /var/ossec/active-response/bin/
```

**Interfaz web:** `https://localhost` (puerto publicado en `docker-compose.yml`; si lo has
cambiado a 8443, usa `https://localhost:8443`). Usuario `admin`. El certificado es
autofirmado, por lo que el navegador mostrará una advertencia.

Para filtrar únicamente las alertas del laboratorio, en **Threat Hunting** usa la consulta:

```
rule.groups:tfm_apt_lab
```

---

## 6. Cómo ejecutar cada escenario

```bash
# Escenario 1 — Fuerza bruta SSH (T1110)
docker compose exec attacker /opt/scripts/ssh_bruteforce_test.sh

# Escenario 2 — Creación de cuenta local (T1136)
docker compose exec attacker /opt/scripts/create_user_attack.sh

# Escenario 3 — Inserción de clave SSH (T1098.004)
docker compose exec attacker /opt/scripts/add_ssh_key_attack.sh
```

Notas de repetibilidad:

- El escenario 2 falla si `backdoor01` ya existe. Para repetirlo:
  `docker compose exec wazuh.agent userdel -r backdoor01`
- El escenario 3 requiere que el contenido de `authorized_keys` cambie realmente; el FIM no
  genera eventos si el fichero queda idéntico.
- **No recrees contenedores entre el ataque y la comprobación**: `/home` no es persistente
  y la evidencia en disco se perdería.

---

## 7. Qué alerta se espera

| Escenario | Regla local | Nivel | Se encadena a | Descripción |
|-----------|-------------|-------|---------------|-------------|
| 1 | `100010` | 12 | `5720`, `5763` | Múltiples fallos de autenticación SSH |
| 2 | `100020` | 12 | `550`, `554` | Cambio en `/etc/passwd` o `/etc/group` |
| 3 | `100030` | 12 | `550`, `554` | Modificación de `authorized_keys` |
| 3 | `100031` | 12 | `550`, `554` | Modificación de `sshd_config` |

Las reglas locales no reimplementan detección: reutilizan las reglas base del ruleset de
Wazuh y añaden únicamente la correlación necesaria para identificar el escenario y disparar
la respuesta adecuada.

> La regla base que dispara la fuerza bruta en este entorno es la **5763**, no la 5720 que
> aparece en buena parte de la documentación. Ambas se declaran en `<if_sid>` por
> compatibilidad entre versiones del ruleset. Conviene verificar estos identificadores antes
> de una demostración, ya que Wazuh los reorganiza entre versiones.

Comprobación del recuento de alertas generadas:

```bash
docker compose exec wazuh.manager \
  grep -o '"id":"1000[0-9][0-9]"' /var/ossec/logs/alerts/alerts.json | sort | uniq -c
```

---

## 8. Qué respuesta automática se espera

| Escenario | Script | Acción | Reversión |
|-----------|--------|--------|-----------|
| 1 | `block_ip.sh` | Bloqueo de la IP origen en la cadena `WAZUH_AR` de iptables | Automática a los 300 s (`<timeout>`), verificada (300,349 s medidos). Requiere que el script implemente el *handshake* `check_keys` con `execd` — ver `docs/validation_plan.md` §7.5. Manual: `iptables -D WAZUH_AR -s <IP> -j DROP` dentro de `wazuh.agent` |
| 2 | `disable_suspicious_user.sh` | Bloqueo de la cuenta (`usermod -L` + shell `nologin`) | Manual: `usermod -U <usuario>` |
| 3 | `preserve_and_restore_file.sh` | Preserva copia con hash SHA256 y restaura el baseline limpio | Manual: copia preservada en `./evidence/` |

Salvaguardas comunes a los tres scripts:

- **Whitelists** (`whitelist.conf`) de IPs y usuarios que nunca deben verse afectados,
  incluidas las cuentas del sistema y la infraestructura del propio laboratorio.
- **Registro con marcas de tiempo** de inicio y fin en cada ejecución.
- **Nunca se destruye evidencia**: el fichero alterado se copia antes de cualquier
  modificación, y los nombres incluyen milisegundos más un sufijo anticolisión.
- **Corte de realimentación**: la restauración de un fichero monitorizado es a su vez una
  modificación que el FIM detecta. El script compara con el baseline y, si coinciden,
  registra `SIN_CAMBIOS` y no actúa, evitando un bucle de auto-disparo.

Tiempos de ejecución medidos en el laboratorio:

| Escenario | Script | Tiempo |
|-----------|--------|--------|
| 1 | `block_ip.sh` | 41 ms |
| 2 | `disable_suspicious_user.sh` | 88 ms |
| 3 | `preserve_and_restore_file.sh` | 45 ms |

---

## 9. Cómo consultar evidencias

Todas las evidencias se escriben en el directorio `./evidence/` del host, montado en el
agente como `/var/ossec/evidence`.

```bash
# Registro cronológico de todas las respuestas automáticas
cat evidence/active_response.log

# Ficheros preservados antes de su restauración
ls -la evidence/

# Registro de hashes SHA256 (integridad de la evidencia)
cat evidence/hashes.txt

# Verificación de un fichero preservado
sha256sum evidence/2026*_home_corpuser_.ssh_authorized_keys

# Marcas de tiempo del lado atacante (para calcular el tiempo total de respuesta)
docker compose exec attacker cat /opt/results/timings.log

# Log nativo de Active Response de Wazuh
docker compose exec wazuh.agent tail -20 /var/ossec/logs/active-responses.log
```

Comprobación del efecto real sobre el sistema:

```bash
docker compose exec wazuh.agent iptables -L WAZUH_AR -n     # IP bloqueada
docker compose exec wazuh.agent passwd -S backdoor01        # 'L' = cuenta bloqueada
docker compose exec wazuh.agent cat /home/corpuser/.ssh/authorized_keys  # restaurado
```

### Cálculo de métricas

Cruzando `results/timings.log` (instante del ataque), el campo `timestamp` de
`alerts.json` (instante de la alerta) y `evidence/active_response.log` (inicio y fin del
script) se obtienen el tiempo de detección, el tiempo de ejecución de la respuesta y el
tiempo total de respuesta.

---

## 10. Cómo apagar y limpiar el entorno

```bash
# Parada conservando volúmenes y evidencias
docker compose down

# Limpieza completa (elimina volúmenes: certificados, índices, configuración del agente)
docker compose down -v
```

Tras `down -v` es obligatorio repetir los pasos 1 y 2 del apartado 4, ya que el volumen de
certificados se elimina.

Las evidencias de `./evidence/` y `./results/` residen en el host y **no se borran** con
`docker compose down -v`. Elimínalas manualmente si quieres partir de cero:

```bash
rm -f evidence/2026* evidence/active_response.log evidence/hashes.txt results/timings.log
```

---

## Apéndice — Puntos de fricción conocidos

Recopilación de los problemas encontrados durante el despliegue. Su documentación forma
parte del objetivo de reproducibilidad.

| Síntoma | Causa | Solución |
|---------|-------|----------|
| `The tool to create the certificates does not exist in any bucket` | El generador necesita salida a Internet | No incluir ese contenedor en redes `internal: true` |
| `Invalid IP or DNS wazuh-indexer` | El validador rechaza nombres de una sola etiqueta | Nombrar los servicios con punto: `wazuh.indexer`, `wazuh.manager` |
| `Directory wazuh-certificates already exists` | El generador no es idempotente | `rm -rf config/wazuh_indexer_ssl_certs/*` — **no** basta con `docker compose down -v`, porque ese directorio es un *bind mount* y `down -v` solo elimina volúmenes con nombre |
| `AccessDeniedException: .../certs` | Permisos del volumen de certificados | Contenedor `wazuh-certs-permissions` (`chmod -R a+rX`) |
| `no such service: wazuh-certs-generator` | El README documentaba estos comandos antes de que los servicios existieran en `docker-compose.yml` | Añadidos como servicios `profiles: [bootstrap]` en el propio compose (detalle en `docs/validation_plan.md` §7.4) |
| `OutOfMemoryError: direct buffer memory` | Heap JVM insuficiente | `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g` en el compose |
| `not a directory` al montar un `.yml` | Docker crea un directorio si el fichero de origen no existe | Borrar el directorio fantasma y crear el fichero real |
| Cambios en `ossec.conf` sin efecto | El volumen `agent-etc` cachea la configuración anterior | `docker volume rm <proyecto>_agent-etc` y recrear |
| Alertas SSH ausentes | El agente leía `/var/log/secure`, inexistente en esta imagen | Configurar `/var/log/auth.log` |
| El escenario 2 no crea el usuario | `sudo -n` falla si se solicita contraseña | `NOPASSWD` acotado a `useradd`, `chpasswd`, `userdel`, `usermod` |
| Variables del `.env` ignoradas | Terminadores CRLF o BOM procedentes de Windows | Regenerar el fichero en Linux o aplicar `dos2unix` |

---

## Advertencias de seguridad

Este laboratorio contiene configuraciones **deliberadamente débiles** con fines
demostrativos, que no deben trasladarse a ningún entorno real:

- `PasswordAuthentication yes` en SSH, necesario para simular el escenario 1.
- Registro automático de agentes sin contraseña (`<auth><use_password>no`).
- Certificados autofirmados con permisos de lectura universal.
- Credenciales de laboratorio explícitamente ficticias (`corpuser` / `Lab-Ficticio-2026!`).
- Privilegios `sudo` sin contraseña, acotados a la gestión de cuentas.

Todo el tráfico ofensivo queda confinado a la red Docker del laboratorio. Ninguna acción
automática modifica el sistema anfitrión.
