# TFM — Laboratorio de detección y respuesta automática ante técnicas APT con Wazuh

Prueba de concepto reproducible que demuestra, sobre un servidor Linux corporativo simulado,
el ciclo completo:

```
Ataque simulado → evento en el servidor víctima → alerta en Wazuh
→ respuesta automática → evidencia generada → validación del resultado
```

El laboratorio cubre tres escenarios mapeados a MITRE ATT&CK:

| # | Escenario | Táctica | Técnica |
|---|-----------|---------|---------|
| 1 | Acceso no autorizado por SSH (fuerza bruta) | Credential Access | T1110 — Brute Force |
| 2 | Creación de cuenta local no autorizada | Persistence | T1136 — Create Account |
| 3 | Inserción de clave SSH no autorizada | Persistence / Privilege Escalation | T1098.004 — SSH Authorized Keys |

Documentación ampliada:

- [`docs/architecture.md`](docs/architecture.md) — arquitectura, flujo detallado y decisiones técnicas.
- [`docs/mitre_mapping.md`](docs/mitre_mapping.md) — mapeo MITRE ATT&CK de cada escenario.
- [`docs/validation_plan.md`](docs/validation_plan.md) — qué se espera de cada escenario, casos de prueba, métricas y resultados obtenidos.

---

## Requisitos previos

- Docker Engine ≥ 24 y Docker Compose v2.
- **10 GB de RAM disponibles para Docker** (indexer + cortex-elasticsearch reservan 1 GB y
  256 MB de heap JVM respectivamente; TheHive y Cortex, JVMs propias adicionales).
- Acceso al socket de Docker del host (`/var/run/docker.sock`) para el usuario que ejecuta
  `docker compose`: lo necesita `cortex` para lanzar analizadores como contenedores efímeros
  (`docs/architecture.md` §3.12).
- Salida a Internet **únicamente** la primera vez que se generan los certificados TLS o se
  invoca un analizador de Cortex (descarga su imagen la primera vez).
- `vm.max_map_count` ≥ 262144 en el host que ejecuta el motor de Docker:

```bash
sudo sysctl -w vm.max_map_count=262144
```

> **Windows / WSL2.** Ejecuta el laboratorio desde el sistema de ficheros nativo de la
> distribución WSL (`~/proyectos/...`), **nunca desde `/mnt/c/...`**: los bind mounts vía
> `drvfs` dan problemas de permisos. Si `.env` se ha editado en Windows, verifica que no tenga
> terminadores CRLF/BOM (`dos2unix .env`), o `docker compose` puede ignorar sus variables.

---

## Levantar el laboratorio

El repositorio incluye un fichero `.env` con las variables del laboratorio (versiones de
imagen y credenciales explícitamente ficticias); `docker compose` lo carga automáticamente.

```bash
docker compose up -d
docker compose ps
```

Un único comando basta tanto en el primer arranque como en los siguientes. Los siete
servicios principales (`wazuh.manager`, `wazuh.indexer`, `victim`, `attacker`, `cortex`,
`cortex-elasticsearch`, `thehive`) deben aparecer como `Up`; los de bootstrap de un solo uso
(`wazuh-certs-generator`, `wazuh-certs-permissions`, `thehive-volume-permissions`,
`thehive-wazuh-bootstrap`) aparecerán como `Exited (0)` — es el comportamiento esperado. El
indexer tarda entre 40 y 90 segundos en quedar operativo; TheHive, algo más.

Verificación rápida de que todo está listo:

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l   # agente "Active"
```

El ciclo de detección de Wazuh no tiene interfaz web (sin `wazuh.dashboard`): las alertas se
consultan directamente sobre `alerts.json` o la API REST del indexer. La gestión de
incidentes sí la tiene — ver [más abajo](#gestión-de-incidentes-thehive--cortex). El checklist
completo de comprobaciones (P1-P9) está en
[`docs/validation_plan.md`](docs/validation_plan.md#2-comprobaciones-previas).

---

## Lanzar los ataques

`scripts/measure_timings.sh` (en el host, no dentro de un contenedor) lanza el escenario y
mide automáticamente tiempo de detección, latencia de despacho y duración de la respuesta,
cruzando `results/timings.log`, `alerts.json` y `evidence/active_response.log`:

```bash
# Escenario 1 — Fuerza bruta SSH (T1110)
scripts/measure_timings.sh 1

# Escenario 2 — Creación de cuenta local (T1136)
scripts/measure_timings.sh 2

# Escenario 3 — Inserción de clave SSH (T1098.004)
scripts/measure_timings.sh 3
```

Cada uno lanza el ataque, espera 10 s a que se propaguen alerta y respuesta, e imprime una
tabla como:

```
=== Escenario 3 - Clave SSH no autorizada (T1098.004) ===
Inicio del ataque:               2026-08-04T12:37:21.544Z
Alerta generada (100030):        2026-08-04T12:37:21.742+0000
Respuesta (inicio -> fin):       2026-08-04T12:37:21.744Z -> 2026-08-04T12:37:21.792Z
---
Tiempo de deteccion:             0,198 s
Despacho manager->agente:        0,003 s
Duracion de la respuesta:        0,048 s
Tiempo total:                    0,248 s
```

Si ya has lanzado un ataque a mano y solo quieres medir el último (por ejemplo, con
`docker compose exec attacker /opt/scripts/ssh_bruteforce_test.sh`), añade `--no-launch`:
`scripts/measure_timings.sh 1 --no-launch`.

Qué alerta y qué respuesta esperar de cada uno está en
[`docs/validation_plan.md`](docs/validation_plan.md#3-qué-se-espera-por-escenario), que también
recoge una tabla de tiempos de referencia obtenida con este mismo script.

Notas de repetibilidad:

- El escenario 1 bloquea la IP de `attacker` durante 300 s (reversión automática) y eso
  impide repetir el escenario 1 y bloquea SSH para los escenarios 2 y 3 mientras dure. Para
  quitar el bloqueo a mano en vez de esperar:
  ```bash
  docker compose exec victim iptables -L WAZUH_AR -n            # ver la IP bloqueada
  docker compose exec victim iptables -D WAZUH_AR -s <IP> -j DROP
  ```
- El escenario 2 solo detecta el **primer** cambio en `/etc/passwd`/`/etc/group` desde que
  arranca el agente: `useradd`/`userdel` reescriben esos ficheros con un patrón de *rename*
  atómico que invalida el *watch* de `inotify` de la monitorización en tiempo real, y ni un
  `agent_control -r` (rescan remoto) lo repara — solo un reinicio del agente. Para repetir el
  escenario 2 de forma fiable, en este orden exacto (el orden importa: `restart` no borra
  `/etc/passwd`, así que si el `userdel` va después del reinicio, es él quien consume el único
  cambio detectable, no el ataque):
  ```bash
  docker compose exec victim userdel -r backdoor01   # 1. limpiar el usuario, ANTES de reiniciar
  docker compose restart victim                       # 2. reiniciar para rearmar el watch
  # esperar ~15 s a que syscheckd termine su arranque antes de atacar de nuevo
  ```
  Detalle, investigación y verificación en `docs/validation_plan.md` §7.11.
- El escenario 3 requiere que el contenido de `authorized_keys` cambie realmente; el FIM no
  genera eventos si el fichero queda idéntico.
- **No recrees contenedores entre el ataque y la comprobación**: `/home` no es persistente
  y la evidencia en disco se perdería.

Las evidencias quedan en `./evidence/` y `./results/` (ambos en el host, no se borran con
`docker compose down -v`).

---

## Gestión de incidentes (TheHive + Cortex)

Cada alerta de los tres escenarios (reglas 100010-100031) se reenvía automáticamente a TheHive
como una alerta de caso, con regla, agente, técnica MITRE y log completo — sin ningún paso
manual: es una integración nativa de Wazuh (`<integration>` en `wazuh_manager.conf` +
`config/wazuh_cluster/integrations/custom-w2thive.py`), verificada en vivo para los tres
escenarios (`docs/validation_plan.md` §7.12).

**TheHive**: `http://localhost:9000` — usuario `admin@thehive.local`, contraseña `secret`
(credenciales por defecto del propio proyecto TheHive, no elegidas por este laboratorio). Las
alertas del laboratorio las crea el usuario `wazuh@thehive.local` dentro de la organización
`tfm-apt-lab` (ambos creados automáticamente por el bootstrap); si no las ves con el usuario
`admin`, añádelo también a esa organización desde **Administration → Organisations**.

**Cortex**: `http://localhost:9001`. El enlace Cortex↔TheHive (para poder analizar artefactos
desde una alerta) **es automático**: el servicio de un solo uso `cortex-org-bootstrap`
(`thehive-cortex/bootstrap/create_cortex_org.sh`) inicializa la base de datos de Cortex, crea
una organización de trabajo (`TFM`) y un usuario analista, habilita el analizador `FileInfo` y
escribe su clave API en `thehive-cortex/thehive/application.conf` antes de que arranque
`thehive` — sin ningún paso manual. Las credenciales que usa (ficticias, de laboratorio) están
en `.env` (`CORTEX_ADMIN_*`, `CORTEX_ANALYST_*`). Detalle de cómo se automatizó (los endpoints
de la API de Cortex no son públicos ni están documentados; se confirmaron leyendo su código
fuente) en `docs/validation_plan.md` §7.15.

Verifica que quedó enlazado en el menú de usuario de TheHive → **About**: Cortex debe aparecer
como `OK`, y `FileInfo` como analizador disponible al añadir un observable de tipo `file` a un
caso.

Si `docker compose logs cortex-org-bootstrap` muestra que algún paso no se pudo completar (por
ejemplo, porque ya existía un superadmin distinto creado a mano antes de que existiera este
script, con otras credenciales), hazlo tú mismo en la UI de Cortex:

1. Entra en `http://localhost:9001` y crea el primer usuario (superadmin) si no existe.
2. **Organizations** → crea una organización de trabajo (el nombre es libre). Solo existe de
   entrada la organización de sistema `cortex`, que es de gestión de la instancia.
3. Dentro de ella, crea un usuario con roles **`read`, `analyze` y `orgadmin`** — los tres son
   necesarios: `read`/`analyze` para ejecutar analizadores, `orgadmin` para poder habilitarlos
   (con solo `read, analyze` esa opción de la interfaz ni aparece). No uses el superadmin para
   esto: pertenece a la organización de sistema y no puede ejecutar analizadores.
4. Cierra sesión del superadmin y entra con ese usuario nuevo. **Organization → Analyzers**,
   busca **FileInfo** en el catálogo y actívalo.
5. En su perfil, genera una clave API (**Create API key** → **reveal**) y pégala en
   `thehive-cortex/thehive/application.conf`, sustituyendo `PENDIENTE_DE_CONFIGURACION_MANUAL`.
6. `docker compose restart thehive`.

---

## Apagar y limpiar el entorno

```bash
# Parada conservando volúmenes y evidencias
docker compose down

# Limpieza completa (elimina volúmenes con nombre: índices, configuración del agente, etc.)
docker compose down -v
```

`docker compose up -d` basta para volver a levantar el laboratorio después de cualquiera de
los dos comandos anteriores; no hace falta ningún paso adicional (los certificados TLS son un
*bind mount*, no un volumen con nombre, así que `down -v` no los toca).

**Excepción: el enlace manual Cortex↔TheHive no sobrevive a un `down -v`.** Los datos de
Cortex (organizaciones, usuarios, clave API) viven en `cortex-elasticsearch-data`, un volumen
con nombre — `down -v` lo borra. La clave que pegaste en
`thehive-cortex/thehive/application.conf` queda entonces apuntando a una organización que ya
no existe; hay que repetir los pasos de la sección
["Gestión de incidentes"](#gestión-de-incidentes-thehive--cortex) tras cualquier `down -v`. La
clave de la integración Wazuh→TheHive **sí** sobrevive sin hacer nada: el bootstrap la
regenera automáticamente en cada `up -d`.

Para partir de cero también en evidencias:

```bash
rm -f evidence/2026* evidence/active_response.log evidence/hashes.txt results/timings.log
```

---

## Advertencia de seguridad

Este laboratorio contiene configuraciones **deliberadamente débiles** con fines
demostrativos (SSH con autenticación por contraseña, registro de agentes sin contraseña,
credenciales ficticias en texto plano) que no deben trasladarse a ningún entorno real.
Detalle completo y justificación en
[`docs/architecture.md`](docs/architecture.md#4-consideraciones-de-seguridad-del-entorno).
Todo el tráfico ofensivo queda confinado a la red Docker del laboratorio; ninguna acción
automática modifica el sistema anfitrión.
