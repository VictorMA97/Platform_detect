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
- 6 GB de RAM disponibles para Docker (el indexer reserva 1 GB de heap JVM).
- Salida a Internet **únicamente** la primera vez que se generan los certificados TLS.
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

Un único comando basta tanto en el primer arranque como en los siguientes. Los cuatro
servicios principales (`wazuh.manager`, `wazuh.indexer`, `victim`, `attacker`) deben aparecer
como `Up`; `wazuh-certs-generator` y `wazuh-certs-permissions` (bootstrap de certificados TLS,
idempotente) aparecerán como `Exited (0)` — es el comportamiento esperado. El indexer tarda
entre 40 y 90 segundos en quedar operativo.

Verificación rápida de que todo está listo:

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l   # agente "Active"
```

El laboratorio no incluye interfaz web (sin `wazuh.dashboard`): las alertas se consultan
directamente sobre `alerts.json` o la API REST del indexer. El checklist completo de
comprobaciones (P1-P9) está en
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
