# TFM — Laboratorio de detección y respuesta automática ante técnicas APT con Wazuh

## Introducción

Prueba de concepto reproducible que demuestra, sobre un servidor Linux corporativo simulado,
el ciclo completo:

```
Ataque simulado → evento en el servidor víctima → alerta en Wazuh
→ respuesta automática → evidencia generada → gestión del incidente → análisis del artefacto
```

El laboratorio cubre tres escenarios mapeados a MITRE ATT&CK:

| # | Escenario | Táctica | Técnica |
|---|-----------|---------|---------|
| 1 | Acceso no autorizado por SSH (fuerza bruta) | Credential Access | T1110 — Brute Force |
| 2 | Creación de cuenta local no autorizada | Persistence | T1136 — Create Account |
| 3 | Inserción de clave SSH no autorizada | Persistence / Privilege Escalation | T1098.004 — SSH Authorized Keys |

Todo el stack se despliega con un único `docker compose up -d`: Wazuh (detección y respuesta),
TheHive (gestión de incidentes) y Cortex (análisis de artefactos), enlazados entre sí sin
ningún paso manual. Detección, respuesta y la integración con TheHive son completamente
automáticas; decidir qué alerta se convierte en caso y qué evidencia se analiza sigue siendo
criterio del analista — es justo lo que este laboratorio pone a prueba.

Documentación ampliada: [`docs/validation_plan.md`](docs/validation_plan.md) — qué se espera de cada escenario, casos de prueba, métricas y resultados obtenidos.

---

## Requisitos previos

- Docker Engine ≥ 24 y Docker Compose v2.
- **10 GB de RAM disponibles para Docker** (indexer + cortex-elasticsearch reservan 1 GB y
  256 MB de heap JVM respectivamente; TheHive y Cortex, JVMs propias adicionales).
- Acceso al socket de Docker del host (`/var/run/docker.sock`) para el usuario que ejecuta
  `docker compose`: lo necesita `cortex` para lanzar analizadores como contenedores efímeros.
- Salida a Internet **únicamente** la primera vez que se generan los certificados TLS o se
  invoca un analizador de Cortex (descarga su imagen la primera vez).
- `vm.max_map_count` ≥ 262144 en el host que ejecuta el motor de Docker:

```bash
sudo sysctl -w vm.max_map_count=262144
```

---

## 1. Levantar el laboratorio

El repositorio incluye un fichero `.env` con las variables del laboratorio (versiones de
imagen y credenciales explícitamente ficticias); `docker compose` lo carga automáticamente.

```bash
docker compose up -d
docker compose ps
```

Un único comando basta tanto en el primer arranque como en los siguientes: incluye Wazuh,
TheHive y Cortex ya enlazados entre sí, sin pasos manuales. Los siete servicios principales
(`wazuh.manager`, `wazuh.indexer`, `victim`, `attacker`, `cortex`, `cortex-elasticsearch`,
`thehive`) deben aparecer como `Up`; los de bootstrap de un solo uso
(`wazuh-certs-generator`, `wazuh-certs-permissions`, `thehive-volume-permissions`,
`thehive-wazuh-bootstrap`, `cortex-jobs-permissions`, `cortex-org-bootstrap`) aparecerán como
`Exited (0)` — es el comportamiento esperado. El indexer tarda entre 40 y 90 segundos en
quedar operativo; TheHive y Cortex, algo más.

Verificación rápida de que todo está listo:

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l   # agente "Active"
```

El ciclo de detección de Wazuh no tiene interfaz web (sin `wazuh.dashboard`): las alertas se
consultan directamente sobre `alerts.json` o la API REST del indexer. La gestión de
incidentes sí la tiene — TheHive en `http://localhost:9000`, Cortex en `http://localhost:9001`.
El checklist completo de comprobaciones (P1-P9) está en
[`docs/validation_plan.md`](docs/validation_plan.md#2-comprobaciones-previas).

### TheHive + Cortex: qué queda enlazado automáticamente

Nada que configurar a mano en un arranque normal, pero conviene saber qué hace cada pieza:

- **Wazuh → TheHive** (reglas 100010-100031 reenviadas como alerta): integración nativa de
  Wazuh (`<integration>` en `wazuh_manager.conf` + `custom-w2thive.py`) más un bootstrap
  (`thehive-wazuh-bootstrap`) que crea en TheHive la organización `tfm-apt-lab` y el usuario
  `wazuh@thehive.local`, y genera su clave API — verificado en vivo para los tres escenarios
  (`docs/validation_plan.md` §7.12).
- **Cortex ↔ TheHive** (para poder analizar artefactos desde un caso): otro bootstrap
  (`cortex-org-bootstrap`) inicializa Cortex, crea la organización `TFM` y un usuario analista,
  habilita el analizador `FileInfo` y escribe su clave API en `thehive/application.conf` antes
  de que arranque TheHive (`docs/validation_plan.md` §7.15).

TheHive: usuario `admin@thehive.local`, contraseña `secret` (credenciales por defecto del
propio proyecto TheHive, no elegidas por este laboratorio). Las alertas del laboratorio las
crea `wazuh@thehive.local` dentro de `tfm-apt-lab`; si no las ves con `admin`, añádelo también
a esa organización desde **Administration → Organisations**.

Verifica el enlace con Cortex en el menú de usuario de TheHive → **About**: debe aparecer como
`OK`, y `FileInfo` como analizador disponible al añadir un observable de tipo `file` a un caso.

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

## 2. Lanzar los ataques

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

## 3. Seguir el flujo completo

Con el laboratorio arriba y un ataque ya lanzado (paso anterior), esto es lo que hace un
analista con lo que llega a TheHive — la parte del flujo que, a propósito, no está
automatizada (ver [Introducción](#introducción)):

1. **Comprobar que la alerta llegó a TheHive.** Entra en `http://localhost:9000` con
   `admin@thehive.local` / `secret` (o añade ese usuario a `tfm-apt-lab` si no ve las alertas,
   ver arriba) y abre **Alerts**. Debe haber una alerta nueva con el título
   `TFM-LAB [10003x] ...`, la regla de Wazuh, el agente, la técnica MITRE y el log completo en
   la descripción — nada de esto requiere ningún paso manual, lo hace la integración
   Wazuh→TheHive en cuanto se dispara la alerta.
2. **Promocionar la alerta a caso.** Desde la alerta, **Import** (o el botón equivalente para
   convertirla en caso). Es la decisión del analista de que esa alerta merece investigarse a
   fondo.
3. **Añadir la evidencia como observable.** El escenario 3 (inserción de clave SSH) preserva
   una copia del `authorized_keys` original antes de restaurarlo, en `./evidence/` (fichero
   `<timestamp>_home_corpuser_.ssh_authorized_keys`; el hash exacto queda también en
   `evidence/active_response.log`). Dentro del caso, en la pestaña **Observables**, añade uno
   nuevo de tipo **file** y sube ese fichero.
4. **Lanzar el análisis.** Sobre el observable recién creado, ejecuta el analizador
   **FileInfo** (Cortex ya está enlazado — ver arriba). Cortex lo ejecuta como un contenedor
   Docker efímero; la primera vez tarda más porque descarga su imagen.
5. **Leer el informe.** El resultado incluye hashes (MD5/SHA1/SHA256), tipo de fichero y
   *MIME type* — para el `authorized_keys` del escenario 3, hashes idénticos a los registrados
   en `evidence/active_response.log` y `Filetype: TXT`, confirmando que la evidencia preservada
   es exactamente la que se analizó.

Con esto queda demostrado el ciclo completo que persigue el laboratorio:

```
Ataque → alerta Wazuh → respuesta automática → evidencia preservada
  → alerta en TheHive → caso → observable → análisis en Cortex → informe
```

Los escenarios 1 y 2 no generan un fichero de evidencia analizable con `FileInfo` de la misma
forma (bloqueo de IP y cuenta deshabilitada, no un artefacto de fichero), así que el paso 3-5
de este flujo se demuestra con el escenario 3.

---

## Apagar y limpiar el entorno

```bash
# Parada conservando volúmenes y evidencias
docker compose down

# Limpieza completa (elimina volúmenes con nombre: índices, configuración del agente, etc.)
docker compose down -v
```

`docker compose up -d` basta para volver a levantar el laboratorio después de cualquiera de
los dos comandos anteriores; no hace falta ningún paso adicional, incluido el enlace
Cortex↔TheHive (los bootstraps de TheHive y Cortex se rehacen solos en cada arranque). Los
certificados TLS son un *bind mount*, no un volumen con nombre, así que `down -v` no los toca.

Para partir de cero también en evidencias:

```bash
rm -f evidence/2026* evidence/active_response.log evidence/hashes.txt results/timings.log
```

---

## Advertencia de seguridad

Este laboratorio contiene configuraciones **deliberadamente débiles** con fines
demostrativos (SSH con autenticación por contraseña, registro de agentes sin contraseña,
credenciales ficticias en texto plano) que no deben trasladarse a ningún entorno real.
Todo el tráfico ofensivo queda confinado a la red Docker del laboratorio; ninguna acción
automática modifica el sistema anfitrión.
