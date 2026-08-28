# Arquitectura del laboratorio

Descripción de la arquitectura de la prueba de concepto, del flujo de detección y respuesta,
y de las decisiones técnicas adoptadas con su justificación.

---

## 1. Visión general

El laboratorio reproduce, de forma acotada, un entorno corporativo mínimo compuesto por un
servidor Linux accesible por SSH, una plataforma SIEM/EDR que lo monitoriza y un origen de
actividad ofensiva. Todo el conjunto se despliega mediante contenedores sobre una única red
virtual, sin dependencias del sistema anfitrión más allá del motor de contenedores.

```
                         Red Docker: wazuh-network
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │  ┌──────────────┐   SSH (22)   ┌──────────────────┐                  │
  │  │  attacker    │─────────────▶│  victim          │                  │
  │  │              │              │                  │                  │
  │  │ • bruteforce │              │ • sshd + rsyslog │                  │
  │  │ • create_user│              │ • usuario corpuser│                 │
  │  │ • add_ssh_key│              │ • agente Wazuh   │                  │
  │  └──────────────┘              │ • FIM (syscheck) │                  │
  │                                │ • scripts de AR  │──▶ ./evidence/   │
  │                                └────────┬─────────┘    (bind mount) │
  │                          eventos (1514) │  ▲ comando AR              │
  │                                         ▼  │                         │
  │                                ┌──────────────────┐                  │
  │                                │  wazuh.manager   │                  │
  │                                │                  │                  │
  │                                │ • decoders       │                  │
  │                                │ • ruleset base   │                  │
  │                                │ • local_rules    │                  │
  │                                │ • Active Response│                  │
  │                                └────────┬─────────┘                  │
  │                                         │ alertas (9200)             │
  │                                         ▼                            │
  │                                ┌──────────────────┐                  │
  │                                │  wazuh.indexer   │──▶ host :9200    │
  │                                └──────────────────┘   (API REST)    │
  └──────────────────────────────────────────────────────────────────────┘
```

La consulta de alertas del ciclo de detección se hace directamente sobre `alerts.json` en el
manager o contra la API REST del indexer (puerto 9200, publicado al host): no hay dashboard de
Wazuh (§3.10). Eso es distinto de la gestión de incidentes: las alertas del laboratorio
(reglas 100010-100031) se reenvían además a TheHive, que sí tiene interfaz web, para que un
analista pueda triarlas con contexto:

```
  wazuh.manager ──alertas del laboratorio──▶ thehive ──analiza artefactos──▶ cortex
  (integracion custom-w2thive)          host :9000              (+ su propio  host :9001
                                        (interfaz web)            elasticsearch)
```

Detalle de esta parte en §3.12.

### Componentes y responsabilidades

| Componente | Rol en la arquitectura |
|------------|------------------------|
| `attacker` | Origen controlado de actividad ofensiva. Contiene únicamente cliente SSH y `sshpass`; no incorpora herramientas ofensivas de propósito general, ya que los tres escenarios se reproducen con scripts propios y deterministas. |
| `victim` | Servidor víctima. Concentra tres funciones que en un entorno real coexisten en la misma máquina: servicio expuesto (`sshd`), telemetría (agente Wazuh con FIM) y capacidad de respuesta (scripts de Active Response). |
| `wazuh.manager` | Núcleo de detección. Recibe los eventos, los normaliza mediante decoders, los evalúa contra el ruleset, decide qué respuesta ordenar, y reenvía las alertas del laboratorio a TheHive. |
| `wazuh.indexer` | Persistencia e indexado de alertas (OpenSearch). No participa en la detección ni en la respuesta. Única capa de consulta del ciclo de detección (§3.10). |
| `wazuh-certs-generator` | Bootstrap de un solo uso. Genera la autoridad de certificación y los certificados TLS de los nodos Wazuh, y finaliza. Idempotente (§3.8). |
| `wazuh-certs-permissions` | Bootstrap de un solo uso. Normaliza los permisos del volumen de certificados para que los tres nodos Wazuh, con UID distintos, puedan leerlos (§3.8). |
| `thehive` | Gestión de incidentes. Recibe como alertas propias las alertas del laboratorio y las presenta con contexto (regla, agente, técnica MITRE, log completo) para que un analista las triage. |
| `cortex` | Análisis de artefactos bajo demanda de TheHive (ejecuta analizadores como contenedores Docker efímeros). |
| `cortex-elasticsearch` | Almacenamiento de organizaciones, usuarios, trabajos y resultados de Cortex. Independiente del indexer de Wazuh (productos distintos, sin compatibilidad garantizada entre versiones). |
| `thehive-volume-permissions` | Bootstrap de un solo uso. Normaliza a UID/GID 1000 los volúmenes de TheHive, creados por Docker como `root` (§3.12, `docs/validation_plan.md` §7.12). |
| `thehive-wazuh-bootstrap` | Bootstrap de un solo uso. Crea en TheHive la organización y el usuario de la integración Wazuh→TheHive y genera su clave API automáticamente (§3.12). |
| `cortex-jobs-permissions` | Bootstrap de un solo uso. Da permiso de escritura a Cortex (UID 1001) sobre el directorio de trabajo de los analizadores (`docs/validation_plan.md` §7.14). |
| `cortex-org-bootstrap` | Bootstrap de un solo uso. Inicializa Cortex, crea su organización de trabajo y usuario analista, habilita `FileInfo` y escribe su clave API en `application.conf` de TheHive — automatiza el enlace Cortex↔TheHive (§3.12, `docs/validation_plan.md` §7.15). |

---

## 2. Flujo: ataque → evento → alerta → respuesta → evidencia

### 2.1 Ataque

El contenedor `attacker` ejecuta uno de los tres scripts de simulación contra
`victim`, resuelto por DNS interno de Docker. Cada script registra en
`/opt/results/timings.log` una marca de tiempo de inicio y de fin en formato ISO 8601 con
milisegundos, que constituye el instante de referencia para el cálculo posterior de métricas.

### 2.2 Evento en el servidor víctima

La actividad ofensiva deja rastro en dos canales de telemetría distintos:

- **Registro de autenticación.** El servicio `sshd` escribe en `/var/log/auth.log` a través
  de `rsyslog`, que el agente lee mediante un bloque `<localfile>`. Es el canal del
  escenario 1.
- **Integridad de ficheros (FIM).** El módulo `syscheck` vigila en modo `realtime` los
  ficheros de cuentas (`/etc/passwd`, `/etc/group`, `/etc/shadow`) y los ficheros de
  autenticación SSH (`~/.ssh`, `/etc/ssh/sshd_config`). Es el canal de los escenarios 2 y 3.

### 2.3 Alerta

El agente transmite el evento al manager por el canal cifrado 1514/tcp. El manager lo
decodifica y evalúa. Las reglas base del ruleset de Wazuh generan una primera alerta
genérica, sobre la que se encadena una regla local del laboratorio que identifica el
escenario concreto, le asigna la técnica MITRE ATT&CK correspondiente y sirve de punto de
enganche estable para la respuesta automática.

### 2.4 Respuesta automática

El manager ordena la ejecución del comando asociado. Con `location: local`, el script se
ejecuta **en el agente donde se originó el evento**, no en el manager. Wazuh entrega al
script un objeto JSON por entrada estándar con la alerta completa y un argumento
`add` o `delete`, este último para la reversión automática por expiración de tiempo.

Cada script aplica el mismo patrón: comprobación contra la whitelist, ejecución de la
acción, registro del resultado con marcas de tiempo y depósito de evidencia.

### 2.5 Evidencia

Los tres scripts escriben en `/var/ossec/evidence`, montado como `./evidence/` en el
anfitrión. Esto permite consultar los resultados sin necesidad de entrar en los contenedores
y garantiza que la evidencia sobrevive a la destrucción del entorno (`docker compose down -v`).

---

## 3. Decisiones técnicas

### 3.1 Docker Compose como plataforma de despliegue

La reproducibilidad es el requisito dominante de la prueba de concepto: un tercero debe
poder levantar el entorno completo sin resolver dependencias locales. Docker Compose aporta
tres propiedades relevantes:

- **Descripción declarativa** del entorno completo en un único fichero versionable, que
  incluye imágenes, red, volúmenes y variables.
- **Aislamiento** respecto al sistema anfitrión: la actividad ofensiva y las respuestas
  automáticas quedan confinadas a los contenedores y a su red virtual.
- **Reversibilidad y coste nulo de reconstrucción**: `docker compose down -v` seguido de un
  nuevo despliegue devuelve el laboratorio a un estado inicial conocido, lo que hace que
  cada escenario sea repetible en condiciones idénticas.

Se descartó una plataforma de orquestación como Kubernetes por desproporción respecto al
alcance: introduce complejidad operativa que no aporta valor demostrativo a un entorno de un
puñado de contenedores en una sola máquina.

### 3.2 Wazuh como plataforma SIEM/EDR

Wazuh reúne en un mismo producto las tres capacidades que exige el ciclo a demostrar, lo que
evita integrar varias herramientas y reduce la superficie de fallo:

- **Recolección y correlación** de eventos con un ruleset amplio y mantenido, que ya cubre
  de fábrica los tres comportamientos simulados.
- **Monitorización de integridad de ficheros** integrada, sin agente adicional.
- **Active Response** nativo, con ejecución en el punto de origen del evento y reversión por
  tiempo, que es precisamente el mecanismo objeto de estudio.

Es además software libre, desplegable sin licencia, con imágenes oficiales, lo que resulta
coherente con una prueba de concepto orientada a una organización que quiere validar
capacidades antes de invertir.

### 3.3 Reutilización del ruleset frente a reglas propias

Las reglas locales **no reimplementan la detección**. Se encadenan a las reglas base
mediante `<if_sid>` y se limitan a acotar el evento al escenario concreto, etiquetarlo con la
técnica MITRE correspondiente y ofrecer un identificador estable en el rango local
(100010–100031) al que enganchar la respuesta.

Esta decisión tiene dos motivaciones. La primera es de mantenimiento: duplicar lógica de
detección ya existente obligaría a mantenerla en paralelo al ruleset oficial. La segunda es
de estabilidad: los identificadores del ruleset base pueden reorganizarse entre versiones,
por lo que enganchar la respuesta directamente a ellos resulta frágil.

Durante la validación se comprobó, de hecho, que la regla que dispara en este entorno ante
un ataque de fuerza bruta es la **5763** y no la 5720 que aparece con frecuencia en la
documentación. Ambas se declaran en `<if_sid>` por compatibilidad. Se documenta como paso
previo obligatorio la verificación de estos identificadores sobre el despliegue concreto.

### 3.4 Ejecución de la respuesta en el agente

Se configuró `location: local` en lugar de ejecutar la respuesta desde el manager. La
justificación es de modelo: en una arquitectura EDR real la contención se aplica en el
extremo comprometido, que es quien dispone del contexto y de los medios para actuar
(cortafuegos local, gestión de cuentas, sistema de ficheros). Ejecutar la acción desde el
manager exigiría un canal administrativo adicional hacia la víctima, ampliando la superficie
de ataque sin beneficio para la demostración.

### 3.5 Contención sin privilegios excesivos

El escenario 1 requiere manipular reglas de cortafuegos dentro del contenedor víctima. Se
optó por conceder únicamente las capacidades `NET_ADMIN` y `NET_RAW` al servicio
`victim`, en lugar de ejecutar el contenedor en modo `privileged`. El resto de
servicios no recibe capacidad adicional alguna.

Las reglas se insertan en una cadena dedicada (`WAZUH_AR`) en lugar de en `INPUT`
directamente, lo que aísla las reglas generadas automáticamente, facilita su inspección y
permite eliminarlas en bloque sin afectar a otras reglas del sistema.

### 3.6 Whitelists y reversibilidad

Toda acción automática está condicionada a una lista de exclusión (`whitelist.conf`) que
protege las direcciones de la propia infraestructura del laboratorio y las cuentas del
sistema. Este control es imprescindible: durante la validación se observó que una alerta
podía llevar a bloquear la dirección de un contenedor de la propia plataforma, con impacto
operativo directo.

Todas las respuestas son reversibles:

| Respuesta | Mecanismo de reversión |
|-----------|------------------------|
| Bloqueo de IP | Automática. `<timeout>300</timeout>`; Wazuh invoca el script con `delete` (verificado: 300,349 s). Manual como vía alternativa: `iptables -D WAZUH_AR -s <IP> -j DROP` |
| Deshabilitación de cuenta | Manual y documentada en el propio registro: `usermod -U <usuario>` |
| Restauración de fichero | Manual. La versión alterada se conserva íntegra en `./evidence/` |

Se optó por reversión automática por tiempo únicamente en el bloqueo de IP, por ser la
acción con mayor probabilidad de falso positivo y menor coste de reintento. Las otras dos
requieren decisión humana explícita, ya que revertirlas de forma automática podría
restablecer precisamente el mecanismo de persistencia del atacante.

La reversión automática por temporizador exige que el propio script de Active Response
implemente el protocolo de *stateful active response* de Wazuh: tras el `add`, debe enviar por
stdout un mensaje de control `check_keys` con las claves a vigilar (la IP, en este caso) y leer
la confirmación antes de actuar. Es ese intercambio, no el `<timeout>` en sí, lo que permite a
`execd` programar el `delete` posterior. `block_ip.sh` no lo implementaba en la primera
validación íntegra del laboratorio, lo que dejó bloqueos sin revertir; corregido el script
(`docs/validation_plan.md` §7.5), la reversión automática quedó verificada.

### 3.7 Preservación de evidencia y ruptura de la realimentación

El script del escenario 3 preserva siempre el fichero alterado **antes** de modificarlo,
calcula su resumen SHA-256 y lo registra en un fichero de hashes. Los nombres incorporan
milisegundos y un sufijo anticolisión, tras detectarse que dos ejecuciones dentro del mismo
segundo sobrescribían la evidencia previa.

Se identificó además un efecto de realimentación relevante: la restauración de un fichero
monitorizado constituye, en sí misma, una modificación que el FIM detecta, lo que reactiva
la alerta y vuelve a lanzar la respuesta. El script incorpora una comparación con el
baseline y, si el fichero ya coincide, registra el evento como auto-inducido y no actúa.
Este patrón —una respuesta automática que dispara su propio detonante— es un riesgo general
de cualquier automatización que modifique elementos supervisados.

### 3.8 Bootstrap de certificados idempotente, integrado en `docker compose up -d`

La generación de certificados TLS se resolvió con un único requisito no negociable de la
prueba de concepto: el laboratorio debe levantarse con `docker compose up -d` y nada más,
tanto en el primer arranque como en los siguientes. La herramienta oficial de generación de
certificados **no es idempotente** — aborta si detecta certificados de una ejecución
anterior—, lo que en un primer diseño obligó a tratarla como un paso manual previo
(`docker compose run --rm`). Esa solución generaba exactamente el problema que se quería
evitar: un despliegue que no arrancaba con un único comando.

La solución adoptada envuelve el `entrypoint` de `wazuh-certs-generator` en una comprobación:
si `./config/wazuh_indexer_ssl_certs/root-ca.pem` ya existe, el contenedor se limita a
informar y termina con éxito; si no existe, invoca la herramienta oficial. `wazuh.manager` y
`wazuh.indexer` declaran `depends_on` sobre `wazuh-certs-generator` y
`wazuh-certs-permissions` con la condición `service_completed_successfully`, de modo que
Compose ejecuta la cadena completa (certificados → permisos → nodos Wazuh) dentro de un único
`docker compose up -d`, sin intervención humana y sin fallar en reintentos.

El contenedor generador sigue siendo el **único elemento del laboratorio que requiere salida a
Internet**, ya que descarga la utilidad de generación la primera vez que se ejecuta de verdad;
en arranques posteriores, al detectar certificados existentes, ni siquiera llega a
necesitarla.

Como el volumen de certificados es un *bind mount* (`./config/wazuh_indexer_ssl_certs/`) y no
un volumen Docker con nombre, `docker compose down -v` no lo elimina — es intencional: permite
que `up -d` sea instantáneo tras un `down -v` en lugar de tener que regenerar la CA y todos los
certificados derivados en cada ciclo de prueba.

### 3.9 Nomenclatura de los servicios

Los servicios Wazuh que participan en el intercambio TLS se nombran con punto
(`wazuh.manager`, `wazuh.indexer`) siguiendo la convención del despliegue oficial. No es una
elección estética: el validador de la herramienta de certificados rechaza los nombres de una
sola etiqueta, por lo que un nombre como `wazuh-indexer` impide generar los certificados. Los
nombres deben coincidir exactamente con los declarados en `certs.yml`, ya que se incorporan al
certificado y la verificación TLS posterior los compara. Los servicios ajenos a ese intercambio
(`victim`, `attacker`) no están sujetos a esta restricción y se nombran por su rol.

### 3.10 Retirada de `wazuh.dashboard`

El laboratorio se simplificó eliminando el nodo `wazuh.dashboard`. La justificación es de
alcance: el dashboard es una capa de visualización orientada a un operador humano explorando
alertas de forma interactiva, y no participa en ningún punto del ciclo que la prueba de
concepto necesita demostrar (ataque → evento → alerta → respuesta → evidencia → validación).
Todo ese ciclo es verificable sin interfaz web: las alertas son consultables directamente
sobre `alerts.json` en el manager o contra la API REST del indexer (puerto 9200), como hace de
hecho todo el plan de validación (`docs/validation_plan.md`).

Retirarlo reduce además la superficie de la prueba de concepto: un nodo menos que desplegar,
un certificado TLS menos que generar y mantener, y un usuario interno (`kibanaserver`) menos
en `internal_users.yml`. Para una demostración en vídeo o ante tribunal, sigue siendo posible
añadir de nuevo `wazuh.dashboard` como servicio opcional sin afectar al resto de la
arquitectura, ya que ningún otro componente depende de él.

Esta decisión se tomó después de que el laboratorio ya funcionara con dashboard incluido; el
proceso de retirarlo — y los puntos que quedaron rotos al hacerlo, en particular el servicio
`wazuh.agent` renombrado a `victim` sin actualizar quién más lo daba por sentado — está
documentado como incidencia en `docs/validation_plan.md` §7.7.

### 3.11 Reducción de volúmenes con nombre

El `docker-compose.yml` oficial de Wazuh declara volúmenes con nombre para cada subsistema del
manager, pensado para un despliegue de producción con todas sus capacidades activas. Este
laboratorio no las usa todas: no hay grupos de agentes más allá de `default`, ninguna
integración de terceros configurada, ningún dispositivo monitorizado sin agente, ningún módulo
extendido (osquery, CIS-CAT, nubes...), y con `location: local` es el agente —no el
manager— quien ejecuta las respuestas automáticas (§3.4), por lo que el directorio de Active
Response del propio manager no cumple ninguna función en esta arquitectura.

Mantener volúmenes con nombre para directorios que el laboratorio nunca usa no aporta nada:
solo persisten un contenido vacío o irrelevante a través de `docker compose down`. Se
eliminaron siete de los catorce originales (`wazuh_api_configuration`, `wazuh_var_multigroups`,
`wazuh_integrations`, `wazuh_active_response` del manager, `wazuh_agentless`, `wazuh_wodles`,
`filebeat_etc`), dejando solo los que el laboratorio ejercita de verdad: los datos indexados
(`wazuh-indexer-data`), los logs nativos del manager (`wazuh_logs`), el registro de Filebeat
que evita reenvíos duplicados al indexer (`filebeat_var`), y el estado de registro del agente a
ambos lados —manager y agente deben ir sincronizados, o uno cree que el otro lo reconoce cuando
no es así— (`wazuh_etc`/`agent-etc`, `wazuh_queue`/`agent-queue`).

Verificado con un ciclo completo `down -v` + `up -d` + los tres escenarios + una consulta a la
API del indexer: el laboratorio funciona igual, incluyendo el envío de alertas a través de
Filebeat pese a no persistir su configuración (`filebeat_etc`), que se regenera en cada
arranque desde la plantilla y las variables de entorno. Detalle y hallazgos en
`docs/validation_plan.md` §7.8.

### 3.12 Integración con TheHive + Cortex

El enunciado del TFM pide explícitamente un componente de "notificaciones enriquecidas a un
hipotético analista de SOC" y recomienda TheHive+Cortex para gestión de incidentes y análisis
de artefactos. Se añadió con tres decisiones deliberadas que se apartan, en distinto grado, de
la instalación de referencia de TheHive/Cortex.

**Stack mínimo, no el de producción.** TheHive 5 (la versión actual) exige Cassandra +
Elasticsearch + MinIO + un proxy Nginx con certificados propios — desproporcionado para esta
prueba de concepto y contrario a la reproducibilidad mínima que persigue todo el laboratorio.
Se usa en su lugar **TheHive 4** con almacenamiento embebido (BerkeleyDB + índice Lucene local,
sin Cassandra ni MinIO) y **Cortex 3**, siguiendo la plantilla oficial mínima de
`TheHive-Project/Docker-Templates` (`thehive4-berkleydb-cortex31`). Cortex necesita su propio
Elasticsearch para sus trabajos y resultados; no se comparte con el indexer de Wazuh —son
productos distintos, sin compatibilidad de versión garantizada— así que es un servicio más
(`cortex-elasticsearch`), con heap mínimo (256 MB) igual que el resto de instancias auxiliares
del laboratorio.

**El socket de Docker montado en `cortex`.** Cortex ejecuta cada análisis como un contenedor
Docker efímero (imagen oficial del analizador correspondiente), lo que exige montar
`/var/run/docker.sock` dentro del propio contenedor `cortex` — acceso equivalente a root sobre
el Docker del host. Es el único servicio de todo el laboratorio con ese nivel de privilegio,
en contraste deliberado con el resto (donde se evitó `--privileged` y se acotaron las
capacidades al mínimo, p. ej. `NET_ADMIN`/`NET_RAW` solo en `victim`, §3.5). Es también cómo
funciona Cortex en cualquier despliegue, no una elección de este laboratorio; el analizador
concreto habilitado (`FileInfo`) es estático, sin claves API externas, y no ejecuta nada contra
la red del laboratorio.

**Ambas integraciones automatizadas, con superficies de API muy distintas.** TheHive expone una
API REST v1 estable y documentada (`TheHive-Project/api-docs`) para crear organizaciones,
usuarios y claves API. El bootstrap (`thehive-cortex/bootstrap/create_wazuh_api_key.sh`) la usa
para crear una organización y un usuario dedicados a la integración Wazuh→TheHive y generar su
clave, sin intervención humana. El bloque `<integration>` de `wazuh_manager.conf` reenvía como
alerta de TheHive las alertas de las reglas del laboratorio (100010-100031), usando solo la
biblioteca estándar de Python (`config/wazuh_cluster/integrations/custom-w2thive.py`) porque la
imagen oficial de `wazuh.manager` no permite instalar dependencias sin un Dockerfile propio.
Verificado en vivo para los tres escenarios — detalle en `docs/validation_plan.md` §7.12.

El enlace Cortex↔TheHive (organización + usuario + clave API *dentro de Cortex*, pegada después
en `application.conf` de TheHive) es harina de otro costal: Cortex **no** publica ninguna API
pública ni documentada para esto — la propia plantilla oficial mínima lo resuelve a golpe de
clic en la interfaz web, y existe una petición de automatizarlo abierta en el repositorio
oficial de TheHive desde 2018, nunca implementada, con el repositorio ya archivado. Pero
"sin documentar" no es lo mismo que "sin API": Cortex es software libre, y su código fuente (no
su documentación) confirma que los endpoints necesarios existen — `POST /api/organization`,
`POST /api/user`, `POST /api/organization/analyzer/:id`, `POST /api/user/:id/key/renew`, todos
en `org.thp.cortex.controllers.*` — y hasta un mecanismo de *bootstrap* pensado exactamente para
este caso: mientras la instancia no tenga ningún usuario, admite crear el primer superadmin sin
autenticar (`UserSrv.getInitialUser`, condicionado a que el índice de usuarios esté vacío).
`thehive-cortex/bootstrap/create_cortex_org.sh` encadena esos endpoints — inicializar la base de
datos, crear el superadmin inicial, una organización de trabajo, un usuario analista con permiso
para habilitar analizadores, habilitar `FileInfo` y generar su clave — y escribe esa clave
directamente en `application.conf` de TheHive antes de que arranque. Detalle de cómo se
localizaron los endpoints (leyendo el código fuente de Cortex 3.2.1, no por prueba y error) y
verificación en vivo en `docs/validation_plan.md` §7.15.

**Permisos de UID, otra vez.** El despliegue reveló tres fallos reales de UID/permisos
(volúmenes de TheHive creados como `root` pero consumidos por UID 1000; un directorio
bind-mount sin permiso de escritura para el UID del contenedor de bootstrap; un `chmod` sobre
un fichero ajeno que abortaba el script después de haber tenido éxito) — la misma familia de
problema que ya apareció con los certificados de Wazuh al principio del proyecto. Investigación,
corrección y verificación completas en `docs/validation_plan.md` §7.12.

---

## 4. Consideraciones de seguridad del entorno

El laboratorio incorpora configuraciones deliberadamente débiles, necesarias para reproducir
los escenarios, que se enumeran explícitamente para dejar constancia de que son conscientes
y acotadas:

| Configuración | Motivo | Riesgo asumido |
|---------------|--------|----------------|
| `PasswordAuthentication yes` | Sin ella no es posible simular fuerza bruta | Confinado a la red del laboratorio |
| Registro de agentes sin contraseña | Evita un paso manual en el arranque | Solo alcanzable desde la red interna |
| Certificados con lectura universal | Los procesos de los contenedores usan UID distintos | Certificados autofirmados sin valor fuera del entorno |
| `sudo` sin contraseña | El ataque automatizado necesita `sudo -n` | Acotado a cuatro binarios de gestión de cuentas |
| Credenciales en texto plano | Reproducibilidad de la prueba | Ficticias y sin correspondencia con sistema real alguno |
| `/var/run/docker.sock` montado en `cortex` | Cortex ejecuta analizadores como contenedores Docker efímeros (§3.12) | Acceso equivalente a root sobre el Docker del host; único servicio del laboratorio con este privilegio, analizador habilitado sin claves API externas |

Ninguna acción automática actúa sobre el sistema anfitrión: los bloqueos se aplican dentro
del espacio de nombres de red del contenedor víctima y las modificaciones de cuentas y
ficheros afectan exclusivamente a su sistema de ficheros. La única excepción deliberada es el
socket de Docker de `cortex`, justificada arriba.

---

## 5. Limitaciones de la arquitectura

- **Un único agente monitorizado.** No se evalúa correlación entre varios equipos ni
  movimiento lateral.
- **Ausencia de sistemas Windows.** El entorno es exclusivamente Linux, por lo que quedan
  fuera técnicas asociadas a Active Directory o a la telemetría de Sysmon.
- **Escenarios deterministas.** Los ataques son scripts controlados, no una campaña real,
  lo que impide evaluar la tasa de falsos negativos frente a técnicas de evasión.
- **Volumen de eventos reducido.** No se mide el rendimiento de la detección bajo carga ni
  la tasa de falsos positivos sobre tráfico legítimo sostenido.
- **Persistencia parcial.** El directorio `/home` del agente no es persistente, lo que
  favorece la repetibilidad de las pruebas pero impide analizar la evolución del sistema a
  lo largo de reinicios.
- **Contenedores frente a máquinas completas.** Algunos mecanismos de auditoría del núcleo,
  como `whodata` basado en `auditd`, no están plenamente disponibles en contenedores; el FIM
  opera en modo `realtime` mediante notificaciones del sistema de ficheros.
- **Repetibilidad del escenario 2 dentro de la misma vida del contenedor.** El FIM en tiempo
  real de `/etc/passwd`/`/etc/group` solo detecta el primer cambio desde que arranca el
  agente: herramientas como `useradd`/`userdel` reescriben esos ficheros por *rename* atómico,
  lo que invalida el *watch* de `inotify` y deja el resto de cambios sin detectar hasta
  reiniciar el agente (`docker compose restart victim`). No afecta a la demostración del ciclo
  una vez, pero sí a repetirlo sin reiniciar. Investigación y verificación en
  `docs/validation_plan.md` §7.11.

---

## 6. Notas operativas

Problemas de entorno —no de diseño— que conviene conocer antes de tocar el compose o los
volúmenes.

| Síntoma | Causa | Solución |
|---------|-------|----------|
| `OutOfMemoryError: direct buffer memory` en `wazuh.indexer` | Heap JVM por defecto insuficiente para OpenSearch | Ya fijado en el compose: `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g` |
| `not a directory` al levantar el laboratorio | Docker crea un directorio si el fichero de origen de un bind mount no existe (p. ej. un `.yml` borrado por error) | Borrar el directorio fantasma y restaurar el fichero real desde git |
| Cambios en `ossec.conf` sin efecto tras editarlo | El volumen con nombre `agent-etc` cachea la configuración de un arranque anterior | `docker volume rm <proyecto>_agent-etc` y recrear el contenedor |

Los problemas de certificados (herramienta no idempotente, servicios de bootstrap ausentes,
permisos) y sus soluciones están documentados como incidencias reales, con causa raíz y
verificación, en `docs/validation_plan.md` §7.4 y §7.6.