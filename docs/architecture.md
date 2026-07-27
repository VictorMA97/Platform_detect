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
  │  │  attacker    │─────────────▶│  wazuh.agent     │                  │
  │  │              │              │                  │                  │
  │  │ • bruteforce │              │ • sshd + rsyslog │                  │
  │  │ • create_user│              │ • usuario corpuser│                 │
  │  │ • add_ssh_key│              │ • agente Wazuh   │                  │
  │  └──────────────┘              │ • FIM (syscheck) │                  │
  │                                │ • scripts de AR  │                  │
  │                                └────────┬─────────┘                  │
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
  │                                │  wazuh.indexer   │                  │
  │                                └────────┬─────────┘                  │
  │                                         │                            │
  │                                         ▼                            │
  │                                ┌──────────────────┐                  │
  │                                │ wazuh.dashboard  │───▶ host :443    │
  │                                └──────────────────┘                  │
  └──────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
                              ./evidence/  (bind mount)
```

### Componentes y responsabilidades

| Componente | Rol en la arquitectura |
|------------|------------------------|
| `attacker` | Origen controlado de actividad ofensiva. Contiene únicamente cliente SSH y `sshpass`; no incorpora herramientas ofensivas de propósito general, ya que los tres escenarios se reproducen con scripts propios y deterministas. |
| `wazuh.agent` | Servidor víctima. Concentra tres funciones que en un entorno real coexisten en la misma máquina: servicio expuesto (`sshd`), telemetría (agente Wazuh con FIM) y capacidad de respuesta (scripts de Active Response). |
| `wazuh.manager` | Núcleo de detección. Recibe los eventos, los normaliza mediante decoders, los evalúa contra el ruleset y decide qué respuesta ordenar. |
| `wazuh.indexer` | Persistencia e indexado de alertas (OpenSearch). No participa en la detección ni en la respuesta. |
| `wazuh.dashboard` | Capa de consulta. Permite explorar las alertas y sirve de soporte visual para la demostración. |
| `wazuh-certs-generator` | Contenedor de bootstrap de un solo uso. Genera la autoridad de certificación y los certificados TLS de los tres nodos Wazuh, y finaliza. |

---

## 2. Flujo: ataque → evento → alerta → respuesta → evidencia

### 2.1 Ataque

El contenedor `attacker` ejecuta uno de los tres scripts de simulación contra
`wazuh.agent`, resuelto por DNS interno de Docker. Cada script registra en
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
alcance: introduce complejidad operativa que no aporta valor demostrativo a un entorno de
cinco contenedores en una sola máquina.

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
`wazuh.agent`, en lugar de ejecutar el contenedor en modo `privileged`. El resto de
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
informar y termina con éxito; si no existe, invoca la herramienta oficial. `wazuh.manager`,
`wazuh.indexer` y `wazuh.dashboard` declaran `depends_on` sobre `wazuh-certs-generator` y
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

Los servicios Wazuh se nombran con punto (`wazuh.manager`, `wazuh.indexer`,
`wazuh.dashboard`) siguiendo la convención del despliegue oficial. No es una elección
estética: el validador de la herramienta de certificados rechaza los nombres de una sola
etiqueta, por lo que un nombre como `wazuh-indexer` impide generar los certificados. Los
nombres deben coincidir exactamente con los declarados en `certs.yml`, ya que se
incorporan al certificado y la verificación TLS posterior los compara.

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

Ninguna acción automática actúa sobre el sistema anfitrión: los bloqueos se aplican dentro
del espacio de nombres de red del contenedor víctima y las modificaciones de cuentas y
ficheros afectan exclusivamente a su sistema de ficheros.

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