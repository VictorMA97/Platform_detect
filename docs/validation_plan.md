# Plan de validación

Procedimiento de verificación del laboratorio, qué se espera de cada escenario, métricas
definidas, resultados obtenidos e incidencias detectadas durante la validación.

---

## 1. Objetivo y alcance

Comprobar que, para cada uno de los tres escenarios implementados, el laboratorio completa
el ciclo:

```
Ataque simulado → evento → alerta → respuesta automática → evidencia → validación
```

La validación se considera superada cuando, para cada escenario, se verifica que: se genera
la alerta esperada con el identificador previsto, se ejecuta la respuesta automática
asociada, la respuesta produce un efecto comprobable sobre el sistema, se genera evidencia
recuperable desde el anfitrión y la acción es reversible.

---

## 2. Comprobaciones previas

Deben superarse todas antes de iniciar los casos de prueba.

| # | Comprobación | Orden | Resultado esperado |
|---|--------------|-------|--------------------|
| P1 | Servicios activos | `docker compose ps` | Cinco servicios en estado `Up`; `wazuh-certs-generator` y `wazuh-certs-permissions` en `Exited (0)` |
| P2 | Agente registrado | `docker compose exec wazuh.manager /var/ossec/bin/agent_control -l` | Agente en estado `Active` |
| P3 | Procesos del manager | `docker compose exec wazuh.manager /var/ossec/bin/wazuh-control status` | Todos en ejecución |
| P4 | Reglas locales cargadas | `docker compose exec wazuh.manager cat /var/ossec/etc/rules/local_rules.xml` | Reglas 100010–100031 presentes |
| P5 | Scripts de respuesta instalados | `docker compose exec wazuh.agent ls -la /var/ossec/active-response/bin/` | Tres scripts con permisos `750 root:wazuh` |
| P6 | Dependencias del agente | `docker compose exec wazuh.agent sh -c "which jq iptables"` | Ambas utilidades presentes |
| P7 | Configuración de Active Response | `docker compose exec wazuh.manager grep -c "block-ip-lab" /var/ossec/etc/ossec.conf` | Valor mayor que cero |
| P8 | Línea base de cuentas | `docker compose exec wazuh.agent sh -c "cut -d: -f1 /etc/passwd \| sort > /var/ossec/evidence/passwd.baseline"` | Fichero generado |
| P9 | Interfaz web accesible | `https://localhost` (usuario `admin`) | Autenticación correcta |

Para filtrar únicamente las alertas del laboratorio en **Threat Hunting** del dashboard, usa
la consulta `rule.groups:tfm_apt_lab`.

> **Verificación de identificadores del ruleset.** Antes de una demostración conviene
> confirmar que las reglas base declaradas en `<if_sid>` siguen siendo las que dispara la
> versión desplegada, mediante `wazuh-logtest`. Wazuh reorganiza identificadores entre
> versiones.

---

## 3. Qué se espera por escenario

### 3.1 Alertas

| Escenario | Regla local | Nivel | Se encadena a | Descripción |
|-----------|-------------|-------|----------------|-------------|
| 1 | `100010` | 12 | `5720`, `5763` | Múltiples fallos de autenticación SSH |
| 2 | `100020` | 12 | `550`, `554` | Cambio en `/etc/passwd` o `/etc/group` |
| 3 | `100030` | 12 | `550`, `554` | Modificación de `authorized_keys` |
| 3b | `100031` | 12 | `550`, `554` | Modificación de `sshd_config` |

Las reglas locales no reimplementan detección: reutilizan las reglas base del ruleset de
Wazuh y añaden únicamente la correlación necesaria para identificar el escenario y disparar
la respuesta adecuada.

> La regla base que dispara la fuerza bruta en este entorno es la **5763**, no la 5720 que
> aparece en buena parte de la documentación. Ambas se declaran en `<if_sid>` por
> compatibilidad entre versiones del ruleset. Conviene verificar estos identificadores antes
> de una demostración.

Comprobación del recuento de alertas generadas:

```bash
docker compose exec wazuh.manager \
  grep -o '"id":"1000[0-9][0-9]"' /var/ossec/logs/alerts/alerts.json | sort | uniq -c
```

### 3.2 Respuestas automáticas

| Escenario | Script | Acción | Reversión |
|-----------|--------|--------|-----------|
| 1 | `block_ip.sh` | Bloqueo de la IP origen en la cadena `WAZUH_AR` de iptables | Automática a los 300 s (`<timeout>`), verificada (300,349 s medidos, §7.5). Manual: `iptables -D WAZUH_AR -s <IP> -j DROP` dentro de `wazuh.agent` |
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
  registra `SIN_CAMBIOS` y no actúa, evitando un bucle de auto-disparo (§7.1).

Tiempos de ejecución esperados (orden de magnitud, medidos en `evidence/active_response.log`):

| Escenario | Script | Tiempo típico |
|-----------|--------|----------------|
| 1 | `block_ip.sh` | 40-50 ms |
| 2 | `disable_suspicious_user.sh` | 60-90 ms |
| 3 | `preserve_and_restore_file.sh` | 45-50 ms |

El tiempo de ejecución de la respuesta es despreciable frente al tiempo de detección: el
factor determinante del tiempo total no es la automatización, sino la latencia de
correlación del SIEM —especialmente en el escenario 1, donde la regla debe acumular varios
intentos antes de disparar.

### 3.3 Tabla resumen de validación

| Escenario | Técnica MITRE | Acción simulada | Alerta esperada | Respuesta automática | Evidencia | Resultado |
|-----------|---------------|-----------------|-----------------|----------------------|-----------|-----------|
| 1. Acceso no autorizado SSH | T1110.001 | 10 intentos de autenticación fallidos desde `attacker` | Regla `100010`, nivel 12 | `block_ip.sh` — bloqueo temporal de la IP origen | Registro con marcas de tiempo; regla en cadena `WAZUH_AR` | **Superado** |
| 1b. Reversión automática del bloqueo (CP-02) | T1110.001 | Vencimiento del `<timeout>300</timeout>` tras el bloqueo anterior | — (no genera alerta nueva) | `block_ip.sh delete` — retirada de la regla `DROP` | Entrada `REVERTIDO` en `active-responses.log` | **Superado tras corrección** (§7.5) |
| 2. Cuenta local no autorizada | T1136.001 | Creación de la cuenta `backdoor01` vía `useradd` | Regla `100020`, nivel 12 | `disable_suspicious_user.sh` — bloqueo de la cuenta | Registro con marcas de tiempo; estado `L` en `passwd -S` | **Superado** |
| 3. Clave SSH no autorizada | T1098.004 | Adición de clave pública a `authorized_keys` | Regla `100030`, nivel 12 | `preserve_and_restore_file.sh` — preservación y restauración | Fichero preservado + resumen SHA-256 en `hashes.txt` | **Superado** |
| 3b. Modificación de `sshd_config` | T1098.004 | Alteración de la configuración del servicio SSH | Regla `100031`, nivel 12 | `preserve_and_restore_file.sh` | Fichero preservado + resumen SHA-256 | **Pendiente** |

---

## 4. Casos de prueba

### CP-01 — Detección y bloqueo ante fuerza bruta SSH

**Precondición.** La dirección del contenedor `attacker` no figura en `whitelist.conf`.

```bash
docker compose exec attacker /opt/scripts/ssh_bruteforce_test.sh
sleep 15
docker compose exec wazuh.manager grep -o '"id":"100010"' /var/ossec/logs/alerts/alerts.json | wc -l
docker compose exec wazuh.agent tail -3 /var/ossec/logs/active-responses.log
docker compose exec wazuh.agent iptables -L WAZUH_AR -n
```

**Criterios de aceptación.** Se genera al menos una alerta `100010`; el registro contiene una
entrada `block_ip.sh RESULTADO=OK`; la cadena `WAZUH_AR` contiene una regla `DROP` para la
dirección origen.

### CP-02 — Reversión automática del bloqueo

Verifica que la contención es temporal y no requiere intervención humana.

```bash
# Transcurridos 300 s desde CP-01
docker compose exec wazuh.agent grep REVERTIDO /var/ossec/logs/active-responses.log
docker compose exec wazuh.agent iptables -L WAZUH_AR -n
```

**Criterios de aceptación.** Aparece una entrada `RESULTADO=REVERTIDO`; la regla `DROP` ha
desaparecido de la cadena.

### CP-03 — Detección y neutralización de cuenta no autorizada

**Precondición.** La cuenta `backdoor01` no existe (`userdel -r backdoor01` si procede).

```bash
docker compose exec attacker /opt/scripts/create_user_attack.sh
sleep 15
docker compose exec wazuh.agent tail -3 /var/ossec/logs/active-responses.log
docker compose exec wazuh.agent passwd -S backdoor01
```

**Criterios de aceptación.** Se genera la alerta `100020`; el registro contiene
`disable_user.sh RESULTADO=OK`; `passwd -S` devuelve `L` en el segundo campo; la cuenta
**sigue existiendo**, no ha sido eliminada.

### CP-04 — Preservación de evidencia y restauración de fichero

**Precondición.** `authorized_keys` coincide con la copia de referencia.

```bash
docker compose exec attacker /opt/scripts/add_ssh_key_attack.sh
sleep 15
docker compose exec wazuh.agent tail -5 /var/ossec/logs/active-responses.log
ls -la evidence/
cat evidence/hashes.txt
docker compose exec wazuh.agent cat /home/corpuser/.ssh/authorized_keys
```

**Criterios de aceptación.** Registro con `PRESERVADO` y `RESTAURADO`; existe un fichero
preservado que **contiene la clave del atacante**; el resumen SHA-256 registrado coincide con
el del fichero preservado; `authorized_keys` ha vuelto al estado de referencia.

### CP-05 — Eficacia de las listas de exclusión

Comprueba que las salvaguardas impiden actuar sobre elementos protegidos.

```bash
# Añadir temporalmente la IP del atacante a WHITELIST_IPS en whitelist.conf
docker compose exec attacker /opt/scripts/ssh_bruteforce_test.sh
sleep 15
docker compose exec wazuh.agent grep OMITIDO_WHITELIST /var/ossec/logs/active-responses.log
```

**Criterios de aceptación.** Se genera la alerta, pero el registro indica
`RESULTADO=OMITIDO_WHITELIST` y no se aplica bloqueo alguno. Demuestra que detección y
respuesta son decisiones independientes.

### CP-06 — Integridad de la evidencia frente a ejecuciones repetidas

Verifica que una segunda ejecución no sobrescribe la evidencia previa.

```bash
docker compose exec attacker /opt/scripts/add_ssh_key_attack.sh
sleep 10
docker compose exec attacker /opt/scripts/add_ssh_key_attack.sh
sleep 10
ls -la evidence/
```

**Criterios de aceptación.** Existen dos ficheros preservados con nombres distintos; ninguna
evidencia previa ha sido reemplazada.

---

## 5. Métricas

### Definiciones

| Métrica | Definición | Origen del dato |
|---------|------------|-----------------|
| **Tiempo de detección** | Intervalo entre la acción ofensiva y la generación de la alerta | `results/timings.log` → campo `timestamp` de `alerts.json` |
| **Tiempo de ejecución de la respuesta** | Duración del script de Active Response | Campos `inicio` y `fin` de `evidence/active_response.log` |
| **Tiempo total de respuesta** | Intervalo entre la acción ofensiva y la finalización de la respuesta | `results/timings.log` → campo `fin` del registro de respuesta |
| **Ejecución correcta** | La respuesta produce el efecto previsto sobre el sistema | Verificación directa (`iptables -L`, `passwd -S`, contenido del fichero) |
| **Falsos positivos** | Respuestas ejecutadas sobre elementos legítimos | Revisión del registro frente a la lista de exclusión |
| **Impacto operativo** | Efecto de la respuesta sobre la disponibilidad del servicio | Análisis cualitativo por escenario |
| **Reversibilidad** | Posibilidad de deshacer la acción y coste de hacerlo | Automática, manual documentada o no reversible |

### Cómo consultar evidencias

Todas las evidencias se escriben en `./evidence/` (host) y `./results/` (host), montados
respectivamente en el agente como `/var/ossec/evidence` y en el atacante como
`/opt/results`.

```bash
# Registro cronológico de todas las respuestas automáticas
cat evidence/active_response.log

# Ficheros preservados antes de su restauración
ls -la evidence/

# Registro de hashes SHA256 (integridad de la evidencia)
cat evidence/hashes.txt

# Verificación de un fichero preservado
sha256sum evidence/2026*_home_corpuser_.ssh_authorized_keys

# Marcas de tiempo del lado atacante
cat results/timings.log

# Log nativo de Active Response de Wazuh (no persistente entre redespliegues)
docker compose exec wazuh.agent tail -20 /var/ossec/logs/active-responses.log
```

Comprobación del efecto real sobre el sistema:

```bash
docker compose exec wazuh.agent iptables -L WAZUH_AR -n     # IP bloqueada
docker compose exec wazuh.agent passwd -S backdoor01        # 'L' = cuenta bloqueada
docker compose exec wazuh.agent cat /home/corpuser/.ssh/authorized_keys  # restaurado
```

### Método de cálculo

Todos los registros emplean el formato ISO 8601 en UTC con precisión de milisegundos, lo que
permite el cruce directo entre tres orígenes: el instante del ataque (`results/timings.log`),
el instante de la alerta (campo `timestamp` de `alerts.json`) y los instantes de inicio/fin de
la respuesta (`evidence/active_response.log`). De ese cruce se obtienen el tiempo de
detección, el tiempo de ejecución de la respuesta y el tiempo total de respuesta.

```bash
# Instante del ataque
cat results/timings.log

# Instante de la alerta
docker compose exec wazuh.manager grep '"id":"100010"' /var/ossec/logs/alerts/alerts.json \
  | grep -o '"timestamp":"[^"]*"' | tail -1

# Instantes de inicio y fin de la respuesta
cat evidence/active_response.log
```

---

## 6. Ejecuciones de referencia

### 6.1 Primera ejecución (2026-07-23)

Ejecución de referencia realizada sobre Wazuh 4.14.6, antes de las correcciones descritas en
la sección 7.

**Tiempos de ejecución de las respuestas**

| Escenario | Script | Inicio | Fin | Duración |
|-----------|--------|--------|-----|----------|
| 1 | `block_ip.sh` | 19:37:49.639 | 19:37:49.680 | **41 ms** |
| 2 | `disable_suspicious_user.sh` | 19:57:54.327 | 19:57:54.415 | **88 ms** |
| 2 (segunda invocación) | `disable_suspicious_user.sh` | 19:57:54.417 | 19:57:54.483 | **66 ms** |
| 3 | `preserve_and_restore_file.sh` | 19:56:33.623 | 19:56:33.668 | **45 ms** |

**Verificación del efecto sobre el sistema**

| Escenario | Comprobación | Resultado |
|-----------|--------------|-----------|
| 1 | Regla en cadena `WAZUH_AR` | Bloqueo aplicado sobre la dirección origen |
| 2 | `passwd -S backdoor01` | `backdoor01 L 2026-07-23 0 99999 7 -1` — cuenta bloqueada, no eliminada |
| 3 | Fichero preservado y resumen | SHA-256 `f33a6f9c61c2fc5d47a1c5b0ef0e49409c00e5f8a861dd59831438d996b2c009` |
| 3 | Contenido de `authorized_keys` | Restaurado al estado de referencia |

**Valoración por métrica**

| Métrica | Escenario 1 | Escenario 2 | Escenario 3 |
|---------|-------------|-------------|-------------|
| Ejecución correcta | Sí | Sí | Sí |
| Falsos positivos | Uno detectado (§7.3) | No observados | No observados |
| Impacto operativo | Medio — pérdida de conectividad del origen durante 300 s | Alto — la cuenta queda inutilizable hasta intervención | Bajo — solo se altera el fichero comprometido |
| Reversibilidad | Automática (300 s) — no verificada aún en esta ejecución | Manual: `usermod -U` | Manual: copia preservada |

### 6.2 Segunda ejecución — reproducibilidad íntegra (2026-07-27)

Verificación de C7: `docker compose down -v`, seguido de un despliegue completo desde cero y
la ejecución de los tres escenarios principales, sin ninguna intervención manual dentro de
contenedores más allá de los comandos ya documentados en el README.

```bash
docker compose down -v
rm -rf config/wazuh_indexer_ssl_certs/*        # bind mount; down -v no lo limpia (§7.4)
docker compose run --rm wazuh-certs-generator
docker compose run --rm wazuh-certs-permissions
docker compose up -d
```

**Resultado.** Los cinco servicios alcanzaron el estado `Up` sin reintentos. El agente quedó
`Active` en el manager en menos de un minuto. Las comprobaciones P1-P9 se superaron todas.
Los tres escenarios (CP-01, CP-03, CP-04) generaron su alerta y ejecutaron su respuesta
correctamente sobre el despliegue limpio:

| Caso | Alerta | Respuesta | Efecto verificado |
|------|--------|-----------|--------------------|
| CP-01 | `100010` (17:58:46.418) | `block_ip.sh` OK (17:58:46.961 → 17:58:47.009, 48 ms) | IP `172.19.0.2` bloqueada en `WAZUH_AR`; la propia fuerza bruta quedó cortada a mitad de ejecución (intentos 9-10 con `Connection timed out`) |
| CP-03 | `100020` ×2 | `disable_suspicious_user.sh` OK (dos invocaciones, 127 ms y 79 ms) | `passwd -S backdoor01` → `L` |
| CP-04 | `100030` ×2 | `preserve_and_restore_file.sh`: `PRESERVADO` → `RESTAURADO` → `SIN_CAMBIOS` | Fichero preservado con hash registrado; `authorized_keys` restaurado al baseline |

Antes de esta ejecución, la prueba de reproducibilidad íntegra era la pendiente más
relevante del laboratorio. Quedó superada, con dos incidencias de artefacto corregidas
durante la propia prueba (§7.4) y una incidencia funcional real detectada y corregida
(§7.5): CP-02 (reversión automática de CP-01) falló en esta primera pasada porque
`block_ip.sh` no implementaba el *handshake* `check_keys` que `execd` exige para programar el
`delete`. Corregido el script y repetido CP-01 sobre el mismo despliegue, la reversión se
disparó a los 300,349 s, dentro del margen del `<timeout>300</timeout>` configurado.

Una revisión posterior (§7.6, mismo día) corrigió además cuatro desviaciones estructurales
entre el repositorio y los requisitos originales de la prueba de concepto (arranque en un
solo comando, persistencia de `results/`, fichero `.env`, limpieza de dependencias sin usar
en el atacante). El redeploy final, repetido tras esas correcciones (`down -v` + `up -d
--build` + CP-01/CP-03/CP-04), reprodujo los mismos resultados: alerta, respuesta y evidencia
correctas en los tres escenarios, y `results/timings.log` persistiendo en el host.

---

## 7. Incidencias detectadas durante la validación

### 7.1 Realimentación de la respuesta sobre su propio detonante

**Observación.** La restauración del fichero por parte del script constituye, en sí misma,
una modificación que el módulo de integridad detecta, lo que reactiva la alerta y vuelve a
invocar la respuesta.

**Consecuencia observada.** Dos ejecuciones consecutivas separadas por 53 ms. La segunda
preservó como evidencia el propio fichero de referencia —resumen
`e3b0c44298fc1c14…`, correspondiente a un fichero vacío— sobrescribiendo la evidencia real
por coincidir el nombre, generado con precisión de segundos.

**Corrección aplicada.** Comparación previa con la copia de referencia: si el fichero ya
coincide, el evento se clasifica como auto-inducido y no se actúa. Adicionalmente, los
nombres de evidencia incorporan milisegundos y un sufijo anticolisión.

**Verificación posterior.** Secuencia `PRESERVADO` → `RESTAURADO` → `SIN_CAMBIOS`, con la
evidencia real conservada. Reproducida de forma consistente en más de una decena de
ejecuciones posteriores, sin ningún caso de `RESTAURADO` sin su `SIN_CAMBIOS` correspondiente.

**Generalización.** Toda automatización que modifique un elemento supervisado puede activar
su propio detonante. Es un riesgo estructural, no una particularidad de este laboratorio.

### 7.2 Ejecución múltiple ante una única acción ofensiva

**Observación.** La creación de una cuenta modifica `/etc/passwd` y `/etc/group`, generando
dos eventos y, en consecuencia, dos invocaciones de la respuesta.

**Valoración.** No produce daño, ya que `usermod -L` es idempotente. Se documenta como
requisito de diseño: **las acciones automáticas deben ser idempotentes**. Respuestas no
idempotentes —notificaciones, apertura de incidencias, acciones acumulativas— requerirían
un mecanismo de deduplicación.

### 7.3 Falso positivo sobre infraestructura del laboratorio

**Observación.** Una ejecución bloqueó la dirección `172.19.0.2`, perteneciente a un
contenedor de la propia plataforma y no al atacante, debido a que las direcciones asignadas
por Docker varían al recrear contenedores.

**Consecuencia.** Interrupción de la comunicación entre componentes hasta la expiración del
bloqueo.

**Corrección.** Incorporación de las direcciones de la infraestructura a `WHITELIST_IPS`.

**Valoración.** Ilustra el riesgo principal de la respuesta automática de contención de red:
un identificador de red no es un identificador estable de atacante. En un entorno real, la
lista de exclusión debe mantenerse actualizada con rangos de administración, servidores
internos y accesos remotos legítimos.

### 7.4 Pasos de despliegue documentados que no existían como artefacto ejecutable

**Observación.** El README instruía ejecutar `docker compose run --rm wazuh-certs-generator`
y `docker compose run --rm wazuh-certs-permissions` como paso 1 del despliegue. Al intentar
una reproducción íntegra desde cero, ninguno de los dos servicios estaba definido en
`docker-compose.yml`: el generador existía como fichero suelto (`generate-indexer-certs.yml`)
con el servicio nombrado `generator`, no `wazuh-certs-generator`, y el servicio de permisos no
existía en ningún fichero. El primer comando documentado fallaba con `no such service`.

**Causa.** El fichero de certificados se desarrolló y probó por separado (`docker compose -f
generate-indexer-certs.yml run --rm generator`) y el ajuste de permisos se aplicó a mano en
su momento; ninguno de los dos pasos se trasladó al `docker-compose.yml` que el README daba
por válido, ni quedó registrado como comando reproducible.

**Corrección aplicada (primera fase).** Se incorporaron ambos servicios a
`docker-compose.yml` con los nombres exactos que ya usaba el README, bajo `profiles:
[bootstrap]` para que no se levantaran con `docker compose up -d`. Se eliminó
`generate-indexer-certs.yml` por quedar duplicado. El servicio de permisos usa una imagen
`alpine` mínima y un único `chmod -R a+rX`. (Esta solución quedó posteriormente sustituida
por una más completa: ver §7.6, punto 1.)

**Segundo hallazgo relacionado.** El propio README describía la limpieza previa a una nueva
generación de certificados como `docker compose down -v`. Es incorrecto: el volumen de
certificados es un *bind mount* (`./config/wazuh_indexer_ssl_certs/`), no un volumen Docker
con nombre, por lo que `down -v` no lo elimina. Repetir el generador sin borrar antes ese
directorio falla, porque la herramienta oficial no es idempotente.

**Generalización.** Un paso de despliegue probado manualmente una vez y después descrito solo
en prosa dejó de ser reproducible en cuanto se intentó repetir sin la persona que lo ejecutó
la primera vez. Es el mismo riesgo, a nivel de infraestructura, que motivó la exigencia C7.

### 7.5 La reversión automática por temporizador del bloqueo de IP no se disparaba

**Observación.** El bloqueo de CP-01 se aplicó a las 17:58:47.009Z con
`<timeout>300</timeout>` configurado en el `active-response` de `block-ip-lab`. Transcurridos
17 minutos y 49 segundos sin que `active-responses.log` registrara una invocación con
`delete` ni una entrada `REVERTIDO`, y con la regla `DROP` seguía presente en `WAZUH_AR`, se
desbloqueó manualmente (`iptables -D`) para no bloquear el resto de la validación.

**Investigación descartada.** Se comprobaron, sin encontrar anomalías: reloj sincronizado
entre manager y agente; proceso `wazuh-execd` activo de forma continua en ambos nodos, sin
reinicios ni caídas posteriores a la aplicación del bloqueo; ausencia de procesos
`block_ip.sh` colgados o zombis en el agente; configuración de `<active-response>` y
`<command>` (`timeout_allowed>yes`, `<timeout>300</timeout>`) sintácticamente correcta.

**Causa raíz.** El código fuente oficial de Wazuh
(`src/active-response/src/active_responses.c`, función `send_keys_and_check_message`, y
`src/active-response/src/block-ip-unix.c`) muestra que una respuesta con temporizador debe
implementar un *handshake* con `execd` antes de actuar: al recibir `add`, el script debe
escribir por stdout un mensaje de control

```json
{"version":1,"origin":{"name":"block_ip.sh","module":"active-response"},"command":"check_keys","parameters":{"keys":["<IP>"]}}
```

y leer de stdin la respuesta (`continue` o `abort`) antes de continuar. Es este intercambio
—no el bloqueo en sí— el que le indica a `execd` qué claves debe registrar en su lista interna
de timeouts para poder invocar después el `delete`. `block_ip.sh` nunca implementaba este
paso: leía el `add`, bloqueaba la IP y terminaba, de modo que `execd` no tenía ninguna entrada
que expirar. Por eso no aparecía ni siquiera un intento fallido de reversión: `execd`
simplemente no sabía que debía reintentarlo.

**Corrección aplicada.** Se añadió el *handshake* al bloque `add` de `block_ip.sh`: construye
el mensaje `check_keys` con `jq`, lo escribe por stdout y espera una línea de respuesta con
`read -r -t 5`. Si `execd` responde `abort`, el script registra `ABORTADO_EXECD` y no bloquea.
Si no llega ninguna respuesta en 5 s (fail-open, para no bloquear el script si esta ruta de
invocación no soportara el protocolo), se registra `SIN_RESPUESTA_EXECD` y se continúa igual
que antes de la corrección — así el fix no puede empeorar el comportamiento previo, solo
mejorarlo.

**Verificación.** Repetido CP-01 con el script corregido: bloqueo a las 18:35:02.002Z,
reversión automática registrada a las 18:40:02.351Z — **300,349 s** después, dentro del margen
esperado para un `<timeout>300</timeout>`. La regla `DROP` desapareció de `WAZUH_AR` sin
intervención manual.

**Impacto en los criterios de aceptación.** C5 ("toda respuesta es reversible") queda
cumplido sin matices: la reversión automática del escenario 1 está verificada, no solo
prevista. La reversión manual (`iptables -D WAZUH_AR -s <IP> -j DROP`) se mantiene documentada
como vía alternativa.

**Generalización.** Un script de Active Response con `<timeout>` que no implementa el
protocolo de *stateful active response* de Wazuh puede ejecutar correctamente su acción
inicial y, aun así, no ser reversible de forma automática — el fallo es silencioso porque no
hay ningún error que registrar: simplemente nadie programó el recordatorio. Cualquier AR con
temporizador que se añada al laboratorio en el futuro (o se adapte de este) debe replicar este
handshake, no solo el manejo de `add`/`delete`.

### 7.6 Desviaciones estructurales respecto a los requisitos originales

Tras cerrar C7 (§6.2), una revisión posterior identificó cuatro desviaciones entre el
repositorio y los requisitos originales de la prueba de concepto que la ejecución de §6.2 no
cubría por seguir siendo, en ese momento, técnicamente correctas aunque incómodas.

1. **`docker compose up -d` no bastaba por sí solo.** Corregido en §7.4 solo a medias: los
   servicios `wazuh-certs-generator`/`wazuh-certs-permissions` ya existían, pero seguían bajo
   `profiles: [bootstrap]` y exigían dos `docker compose run --rm` previos. Se sustituyó el
   perfil por `depends_on: condition: service_completed_successfully` desde
   `wazuh.manager`/`wazuh.indexer`/`wazuh.dashboard`, y se hizo idempotente el `entrypoint` del
   generador (comprueba `root-ca.pem` antes de invocar la herramienta oficial). Verificado:
   `docker compose down` + `docker compose up -d` sin ningún paso intermedio, con el generador
   detectando los certificados existentes y omitiendo la regeneración (`docker compose logs
   wazuh-certs-generator` → `"Certificados ya existentes... no se regeneran."`).

2. **`results/` no era persistente.** El servicio `attacker` no montaba ningún volumen para
   `/opt/results`; los tiempos de ataque (`timings.log`) vivían solo dentro del contenedor y se
   perdían al recrearlo, pese a que el README y la estructura de repositorio esperada los daban
   por accesibles desde el host. Se añadió `./results:/opt/results` al servicio `attacker` y
   `results/.gitkeep` con la misma convención de `.gitignore` que `evidence/`. Verificado:
   `results/timings.log` aparece en el host tras ejecutar `ssh_bruteforce_test.sh`.

3. **No existía `.env`.** Las credenciales y versiones de imagen estaban escritas directamente
   en `docker-compose.yml`. Se creó `.env` con todas ellas (`WAZUH_STACK_VERSION`,
   `WAZUH_AGENT_PACKAGE_VERSION`, credenciales de indexer/dashboard/API, usuario de laboratorio)
   y se sustituyeron los valores literales por `${VAR:?...}` en el compose, de modo que un
   `.env` ausente o incompleto falla explícitamente en vez de arrancar con un valor equivocado.
   **Aviso documentado en el propio `.env`**: los usuarios `admin` y `kibanaserver` del indexer
   tienen un hash bcrypt fijo en `config/wazuh_indexer/internal_users.yml`; cambiar
   `INDEXER_PASSWORD` o `DASHBOARD_PASSWORD` sin regenerar ese hash rompe la autenticación. Las
   demás variables (API, laboratorio, versiones) son libres.

4. **El Dockerfile del atacante instalaba `hydra` y diccionarios sin usar.**
   `ssh_bruteforce_test.sh` siempre implementó la fuerza bruta con un bucle propio de
   `sshpass`, no con `hydra`; el binario y los ficheros `users.txt`/`passwords.txt` eran peso
   muerto que además contradecía la afirmación de `docs/architecture.md` de que el atacante
   "no incorpora herramientas ofensivas de propósito general". Eliminados del Dockerfile.

**Generalización.** Ninguna de las cuatro era un defecto funcional del laboratorio en el
sentido de C1-C7 — el entorno detectaba, respondía y generaba evidencia igualmente. Eran
desviaciones entre lo que el repositorio hace y lo que dice que hace (o lo que la propia
estructura del proyecto promete). En una prueba de concepto cuyo argumento central es la
reproducibilidad, esa clase de desviación es tan relevante como un fallo funcional: cada una
habría obligado al tribunal, o a la empresa evaluando el POC, a improvisar un paso no
documentado.

---

## 8. Pruebas pendientes

| Prueba | Motivo |
|--------|--------|
| Escenario 3b (`sshd_config`, regla `100031`) | No ejecutado; requiere un script de simulación específico |
| CP-05 (listas de exclusión) | Verificado de forma incidental (§7.3), no como caso formal |
| CP-06 (integridad ante repetición) | Verificado tras la corrección de §7.1, no como caso formal |
| Medición formal del tiempo de detección | Los tiempos de ejecución están medidos; el cruce con las marcas de tiempo de las alertas está pendiente de una ejecución completa |

---

## 9. Criterios de aceptación global

| # | Criterio | Estado |
|---|----------|--------|
| C1 | Los tres escenarios generan la alerta prevista | Cumplido |
| C2 | Los tres escenarios ejecutan la respuesta asociada | Cumplido |
| C3 | Cada respuesta produce un efecto verificable sobre el sistema | Cumplido |
| C4 | Toda respuesta genera evidencia accesible desde el anfitrión | Cumplido |
| C5 | Toda respuesta es reversible | Cumplido. La reversión automática de escenario 1 falló en la primera prueba, se diagnosticó (§7.5) y quedó verificada tras corregir `block_ip.sh` |
| C6 | Ninguna acción automática afecta al sistema anfitrión | Cumplido |
| C7 | El entorno se despliega sin intervención manual sobre contenedores | Cumplido — verificado el 2026-07-27 (§6.2) y de nuevo tras las correcciones de §7.6 |
