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
| P1 | Servicios activos | `docker compose ps` | Cuatro servicios en estado `Up` (`wazuh.manager`, `wazuh.indexer`, `victim`, `attacker`); `wazuh-certs-generator` y `wazuh-certs-permissions` en `Exited (0)` |
| P2 | Agente registrado | `docker compose exec wazuh.manager /var/ossec/bin/agent_control -l` | Agente en estado `Active` |
| P3 | Procesos del manager | `docker compose exec wazuh.manager /var/ossec/bin/wazuh-control status` | Todos en ejecución |
| P4 | Reglas locales cargadas | `docker compose exec wazuh.manager cat /var/ossec/etc/rules/local_rules.xml` | Reglas 100010–100031 presentes |
| P5 | Scripts de respuesta instalados | `docker compose exec victim ls -la /var/ossec/active-response/bin/` | Tres scripts con permisos `750 root:wazuh` |
| P6 | Dependencias del agente | `docker compose exec victim sh -c "which jq iptables"` | Ambas utilidades presentes |
| P7 | Configuración de Active Response | `docker compose exec wazuh.manager grep -c "block-ip-lab" /var/ossec/etc/ossec.conf` | Valor mayor que cero |
| P8 | Línea base de cuentas | `docker compose exec victim sh -c "cut -d: -f1 /etc/passwd \| sort > /var/ossec/evidence/passwd.baseline"` | Fichero generado |
| P9 | API REST del indexer accesible | `curl -sk -u admin:<INDEXER_PASSWORD> https://localhost:9200` | Respuesta JSON con `"cluster_name"` |

Sin interfaz web, filtrar las alertas del laboratorio se
hace por el campo `rule.groups` directamente sobre `alerts.json`:

```bash
docker compose exec wazuh.manager \
  grep '"groups":\["local","tfm_apt_lab"' /var/ossec/logs/alerts/alerts.json
```

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
| 1 | `block_ip.sh` | Bloqueo de la IP origen en la cadena `WAZUH_AR` de iptables | Automática a los 300 s (`<timeout>`), verificada (300,349 s medidos, §7.5). Manual: `iptables -D WAZUH_AR -s <IP> -j DROP` dentro de `victim` |
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
docker compose exec victim tail -3 /var/ossec/logs/active-responses.log
docker compose exec victim iptables -L WAZUH_AR -n
```

**Criterios de aceptación.** Se genera al menos una alerta `100010`; el registro contiene una
entrada `block_ip.sh RESULTADO=OK`; la cadena `WAZUH_AR` contiene una regla `DROP` para la
dirección origen.

### CP-02 — Reversión automática del bloqueo

Verifica que la contención es temporal y no requiere intervención humana.

```bash
# Transcurridos 300 s desde CP-01
docker compose exec victim grep REVERTIDO /var/ossec/logs/active-responses.log
docker compose exec victim iptables -L WAZUH_AR -n
```

**Criterios de aceptación.** Aparece una entrada `RESULTADO=REVERTIDO`; la regla `DROP` ha
desaparecido de la cadena.

### CP-03 — Detección y neutralización de cuenta no autorizada

**Precondición.** La cuenta `backdoor01` no existe (`userdel -r backdoor01` si procede).

```bash
docker compose exec attacker /opt/scripts/create_user_attack.sh
sleep 15
docker compose exec victim tail -3 /var/ossec/logs/active-responses.log
docker compose exec victim passwd -S backdoor01
```

**Criterios de aceptación.** Se genera la alerta `100020`; el registro contiene
`disable_user.sh RESULTADO=OK`; `passwd -S` devuelve `L` en el segundo campo; la cuenta
**sigue existiendo**, no ha sido eliminada.

### CP-04 — Preservación de evidencia y restauración de fichero

**Precondición.** `authorized_keys` coincide con la copia de referencia.

```bash
docker compose exec attacker /opt/scripts/add_ssh_key_attack.sh
sleep 15
docker compose exec victim tail -5 /var/ossec/logs/active-responses.log
ls -la evidence/
cat evidence/hashes.txt
docker compose exec victim cat /home/corpuser/.ssh/authorized_keys
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
docker compose exec victim grep OMITIDO_WHITELIST /var/ossec/logs/active-responses.log
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
docker compose exec victim tail -20 /var/ossec/logs/active-responses.log
```

Comprobación del efecto real sobre el sistema:

```bash
docker compose exec victim iptables -L WAZUH_AR -n     # IP bloqueada
docker compose exec victim passwd -S backdoor01        # 'L' = cuenta bloqueada
docker compose exec victim cat /home/corpuser/.ssh/authorized_keys  # restaurado
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
   muerto. Eliminados del Dockerfile.

**Generalización.** Ninguna de las cuatro era un defecto funcional del laboratorio en el
sentido de C1-C7 — el entorno detectaba, respondía y generaba evidencia igualmente. Eran
desviaciones entre lo que el repositorio hace y lo que dice que hace (o lo que la propia
estructura del proyecto promete). En una prueba de concepto cuyo argumento central es la
reproducibilidad, esa clase de desviación es tan relevante como un fallo funcional: cada una
habría obligado al tribunal, o a la empresa evaluando el POC, a improvisar un paso no
documentado.

### 7.7 Retirada de `wazuh.dashboard` sin actualizar quién más lo daba por sentado

**Observación.** Se retiró el servicio `wazuh.dashboard` de `docker-compose.yml` y, en el mismo cambio, 
se renombró el servicio `wazuh.agent` a `victim`. El segundo cambio, aparentemente cosmético, rompió los tres
scripts de ataque: `attacker/scripts/common.sh` fijaba `TARGET_HOST="${TARGET_HOST:-wazuh.agent}"`,
y ese nombre dejó de resolver por DNS interno de Docker en cuanto el servicio pasó a llamarse
`victim` (`getent hosts wazuh.agent` → sin resultado; `getent hosts victim` → resuelve).
Confirmado que el fallo era real y no solo teórico: antes de la corrección, los tres escenarios
habrían fallado en el primer paso, con un error de conexión SSH.

**Otros artefactos huérfanos encontrados al auditar la retirada:**

- Certificados TLS generados para el nodo `dashboard` (`wazuh.dashboard.pem`,
  `wazuh.dashboard-key.pem`) que ya no los consume nadie — eliminados.
- El nodo `dashboard` seguía declarado en `config/certs.yml`, por lo que una regeneración de
  certificados los habría vuelto a crear — eliminado del fichero.
- El usuario interno `kibanaserver` en `config/wazuh_indexer/internal_users.yml`, exclusivo
  del dashboard — eliminado.
- Las variables `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD` en `.env`, sin ningún consumidor en
  `docker-compose.yml` tras la retirada del servicio — eliminadas.
- La comprobación P9 ("Interfaz web accesible") y el consejo de usar **Threat Hunting** para
  filtrar alertas (§2) daban por hecho que existía un dashboard — sustituidos por una
  comprobación directa contra la API REST del indexer y un `grep` sobre `alerts.json`.

**Corrección aplicada.** `attacker/scripts/common.sh` actualizado a `TARGET_HOST:-victim`,
imagen del atacante reconstruida, y los artefactos huérfanos listados arriba eliminados.

**Verificación.** Tras la corrección: `getent hosts victim` resuelve desde `attacker`;
`ssh_bruteforce_test.sh` ejecutado de nuevo genera la alerta `100010`
(`"groups":["local","tfm_apt_lab","tfm_scenario_1","authentication_failures"]`), `block_ip.sh`
bloquea la IP y la revierte automáticamente a los ~301 s; la API REST del indexer responde en
`https://localhost:9200` con las credenciales de `.env`.

**Generalización.** Un rename de servicio en `docker-compose.yml` no es un cambio aislado: todo
lo que resuelve ese nombre por DNS interno (scripts propios, pero también cualquier
configuración que lo dé por sentado) deja de funcionar en silencio, sin ningún mensaje de error
hasta el intento de conexión. Es la misma clase de riesgo que motivó §7.4 y §7.6: cambiar la
infraestructura sin auditar exhaustivamente quién depende de sus nombres.

### 7.8 Reducción de volúmenes con nombre (14 → 7)

**Motivación.** Revisión de qué volúmenes con nombre del manager tienen una función real en
este laboratorio, frente a los heredados del `docker-compose.yml` oficial de Wazuh pensados
para capacidades que aquí no se usan (grupos de agentes múltiples, integraciones de terceros,
dispositivos sin agente, módulos extendidos, Active Response ejecutado en el manager en vez de
en el agente).

**Cambio aplicado.** Eliminados de `docker-compose.yml`: `wazuh_api_configuration`,
`wazuh_var_multigroups`, `wazuh_integrations`, `wazuh_active_response` (del manager),
`wazuh_agentless`, `wazuh_wodles`, `filebeat_etc`. Se mantienen `wazuh-indexer-data`,
`wazuh_logs`, `wazuh_queue`/`agent-queue`, `wazuh_etc`/`agent-etc` y `filebeat_var`.

**Verificación.** Ciclo completo `docker compose down -v` + `up -d` con el compose reducido,
seguido de los tres escenarios y una consulta directa a la API del indexer:

| Comprobación | Resultado |
|---|---|
| Arranque del manager sin `wazuh_active_response`/`wazuh_agentless`/`wazuh_wodles`/`wazuh_api_configuration`/`wazuh_var_multigroups`/`wazuh_integrations` | `wazuh-control status`: mismos procesos en ejecución que antes del cambio |
| CP-01 (fuerza bruta) | Alerta `100010`, `block_ip.sh RESULTADO=OK` |
| CP-03 (cuenta local) | Alerta `100020` ×2, `passwd -S backdoor01` → `L` |
| CP-04 (clave SSH) | Alerta `100030` ×2, secuencia `PRESERVADO`→`RESTAURADO`→`SIN_CAMBIOS` |
| Filebeat sin `filebeat_etc` como volumen | Proceso arrancado con configuración regenerada; `GET /wazuh-alerts-*/_count` en el indexer → `432` documentos, sin errores de envío |

**Hallazgo colateral: volúmenes huérfanos.** Tras eliminar los siete volúmenes de
`docker-compose.yml` y ejecutar `docker compose down -v`, `docker volume ls` seguía mostrando
los siete: `down -v` solo elimina los volúmenes **declarados en el fichero en ese momento**, no
los que declaraba una versión anterior. Quedaron huérfanos en disco, invisibles para cualquier
`down -v` futuro, hasta que se eliminaron a mano con `docker volume rm`. Es la misma naturaleza
de problema que el `bind mount` de certificados que `down -v` tampoco limpia (§7.4): cambiar
qué persiste una configuración no limpia retroactivamente lo que ya había persistido con la
configuración anterior.

**Impacto en la reproducibilidad.** Ninguno sobre el ciclo ataque→alerta→respuesta→evidencia:
todas las comprobaciones dieron el mismo resultado que con los catorce volúmenes. El único
efecto es que `docker compose down` (sin `-v`) ya no conserva estado en los siete directorios
retirados — irrelevante, porque ninguno de los tres escenarios ni las comprobaciones P1-P9 lo
necesitaban.

### 7.9 Limpieza de artefactos huérfanos de la reorganización a `victim`

**Observación.** Una revisión de la estructura del repositorio encontró restos del rename
`wazuh.agent` → `victim` (§7.7) que no eran errores funcionales pero sí desviaciones entre lo
que el repositorio contiene y lo que realmente se usa:

- `docker-compose.yml` montaba `./victim/ossec.conf:/wazuh-config-mount/etc/ossec.conf:ro` en
  el servicio `victim`. Ese bind mount no lo lee nadie: `entrypoint-wrapper.sh` usa
  directamente `/var/ossec/etc/ossec.conf` (horneado en la imagen desde
  `victim/wazuh_agent/ossec.conf` vía `COPY`), no `/wazuh-config-mount`. Ese mecanismo solo es
  real en la imagen **oficial** del manager (`wazuh.manager` sí lo consume); se copió por
  analogía al Dockerfile propio de `victim` sin implementar el lado que lo hace funcionar.
- El origen de ese bind mount, `victim/ossec.conf`, era además un **directorio fantasma**
  vacío — ni siquiera estaba trackeado en git (`git ls-files` no lo lista) — recreado por
  Docker en cada arranque por apuntar a un fichero inexistente.
- `attacker/scripts/create_user_attack.sh` tenía tres mensajes de error que mencionaban
  `agent-target`, el nombre del directorio antes del rename a `victim`.
- Los ocho scripts `.sh` del repositorio estaban trackeados en git con modo `100644` (sin bit
  de ejecución) en vez de `100755`. No rompía nada porque tanto el Dockerfile del atacante
  como `entrypoint-wrapper.sh` fuerzan `chmod` en build/arranque — pero cualquiera que clonara
  el repo para ejecutar un script directamente, sin pasar por Docker, se habría encontrado con
  un permiso denegado sin motivo aparente.

**Corrección aplicada.** Eliminados el bind mount muerto y el directorio fantasma; corregidos
los tres mensajes de error a `victim`; los ocho scripts recommiteados con `git update-index
--chmod=+x`.

**Verificación.** Ciclo completo `docker compose down -v` + `up -d --build`: `victim/` no
contiene ningún `ossec.conf` tras el arranque (no se recreó el fantasma), `wazuh-control
status` muestra los mismos procesos activos que antes de la limpieza, y los tres escenarios
(CP-01, CP-03, CP-04) generan su alerta, ejecutan su respuesta y dejan evidencia igual que en
todas las ejecuciones anteriores.

**Generalización.** Ningún hallazgo de esta entrada afectaba al ciclo
ataque→alerta→respuesta→evidencia — a diferencia de §7.7, aquí no había nada roto en
funcionamiento. Se documenta de todos modos porque en una prueba de concepto cuyo argumento es
la reproducibilidad y la claridad para un tribunal externo, un bind mount que no hace nada y un
directorio con el mismo nombre que el fichero que sí se usa son ruido que cuesta tiempo de
lectura ajeno, aunque no cuesten funcionalidad.

### 7.10 Medición formal del tiempo de detección

**Motivación.** Cerrar la pendiente de §8: hasta ahora se medía la duración de cada script de
respuesta (tabla de §6.1), pero nunca se había cruzado sistemáticamente con el instante del
ataque y el de la alerta para obtener el tiempo de detección y el tiempo total, tal como exige
la definición de métricas de §5.

**Herramienta.** `scripts/measure_timings.sh <1|2|3> [--no-launch]` automatiza el cruce que
antes se hacía a mano con `grep`: lanza el escenario (o mide el último ya lanzado, con
`--no-launch`), y calcula tiempo de detección, latencia de despacho manager→agente, duración
de la respuesta y tiempo total, leyendo `results/timings.log`, consultando `alerts.json` en
`wazuh.manager` vía `docker compose exec`, y leyendo `evidence/active_response.log`.

Como los tres logs son acumulativos entre ejecuciones —y el escenario 3 genera además una
segunda alerta auto-inducida al restaurar el fichero (§7.1)— no basta con tomar la última línea
de cada fichero: el script filtra por lo que ocurre en o después del inicio del ataque medido,
y de ahí toma lo más temprano.

**Hallazgo durante la construcción de la herramienta.** Una primera medición manual (antes de
escribir el script) tomó por error el timestamp de alerta más temprano por orden cronológico
para el escenario 1, y calculó una latencia de despacho de ~1,4 s entre alerta y respuesta. Al
automatizar la extracción se descubrió la causa: `alerts.json` no está estrictamente ordenado
por timestamp a nivel de milisegundo — dos alertas de la regla `100010` para el mismo ataque
aparecen en el fichero en orden inverso a su marca de tiempo. Tomando la alerta correcta (la
que coincide en orden de fichero, no la más temprana por valor), la latencia de despacho baja a
3-5 ms, coherente con una llamada local entre contenedores. El dato de 1,4 s no era real; era
un artefacto de medir a mano sin tener en cuenta este comportamiento de Wazuh.

**Resultados (2026-08-04, `docker compose up -d` limpio):**

| Escenario | Tiempo de detección | Despacho manager→agente | Duración de la respuesta | Tiempo total |
|---|---|---|---|---|
| 1 — Fuerza bruta SSH | 29,79 s | 5 ms | 74 ms | 29,87 s |
| 2 — Cuenta local | 262 ms | 3 ms | 221 ms (2 invocaciones) | 486 ms |
| 3 — Clave SSH | 198 ms | 2 ms | 48 ms | 248 ms |

**Lectura.** En el escenario 1, el 99,7 % del tiempo total es correlación del SIEM acumulando
intentos fallidos hasta cruzar el umbral de la regla de frecuencia — la respuesta en sí (74 ms)
es irrelevante frente a eso. En los escenarios 2 y 3, con detección por FIM en vez de por
correlación de frecuencia, el tiempo de detección baja a cientos de milisegundos y la respuesta
pesa proporcionalmente más. La latencia de despacho manager→agente es, en los tres casos,
despreciable (≤5 ms).

**Generalización.** El caso de los ~1,4 s medidos a mano es un recordatorio de que cruzar logs
manualmente con `grep`/`tail` es propenso a error precisamente en los casos con varias líneas
candidatas — que son, además, los más interesantes de medir. Vale la pena automatizarlo con una
herramienta que aplique el mismo criterio de filtrado siempre, en vez de fiarse del ojo.

### 7.11 El FIM en tiempo real de `/etc/passwd`/`/etc/group` solo detecta el primer cambio por arranque

**Observación.** Al verificar `scripts/measure_timings.sh` con lanzamientos reales y repetidos
del escenario 2, la primera ejecución generó su alerta `100020` con normalidad, pero un
`userdel -r backdoor01` + `create_user_attack.sh` posteriores, sobre el mismo contenedor
`victim` sin reiniciar, **no generaron ninguna alerta nueva** — ni con 15 s de margen, ni tras
un `sed -i` directo sobre `/etc/passwd`, ni tras un `docker compose exec wazuh.manager
agent_control -r -u 001` (rescan remoto de syscheck).

**Investigación.** Prueba controlada, aislando la variable "cuántos cambios lleva el agente
desde que arrancó":

| Prueba | Momento | Resultado |
|---|---|---|
| A | Primer cambio en `/etc/passwd`/`/etc/group` tras `docker compose restart victim` (con margen para que `syscheckd` termine su arranque) | **Detectado** (alertas 2→4) |
| B | Segundo cambio, mismo contenedor, sin reiniciar | **No detectado** (4→4) |
| — | `agent_control -r -u 001` (rescan remoto) + tercer cambio | **No detectado** (4→4) |
| C | `docker compose restart victim` de nuevo + cuarto cambio, con margen | **Detectado** (4→6) |

Repetido tres veces el ciclo "reinicio → primer cambio detectado → segundo cambio no
detectado", con el mismo resultado las tres veces.

**Causa probable.** `/etc/passwd` y `/etc/group` están declarados con `realtime="yes"` en
`ossec.conf` (no `whodata`: el motor whodata no arranca en este contenedor por no haber `auditd`, y `syscheckd` 
lo degrada automáticamente a`realtime` — confirmado en el log: `WARNING: (6923): Who-data engine cannot start because
Auditd is not running`). El modo `realtime` depende de un *watch* de `inotify` sobre el inodo
del fichero. `useradd`/`userdel` (como la mayoría de herramientas de `shadow-utils`) no
modifican el fichero en su sitio: escriben una copia temporal y hacen `rename()` sobre el
original — lo habitual para garantizar una escritura atómica. Ese `rename()` sustituye el
inodo que el *watch* vigilaba; si `syscheckd` no vuelve a armar el *watch* sobre el inodo
nuevo, cualquier cambio posterior a esa ruta deja de ser visible para el motor de tiempo real,
sin que se registre ningún error ni aviso — el proceso `wazuh-syscheckd` sigue "corriendo" con
total normalidad. Es coherente con que el resto de rutas monitorizadas con éxito repetido en
todas las validaciones anteriores (`~/.ssh/authorized_keys`, vía `echo >> fichero`, que
modifica el inodo existente en lugar de sustituirlo) no sufran este problema.

**Mitigación verificada.** `docker compose restart victim` reinicia `syscheckd` desde cero
(nuevo escaneo inicial + nuevo *watch*), lo que restablece la detección para el siguiente
cambio. No existe una vía más ligera verificada: ni una señal (`SIGUSR1` al proceso) ni el
rescan remoto de la API interna (`agent_control -r`) lo reparan sin reiniciar el agente
completo.

**El orden importa.** `docker compose restart` no borra `/etc/passwd` — no es un volumen, es
parte del sistema de ficheros del propio contenedor, que sobrevive al reinicio. Se comprobó
que ejecutar `userdel -r backdoor01` **después** de reiniciar consume él mismo el único cambio
detectable tras el arranque, dejando el `useradd` del ataque siguiente sin detectar otra vez
(reproducido dos veces). El orden correcto, verificado con `scripts/measure_timings.sh 2`
lanzando el ataque de verdad: `userdel` primero (con el agente aún corriendo), **después**
`docker compose restart victim`, esperar ~15 s, y entonces atacar. Así el primer cambio que ve
el `syscheckd` recién arrancado es el del ataque, no el de la limpieza previa.

**No se ha aplicado ningún cambio de configuración** (por ejemplo, forzar `whodata` con
`auditd` instalado, o pasar estas rutas a `scheduled` con una frecuencia corta) porque ambas
opciones alteran el mecanismo de detección para el escenario 2, y esta incidencia no impide demostrar el ciclo
completo una vez — solo su repetición dentro de la misma vida del contenedor. Queda como
mejora futura si se prioriza la repetibilidad del escenario 2 sobre la fidelidad del mecanismo
de detección documentado.

**Impacto práctico.** Para el vídeo de la defensa: si el escenario 2 se ensaya más de una vez
sobre el mismo contenedor `victim`, el segundo intento fallará en silencio — sin alerta, sin
respuesta, sin ningún mensaje de error que lo delate. `docker compose restart victim` antes de
cada repetición evita el problema. Añadido a las notas de repetibilidad del README.

**Generalización.** Es la misma familia de riesgo que §7.5 (un mecanismo que deja de funcionar
sin generar ningún error) y que la advertencia general de §7.1: en FIM basado en `inotify`
dentro de contenedores, las herramientas que escriben por *rename* atómico son más propensas
a este fallo silencioso que las que escriben por *append*. Vale la pena tenerlo en cuenta para
cualquier ruta que se añada al `syscheck` en el futuro (por ejemplo, si se implementa el
escenario 3b sobre `sshd_config`, que herramientas como `sed -i` también reescriben por
*rename*).

### 7.12 Integración con TheHive + Cortex (gestión de incidentes y análisis de artefactos)

**Motivación.** El enunciado del TFM pide explícitamente un componente de "notificaciones
enriquecidas a un hipotético analista de SOC" y recomienda TheHive+Cortex para gestión de
incidentes y análisis de artefactos — ausentes hasta ahora del laboratorio (ver análisis de
cumplimiento previo). Se añadió un stack mínimo (TheHive 4 con almacenamiento embebido
BerkeleyDB+Lucene, sin Cassandra/MinIO; Cortex 3 con su propio Elasticsearch) y una
integración nativa Wazuh→TheHive (bloque `<integration>` en `wazuh_manager.conf`) que reenvía
como alerta de TheHive las alertas de las reglas locales del laboratorio (100010-100031).

Esta sección documenta tres fallos reales encontrados y corregidos durante el despliegue —
ninguno hipotético, los tres bloqueaban el arranque o la integración por completo hasta
solucionarlos.

**Fallo 1 — `AccessDeniedException` al arrancar TheHive.** El contenedor `thehive` entraba en
bucle de reinicio: `java.nio.file.AccessDeniedException: /opt/thp/thehive/db/je.properties`.
Causa: los volúmenes con nombre (`thehive-db`, `thehive-index`, `thehive-data`) los crea
Docker como `root`, pero el proceso de TheHive corre como UID/GID 1000 (usuario `thehive` de
la imagen, confirmado con `docker run --rm --entrypoint id thehiveproject/thehive4:4.1.24-1`).
Es la misma familia de problema que los certificados del indexer de Wazuh al principio del
proyecto. **Corrección**: nuevo servicio de un solo uso `thehive-volume-permissions`
(`chown -R 1000:1000` sobre los tres volúmenes), con `thehive` esperando a que termine vía
`depends_on: condition: service_completed_successfully` — mismo patrón que
`wazuh-certs-permissions`. **Verificado**: tras el fix, `thehive` arranca y queda estable
(`Play application started`).

**Fallo 2 — el propio script de bootstrap abortaba después de haber tenido éxito.** El
contenedor `thehive-wazuh-bootstrap` (genera la clave API que usa la integración) terminaba
con `Exited (1)` incluso cuando la clave se había generado y escrito correctamente. Causas,
en dos capas:

1. El directorio `thehive-cortex/shared/` (bind mount) estaba a `755`, propiedad de
   `riku` (UID 1000 en el host); la imagen `curlimages/curl` corre como `curl_user` (UID
   **100**, *distinto* del UID 1000 de TheHive), sin permiso de escritura como "otros".
2. Corregido eso, un segundo fallo: el propio script hacía `chmod 644` sobre el fichero de
   clave *después* de escribirlo. Como el fichero placeholder ya existía y pertenecía a
   `riku`, no a `curl_user`, ese `chmod` fallaba con `Operation not permitted` — y con
   `set -e` activo, abortaba el script con código 1 **después** de que la clave ya se hubiera
   guardado bien. El síntoma (`Exited (1)`) sugería un fallo total; en realidad el trabajo
   útil ya estaba hecho.

**Corrección**: permisos del directorio ampliados (`chmod 777` sobre `thehive-cortex/shared/`,
`chmod 666` sobre el placeholder ya existente) y eliminada la línea `chmod` innecesaria del
script — los permisos se fijan una vez al crear el fichero, no hace falta re-fijarlos en cada
ejecución del bootstrap. **Verificado**: `thehive-wazuh-bootstrap` termina con `Exited (0)` y
el fichero contiene una clave válida.

**Fallo 3 — `403 AuthorizationError` al reenviar la primera alerta real.** Con la clave ya
generada para `admin@thehive.local` (el superadministrador del sistema), el primer intento
real de reenvío de una alerta devolvió `{"type":"AuthorizationError","message":"Operation not
permitted"}`. Causa: en TheHive, el superadministrador pertenece a la organización especial
`admin` (gestión del sistema), que **no** tiene permiso para crear alertas de caso — esa
capacidad requiere un usuario con perfil `org-admin` (o similar) dentro de una organización de
trabajo normal. No es una particularidad de este laboratorio: la propia plantilla oficial
mínima de TheHive+Cortex (`TheHive-Project/Docker-Templates`) instruye a crear una
organización y un usuario dedicados a mano por el mismo motivo.

**Corrección**: el bootstrap crea también, vía la API v1 documentada de TheHive
(`POST /api/v1/organisation`, `POST /api/v1/user` con `"profile":"org-admin"`), una
organización `tfm-apt-lab` y un usuario `wazuh@thehive.local` dentro de ella, y genera la
clave API de **ese** usuario en vez de la del superadministrador. Idempotente: si la
organización o el usuario ya existen (ejecuciones repetidas del bootstrap), la API devuelve un
error que el script registra como aviso y del que continúa sin abortar.

**Verificación end-to-end (2026-08-24).** Con las tres correcciones aplicadas, los tres
escenarios reenviaron su alerta a TheHive con éxito, confirmado consultando la API de TheHive
directamente (`listAlert`), no solo el log del lado de Wazuh:

| Escenario | Regla | `integrations.log` | Confirmado en TheHive |
|---|---|---|---|
| 2 — Cuenta local | 100020 | 2× `HTTP 201` (18:21:09) | 2 alertas, título `TFM-LAB [100020] TFM-LAB: Cambio en /etc/passwd o /etc/group...`, MITRE `T1136`, `full_log` con el diff real del fichero |
| 3 — Clave SSH | 100030 | 2× `HTTP 201` (18:25:40) | Confirmado por log; formato identico al anterior |
| 1 — Fuerza bruta SSH | 100010 | 1× `HTTP 201` (18:26:59) | Confirmado por log |

**Impacto en el cumplimiento del enunciado.** Cierra el hueco de "notificaciones enriquecidas
a un analista de SOC" — cada alerta del laboratorio llega a TheHive con descripción en
markdown (regla, agente, grupos, técnica MITRE, log completo), etiquetas y severidad, lista
para que un analista la triage.

**Enlace Cortex↔TheHive y analizador `FileInfo` — verificado (2026-08-24).** Al completar el
paso manual (README, sección "Gestión de incidentes"), un primer intento generó una clave de
API que pertenecía al superadmin del sistema (organización `cortex`, creada automáticamente al
inicializar la base de datos) en vez de a un usuario de una organización de trabajo — mismo
patrón de fondo que el Fallo 3 de esta misma sección, pero en el lado de Cortex: el superadmin
gestiona la instancia, no puede ejecutar analizadores. Verificado por API
(`GET /api/analyzer` con esa clave devolvía `AuthorizationError`). Corregido creando una
organización de trabajo (`TFM`) y un usuario dentro de ella con roles `read`, `analyze` y
**`orgadmin`** — este último imprescindible: sin él, la opción de habilitar analizadores no
aparece en la interfaz para nadie, ni siquiera para el superadmin gestionando esa organización
desde fuera. Con la clave de ese usuario y `FileInfo` habilitado, verificado extremo a extremo
por API:

```
GET /api/analyzer (Cortex, con la clave del usuario de la organizacion)
  -> FileInfo_8_0 habilitado para la organizacion TFM

GET /api/connector/cortex/analyzer/type/file (TheHive, con la clave de wazuh@thehive.local)
  -> FileInfo_8_0 visible como analizador disponible para observables de tipo 'file'
```

Con la conexión y los permisos verificados, un análisis real (relanzando el escenario 3 desde
cero y llevando su alerta hasta un informe de `FileInfo`) reveló un problema distinto en la
propia ejecución de los analizadores, ya en Cortex — corregido y verificado en §7.14. Con esa
corrección aplicada, el flujo completo quedó verificado de punta a punta el 2026-08-25: ataque →
alerta Wazuh → respuesta automática → evidencia → alerta en TheHive → caso → observable →
análisis con `FileInfo` en Cortex con informe real (detalle en §7.14). Cierra el último
pendiente de §8 para este componente.

**Generalización.** Los tres fallos comparten un patrón ya visto varias veces en este
documento: un desajuste de UID entre lo que crea un recurso (Docker, o quien prepara un
fichero en el host) y lo que lo consume (el proceso de la aplicación). Merece la pena, para
cualquier servicio nuevo que se añada al laboratorio, comprobar desde el principio con qué UID
corre su imagen oficial, en vez de descubrirlo por el camino largo de un `AccessDeniedException`.

### 7.13 Secreto de Cortex por debajo del mínimo de entropía exigido por Play (HS256)

**Síntoma.** El contenedor `cortex` entraba en bucle de reinicio con `Oops, cannot start the
server` y este error de configuración de Play Framework:

```
The application secret is too short and does not have the recommended amount of entropy
for algorithm HS256 [...]. Current application secret bits: 248, minimal required bits: 256.
```

248 bits coincide exactamente con los 31 caracteres ASCII (31 × 8) del literal de reserva que
`thehive-cortex/cortex/application.conf` fijaba para `play.http.secret.key`. El fichero tenía
dos líneas para esa clave:

```hocon
play.http.secret.key = "lab-cortex-secret-2026-fallback"   # 31 caracteres = 248 bits
play.http.secret.key = ${?CORTEX_SECRET}                    # opcional: sustituye si la variable existe
```

**Causa raíz.** La variable de entorno `CORTEX_SECRET` (36 caracteres, 288 bits, definida en
`.env` y pasada al contenedor vía `environment:` en `docker-compose.yml`) nunca llegó a
sustituir el `${?CORTEX_SECRET}` dentro del proceso de Cortex. Con la sintaxis `${?VAR}` de
HOCON, si la variable no se resuelve la asignación se omite sin más — sin error — y queda en
pie la línea anterior, el literal corto. El resultado fue el mismo tanto pasando el secreto por
variable de entorno como probando la vía nativa del propio `entrypoint` de la imagen
(`command: ["--secret", "${CORTEX_SECRET}"]`), lo que descarta que el problema estuviera en
*cómo* se le pasaba el valor al contenedor y lo sitúa en la resolución de `${?CORTEX_SECRET}`
dentro del proceso Java en sí — probablemente relacionado con cómo el `entrypoint` de la imagen
cambia de usuario (`su -m cortex -c "..."`) antes de lanzar Cortex, aunque no se aisló el
mecanismo exacto: no merecía la pena seguir instrumentando algo que tiene una solución mucho
más simple y robusta (ver corrección).

**Corrección.** Se sustituyeron las dos líneas por una única asignación con un literal fijo de
36 caracteres (288 bits, mismo valor que `CORTEX_SECRET` en `.env`), sin ninguna dependencia de
sustitución de variable de entorno:

```hocon
play.http.secret.key = "Lab-Cortex-Secret-2026-Ficticio-POC"
```

Se mantuvo `command: ["--secret", "${CORTEX_SECRET}"]` en `docker-compose.yml` como red de
seguridad adicional (vía nativa del `entrypoint`, no hace daño si de todos modos gana el
literal del `application.conf`), pero la corrección real no depende de que esa vía funcione.

**Verificado (2026-08-24).** Tras el cambio, `cortex` arranca sin el error de entropía: Play
inicia el servidor HTTP y responde en `/api/status`, `/api/user/current`, etc. Los errores que
siguen apareciendo en el log en ese punto (`index_not_found_exception` sobre `cortex_N`,
`Authentication using API key is not supported` con la clave `PENDIENTE_DE_CONFIGURACION_MANUAL`)
son el estado esperado **antes** de completar la configuración manual de Cortex — ver README,
sección "Gestión de incidentes" — no síntomas de este bug.

**Generalización.** Cuando una sustitución de variable de entorno en HOCON (`${?VAR}`) no hace
lo que se espera, no lanza ningún error: la asignación simplemente desaparece y gana lo que
esté escrito justo antes en el fichero. Para un valor crítico para el arranque (como un secreto
de sesión), es más robusto fijar un literal suficientemente largo directamente que encadenar un
fallback corto pensado para "nunca ganar" — si la sustitución falla por cualquier motivo, ese
fallback sí gana, silenciosamente.

### 7.14 Los analizadores de Cortex fallaban al arrancar: "Docker fuera de Docker" mal configurado

**Síntoma.** Con el enlace Cortex↔TheHive ya correctamente configurado (§7.12, adenda), el
primer análisis real con `FileInfo` sobre una evidencia terminaba en `Failure`. Dos síntomas
distintos, en dos intentos:

1. Con el contenedor del analizador tardando ~2,5 minutos en fallar (compatible con la primera
   descarga de su imagen), el error era un traceback de Python:
   `json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)` al leer `stdin`.
2. Tras un primer intento de corrección, el fallo pasó a ser casi instantáneo (~7 s), con
   `errorMessage` igual a una ruta sin más contexto:
   `/tmp/cortex-jobs/cortex-job-IknPOKABCrIAaC6oFEpt-2297875958634964880`.

**Causa raíz.** Cortex corre él mismo como contenedor, pero lanza cada analizador como un
contenedor **hermano** a través del socket de Docker del host montado en el servicio. 
Para pasarle el trabajo a analizar, Cortex escribe `input.json` en un directorio y le
pide al **daemon del host** que monte esa misma ruta dentro del contenedor del analizador en
`/job` (confirmado leyendo el código fuente de Cortex 3.2.1:
`app/org/thp/cortex/services/DockerJobRunnerSrv.scala` y `.../util/docker/DockerClient.scala`,
y `cortexutils/worker.py`, que hace `json.load(sys.stdin)` como *fallback* solo si
`/job/input/input.json` no existe). El daemon del host resuelve esa ruta contra el filesystem
**real del host**, no contra el del propio contenedor de Cortex — así que, para que funcione,
la ruta tiene que existir, con el mismo contenido, en ambos sitios. Esto ocurrió en dos capas:

1. `job.directory` no estaba fijado en `application.conf` (Cortex usaba su valor por defecto,
   `${java.io.tmpdir}` = `/tmp` directamente), así que el volumen que ya existía en
   `docker-compose.yml` (`/tmp/cortex-jobs:/tmp/cortex-jobs`, heredado sin usar del commit
   inicial) no cubría la ruta real que Cortex empleaba. Confirmado comparando con el
   `docker-compose.yml` oficial del propio proyecto Cortex (rama `3.2.1`), que monta
   `${job_directory}:${job_directory}` — la misma ruta a los dos lados — y la referencia en el
   `reference.conf` de Cortex (`job.directory`, `job.dockerDirectory = ${job.directory}`).
2. Corregido eso (`job.directory = "/tmp/cortex-jobs"` en `application.conf`), Docker había
   creado `/tmp/cortex-jobs` como `root:root` con permisos `0755` al montarlo por primera vez
   (es un *bind mount* de host, no un volumen con nombre) — pero Cortex corre como UID/GID
   **1001** (visible en su log de arranque: `Using user 1001 and group 1001`) y no tenía
   permiso de escritura para crear ahí el subdirectorio de cada trabajo. El mensaje de la
   excepción de Java (`AccessDeniedException`/`NoSuchFileException`) es solo la ruta, sin
   ninguna palabra sobre permisos, lo que lo hace fácil de confundir con otra cosa.

**Corrección.** Dos cambios, ambos en el laboratorio (no en la imagen oficial):

- `thehive-cortex/cortex/application.conf`: `job.directory = "/tmp/cortex-jobs"`, fijando
  explícitamente la misma ruta que ya se montaba (sin usar) en `docker-compose.yml`.
- `docker-compose.yml`: nuevo servicio de un solo uso `cortex-jobs-permissions`
  (`chown -R 1001:1001 /tmp/cortex-jobs`), con `cortex` esperando a que termine vía
  `depends_on: condition: service_completed_successfully` — mismo patrón que
  `thehive-volume-permissions` y `wazuh-certs-permissions`. De paso se retiraron
  `JOB_DIRECTORY` (variable de entorno) y `--job-directory` (argumento de `command`) que
  también venían del commit inicial sin hacer nada: ninguno de los dos es una clave o *flag*
  real del `entrypoint` de Cortex, y su presencia sugería (incorrectamente) que el directorio
  de trabajo ya estaba resuelto.

**Verificado (2026-08-25).** Con las dos correcciones aplicadas, un análisis real de `FileInfo`
sobre la evidencia del escenario 3 (el `authorized_keys` preservado por `preserve_restore.sh`)
terminó en `Success` en 6 segundos, con un informe completo y coherente con la evidencia real:
hashes MD5/SHA1/SHA256 idénticos a los registrados en `evidence/active_response.log` para ese
mismo fichero, `MimeType: text/plain; charset=us-ascii`, `Filetype: TXT`. Cierra de forma
definitiva el flujo completo: ataque → alerta Wazuh → respuesta automática → evidencia → alerta
en TheHive → caso → observable → análisis en Cortex con resultado real.

**Generalización.** Cuando una aplicación containerizada necesita lanzar contenedores hermanos
vía el socket de Docker del host ("Docker fuera de Docker"), cualquier ruta que le pase al
daemon para montar tiene que ser una ruta válida **en el host real**, no en el filesystem propio
del contenedor — y, si esa ruta es un *bind mount* nuevo, Docker la crea como `root` sin más:
hay que ajustar sus permisos explícitamente para el usuario con el que corre el proceso, igual
que con cualquier volumen con nombre.

### 7.15 Automatización del enlace Cortex↔TheHive (antes manual, sin API pública documentada)

**Motivación.** El enlace Cortex↔TheHive (organización + usuario analista + clave API dentro de
Cortex) se dejó como paso manual de un solo uso desde su primera versión (§7.12), justificado en
que Cortex no publica ninguna API pública ni documentada para ello. Esa justificación seguía
siendo cierta, pero "sin documentar" no es lo mismo que "sin API": Cortex es software libre, y
su propio código fuente confirma qué endpoints existen y qué hace falta para usarlos. Se decidió
automatizarlo leyendo ese código en vez de seguir dependiendo de una serie de clics manuales
propensos a error (los tres fallos de configuración de esta misma sesión — clave del superadmin
en vez de la del analista, falta del rol `orgadmin`, `FileInfo` sin habilitar — fueron todos
errores humanos en ese flujo manual).

**Diseño.** Se leyó el código fuente de Cortex 3.2.1 directamente desde GitHub
(`TheHive-Project/Cortex`, *tag* `3.2.1`) para encontrar los endpoints reales y sus requisitos,
en vez de adivinarlos por prueba y error:

- `conf/routes` — lista completa de endpoints y su controlador.
- `app/org/thp/cortex/services/UserSrv.scala` — `getInitialUser` concede una identidad especial
  (`"init"`, con todos los roles) a la primera petición no autenticada que crea un usuario,
  **mientras el índice de usuarios de toda la instancia esté vacío** (no se filtra por
  organización: el primer usuario creado en cualquier organización cierra la ventana para
  siempre, sea cual sea la organización). También confirma que `create()` acepta un campo
  `password` y lo fija atómicamente en la misma llamada (`authSrv.get.setPassword(...)`) — no
  hace falta una segunda llamada autenticada para el usuario que todavía no tiene credenciales.
- `app/org/thp/cortex/controllers/AnalyzerCtrl.scala` — habilitar un analizador para una
  organización (`POST /api/organization/analyzer/:id`) exige rol `orgadmin` **del usuario que
  hace la llamada**, sobre su propia organización; no hay parámetro de organización en la ruta,
  así que el superadmin no puede hacerlo por otra organización aunque tenga más privilegios en
  apariencia (confirma lo ya visto empíricamente en la adenda de §7.12).
- `elastic4play/app/org/elastic4play/controllers/MigrationCtrl.scala` — `POST
  /api/maintenance/migrate` (inicializa la base de datos) no exige autenticación en absoluto.

Con esto, `thehive-cortex/bootstrap/create_cortex_org.sh` (nuevo servicio `cortex-org-bootstrap`
en `docker-compose.yml`, mismo patrón que `thehive-wazuh-bootstrap`) encadena: inicializar la
base de datos → crear el superadmin inicial (con contraseña, en la ventana sin autenticar) →
crear la organización de trabajo `TFM` → crear un usuario analista con roles `read`, `analyze`,
`orgadmin` → habilitar `FileInfo` para esa organización → obtener (o generar si no existe) su
clave API → escribirla en `thehive/application.conf`, antes de que arranque `thehive`
(`depends_on: condition: service_completed_successfully`). Credenciales fijas y ficticias en
`.env` (`CORTEX_ADMIN_*`, `CORTEX_ANALYST_*`), igual que el resto de credenciales del
laboratorio.

**Tres fallos reales durante la implementación**, los tres detectados probando el script en
vivo, no solo leyendo el código:

1. **HTTP Basic no soportado.** Pese a que la configuración por defecto de Cortex sugiere lo
   contrario, `curl -u usuario:clave` devuelve `401 AuthenticationError` en cualquier endpoint,
   incluso con una contraseña recién fijada y verificada por otra vía. Confirmado en vivo:
   `/api/login` (usuario + contraseña en JSON, cookie de sesión `CORTEX_SESSION` de vuelta)
   funciona perfectamente con las mismas credenciales que Basic rechaza. El script se reescribió
   para autenticar con `/api/login` y una *cookie jar* por identidad.
2. **CSRF.** Con la sesión de cookie, el primer `POST` devolvía `403 Forbidden: No CSRF token
   found`. Cortex fija su cookie CSRF (`CORTEX-XSRF-TOKEN`, cabecera de respuesta
   `X-CORTEX-XSRF-TOKEN` — nombres definidos en su propio `reference.conf`) en la respuesta de
   **cualquier llamada autenticada**, pero no en la del propio `/api/login`: hace falta una
   llamada de más (`GET /api/user/current`) después de iniciar sesión para que la cookie
   aparezca, antes de poder hacer ningún `POST`.
3. **Falta el campo `name` al habilitar un analizador.** `POST
   /api/organization/analyzer/FileInfo_8_0` con cuerpo `{}` devolvía `400
   AttributeCheckingError: Attribute name is missing` — el modelo interno de Cortex para
   analizadores habilitados exige `name` explícito en el cuerpo (no lo rellena a partir del id
   de la URL). Corregido enviando `{"name": "FileInfo_8_0"}`.
4. (Ya documentado como parte de §7.14, pero afectó también a este script) **Permission denied**
   al escribir la clave en `application.conf`: el contenedor de `curlimages/curl` corre como UID
   100 (mismo caso que `thehive-wazuh-bootstrap`, §7.12 Fallo 2), y el reemplazo atómico
   (escribir aparte + mover) necesita permiso de escritura sobre el **directorio**, no solo
   sobre el fichero. Corregido montando el directorio completo (no el fichero suelto) con
   `chmod 777` (mismo patrón que `thehive-cortex/shared/`), en vez del fichero de configuración
   solo.

**Verificado (2026-08-25).** Reset completo (`docker compose down -v && docker compose up -d`)
y log de `cortex-org-bootstrap` sin errores: superadmin creado, organización `TFM` creada,
usuario analista creado, `FileInfo_8_0` habilitado, clave obtenida y escrita en
`application.conf` — sin ningún paso manual. Confirmado por API, sin tocar la interfaz de
Cortex para nada:

```
GET /api/status (TheHive)
  -> connectors.cortex.status = "OK"

GET /api/connector/cortex/analyzer/type/file (TheHive, con la clave de wazuh@thehive.local)
  -> FileInfo_8_0 visible como analizador disponible
```

**Qué se dejó manual, a propósito.** Lanzar el ataque y decidir qué alerta se convierte en caso,
qué evidencia se analiza y con qué analizador sigue siendo un paso manual — no por limitación
técnica (con lo aprendido aquí, sería tan automatizable como esto), sino porque automatizarlo
cambiaría lo que el laboratorio demuestra: el ataque representa al adversario real, y el triage
es precisamente el criterio del analista que el laboratorio pone a prueba.

---

## 8. Pruebas pendientes

| Prueba | Motivo |
|--------|--------|
| CP-05 (listas de exclusión) | Verificado de forma incidental (§7.3), no como caso formal |
| CP-06 (integridad ante repetición) | Verificado tras la corrección de §7.1, no como caso formal |

La medición formal del tiempo de detección, que figuraba aquí como pendiente, se cerró el
2026-08-04 con `scripts/measure_timings.sh` (§7.10). La integración Wazuh→TheHive, que no
figuraba aquí porque no existía, se implementó y verificó el 2026-08-24 (§7.12). El enlace
Cortex↔TheHive y el analizador `FileInfo`, que figuraban aquí como pendientes, se completaron y
verificaron el mismo día (§7.12, adenda).

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
| C8 | Las alertas del laboratorio llegan a una herramienta de gestión de incidentes con contexto suficiente para un analista | Cumplido — verificado el 2026-08-24 (§7.12) para los tres escenarios; el análisis de artefactos con `FileInfo` en Cortex, incluido en el flujo completo, verificado con informe real el 2026-08-25 (§7.14) |
