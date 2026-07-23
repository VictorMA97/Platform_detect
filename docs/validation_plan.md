# Plan de validación

Procedimiento de verificación del laboratorio, métricas definidas, resultados obtenidos e
incidencias detectadas durante la validación.

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
| P1 | Servicios activos | `docker compose ps` | Cinco servicios en estado `Up` |
| P2 | Agente registrado | `docker compose exec wazuh.manager /var/ossec/bin/agent_control -l` | Agente en estado `Active` |
| P3 | Procesos del manager | `docker compose exec wazuh.manager /var/ossec/bin/wazuh-control status` | Todos en ejecución |
| P4 | Reglas locales cargadas | `docker compose exec wazuh.manager cat /var/ossec/etc/rules/local_rules.xml` | Reglas 100010–100031 presentes |
| P5 | Scripts de respuesta instalados | `docker compose exec wazuh.agent ls -la /var/ossec/active-response/bin/` | Tres scripts con permisos `750 root:wazuh` |
| P6 | Dependencias del agente | `docker compose exec wazuh.agent sh -c "which jq iptables"` | Ambas utilidades presentes |
| P7 | Configuración de Active Response | `docker compose exec wazuh.manager grep -c "block-ip-lab" /var/ossec/etc/ossec.conf` | Valor mayor que cero |
| P8 | Línea base de cuentas | `docker compose exec wazuh.agent sh -c "cut -d: -f1 /etc/passwd \| sort > /var/ossec/evidence/passwd.baseline"` | Fichero generado |
| P9 | Interfaz web accesible | Navegador sobre el puerto publicado | Autenticación correcta |

> **Verificación de identificadores del ruleset.** Antes de una demostración conviene
> confirmar que las reglas base declaradas en `<if_sid>` siguen siendo las que dispara la
> versión desplegada, mediante `wazuh-logtest`. Wazuh reorganiza identificadores entre
> versiones.

---

## 3. Tabla de validación

| Escenario | Técnica MITRE | Acción simulada | Alerta esperada | Respuesta automática | Evidencia | Resultado |
|-----------|---------------|-----------------|-----------------|----------------------|-----------|-----------|
| 1. Acceso no autorizado SSH | T1110.001 | 10 intentos de autenticación fallidos desde `attacker` | Regla `100010`, nivel 12 | `block_ip.sh` — bloqueo temporal de la IP origen | Registro con marcas de tiempo; regla en cadena `WAZUH_AR` | **Superado** |
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

### Método de cálculo

Todos los registros emplean el formato ISO 8601 en UTC con precisión de milisegundos, lo que
permite el cruce directo entre los tres orígenes:

```bash
# Instante del ataque
docker compose exec attacker cat /opt/results/timings.log

# Instante de la alerta
docker compose exec wazuh.manager grep '"id":"100010"' /var/ossec/logs/alerts/alerts.json \
  | grep -o '"timestamp":"[^"]*"' | tail -1

# Instantes de inicio y fin de la respuesta
cat evidence/active_response.log
```

---

## 6. Resultados obtenidos

Ejecución de referencia realizada sobre Wazuh 4.14.6.

### Tiempos de ejecución de las respuestas

| Escenario | Script | Inicio | Fin | Duración |
|-----------|--------|--------|-----|----------|
| 1 | `block_ip.sh` | 19:37:49.639 | 19:37:49.680 | **41 ms** |
| 2 | `disable_suspicious_user.sh` | 19:57:54.327 | 19:57:54.415 | **88 ms** |
| 2 (segunda invocación) | `disable_suspicious_user.sh` | 19:57:54.417 | 19:57:54.483 | **66 ms** |
| 3 | `preserve_and_restore_file.sh` | 19:56:33.623 | 19:56:33.668 | **45 ms** |

El tiempo de ejecución de la respuesta resulta despreciable frente al tiempo de detección.
El factor determinante del tiempo total no es la automatización, sino la latencia de
correlación del SIEM —especialmente en el escenario 1, donde la regla debe acumular varios
intentos antes de disparar.

### Verificación del efecto sobre el sistema

| Escenario | Comprobación | Resultado |
|-----------|--------------|-----------|
| 1 | Regla en cadena `WAZUH_AR` | Bloqueo aplicado sobre la dirección origen |
| 2 | `passwd -S backdoor01` | `backdoor01 L 2026-07-23 0 99999 7 -1` — cuenta bloqueada, no eliminada |
| 3 | Fichero preservado y resumen | SHA-256 `f33a6f9c61c2fc5d47a1c5b0ef0e49409c00e5f8a861dd59831438d996b2c009` |
| 3 | Contenido de `authorized_keys` | Restaurado al estado de referencia |

### Valoración por métrica

| Métrica | Escenario 1 | Escenario 2 | Escenario 3 |
|---------|-------------|-------------|-------------|
| Ejecución correcta | Sí | Sí | Sí |
| Falsos positivos | Uno detectado (ver §7.3) | No observados | No observados |
| Impacto operativo | Medio — pérdida de conectividad del origen durante 300 s | Alto — la cuenta queda inutilizable hasta intervención | Bajo — solo se altera el fichero comprometido |
| Reversibilidad | Automática (300 s) | Manual: `usermod -U` | Manual: copia preservada |

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
evidencia real conservada.

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

---

## 8. Pruebas pendientes

| Prueba | Motivo |
|--------|--------|
| Escenario 3b (`sshd_config`, regla `100031`) | No ejecutado; requiere un script de simulación específico |
| CP-02 (reversión automática) | Requiere esperar el vencimiento completo del temporizador |
| CP-05 (listas de exclusión) | Verificado de forma incidental (§7.3), no como caso formal |
| CP-06 (integridad ante repetición) | Verificado tras la corrección de §7.1, no como caso formal |
| Medición formal del tiempo de detección | Los tiempos de ejecución están medidos; el cruce con las marcas de tiempo de las alertas está pendiente de una ejecución completa |
| Prueba de reproducibilidad íntegra | `docker compose down -v` seguido de despliegue completo y ejecución de los tres escenarios sin intervención manual |

> La prueba de reproducibilidad íntegra es la más relevante de las pendientes: constituye la
> verificación del requisito central de la prueba de concepto y debe superarse antes de la
> defensa.

---

## 9. Criterios de aceptación global

| # | Criterio | Estado |
|---|----------|--------|
| C1 | Los tres escenarios generan la alerta prevista | Cumplido |
| C2 | Los tres escenarios ejecutan la respuesta asociada | Cumplido |
| C3 | Cada respuesta produce un efecto verificable sobre el sistema | Cumplido |
| C4 | Toda respuesta genera evidencia accesible desde el anfitrión | Cumplido |
| C5 | Toda respuesta es reversible | Cumplido |
| C6 | Ninguna acción automática afecta al sistema anfitrión | Cumplido |
| C7 | El entorno se despliega sin intervención manual sobre contenedores | **Pendiente de verificación** |
