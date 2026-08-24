# Mapeo a MITRE ATT&CK

Correspondencia entre los escenarios implementados en el laboratorio y el marco
MITRE ATT&CK Enterprise, con las fuentes de datos empleadas para la detección, las reglas
de Wazuh implicadas y las respuestas automáticas asociadas.

> Los identificadores corresponden a la matriz **ATT&CK for Enterprise**. Conviene verificar
> la vigencia de tácticas, técnicas y mitigaciones frente a la versión publicada en
> `attack.mitre.org` en el momento de la entrega, ya que el marco se revisa periódicamente.

---

## 1. Resumen

| # | Técnica | ID | Táctica | Regla local | Respuesta automática |
|---|---------|-----|---------|-------------|----------------------|
| 1 | Brute Force: Password Guessing | T1110.001 | Credential Access | `100010` | `block_ip.sh` |
| 2 | Create Account: Local Account | T1136.001 | Persistence | `100020` | `disable_suspicious_user.sh` |
| 3 | Account Manipulation: SSH Authorized Keys | T1098.004 | Persistence, Privilege Escalation | `100030` (`100031` para `sshd_config`, pendiente) | `preserve_and_restore_file.sh` |

Los tres escenarios reproducen una secuencia coherente dentro de una intrusión: obtención de
acceso mediante credenciales, establecimiento de persistencia por cuenta propia y
establecimiento de persistencia por clave de autenticación. Es una progresión característica
de actores que priorizan el acceso prolongado sobre el impacto inmediato.

---

## 2. Escenario 1 — Acceso no autorizado mediante SSH

### Clasificación

| Campo | Valor |
|-------|-------|
| **Táctica** | Credential Access (TA0006) |
| **Técnica** | T1110 — Brute Force |
| **Subtécnica** | T1110.001 — Password Guessing |
| **Plataforma** | Linux |
| **Acción simulada** | Diez intentos consecutivos de autenticación SSH con contraseña incorrecta contra una cuenta válida |

Se corresponde con *Password Guessing* y no con *Password Spraying* (T1110.003) porque el
ataque se concentra en una única cuenta conocida (`corpuser`) en lugar de probar una
contraseña común contra muchas cuentas.

### Detección

| Aspecto | Detalle |
|---------|---------|
| **Fuente de datos ATT&CK** | Application Log: Application Log Content; User Account: User Account Authentication |
| **Origen técnico** | `/var/log/auth.log`, alimentado por `rsyslog` desde `sshd` |
| **Mecanismo Wazuh** | Módulo `logcollector` + decoders `sshd` y `pam` |
| **Reglas base** | `5760` (fallo de autenticación), `5503` (fallo PAM), `5763` (correlación por frecuencia) |
| **Regla local** | `100010`, nivel 12, encadenada a `<if_sid>5720,5763</if_sid>` |

La detección no se basa en el intento individual, que es un evento cotidiano y de escaso
valor, sino en la **correlación por frecuencia**: la regla base agrupa varios fallos
procedentes de una misma dirección en una ventana temporal. Este es el rasgo que distingue
un error de usuario de un intento sistemático.

Durante la validación se comprobó que las reglas base de Wazuh ya incorporan la etiqueta
MITRE correspondiente. La regla `5763` reporta `T1110` con táctica *Credential Access*, y las
reglas `5503` y `5760` reportan `T1110.001`. La regla local no reemplaza ese mapeo, lo
refuerza asociando el evento al escenario concreto del laboratorio.

### Respuesta

Bloqueo temporal de la dirección origen mediante una cadena dedicada de cortafuegos en el
propio equipo víctima, con reversión automática transcurridos 300 segundos.

La respuesta se alinea con la lógica de contención de la técnica: interrumpir el canal por
el que se está produciendo la enumeración de credenciales, sin comprometer de forma
permanente la disponibilidad del servicio ante un posible falso positivo.

### Mitigaciones ATT&CK aplicables

| Mitigación | Aplicación en un entorno real |
|------------|-------------------------------|
| M1032 — Multi-factor Authentication | Anula la eficacia del adivinado de contraseñas |
| M1027 — Password Policies | Aumenta el coste del ataque |
| M1036 — Account Use Policies | Bloqueo de cuenta tras un número de intentos |
| M1018 — User Account Management | Restricción de cuentas con acceso remoto |

El laboratorio deshabilita deliberadamente estas mitigaciones (`PasswordAuthentication yes`,
sin MFA) para que el escenario sea reproducible.

---

## 3. Escenario 2 — Creación de cuenta local no autorizada

### Clasificación

| Campo | Valor |
|-------|-------|
| **Táctica** | Persistence (TA0003) |
| **Técnica** | T1136 — Create Account |
| **Subtécnica** | T1136.001 — Local Account |
| **Plataforma** | Linux |
| **Acción simulada** | Creación de la cuenta `backdoor01` mediante `useradd` y asignación de contraseña, desde una sesión SSH con privilegios acotados |

### Detección

| Aspecto | Detalle |
|---------|---------|
| **Fuente de datos ATT&CK** | User Account: User Account Creation; Command: Command Execution; Process: Process Creation |
| **Origen técnico** | Monitorización de integridad sobre `/etc/passwd`, `/etc/group` y `/etc/shadow` |
| **Mecanismo Wazuh** | Módulo `syscheck` (FIM) en modo `realtime` |
| **Reglas base** | `550` (fichero modificado), `554` (fichero nuevo) |
| **Regla local** | `100020`, nivel 12, acotada mediante `<field name="file">` |

La detección se apoya en la **integridad de ficheros** y no en la auditoría de ejecución de
comandos. Es una decisión con consecuencias que conviene explicitar:

- **Ventaja.** Detecta la creación de la cuenta con independencia del medio empleado:
  `useradd`, `adduser` o la edición directa de `/etc/passwd`. Un actor que evite las
  utilidades habituales para eludir la auditoría de procesos seguirá siendo detectado.
- **Limitación.** El evento FIM informa de que el fichero cambió, pero **no identifica qué
  cuenta se creó ni quién la creó**. La correlación con el ejecutor requeriría auditoría del
  núcleo (`auditd`), cuya disponibilidad en contenedores es limitada.

Esta limitación se resuelve en la respuesta automática, que deduce la cuenta a partir del
diferencial reportado por el FIM y, de forma subsidiaria, comparando el estado actual con
una línea base registrada previamente.

Una única acción del atacante genera **dos eventos**, al modificarse `/etc/passwd` y
`/etc/group`, por lo que la respuesta se ejecuta dos veces. El comportamiento es aceptable
porque la acción es idempotente, pero ilustra un requisito general de diseño de las
respuestas automáticas.

### Respuesta

Bloqueo de la cuenta (`usermod -L`) y sustitución del intérprete de órdenes por
`/sbin/nologin`, previa comprobación contra una lista de cuentas protegidas que incluye
`root`, cuentas del sistema y la cuenta legítima del laboratorio.

**La cuenta no se elimina.** Se neutraliza el acceso conservando el objeto y sus atributos,
lo que preserva la evidencia para un análisis forense posterior y permite revertir la acción
con una única orden.

### Mitigaciones ATT&CK aplicables

| Mitigación | Aplicación en un entorno real |
|------------|-------------------------------|
| M1026 — Privileged Account Management | Restringir quién puede crear cuentas |
| M1032 — Multi-factor Authentication | Exigir segundo factor para operaciones administrativas |
| M1018 — User Account Management | Revisión periódica de cuentas existentes |

---

## 4. Escenario 3 — Inserción de clave SSH no autorizada

### Clasificación

| Campo | Valor |
|-------|-------|
| **Táctica** | Persistence (TA0003), Privilege Escalation (TA0004) |
| **Técnica** | T1098 — Account Manipulation |
| **Subtécnica** | T1098.004 — SSH Authorized Keys |
| **Plataforma** | Linux |
| **Acción simulada** | Adición de una clave pública no autorizada al fichero `authorized_keys` de la cuenta comprometida |

La técnica figura también en la táctica *Privilege Escalation* cuando la clave se instala en
la cuenta de un usuario con mayores privilegios. El laboratorio monitoriza igualmente
`/root/.ssh`, cubriendo esa variante.

### Detección

| Aspecto | Detalle |
|---------|---------|
| **Fuente de datos ATT&CK** | File: File Modification; Command: Command Execution; Process: Process Creation |
| **Origen técnico** | Monitorización de integridad sobre `~/.ssh` |
| **Mecanismo Wazuh** | Módulo `syscheck` (FIM) en modo `realtime` |
| **Reglas base** | `550` (fichero modificado), `554` (fichero nuevo) |
| **Regla local** | `100030` (`authorized_keys`); `100031` (`/etc/ssh/sshd_config`, mismo mecanismo de detección — variante 3b, pendiente de script de simulación dedicado, ver `docs/validation_plan.md` §3.3 y §8) |

La regla vigila el fichero de claves autorizadas de la cuenta, cuyo compromiso establece un acceso adicional 
que no depende de credenciales y, por tanto, sobrevive a la rotación de contraseñas. 
Si no existe copia de referencia, el script preserva la evidencia y no modifica el fichero, 
evitando una restauración a ciegas que pudiera degradar el servicio.

Esta técnica es especialmente relevante frente a actores persistentes porque **el acceso
resultante no depende de credenciales**: la rotación de contraseñas, medida habitual tras
detectar un compromiso, no revoca una clave instalada.

### Respuesta

1. Preservación del fichero alterado en el repositorio de evidencias, **antes** de cualquier
   modificación.
2. Cálculo y registro del resumen SHA-256 para garantizar la integridad de la evidencia.
3. Restauración de la copia limpia de referencia, si existe.
4. Registro del resultado con marcas de tiempo de inicio y fin.

Si no existe copia de referencia, el script preserva la evidencia y **no modifica el
fichero**, evitando una restauración a ciegas que pudiera degradar el servicio.

### Mitigaciones ATT&CK aplicables

| Mitigación | Aplicación en un entorno real |
|------------|-------------------------------|
| M1022 — Restrict File and Directory Permissions | Permisos estrictos sobre `~/.ssh` |
| M1026 — Privileged Account Management | Control de las cuentas con acceso por clave |
| M1032 — Multi-factor Authentication | Segundo factor añadido a la autenticación por clave |
| M1042 — Disable or Remove Feature or Program | Deshabilitar autenticación por clave donde no sea necesaria |

---

## 5. Cobertura y limitaciones del mapeo

### Cobertura alcanzada

| Táctica | Cubierta | Técnicas |
|---------|----------|----------|
| Credential Access (TA0006) | Sí | T1110.001 |
| Persistence (TA0003) | Sí | T1136.001, T1098.004 |
| Privilege Escalation (TA0004) | Parcial | T1098.004 (variante sobre cuenta privilegiada) |

### Tácticas no cubiertas

El laboratorio no aborda las fases previas ni posteriores de una intrusión completa:
*Reconnaissance*, *Initial Access* por vectores distintos al acceso remoto, *Defense
Evasion*, *Discovery*, *Lateral Movement*, *Collection*, *Command and Control*,
*Exfiltration* e *Impact*.

Esta acotación es deliberada. La prueba de concepto persigue validar el **ciclo completo de
detección y respuesta automática** sobre un conjunto reducido y representativo de
comportamientos, no evaluar la cobertura de la matriz. Ampliar el número de técnicas sin
profundizar en el ciclo aportaría extensión, no valor demostrativo.

### Consideraciones sobre la calidad del mapeo

- **Las técnicas describen comportamientos, no firmas.** La regla `100010` detecta el patrón
  de adivinado de credenciales, no un atacante concreto ni una herramienta determinada.
- **Una detección puede corresponder a varias técnicas.** Las propias reglas base de Wazuh
  asocian el fallo de autenticación SSH tanto a T1110.001 como a T1021.004 (*Remote
  Services: SSH*), según el contexto.
- **La ausencia de alerta no implica ausencia de técnica.** Un actor que empleara claves
  robadas legítimas no generaría los eventos del escenario 1, pese a estar realizando
  *Valid Accounts* (T1078).

### Ampliaciones naturales

| Técnica | Fuente de datos requerida |
|---------|---------------------------|
| T1053.003 — Scheduled Task/Job: Cron | FIM sobre `/etc/cron*` y `crontab` de usuario |
| T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid | Auditoría de cambios de permisos |
| T1070.002 — Indicator Removal: Clear Linux or Mac System Logs | Monitorización de integridad sobre `/var/log` |
| T1078 — Valid Accounts | Análisis de comportamiento de acceso (horario, origen) |

Las tres primeras son de implementación inmediata sobre la arquitectura actual: requieren
únicamente añadir rutas al módulo de integridad de ficheros y las reglas locales asociadas.
