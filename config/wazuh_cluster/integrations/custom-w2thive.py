#!/var/ossec/framework/python/bin/python3
"""Integracion Wazuh -> TheHive para el laboratorio TFM.

Reenvia como alerta de TheHive unicamente las alertas generadas por las
reglas locales del laboratorio (100010-100031), no todo el ruido del
ruleset base. Usa solo la biblioteca estandar (sin 'requests') porque la
imagen oficial de wazuh.manager no permite instalar dependencias sin un
Dockerfile propio.

La clave API se lee de un fichero generado por
thehive-cortex/bootstrap/create_wazuh_api_key.sh (ver docs/architecture.md),
no del argumento que pasa Wazuh, para no tener que hornear un secreto
generado dinamicamente dentro de ossec.conf.
"""
import json
import os
import sys
from datetime import datetime, timezone
from urllib import error, request

KEY_FILE = "/var/ossec/integrations/shared/wazuh_api_key.txt"
THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://thehive:9000")
LOG_FILE = "/var/ossec/logs/integrations.log"

# Reglas del laboratorio TFM que queremos ver como alertas en TheHive.
LAB_RULE_IDS = {"100010", "100020", "100030", "100031"}


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
    line = f"[{ts}] custom-w2thive: {msg}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except OSError:
        pass
    sys.stderr.write(line)


def read_api_key():
    try:
        with open(KEY_FILE) as f:
            return f.read().strip()
    except OSError:
        return None


def build_payload(alert):
    rule = alert.get("rule", {})
    rule_id = str(rule.get("id", ""))
    agent = alert.get("agent", {})
    mitre_ids = rule.get("mitre", {}).get("id", [])

    payload = {
        "title": f"TFM-LAB [{rule_id}] {rule.get('description', 'Alerta Wazuh')}",
        "description": (
            f"**Regla Wazuh**: {rule_id} (nivel {rule.get('level', '?')})\n\n"
            f"**Agente**: {agent.get('name', '?')} ({agent.get('ip', '?')})\n\n"
            f"**Grupos**: {', '.join(rule.get('groups', []))}\n\n"
            f"**MITRE ATT&CK**: {', '.join(mitre_ids)}\n\n"
            f"```\n{alert.get('full_log', '')}\n```"
        ),
        "type": "wazuh_alert",
        "source": "wazuh",
        "sourceRef": str(alert.get("id", rule_id)),
        "severity": 3 if int(rule.get("level", 0) or 0) >= 12 else 2,
        "tlp": 2,
        "tags": ["tfm-apt-lab", f"rule:{rule_id}"] + mitre_ids,
        "artifacts": [],
    }

    srcip = (alert.get("data") or {}).get("srcip")
    if srcip:
        payload["artifacts"].append(
            {"dataType": "ip", "data": srcip, "message": "IP origen de la alerta"}
        )

    return payload, rule_id


def main():
    if len(sys.argv) < 2:
        log("uso incorrecto: falta la ruta al fichero de alerta")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        alert = json.load(f)

    rule_id = str(alert.get("rule", {}).get("id", ""))
    if rule_id not in LAB_RULE_IDS:
        return

    api_key = read_api_key()
    if not api_key:
        log(f"sin clave API de TheHive disponible ({KEY_FILE}); alerta {rule_id} no reenviada")
        return

    payload, rule_id = build_payload(alert)
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        f"{THEHIVE_URL}/api/alert",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            log(f"alerta {rule_id} reenviada a TheHive (HTTP {resp.status})")
    except error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        log(f"fallo HTTP {e.code} reenviando alerta {rule_id}: {detail}")
    except error.URLError as e:
        log(f"fallo de conexion reenviando alerta {rule_id}: {e.reason}")


if __name__ == "__main__":
    main()
