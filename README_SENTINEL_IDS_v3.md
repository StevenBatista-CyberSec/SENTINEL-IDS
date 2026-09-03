# SENTINEL IDS PRO v3.1

IDS/NSM defensivo orientado a laboratorio y SOC. Esta versión conserva el dashboard Tkinter de v3 y añade controles de producción para estado, riesgo, respuesta automática temporal e integración de telemetría.

## Arquitectura

```text
                 ┌───────────────┐
 Internet/LAN ─►│ Firewall/NAC  │
                 └───────┬───────┘
                         │
              ┌──────────▼──────────┐
              │ Suricata / Zeek     │
              │ SENTINEL Sensor     │
              └──────────┬──────────┘
                         │
                    ┌────▼────┐
                    │  Wazuh  │
                    └────┬────┘
                         │
                ┌────────▼────────┐
                │ SENTINEL SOC    │
                │ correlación/risk│
                │ incidentes      │
                └────────┬────────┘
                         │
                  Firewall Response
```

## Mejoras v3.1

- Corrección de referencias temporales: PCAP conserva `packet.time` en los detectores que dependen de ventanas.
- Corrección de HTTP, DNS y anomalías: ya no dependen de una variable `now` inexistente y respetan el tiempo del evento.
- Expiración de estado para evitar crecimiento indefinido en sensores de larga duración.
- Baseline ARP: una observación posterior no sustituye automáticamente el binding conocido.
- Respuesta automática con TTL: un bloqueo puede revertirse automáticamente después de `ttl_seconds`.
- Lista de IP protegidas separada del baseline ARP.
- Puntuación de riesgo y confianza en alertas, con mapeo MITRE ATT&CK básico.
- Migración compatible de SQLite para instalaciones anteriores.
- Adaptadores offline para Suricata EVE JSON, Zeek JSON y Wazuh alerts JSON.
- `soc_ingest.py` para normalizar telemetría a JSONL sin ejecutar acciones de red.
- Tests unitarios adicionales para riesgo y normalizadores.

## Instalación

```bash
sudo bash install_v3.sh
```

Para captura en vivo:

```bash
sudo /opt/sentinel-ids/.venv/bin/python /opt/sentinel-ids/sentinel_ids_pro_v3.py
```

Para PCAP:

```bash
python3 sentinel_ids_pro_v3.py --pcap captura.pcap
```

## Integraciones

Normalizar Suricata:

```bash
python3 soc_ingest.py suricata /var/log/suricata/eve.json --output suricata.normalized.jsonl
```

Normalizar Zeek JSON:

```bash
python3 soc_ingest.py zeek /var/log/zeek/current/conn.log --output zeek.normalized.jsonl
```

Normalizar Wazuh:

```bash
python3 soc_ingest.py wazuh /var/ossec/logs/alerts/alerts.json --output wazuh.normalized.jsonl
```

> Los adaptadores son de ingesta/normalización: no bloquean IPs ni ejecutan comandos del sistema.

## Respuesta automática

Por seguridad viene deshabilitada. Antes de activarla en un laboratorio, configura:

```json
"auto_response": {
  "enabled": true,
  "block_on_critical": true,
  "method": "iptables",
  "ttl_seconds": 900,
  "protected_ips": ["10.0.0.1"]
}
```

El TTL reduce el riesgo de dejar un bloqueo permanente por un falso positivo.

## Seguridad de API

Si se habilita la API, configura un token aleatorio fuerte y envíalo mediante:

```text
X-Sentinel-Token: <token>
```

No publiques el puerto de administración directamente en Internet.

## Pruebas

```bash
pytest -q
python3 -m py_compile sentinel_ids_pro_v3.py soc_ingest.py
```

En un entorno sin Scapy, las pruebas específicas de captura/PCAP se omiten; los módulos de riesgo e integración no dependen de Scapy.

## Siguiente nivel

Para una plataforma SOC completa, el siguiente paso es separar el dashboard en frontend web y backend API, incorporar almacenamiento de eventos normalizados, correlación multi-fuente, gestión formal de incidentes/IOC, RBAC, secretos fuera de `config.json`, TCP reassembly y despliegue Docker/systemd/CI.
