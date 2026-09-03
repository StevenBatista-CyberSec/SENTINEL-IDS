#!/usr/bin/env python3
"""
================================================================================
 SENTINEL IDS PRO v3.1 — Sistema Profesional de Detección de Intrusiones
================================================================================
Mejoras sobre v1.0:
  - 8 nuevos motores de detección (ICMP flood, Ping of Death, ARP spoofing con
    tabla IP-MAC real, DNS tunneling por entropía/DGA, HTTP anómalo, Slowloris,
    escaneo de versión SSH, escaneo ICMP/ping sweep)
  - Motor de anomalías por baseline estadístico real (antes el buffer nunca se
    llenaba: bug corregido) + puntuación de riesgo con decaimiento temporal
  - Deduplicación / cooldown de alertas repetidas (antes: alert flooding)
  - Persistencia real de configuración en config.json (umbrales, canales,
    interfaz, auto-respuesta)
  - Canales de notificación: Webhook (HTTP POST), Email (SMTP), sonido local
  - Reportes PDF reales con reportlab (antes solo placeholder), export JSON
  - Modo offline: analizar un archivo .pcap sin privilegios de root
  - API REST opcional (Flask) para integraciones externas: /api/stats,
    /api/alerts, /api/block
  - Auto-respuesta opcional: bloqueo de IP vía iptables/ufw (con confirmación)
  - Pestaña de Auditoría (tabla audit_log ahora se usa de verdad)
  - Gestión completa de whitelist/blacklist (listar, eliminar, expiración)
  - Resolución de alertas con notas, búsqueda y paginación
  - Selección de interfaz de red, tema claro/oscuro
  - Escritura a BD en hilo separado (cola) para no bloquear la captura

Requisitos: Python 3.8+, scapy, numpy, matplotlib, reportlab, flask, requests
Uso:
    sudo python3 ids_profesional_v3.py                 # captura en vivo
    python3 ids_profesional_v3.py --pcap captura.pcap  # análisis offline
================================================================================
"""

import argparse
import csv
import html
import ipaddress
import json
import math
import os
import queue
import re
import smtplib
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
import tkinter as tk
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

import matplotlib
try:
    matplotlib.use("TkAgg")
except Exception:
    # Permite ejecutar pruebas, ingesta y análisis offline en servidores sin display.
    matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

try:
    from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Raw, rdpcap, sniff, get_if_list
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

try:
    import requests
    REQUESTS_OK = True
except Exception:
    REQUESTS_OK = False

try:
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                     TableStyle)
    REPORTLAB_OK = True
except Exception:
    REPORTLAB_OK = False

try:
    from flask import Flask, jsonify, request as flask_request
    FLASK_OK = True
except Exception:
    FLASK_OK = False

APP_NAME = "SENTINEL IDS PRO"
APP_VERSION = "3.1"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
DB_PATH = BASE_DIR / "ids_security.db"

DEFAULT_CONFIG = {
    "interface": "auto",
    "thresholds": {
        "syn_flood": 50,
        "udp_flood": 1000,
        "icmp_flood": 100,
        "port_scan": 15,
        "ping_sweep": 10,
        "data_exfiltration_mb": 10,
        "bruteforce_attempts": 50,
        "slowloris_connections": 40,
        "anomaly_score_limit": 100,
        "window_seconds": 2,
        "max_state_entries": 50000,
    },
    "alert_cooldown_seconds": 20,
    "alert_channels": {
        "sound": True,
        "webhook": {"enabled": False, "url": ""},
        "email": {
            "enabled": False, "smtp_host": "", "smtp_port": 587,
            "username": "", "password": "", "to_addr": "",
            "min_severity": "CRÍTICA",
        },
    },
    "auto_response": {"enabled": False, "block_on_critical": False, "method": "iptables", "ttl_seconds": 900, "protected_ips": []},
    "api": {"enabled": False, "port": 8787, "token": ""},
    "theme": "dark",
}


class AlertSeverity(Enum):
    CRITICA = "CRÍTICA"
    ALTA = "ALTA"
    MEDIA = "MEDIA"
    BAJA = "BAJA"
    INFO = "INFO"


class AlertType(Enum):
    DOS_ATTACK = "Ataque DoS (SYN Flood)"
    DDOS_UDP = "Ataque DDoS (UDP Flood)"
    ICMP_FLOOD = "Inundación ICMP / Smurf"
    PING_OF_DEATH = "Ping of Death"
    PING_SWEEP = "Barrido de Ping (Ping Sweep)"
    PORT_SCAN = "Escaneo de Puertos"
    SSH_VERSION_SCAN = "Escaneo de versión SSH"
    SLOWLORIS = "Agotamiento de conexiones (Slowloris)"
    BRUTE_FORCE = "Fuerza Bruta"
    MALWARE_PATTERN = "Patrón de Malware / Inyección"
    DATA_EXFILTRATION = "Exfiltración de Datos"
    ANOMALY = "Anomalía de Red (estadística)"
    DNS_TUNNELING = "Túnel DNS / Dominio sospechoso (DGA)"
    ARP_SPOOFING = "ARP Spoofing (conflicto IP-MAC)"
    HTTP_ANOMALY = "Tráfico HTTP anómalo"
    POLICY_VIOLATION = "Violación de Política (Blacklist)"
    RECONNAISSANCE = "Reconocimiento"


SEVERITY_WEIGHT = {"CRÍTICA": 4, "ALTA": 3, "MEDIA": 2, "BAJA": 1, "INFO": 0}


# ================================================================
# GESTOR DE CONFIGURACIÓN (persistencia real en config.json)
# ================================================================
class ConfigManager:
    def __init__(self, path=CONFIG_PATH):
        self.path = Path(path)
        self.data = self._load()

    def _deep_merge(self, base, override):
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v
        return base

    def _load(self):
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    user_cfg = json.load(f)
                cfg = self._deep_merge(cfg, user_cfg)
            except Exception:
                pass
        return cfg

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False

    def get(self, *keys, default=None):
        node = self.data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def set(self, value, *keys):
        node = self.data
        for k in keys[:-1]:
            node = node.setdefault(k, {})
        node[keys[-1]] = value


# ================================================================
# BASE DE DATOS (con hilo de escritura para no bloquear la captura)
# ================================================================
class DatabaseManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self._write_queue = queue.Queue()
        self._stop = threading.Event()
        self.init_database()
        self._writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._writer_thread.start()

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def init_database(self):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, severity TEXT, alert_type TEXT, description TEXT,
                src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
                protocol TEXT, packet_count INTEGER, bytes_transferred INTEGER,
                resolved INTEGER DEFAULT 0, notes TEXT DEFAULT ''
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS ip_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE, first_seen TEXT, last_seen TEXT,
                total_packets INTEGER DEFAULT 0, total_bytes INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0, risk_score REAL DEFAULT 0,
                is_blocked INTEGER DEFAULT 0
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS ip_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT, list_type TEXT, reason TEXT,
                added_date TEXT, expires_date TEXT,
                UNIQUE(ip_address, list_type)
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, event_type TEXT, user_action TEXT, details TEXT
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS arp_bindings (
                ip TEXT PRIMARY KEY, mac TEXT, last_seen TEXT
            )
        ''')
        # Migración compatible para instalaciones v2/v3 existentes.
        cols = {row[1] for row in cur.execute("PRAGMA table_info(alerts)").fetchall()}
        for name, ddl in (("risk_score", "REAL DEFAULT 0"), ("confidence", "REAL DEFAULT 0"),
                          ("mitre_id", "TEXT DEFAULT ''"), ("mitre_name", "TEXT DEFAULT ''")):
            if name not in cols:
                cur.execute(f"ALTER TABLE alerts ADD COLUMN {name} {ddl}")
        conn.commit()
        conn.close()

    # ---- escritura asíncrona ----
    def _writer_loop(self):
        while not self._stop.is_set() or not self._write_queue.empty():
            try:
                job = self._write_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                job()
            except Exception:
                pass
            finally:
                self._write_queue.task_done()

    def shutdown(self):
        # Drenar la cola antes de cerrar para no perder alertas/auditoría.
        try:
            self._write_queue.join()
        finally:
            self._stop.set()
            if self._writer_thread.is_alive():
                self._writer_thread.join(timeout=3)

    def insert_alert(self, alert_data):
        def job():
            conn = self._conn()
            conn.execute('''
                INSERT INTO alerts (timestamp, severity, alert_type, description,
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    packet_count, bytes_transferred, risk_score, confidence, mitre_id, mitre_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', alert_data)
            conn.commit()
            conn.close()
        self._write_queue.put(job)

    def get_recent_alerts(self, limit=200, severity=None, search=None):
        conn = self._conn()
        cur = conn.cursor()
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity and severity != "TODAS":
            query += " AND severity = ?"
            params.append(severity)
        if search:
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR description LIKE ?)"
            like = f"%{search}%"
            params += [like, like, like]
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()
        return rows

    def resolve_alert(self, alert_id, notes=""):
        def job():
            conn = self._conn()
            conn.execute("UPDATE alerts SET resolved = 1, notes = ? WHERE id = ?", (notes, alert_id))
            conn.commit()
            conn.close()
        self._write_queue.put(job)

    def update_ip_statistics(self, ip, packets=0, nbytes=0, alerts=0, risk_delta=0.0):
        def job():
            conn = self._conn()
            cur = conn.cursor()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur.execute("SELECT risk_score FROM ip_statistics WHERE ip=?", (ip,))
            row = cur.fetchone()
            if row:
                new_score = max(0.0, min(100.0, row[0] + risk_delta))
                cur.execute('''
                    UPDATE ip_statistics SET last_seen=?, total_packets=total_packets+?,
                        total_bytes=total_bytes+?, alert_count=alert_count+?, risk_score=?
                    WHERE ip=?
                ''', (now, packets, nbytes, alerts, new_score, ip))
            else:
                cur.execute('''
                    INSERT INTO ip_statistics (ip, first_seen, last_seen, total_packets,
                        total_bytes, alert_count, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (ip, now, now, packets, nbytes, alerts, max(0.0, risk_delta)))
            conn.commit()
            conn.close()
        self._write_queue.put(job)

    def get_top_ips(self, limit=15):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute('''SELECT ip, total_packets, total_bytes, alert_count, risk_score
                        FROM ip_statistics ORDER BY risk_score DESC, alert_count DESC LIMIT ?''', (limit,))
        rows = cur.fetchall()
        conn.close()
        return rows

    # ---- listas blancas/negras ----
    def add_to_list(self, ip, list_type, reason, expires=None):
        conn = self._conn()
        conn.execute('''INSERT OR REPLACE INTO ip_list (ip_address, list_type, reason, added_date, expires_date)
                         VALUES (?, ?, ?, ?, ?)''',
                      (ip, list_type, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), expires))
        conn.commit()
        conn.close()

    def remove_from_list(self, ip, list_type):
        conn = self._conn()
        conn.execute("DELETE FROM ip_list WHERE ip_address=? AND list_type=?", (ip, list_type))
        conn.commit()
        conn.close()

    def get_list(self, list_type):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT ip_address, reason, added_date, expires_date FROM ip_list WHERE list_type=?", (list_type,))
        rows = cur.fetchall()
        conn.close()
        return rows

    def is_in_list(self, ip, list_type):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT expires_date FROM ip_list WHERE ip_address=? AND list_type=?", (ip, list_type))
        row = cur.fetchone()
        conn.close()
        if not row:
            return False
        if row[0]:
            try:
                if datetime.now() > datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S"):
                    self.remove_from_list(ip, list_type)
                    return False
            except Exception:
                pass
        return True

    # ---- auditoría ----
    def log_audit(self, event_type, user_action, details=""):
        def job():
            conn = self._conn()
            conn.execute('''INSERT INTO audit_log (timestamp, event_type, user_action, details)
                             VALUES (?, ?, ?, ?)''',
                          (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_type, user_action, details))
            conn.commit()
            conn.close()
        self._write_queue.put(job)

    def get_audit_log(self, limit=300):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        return rows

    # ---- bindings ARP (para detección real de spoofing) ----
    def get_arp_binding(self, ip):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT mac FROM arp_bindings WHERE ip=?", (ip,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None

    def set_arp_binding(self, ip, mac):
        def job():
            conn = self._conn()
            conn.execute('''INSERT INTO arp_bindings (ip, mac, last_seen) VALUES (?, ?, ?)
                             ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, last_seen=excluded.last_seen''',
                          (ip, mac, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
        self._write_queue.put(job)


# ================================================================
# UTILIDADES DE ANÁLISIS
# ================================================================
def shannon_entropy(s):
    """Entropía de Shannon de una cadena — usada para detectar dominios DGA / DNS tunneling."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_private_ip(ip):
    try:
        parts = [int(p) for p in ip.split(".")]
    except Exception:
        return False
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    return False


MALWARE_SIGNATURES = {
    "sql_injection": [b"UNION SELECT", b"' OR '1'='1", b"DROP TABLE", b"; SELECT", b"xp_cmdshell"],
    "xss": [b"<script", b"javascript:", b"onerror=", b"onload=", b"document.cookie"],
    "command_injection": [b"; rm -rf", b"| nc ", b"$(", b"`whoami`", b"wget http", b"curl http"],
    "path_traversal": [b"../../../", b"..\\..\\", b"/etc/passwd"],
}

MITRE_MAP = {
    AlertType.DOS_ATTACK: ("T1498", "Network Denial of Service"),
    AlertType.DDOS_UDP: ("T1498", "Network Denial of Service"),
    AlertType.ICMP_FLOOD: ("T1498", "Network Denial of Service"),
    AlertType.PORT_SCAN: ("T1046", "Network Service Scanning"),
    AlertType.PING_SWEEP: ("T1018", "Remote System Discovery"),
    AlertType.SSH_VERSION_SCAN: ("T1046", "Network Service Scanning"),
    AlertType.BRUTE_FORCE: ("T1110", "Brute Force"),
    AlertType.DNS_TUNNELING: ("T1071.004", "DNS"),
    AlertType.MALWARE_PATTERN: ("T1059", "Command and Scripting Interpreter"),
    AlertType.HTTP_ANOMALY: ("T1190", "Exploit Public-Facing Application"),
    AlertType.ARP_SPOOFING: ("T1557", "Adversary-in-the-Middle"),
    AlertType.SLOWLORIS: ("T1498", "Network Denial of Service"),
    AlertType.DATA_EXFILTRATION: ("T1041", "Exfiltration Over C2 Channel"),
}

SEVERITY_WEIGHT = {
    "INFO": 0, "BAJA": 1, "MEDIA": 2, "ALTA": 3, "CRÍTICA": 4, "CRITICA": 4
}


# ================================================================
# MOTOR DE DETECCIÓN AVANZADO v2
# ================================================================
class AdvancedIDSEngine:
    def __init__(self, alert_queue, db_manager, config: ConfigManager, notifier=None):
        self.alert_queue = alert_queue
        self.db_manager = db_manager
        self.config = config
        self.notifier = notifier
        self.is_running = False
        self.offline_mode = False

        self.ip_timestamps = defaultdict(lambda: deque(maxlen=4000))   # SYN/UDP/ICMP flood
        self.ip_ports = defaultdict(lambda: {})                        # port -> last_seen ts (port scan)
        self.ip_size_history = defaultdict(lambda: deque(maxlen=40))   # tamaños recientes (anomalía)
        self.connection_bytes = defaultdict(int)                       # src->dst : bytes (exfiltración)
        self.bruteforce_tracker = defaultdict(lambda: deque(maxlen=200))
        self.slowloris_tracker = defaultdict(dict)                    # src_ip -> flow -> first_seen
        self.flow_last_seen = {}
        self.icmp_sweep_tracker = defaultdict(lambda: set())           # src_ip -> {dst_ip} (ping sweep)
        self.ssh_banner_tracker = defaultdict(lambda: 0)
        self.protocol_distribution = Counter()
        self.anomaly_scores = defaultdict(float)
        self.alert_cooldowns = {}   # (src_ip, alert_type) -> last_ts
        self._ip_stat_buffer = defaultdict(lambda: [0, 0])
        self._ip_stat_lock = threading.Lock()
        self._last_stat_flush = time.monotonic()

        self.stats = {"total_packets": 0, "total_bytes": 0, "alerts_generated": 0, "unique_ips": set(), "pcap_packets": 0, "pcap_path": ""}

        self.suspicious_ports = {135, 139, 445, 3389, 22, 3306, 5432, 27017, 6379, 23, 21}
        self.bruteforce_ports = {22, 3306, 5432, 3389, 21, 23}

    def set_response_manager(self, manager):
        self.response_manager = manager

    def _record_ip_traffic(self, ip, packet_size):
        with self._ip_stat_lock:
            self._ip_stat_buffer[ip][0] += 1
            self._ip_stat_buffer[ip][1] += packet_size
            should_flush = len(self._ip_stat_buffer) >= 100 or (time.monotonic() - self._last_stat_flush) >= 1.0
        if should_flush:
            self.flush_ip_statistics()

    def flush_ip_statistics(self):
        with self._ip_stat_lock:
            pending = dict(self._ip_stat_buffer)
            self._ip_stat_buffer.clear()
            self._last_stat_flush = time.monotonic()
        for ip, (packets, nbytes) in pending.items():
            self.db_manager.update_ip_statistics(ip, packets=packets, nbytes=nbytes)

    # ---------------- umbral helper ----------------
    def th(self, key):
        return self.config.get("thresholds", key, default=DEFAULT_CONFIG["thresholds"].get(key, 50))

    def _cooldown_ok(self, src_ip, alert_type, now=None):
        key = (src_ip, alert_type)
        now = time.time() if now is None else now
        last = self.alert_cooldowns.get(key, 0)
        cooldown = self.config.get("alert_cooldown_seconds", default=20)
        if now - last < cooldown:
            return False
        self.alert_cooldowns[key] = now
        return True

    # ---------------- entrada principal ----------------
    def analyze_packet(self, packet, event_time=None):
        if not self.offline_mode and not self.is_running:
            return

        self.stats["total_packets"] += 1

        if IP not in packet:
            if ARP in packet:
                self._detect_arp_spoofing(packet)
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        now = time.time() if event_time is None else float(event_time)
        self._expire_state(now)

        self.stats["unique_ips"].add(src_ip)
        # Estadísticas de tráfico se agregan en memoria y se escriben en batch para no
        # convertir cada paquete en una operación SQLite.
        self._record_ip_traffic(src_ip, packet_size)
        self.stats["total_bytes"] += packet_size

        if self.db_manager.is_in_list(src_ip, "blacklist"):
            self._trigger_alert(AlertSeverity.CRITICA, AlertType.POLICY_VIOLATION,
                                 f"Paquete de IP en blacklist: {src_ip}", src_ip, dst_ip, protocol="BLOCKED")
            return
        if self.db_manager.is_in_list(src_ip, "whitelist"):
            return

        self.protocol_distribution[packet[IP].proto] += 1
        self.ip_size_history[src_ip].append(packet_size)
        self.connection_bytes[f"{src_ip}->{dst_ip}"] += packet_size

        self._detect_syn_flood(packet, src_ip, dst_ip, now)
        self._detect_udp_flood(packet, src_ip, dst_ip, now)
        self._detect_icmp(packet, src_ip, dst_ip, now)
        self._detect_port_scan(packet, src_ip, dst_ip, now)
        self._detect_slowloris(packet, src_ip, dst_ip, now)
        self._detect_bruteforce(packet, src_ip, dst_ip, now)
        self._detect_data_exfiltration(src_ip, dst_ip, now)
        self._detect_payload_signatures(packet, src_ip, dst_ip, now)
        self._detect_http_anomaly(packet, src_ip, dst_ip, now)
        self._detect_dns(packet, src_ip, dst_ip, now)
        self._detect_statistical_anomaly(src_ip, dst_ip, packet_size, now)

    # ---------------- SYN Flood / DoS ----------------
    def _detect_syn_flood(self, packet, src_ip, dst_ip, now):
        if TCP not in packet or packet[TCP].flags != "S":
            return
        dq = self.ip_timestamps[f"syn:{src_ip}"]
        dq.append(now)
        while dq and now - dq[0] > 2:
            dq.popleft()
        if len(dq) > self.th("syn_flood") and self._cooldown_ok(src_ip, "SYN", now):
            self._trigger_alert(AlertSeverity.CRITICA, AlertType.DOS_ATTACK,
                                 f"SYN Flood: {len(dq)} paquetes SYN en 2s desde {src_ip}",
                                 src_ip, dst_ip, packet[TCP].sport, packet[TCP].dport, "TCP", risk=25)

    # ---------------- UDP Flood ----------------
    def _detect_udp_flood(self, packet, src_ip, dst_ip, now):
        if UDP not in packet:
            return
        dq = self.ip_timestamps[f"udp:{src_ip}"]
        dq.append(now)
        while dq and now - dq[0] > 1:
            dq.popleft()
        if len(dq) > self.th("udp_flood") and self._cooldown_ok(src_ip, "UDP", now):
            self._trigger_alert(AlertSeverity.ALTA, AlertType.DDOS_UDP,
                                 f"UDP Flood: {len(dq)} paquetes UDP en 1s desde {src_ip}",
                                 src_ip, dst_ip, packet[UDP].sport, packet[UDP].dport, "UDP", risk=20)

    # ---------------- ICMP: flood, ping of death, ping sweep ----------------
    def _detect_icmp(self, packet, src_ip, dst_ip, now):
        if ICMP not in packet:
            return
        icmp_type = packet[ICMP].type
        size = len(packet)

        if size > 65507:
            if self._cooldown_ok(src_ip, "POD", now):
                self._trigger_alert(AlertSeverity.CRITICA, AlertType.PING_OF_DEATH,
                                     f"Ping of Death: paquete ICMP de {size} bytes desde {src_ip}",
                                     src_ip, dst_ip, protocol="ICMP", risk=30)

        if icmp_type == 8:  # echo-request
            dq = self.ip_timestamps[f"icmp:{src_ip}"]
            dq.append(now)
            while dq and now - dq[0] > 2:
                dq.popleft()
            if len(dq) > self.th("icmp_flood") and self._cooldown_ok(src_ip, "ICMPFLOOD", now):
                self._trigger_alert(AlertSeverity.ALTA, AlertType.ICMP_FLOOD,
                                     f"Inundación ICMP: {len(dq)} echo-request en 2s desde {src_ip}",
                                     src_ip, dst_ip, protocol="ICMP", risk=18)

            self.icmp_sweep_tracker[src_ip].add(dst_ip)
            if len(self.icmp_sweep_tracker[src_ip]) > self.th("ping_sweep") and self._cooldown_ok(src_ip, "SWEEP", now):
                self._trigger_alert(AlertSeverity.MEDIA, AlertType.PING_SWEEP,
                                     f"Barrido de ping: {src_ip} sondeó {len(self.icmp_sweep_tracker[src_ip])} hosts",
                                     src_ip, "N/A", protocol="ICMP", risk=12)
                self.icmp_sweep_tracker[src_ip].clear()

    # ---------------- Port scanning ----------------
    def _detect_port_scan(self, packet, src_ip, dst_ip, now):
        if TCP not in packet or packet[TCP].flags != "S":
            return
        dst_port = int(packet[TCP].dport)
        key = (src_ip, dst_ip)
        ports = self.ip_ports[key]
        ports[dst_port] = now
        stale = [p for p, t in ports.items() if now - t > 5]
        for p in stale:
            del ports[p]

        # Escaneo vertical: muchos puertos contra el mismo host.
        if len(ports) > self.th("port_scan") and self._cooldown_ok(src_ip, f"PSCAN:{dst_ip}", now):
            self._trigger_alert(AlertSeverity.ALTA, AlertType.PORT_SCAN,
                                 f"Escaneo vertical: {len(ports)} puertos distintos contra {dst_ip} en 5s desde {src_ip}",
                                 src_ip, dst_ip, protocol="TCP", risk=22)
            ports.clear()

        # Reconocimiento SSH: conexiones SYN repetidas al servicio 22.
        if dst_port == 22:
            self.ssh_banner_tracker[src_ip] += 1
            if self.ssh_banner_tracker[src_ip] > 20 and self._cooldown_ok(src_ip, "SSHRECON", now):
                self._trigger_alert(AlertSeverity.MEDIA, AlertType.SSH_VERSION_SCAN,
                                     f"Reconocimiento SSH: más de 20 conexiones SYN al puerto 22 desde {src_ip}",
                                     src_ip, dst_ip, dst_port=22, protocol="TCP", risk=10)
                self.ssh_banner_tracker[src_ip] = 0

    # ---------------- Slowloris ----------------
    def _detect_slowloris(self, packet, src_ip, dst_ip, now):
        if TCP not in packet or packet[TCP].dport not in (80, 443, 8080):
            return
        flow = (dst_ip, packet[TCP].dport, packet[TCP].sport)
        flags = str(packet[TCP].flags)
        if "F" in flags or "R" in flags:
            self.slowloris_tracker[src_ip].pop(flow, None)
            return
        if flags == "S":
            self.slowloris_tracker[src_ip][flow] = now
        # Expirar conexiones que llevan demasiado tiempo sin cierre observado.
        stale = [k for k, seen in self.slowloris_tracker[src_ip].items() if now - seen > 300]
        for k in stale:
            self.slowloris_tracker[src_ip].pop(k, None)
        open_conns = len(self.slowloris_tracker[src_ip])
        if open_conns > self.th("slowloris_connections") and self._cooldown_ok(src_ip, "SLOWLORIS", now):
            self._trigger_alert(AlertSeverity.ALTA, AlertType.SLOWLORIS,
                                 f"Posible Slowloris: {open_conns} conexiones HTTP pendientes desde {src_ip}",
                                 src_ip, dst_ip, protocol="TCP", risk=20)

    # ---------------- Fuerza bruta ----------------
    def _detect_bruteforce(self, packet, src_ip, dst_ip, now):
        if TCP not in packet or packet[TCP].flags != "S":
            return
        dst_port = packet[TCP].dport
        if dst_port not in self.bruteforce_ports:
            return
        key = f"{src_ip}->{dst_ip}:{dst_port}"
        dq = self.bruteforce_tracker[key]
        dq.append(now)
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) > self.th("bruteforce_attempts") and self._cooldown_ok(src_ip, f"BF{dst_port}", now):
            self._trigger_alert(AlertSeverity.ALTA, AlertType.BRUTE_FORCE,
                                 f"Fuerza bruta: {len(dq)} intentos de conexión al puerto {dst_port} en 60s",
                                 src_ip, dst_ip, dst_port=dst_port, protocol="TCP", risk=28)

    # ---------------- Exfiltración de datos ----------------
    def _detect_data_exfiltration(self, src_ip, dst_ip, now=None):
        key = f"{src_ip}->{dst_ip}"
        total = self.connection_bytes[key]
        limit_bytes = self.th("data_exfiltration_mb") * 1024 * 1024
        if total > limit_bytes and self._cooldown_ok(src_ip, "EXFIL", now):
            self._trigger_alert(AlertSeverity.CRITICA, AlertType.DATA_EXFILTRATION,
                                 f"Posible exfiltración: {total / 1024 / 1024:.2f}MB transferidos {src_ip}→{dst_ip}",
                                 src_ip, dst_ip, protocol="TCP/UDP", risk=35)
            self.connection_bytes[key] = 0

    # ---------------- Firmas de malware en payload ----------------
    def _detect_payload_signatures(self, packet, src_ip, dst_ip, now):
        if Raw not in packet:
            return
        try:
            payload = bytes(packet[Raw].load)
        except Exception:
            return
        for kind, sigs in MALWARE_SIGNATURES.items():
            for sig in sigs:
                if sig in payload:
                    if self._cooldown_ok(src_ip, f"SIG{kind}", now):
                        self._trigger_alert(AlertSeverity.CRITICA, AlertType.MALWARE_PATTERN,
                                             f"Firma de {kind.replace('_', ' ')} detectada en payload",
                                             src_ip, dst_ip, protocol="PAYLOAD", risk=40)
                    return

    # ---------------- HTTP anómalo ----------------
    def _detect_http_anomaly(self, packet, src_ip, dst_ip, now):
        if TCP not in packet or Raw not in packet:
            return
        if packet[TCP].dport not in (80, 8080):
            return
        try:
            payload = bytes(packet[Raw].load)
        except Exception:
            return
        first_line = payload.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ", 2)
        if not parts:
            return
        method = parts[0].upper()
        known_methods = {b"GET", b"POST", b"PUT", b"HEAD", b"TRACE", b"CONNECT", b"PROPFIND", b"DEBUG", b"DELETE", b"OPTIONS", b"PATCH"}
        if method not in known_methods:
            return
        suspicious_methods = (b"TRACE", b"CONNECT", b"PROPFIND", b"DEBUG")
        very_long_uri = len(first_line) > 2048
        no_user_agent = b"User-Agent" not in payload and b"user-agent" not in payload.lower()
        if first_line.split(b" ")[0] in suspicious_methods or very_long_uri or no_user_agent:
            if self._cooldown_ok(src_ip, "HTTPANOM", now):
                reason = "método HTTP inusual" if first_line.split(b" ")[0] in suspicious_methods else \
                          "URI extremadamente larga" if very_long_uri else "sin cabecera User-Agent"
                self._trigger_alert(AlertSeverity.MEDIA, AlertType.HTTP_ANOMALY,
                                     f"Tráfico HTTP anómalo ({reason}) desde {src_ip}",
                                     src_ip, dst_ip, dst_port=packet[TCP].dport, protocol="HTTP", risk=10)

    # ---------------- DNS: tunneling / DGA por entropía ----------------
    def _detect_dns(self, packet, src_ip, dst_ip, now):
        if DNS not in packet:
            return
        dns_layer = packet[DNS]
        try:
            if dns_layer.qdcount > 0 and dns_layer.qd is not None:
                qname = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
                label = qname.split(".")[0] if "." in qname else qname
                ent = shannon_entropy(label)
                if len(label) > 20 and ent > 3.8:
                    if self._cooldown_ok(src_ip, "DGA", now):
                        self._trigger_alert(AlertSeverity.MEDIA, AlertType.DNS_TUNNELING,
                                             f"Dominio con alta entropía ({ent:.2f}) — posible DGA/tunneling: {qname[:60]}",
                                             src_ip, dst_ip, dst_port=53, protocol="DNS", risk=15)
        except Exception:
            pass
        if len(packet) > 512:
            if self._cooldown_ok(src_ip, "DNSBIG", now):
                self._trigger_alert(AlertSeverity.MEDIA, AlertType.DNS_TUNNELING,
                                     "Respuesta DNS inusualmente grande (posible túnel DNS)",
                                     src_ip, dst_ip, dst_port=53, protocol="DNS", risk=12)

    # ---------------- ARP Spoofing (con tabla real IP↔MAC) ----------------
    def _detect_arp_spoofing(self, packet):
        arp = packet[ARP]
        if arp.op != 2:  # solo ARP replies
            return
        ip, mac = arp.psrc, arp.hwsrc
        if ip == "0.0.0.0":
            return
        known_mac = self.db_manager.get_arp_binding(ip)
        if known_mac:
            if known_mac.lower() != mac.lower():
                if self._cooldown_ok(ip, "ARPSPOOF", time.time()):
                    self._trigger_alert(AlertSeverity.CRITICA, AlertType.ARP_SPOOFING,
                                         f"Conflicto ARP: {ip} anunciada por {mac} (antes {known_mac})",
                                         ip, "N/A", protocol="ARP", risk=35)
            return
        # Nunca sustituir silenciosamente un binding conocido por uno nuevo.
        # El primer binding se considera observado, no necesariamente confiable.
        self.db_manager.set_arp_binding(ip, mac)

    # ---------------- Anomalía estadística (z-score sobre tamaño de paquete) ----------------
    def _detect_statistical_anomaly(self, src_ip, dst_ip, packet_size, now):
        hist = self.ip_size_history[src_ip]
        if len(hist) < 15:
            return
        sample = list(hist)[:-1]
        mean = statistics.mean(sample)
        try:
            stdev = statistics.stdev(sample)
        except statistics.StatisticsError:
            stdev = 0
        if stdev == 0:
            return
        z = (packet_size - mean) / stdev
        if z > 4:
            self.anomaly_scores[src_ip] = min(100, self.anomaly_scores[src_ip] + 8)
        else:
            self.anomaly_scores[src_ip] = max(0, self.anomaly_scores[src_ip] - 1)  # decaimiento

        if self.anomaly_scores[src_ip] >= self.th("anomaly_score_limit") and self._cooldown_ok(src_ip, "ANOM", now):
            self._trigger_alert(AlertSeverity.ALTA, AlertType.ANOMALY,
                                 f"Comportamiento anómalo sostenido de {src_ip} (score={self.anomaly_scores[src_ip]:.0f})",
                                 src_ip, dst_ip, protocol="ANOMALY", risk=0)
            self.anomaly_scores[src_ip] = 0

    # ---------------- disparo de alertas ----------------
    def _trigger_alert(self, severity, alert_type, description, src_ip, dst_ip,
                        src_port=0, dst_port=0, protocol="", risk=10, event_time=None):
        event_ts = time.time() if event_time is None else float(event_time)
        timestamp = datetime.fromtimestamp(event_ts).strftime("%Y-%m-%d %H:%M:%S")
        mitre_id, mitre_name = MITRE_MAP.get(alert_type, ("", ""))
        base_risk = SEVERITY_WEIGHT.get(severity.value, 30)
        confidence = min(100.0, max(20.0, 55.0 + float(risk) * 0.8))
        final_risk = min(100.0, max(0.0, base_risk * 14.0 + float(risk) * 1.25 + confidence * 0.20))
        alert_data = (timestamp, severity.value, alert_type.value, description,
                      src_ip, dst_ip, src_port, dst_port, protocol, 1, 0)
        db_alert_data = alert_data + (round(final_risk, 2), round(confidence, 2), mitre_id, mitre_name)

        self.alert_queue.put(alert_data)
        self.db_manager.insert_alert(db_alert_data)
        self.stats["alerts_generated"] += 1
        self.db_manager.update_ip_statistics(src_ip, packets=0, nbytes=0, alerts=1, risk_delta=final_risk / 10.0)

        if self.notifier:
            self.notifier.notify(severity.value, alert_type.value, description, src_ip, dst_ip)

        # Respuesta automática solo después de registrar la alerta y respetando exclusiones.
        if (severity == AlertSeverity.CRITICA and
                self.config.get("auto_response", "enabled", default=False) and
                self.config.get("auto_response", "block_on_critical", default=False) and
                hasattr(self, "response_manager") and src_ip not in ("N/A", "0.0.0.0")):
            try:
                self.response_manager.block_ip(src_ip)
            except Exception:
                pass

    # ---------------- mantenimiento ----------------
    def _expire_state(self, now):
        """Limita el crecimiento de estado en sensores de larga duración."""
        max_entries = int(self.th("max_state_entries"))
        if len(self.connection_bytes) > max_entries:
            for key in list(self.connection_bytes)[:len(self.connection_bytes) - max_entries]:
                self.connection_bytes.pop(key, None)
        if len(self.flow_last_seen) > max_entries:
            cutoff = now - max(60, int(self.th("window_seconds")) * 10)
            for key, ts in list(self.flow_last_seen.items()):
                if ts < cutoff:
                    self.flow_last_seen.pop(key, None)
        if len(self.alert_cooldowns) > max_entries:
            cutoff = now - max(60, int(self.config.get("alert_cooldown_seconds", default=20)) * 10)
            for key, ts in list(self.alert_cooldowns.items()):
                if ts < cutoff:
                    self.alert_cooldowns.pop(key, None)

    def reset_state(self):
        self.ip_timestamps.clear()
        self.ip_ports.clear()
        self.ip_size_history.clear()
        self.connection_bytes.clear()
        self.bruteforce_tracker.clear()
        self.slowloris_tracker.clear()
        self.icmp_sweep_tracker.clear()
        self.ssh_banner_tracker.clear()
        self.anomaly_scores.clear()
        self.alert_cooldowns.clear()

    # ---------------- captura ----------------
    def start_sniffing(self, iface=None):
        self.is_running = True
        kwargs = {"prn": self.analyze_packet, "store": False, "stop_filter": lambda x: not self.is_running}
        if iface and iface != "auto":
            kwargs["iface"] = iface
        try:
            sniff(**kwargs)
        except PermissionError:
            self.alert_queue.put((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "CRÍTICA",
                                   "Error de permisos", "Se requieren privilegios de root para capturar paquetes",
                                   "N/A", "N/A", 0, 0, "SYSTEM", 0, 0))
            self.is_running = False
        except Exception as e:
            self.alert_queue.put((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "CRÍTICA",
                                   "Error de captura", str(e), "N/A", "N/A", 0, 0, "SYSTEM", 0, 0))
            self.is_running = False

    def stop_sniffing(self):
        self.is_running = False

    def analyze_pcap_file(self, path, progress_cb=None):
        """Modo offline: analiza un archivo .pcap sin necesitar privilegios de root."""
        self.offline_mode = True
        self.reset_state()
        self.stats["pcap_path"] = str(path)
        try:
            packets = rdpcap(path)
            total = len(packets)
            self.stats["pcap_packets"] = total
            for i, pkt in enumerate(packets):
                # En offline se usa el timestamp real del PCAP para que las ventanas
                # de detección representen el tiempo del incidente y no la velocidad
                # de procesamiento del equipo.
                ts = getattr(pkt, "time", None)
                self.analyze_packet(pkt, event_time=float(ts) if ts is not None else time.time())
                if progress_cb and i % 200 == 0:
                    progress_cb(i, total)
            if progress_cb:
                progress_cb(total, total)
        finally:
            self.flush_ip_statistics()
            self.offline_mode = False


# ================================================================
# NOTIFICADOR (webhook, email, sonido) — corre en hilos, no bloquea el sniffer
# ================================================================
class Notifier:
    def __init__(self, config: ConfigManager, db_manager: DatabaseManager):
        self.config = config
        self.db = db_manager

    def notify(self, severity, alert_type, description, src_ip, dst_ip):
        threading.Thread(target=self._dispatch, args=(severity, alert_type, description, src_ip, dst_ip),
                          daemon=True).start()

    def _dispatch(self, severity, alert_type, description, src_ip, dst_ip):
        if self.config.get("alert_channels", "sound", default=True) and severity in ("CRÍTICA", "ALTA"):
            self._play_sound()

        wh = self.config.get("alert_channels", "webhook", default={})
        if wh.get("enabled") and wh.get("url") and REQUESTS_OK:
            try:
                requests.post(wh["url"], json={
                    "severity": severity, "type": alert_type, "description": description,
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "timestamp": datetime.now().isoformat(),
                }, timeout=4)
            except Exception as e:
                self.db.log_audit("WEBHOOK_ERROR", "notify", str(e))

        em = self.config.get("alert_channels", "email", default={})
        if em.get("enabled") and em.get("smtp_host") and em.get("to_addr"):
            min_sev = em.get("min_severity", "CRÍTICA")
            if SEVERITY_WEIGHT.get(severity, 0) >= SEVERITY_WEIGHT.get(min_sev, 4):
                self._send_email(em, severity, alert_type, description, src_ip, dst_ip)

    def _play_sound(self):
        try:
            if sys.platform.startswith("win"):
                import winsound
                winsound.MessageBeep()
            else:
                sys.stdout.write("\a")
                sys.stdout.flush()
        except Exception:
            pass

    def _send_email(self, em, severity, alert_type, description, src_ip, dst_ip):
        try:
            body = (f"SENTINEL IDS PRO — Alerta {severity}\n\nTipo: {alert_type}\n"
                    f"Descripción: {description}\nOrigen: {src_ip}\nDestino: {dst_ip}\n"
                    f"Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            msg = MIMEText(body, _charset="utf-8")
            msg["Subject"] = f"[SENTINEL IDS] Alerta {severity}: {alert_type}"
            msg["From"] = em.get("username", "sentinel-ids@localhost")
            msg["To"] = em["to_addr"]
            with smtplib.SMTP(em["smtp_host"], int(em.get("smtp_port", 587)), timeout=8) as server:
                server.starttls()
                if em.get("username") and em.get("password"):
                    server.login(em["username"], em["password"])
                server.sendmail(msg["From"], [em["to_addr"]], msg.as_string())
        except Exception as e:
            self.db.log_audit("EMAIL_ERROR", "notify", str(e))


# ================================================================
# AUTO-RESPUESTA (bloqueo de IP) — siempre requiere confirmación explícita
# ================================================================
class ResponseManager:
    def __init__(self, config: ConfigManager, db_manager: DatabaseManager):
        self.config = config
        self.db = db_manager
        self._timers = {}
        self._timer_lock = threading.Lock()

    def _validate_ip(self, ip):
        return str(ipaddress.ip_address(ip))

    def _protected(self, ip):
        protected = set(self.config.get("auto_response", "protected_ips", default=[]))
        protected.update({"127.0.0.1", "0.0.0.0", "::1"})
        return ip in protected or self.db.is_in_list(ip, "whitelist")

    def block_ip(self, ip):
        method = self.config.get("auto_response", "method", default="iptables")
        if not self.config.get("auto_response", "enabled", default=False):
            return False
        try:
            ip = self._validate_ip(ip)
            if self._protected(ip):
                self.db.log_audit("BLOCK_IP_DENIED", "BLOCK_IP", f"IP protegida: {ip}")
                return False
            if method == "iptables":
                check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                                       capture_output=True, text=True, timeout=10)
                if check.returncode == 0:
                    ok = True
                else:
                    result = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                                            capture_output=True, text=True, timeout=10)
                    ok = result.returncode == 0
            elif method == "ufw":
                result = subprocess.run(["ufw", "deny", "from", ip], capture_output=True, text=True, timeout=10)
                ok = result.returncode == 0
            else:
                ok = False
            self.db.log_audit("BLOCK_IP", method, f"{ip} -> {'OK' if ok else 'FALLÓ'}")
            if ok:
                ttl = int(self.config.get("auto_response", "ttl_seconds", default=0) or 0)
                if ttl > 0:
                    with self._timer_lock:
                        old = self._timers.pop(ip, None)
                        if old:
                            old.cancel()
                        timer = threading.Timer(ttl, self._expire_block, args=(ip,))
                        timer.daemon = True
                        self._timers[ip] = timer
                        timer.start()
            return ok
        except (ValueError, TypeError) as e:
            self.db.log_audit("BLOCK_IP_ERROR", method, f"IP inválida {ip}: {e}")
            return False
        except FileNotFoundError:
            self.db.log_audit("BLOCK_IP_ERROR", method, f"{ip}: comando no encontrado")
            return False
        except Exception as e:
            self.db.log_audit("BLOCK_IP_ERROR", method, f"{ip}: {e}")
            return False

    def _expire_block(self, ip):
        try:
            self.unblock_ip(ip)
        finally:
            with self._timer_lock:
                self._timers.pop(ip, None)

    def unblock_ip(self, ip):
        method = self.config.get("auto_response", "method", default="iptables")
        try:
            ip = self._validate_ip(ip)
            if method == "iptables":
                result = subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                                        capture_output=True, text=True, timeout=10)
                ok = result.returncode == 0
            elif method == "ufw":
                result = subprocess.run(["ufw", "delete", "deny", "from", ip],
                                        capture_output=True, text=True, timeout=10)
                ok = result.returncode == 0
            else:
                ok = False
            self.db.log_audit("UNBLOCK_IP", method, f"{ip} -> {'OK' if ok else 'FALLÓ'}")
            return ok
        except Exception as e:
            self.db.log_audit("UNBLOCK_IP_ERROR", method, f"{ip}: {e}")
            return False


# ================================================================
# API REST OPCIONAL (Flask) — solo lectura + bloqueo manual
# ================================================================
class APIServer:
    def __init__(self, db_manager, engine, response_mgr, port=8787, config=None):
        self.db = db_manager
        self.engine = engine
        self.response_mgr = response_mgr
        self.port = port
        self.config = config
        self._thread = None
        self.app = None

    def config_token(self):
        return self.config.get("api", "token", default="") if self.config else ""

    def start(self):
        if not FLASK_OK:
            return False
        self.app = Flask("sentinel_ids_api")
        app = self.app

        def authorized():
            token = self.config_token()
            if not token:
                return True
            supplied = flask_request.headers.get("X-Sentinel-Token", "")
            return supplied == token

        @app.before_request
        def require_auth():
            if flask_request.path.startswith("/api/") and not authorized():
                return jsonify({"error": "unauthorized"}), 401

        @app.route("/api/health")
        def health():
            return jsonify({"status": "ok", "version": APP_VERSION, "running": self.engine.is_running})

        @app.route("/api/stats")
        def stats():
            s = self.engine.stats
            return jsonify({
                "total_packets": s["total_packets"], "total_bytes": s["total_bytes"],
                "alerts_generated": s["alerts_generated"], "unique_ips": len(s["unique_ips"]),
                "running": self.engine.is_running,
            })

        @app.route("/api/alerts")
        def alerts():
            try:
                limit = int(flask_request.args.get("limit", 50))
            except (TypeError, ValueError):
                return jsonify({"error": "limit inválido"}), 400
            limit = max(1, min(limit, 1000))
            rows = self.db.get_recent_alerts(limit=limit)
            cols = ["id", "timestamp", "severity", "alert_type", "description", "src_ip", "dst_ip",
                    "src_port", "dst_port", "protocol", "packet_count", "bytes_transferred", "resolved", "notes"]
            return jsonify([dict(zip(cols, r)) for r in rows])

        @app.route("/api/top_ips")
        def top_ips():
            rows = self.db.get_top_ips(20)
            return jsonify([{"ip": r[0], "packets": r[1], "bytes": r[2], "alerts": r[3], "risk": r[4]} for r in rows])

        @app.route("/api/block/<ip>", methods=["POST"])
        def block(ip):
            ok = self.response_mgr.block_ip(ip)
            return jsonify({"ip": ip, "blocked": ok})

        self._thread = threading.Thread(
            target=lambda: app.run(host="127.0.0.1", port=self.port, debug=False, use_reloader=False),
            daemon=True)
        self._thread.start()
        return True


# ================================================================
# GENERADOR DE REPORTES
# ================================================================
class ReportGenerator:
    def __init__(self, db_manager, engine):
        self.db = db_manager
        self.engine = engine

    def to_json(self, path, limit=1000):
        alerts = self.db.get_recent_alerts(limit)
        cols = ["id", "timestamp", "severity", "alert_type", "description", "src_ip", "dst_ip",
                "src_port", "dst_port", "protocol", "packet_count", "bytes_transferred", "resolved", "notes"]
        data = {
            "generated": datetime.now().isoformat(),
            "stats": {k: (list(v) if isinstance(v, set) else v) for k, v in self.engine.stats.items()},
            "alerts": [dict(zip(cols, a)) for a in alerts],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def to_csv(self, path, limit=10000):
        alerts = self.db.get_recent_alerts(limit)
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Timestamp", "Severity", "Type", "Description", "SrcIP", "DstIP", "SrcPort", "DstPort", "Protocol", "PacketCount", "Bytes", "Resolved", "Notes"])
            writer.writerows(alerts)

    def to_html(self, path, limit=200):
        alerts = self.db.get_recent_alerts(limit)
        stats = self.engine.stats
        sev_counts = Counter(a[2] for a in alerts)
        rows = ""
        for a in alerts[:150]:
            row_class = {"CRÍTICA": "crit", "ALTA": "high", "MEDIA": "med"}.get(a[2], "")
            rows += (f'<tr class="{row_class}"><td>{html.escape(str(a[1]))}</td><td>{html.escape(str(a[2]))}</td><td>{html.escape(str(a[3]))}</td>'
                     f'<td>{html.escape(str(a[4]))}</td><td>{html.escape(str(a[5]))}</td><td>{html.escape(str(a[6]))}</td></tr>\n')
        html = f"""<html><head><meta charset="utf-8"><title>Reporte SENTINEL IDS PRO</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#f4f6f8; color:#1a2332; margin:0; }}
.header {{ background:linear-gradient(135deg,#00d4ff,#0088cc); padding:30px; color:#001a26; }}
.header h1 {{ margin:0; }}
.metrics {{ display:flex; gap:15px; padding:20px 30px; flex-wrap:wrap; }}
.metric {{ background:white; padding:18px 24px; border-radius:8px; box-shadow:0 1px 4px rgba(0,0,0,.1); flex:1; min-width:150px; }}
.metric .val {{ font-size:26px; font-weight:bold; color:#0088cc; }}
table {{ border-collapse:collapse; width:calc(100% - 60px); margin:20px 30px; background:white; box-shadow:0 1px 4px rgba(0,0,0,.1); }}
th, td {{ padding:10px 14px; text-align:left; border-bottom:1px solid #eee; font-size:13px; }}
th {{ background:#1a2332; color:white; }}
tr.crit {{ background:#ffe0e0; }} tr.high {{ background:#fff0dc; }} tr.med {{ background:#e0f0ff; }}
.footer {{ padding:20px 30px; color:#777; font-size:12px; }}
</style></head><body>
<div class="header"><h1>🛡️ SENTINEL IDS PRO v{APP_VERSION}</h1><p>Reporte de seguridad generado: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p></div>
<div class="metrics">
  <div class="metric">Paquetes analizados<div class="val">{stats['total_packets']}</div></div>
  <div class="metric">Alertas totales<div class="val">{stats['alerts_generated']}</div></div>
  <div class="metric">Tráfico<div class="val">{stats['total_bytes']/1024/1024:.2f} MB</div></div>
  <div class="metric">IPs únicas<div class="val">{len(stats['unique_ips'])}</div></div>
  <div class="metric">Críticas<div class="val">{sev_counts.get('CRÍTICA',0)}</div></div>
  <div class="metric">Altas<div class="val">{sev_counts.get('ALTA',0)}</div></div>
</div>
<h2 style="margin-left:30px;">Alertas recientes</h2>
<table><tr><th>Fecha</th><th>Severidad</th><th>Tipo</th><th>Descripción</th><th>IP Origen</th><th>IP Destino</th></tr>
{rows}</table>
<div class="footer">Generado automáticamente por SENTINEL IDS PRO — Hecho para proteger, diseñado para escalar.</div>
</body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def to_pdf(self, path, limit=100):
        if not REPORTLAB_OK:
            raise RuntimeError("reportlab no está instalado (pip install reportlab)")
        alerts = self.db.get_recent_alerts(limit)
        stats = self.engine.stats
        sev_counts = Counter(a[2] for a in alerts)

        doc = SimpleDocTemplate(path, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("TitleX", parent=styles["Title"], textColor=rl_colors.HexColor("#0088cc"))
        elems = []
        elems.append(Paragraph(f"🛡 SENTINEL IDS PRO v{APP_VERSION} — Reporte de Seguridad", title_style))
        elems.append(Paragraph(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        elems.append(Spacer(1, 0.5 * cm))

        summary_data = [
            ["Métrica", "Valor"],
            ["Paquetes analizados", str(stats["total_packets"])],
            ["Alertas totales", str(stats["alerts_generated"])],
            ["Tráfico total (MB)", f"{stats['total_bytes']/1024/1024:.2f}"],
            ["IPs únicas observadas", str(len(stats["unique_ips"]))],
            ["Alertas CRÍTICAS", str(sev_counts.get("CRÍTICA", 0))],
            ["Alertas ALTAS", str(sev_counts.get("ALTA", 0))],
            ["Alertas MEDIAS", str(sev_counts.get("MEDIA", 0))],
        ]
        t = Table(summary_data, colWidths=[8 * cm, 6 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#1a2332")),
            ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#f4f6f8")]),
        ]))
        elems.append(t)
        elems.append(Spacer(1, 0.8 * cm))
        elems.append(Paragraph("Alertas recientes (máx. 60 mostradas)", styles["Heading2"]))

        table_data = [["Fecha", "Sev.", "Tipo", "Origen", "Destino"]]
        for a in alerts[:60]:
            table_data.append([a[1], a[2], Paragraph(a[3][:40], styles["Normal"]), a[5], a[6]])
        t2 = Table(table_data, colWidths=[3.2 * cm, 1.8 * cm, 6 * cm, 3 * cm, 3 * cm], repeatRows=1)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#1a2332")),
            ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, rl_colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for i, a in enumerate(alerts[:60], start=1):
            if a[2] == "CRÍTICA":
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), rl_colors.HexColor("#ffe0e0")))
            elif a[2] == "ALTA":
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), rl_colors.HexColor("#fff0dc")))
        t2.setStyle(TableStyle(style_cmds))
        elems.append(t2)

        doc.build(elems)


# ================================================================
# TEMAS
# ================================================================
THEMES = {
    "dark": {
        "bg": "#0f1419", "fg": "#e0e0e0", "accent": "#00d4ff", "success": "#00ff41",
        "warning": "#ffaa00", "danger": "#ff4455", "dark": "#1a2332", "entry_bg": "#101820",
    },
    "light": {
        "bg": "#f4f6f8", "fg": "#1a2332", "accent": "#0088cc", "success": "#0a8f2f",
        "warning": "#c97800", "danger": "#c62828", "dark": "#ffffff", "entry_bg": "#ffffff",
    },
}


# ================================================================
# INTERFAZ GRÁFICA PRINCIPAL
# ================================================================
class ProfessionalIDSDashboard:
    def __init__(self, root, pcap_file=None):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION} — Sistema Profesional de Detección de Intrusiones")
        self.root.geometry("1500x860")

        self.config = ConfigManager()
        self.colors = THEMES[self.config.get("theme", default="dark")]
        self.root.configure(bg=self.colors["bg"])

        self.db_manager = DatabaseManager()
        self.alert_queue = queue.Queue()
        self.notifier = Notifier(self.config, self.db_manager)
        self.response_mgr = ResponseManager(self.config, self.db_manager)
        self.engine = AdvancedIDSEngine(self.alert_queue, self.db_manager, self.config, self.notifier)
        self.engine.set_response_manager(self.response_mgr)
        self.reporter = ReportGenerator(self.db_manager, self.engine)
        self.api_server = APIServer(self.db_manager, self.engine, self.response_mgr,
                                     port=self.config.get("api", "port", default=8787), config=self.config)

        self.traffic_data = deque(maxlen=60)
        self.alert_data = deque(maxlen=60)
        self.current_severity_filter = "TODAS"
        self.current_search = ""

        self.setup_ui()
        self.check_queue()
        self.update_statistics()
        self.db_manager.log_audit("STARTUP", "app_launch", f"v{APP_VERSION}")

        if self.config.get("api", "enabled", default=False):
            self.api_server.start()

        if pcap_file:
            self.root.after(300, lambda: self._analyze_pcap_path(pcap_file))

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ------------------------------------------------------------
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 8))
        style.configure("Treeview", background=self.colors["entry_bg"], fieldbackground=self.colors["entry_bg"],
                         foreground=self.colors["fg"], rowheight=24)
        style.configure("Treeview.Heading", background=self.colors["dark"], foreground=self.colors["accent"],
                         font=("Segoe UI", 9, "bold"))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.create_dashboard_tab()
        self.create_alerts_tab()
        self.create_analytics_tab()
        self.create_settings_tab()
        self.create_reports_tab()
        self.create_audit_tab()

    # ------------------------------------------------------------
    def create_dashboard_tab(self):
        frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(frame, text="📊 Dashboard")

        control_frame = tk.Frame(frame, bg=self.colors["dark"])
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        button_frame = tk.Frame(control_frame, bg=self.colors["dark"])
        button_frame.pack(side=tk.LEFT, padx=10, pady=10)

        self.btn_start = tk.Button(button_frame, text="▶ INICIAR IDS (en vivo)", bg=self.colors["success"],
                                    fg="#000", font=("Segoe UI", 11, "bold"), command=self.start_ids,
                                    padx=15, pady=8, relief=tk.FLAT, cursor="hand2")
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_stop = tk.Button(button_frame, text="⏹ DETENER", bg=self.colors["danger"], fg="#fff",
                                   font=("Segoe UI", 11, "bold"), command=self.stop_ids,
                                   padx=15, pady=8, relief=tk.FLAT, cursor="hand2", state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_pcap = tk.Button(button_frame, text="📂 Analizar .pcap (offline)", bg=self.colors["accent"],
                                   fg="#000", font=("Segoe UI", 10, "bold"), command=self.open_pcap_dialog,
                                   padx=12, pady=8, relief=tk.FLAT, cursor="hand2")
        self.btn_pcap.pack(side=tk.LEFT, padx=5)

        status_frame = tk.Frame(control_frame, bg=self.colors["dark"])
        status_frame.pack(side=tk.RIGHT, padx=15)
        tk.Label(status_frame, text="Estado:", bg=self.colors["dark"], fg=self.colors["accent"],
                 font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.status_label = tk.Label(status_frame, text="● INACTIVO", bg=self.colors["dark"],
                                      fg=self.colors["danger"], font=("Segoe UI", 10, "bold"))
        self.status_label.pack(side=tk.LEFT, padx=5)

        metrics_frame = tk.Frame(frame, bg=self.colors["bg"])
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)

        self.metric_widgets = {}
        metrics = [
            ("packets", "Paquetes", self.colors["accent"]),
            ("alerts", "Alertas", self.colors["danger"]),
            ("threats", "IPs Únicas", self.colors["warning"]),
            ("bandwidth", "Tráfico", self.colors["success"]),
        ]
        for metric, label, color in metrics:
            box = tk.Frame(metrics_frame, bg=color)
            box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
            tk.Label(box, text=label, bg=color, fg="#000", font=("Segoe UI", 9, "bold")).pack(pady=3)
            val = tk.Label(box, text="0", bg=color, fg="#000", font=("Segoe UI", 16, "bold"))
            val.pack(pady=3)
            self.metric_widgets[metric] = val

        graph_frame = tk.Frame(frame, bg=self.colors["bg"])
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.fig = Figure(figsize=(12, 4), dpi=100, facecolor=self.colors["bg"])
        self.ax1 = self.fig.add_subplot(121)
        self.ax2 = self.fig.add_subplot(122)
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # ------------------------------------------------------------
    def create_alerts_tab(self):
        frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(frame, text="🚨 Alertas")

        toolbar = tk.Frame(frame, bg=self.colors["dark"])
        toolbar.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(toolbar, text="Severidad:", bg=self.colors["dark"], fg=self.colors["accent"],
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=5)
        self.severity_var = tk.StringVar(value="TODAS")
        severity_combo = ttk.Combobox(toolbar, textvariable=self.severity_var,
                                       values=["TODAS", "CRÍTICA", "ALTA", "MEDIA", "BAJA", "INFO"],
                                       state="readonly", width=12)
        severity_combo.pack(side=tk.LEFT, padx=5)

        tk.Label(toolbar, text="Buscar (IP/texto):", bg=self.colors["dark"], fg=self.colors["accent"],
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(15, 5))
        self.search_entry = tk.Entry(toolbar, width=22, font=("Segoe UI", 9))
        self.search_entry.pack(side=tk.LEFT, padx=5)

        tk.Button(toolbar, text="🔄 Actualizar", bg=self.colors["accent"], fg="#000",
                  font=("Segoe UI", 9, "bold"), relief=tk.FLAT,
                  command=self.refresh_alerts).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="✅ Resolver seleccionada", bg=self.colors["success"], fg="#000",
                  font=("Segoe UI", 9, "bold"), relief=tk.FLAT,
                  command=self.resolve_selected_alert).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="🚫 Bloquear IP origen", bg=self.colors["danger"], fg="#fff",
                  font=("Segoe UI", 9, "bold"), relief=tk.FLAT,
                  command=self.block_selected_ip).pack(side=tk.LEFT, padx=5)

        columns = ("ID", "Timestamp", "Severidad", "Tipo", "Descripción", "Origen", "Destino",
                   "SPort", "DPort", "Protocolo", "Resuelto")
        self.alerts_tree = ttk.Treeview(frame, columns=columns, show="headings", height=20)
        widths = {"ID": 45, "Timestamp": 140, "Severidad": 80, "Tipo": 170, "Descripción": 300,
                  "Origen": 110, "Destino": 110, "SPort": 55, "DPort": 55, "Protocolo": 80, "Resuelto": 65}
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=widths.get(col, 100), anchor=tk.W)

        self.alerts_tree.tag_configure("CRÍTICA", background="#660000", foreground="#ff8888")
        self.alerts_tree.tag_configure("ALTA", background="#663300", foreground="#ffcc88")
        self.alerts_tree.tag_configure("MEDIA", background="#334466", foreground="#88ccff")
        self.alerts_tree.tag_configure("BAJA", background="#335533", foreground="#88ff99")
        self.alerts_tree.tag_configure("INFO", background="#333333", foreground="#cccccc")

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscroll=scrollbar.set)
        self.alerts_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5, side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT, pady=5)

    # ------------------------------------------------------------
    def create_analytics_tab(self):
        frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(frame, text="📈 Análisis")

        analytics_notebook = ttk.Notebook(frame)
        analytics_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        stats_frame = ttk.Frame(analytics_notebook)
        analytics_notebook.add(stats_frame, text="Estadísticas Globales")
        self.stats_text = scrolledtext.ScrolledText(stats_frame, bg=self.colors["entry_bg"], fg=self.colors["fg"],
                                                      font=("Consolas", 10), height=20)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ips_frame = ttk.Frame(analytics_notebook)
        analytics_notebook.add(ips_frame, text="IPs Sospechosas")
        columns = ("IP", "Paquetes", "Bytes", "Alertas", "Riesgo")
        self.ips_tree = ttk.Treeview(ips_frame, columns=columns, show="headings", height=18)
        for col in columns:
            self.ips_tree.heading(col, text=col)
            self.ips_tree.column(col, width=180, anchor=tk.CENTER)
        self.ips_tree.tag_configure("risk_high", background="#661111", foreground="#ffaaaa")
        self.ips_tree.tag_configure("risk_mid", background="#664411", foreground="#ffdd99")
        self.ips_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        protocols_frame = ttk.Frame(analytics_notebook)
        analytics_notebook.add(protocols_frame, text="Protocolos")
        self.protocols_text = scrolledtext.ScrolledText(protocols_frame, bg=self.colors["entry_bg"],
                                                          fg=self.colors["fg"], font=("Consolas", 10))
        self.protocols_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # ------------------------------------------------------------
    def create_settings_tab(self):
        frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(frame, text="⚙ Configuración")

        config_notebook = ttk.Notebook(frame)
        config_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self._build_thresholds_tab(config_notebook)
        self._build_lists_tab(config_notebook)
        self._build_channels_tab(config_notebook)
        self._build_system_tab(config_notebook)

    def _build_thresholds_tab(self, parent):
        t = ttk.Frame(parent)
        parent.add(t, text="Umbrales")
        labels = [
            ("SYN Flood (paquetes/2s)", "syn_flood"), ("UDP Flood (paquetes/1s)", "udp_flood"),
            ("ICMP Flood (echo/2s)", "icmp_flood"), ("Escaneo de puertos (puertos/5s)", "port_scan"),
            ("Ping sweep (hosts distintos)", "ping_sweep"), ("Exfiltración de datos (MB)", "data_exfiltration_mb"),
            ("Intentos de fuerza bruta (60s)", "bruteforce_attempts"),
            ("Conexiones Slowloris simultáneas", "slowloris_connections"),
            ("Umbral score de anomalía", "anomaly_score_limit"),
        ]
        self.threshold_entries = {}
        for i, (label, key) in enumerate(labels):
            row = tk.Frame(t, bg=self.colors["bg"])
            row.pack(fill=tk.X, padx=20, pady=6)
            tk.Label(row, text=label, bg=self.colors["bg"], fg=self.colors["fg"],
                     font=("Segoe UI", 10), width=34, anchor="w").pack(side=tk.LEFT)
            entry = tk.Entry(row, width=12, font=("Segoe UI", 10))
            entry.insert(0, str(self.config.get("thresholds", key, default=50)))
            entry.pack(side=tk.LEFT, padx=10)
            self.threshold_entries[key] = entry

        row = tk.Frame(t, bg=self.colors["bg"])
        row.pack(fill=tk.X, padx=20, pady=6)
        tk.Label(row, text="Cooldown entre alertas repetidas (s)", bg=self.colors["bg"], fg=self.colors["fg"],
                 font=("Segoe UI", 10), width=34, anchor="w").pack(side=tk.LEFT)
        self.cooldown_entry = tk.Entry(row, width=12, font=("Segoe UI", 10))
        self.cooldown_entry.insert(0, str(self.config.get("alert_cooldown_seconds", default=20)))
        self.cooldown_entry.pack(side=tk.LEFT, padx=10)

        tk.Button(t, text="💾 Guardar Umbrales", bg=self.colors["success"], fg="#000",
                  font=("Segoe UI", 10, "bold"), relief=tk.FLAT,
                  command=self.save_thresholds).pack(pady=15)

    def _build_lists_tab(self, parent):
        t = ttk.Frame(parent)
        parent.add(t, text="Listas IP")

        control = tk.Frame(t, bg=self.colors["bg"])
        control.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(control, text="IP:", bg=self.colors["bg"], fg=self.colors["fg"]).pack(side=tk.LEFT, padx=5)
        self.ip_entry = tk.Entry(control, width=18)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.list_type_var = tk.StringVar(value="blacklist")
        ttk.Combobox(control, textvariable=self.list_type_var, values=["whitelist", "blacklist"],
                     state="readonly", width=12).pack(side=tk.LEFT, padx=5)
        tk.Label(control, text="Motivo:", bg=self.colors["bg"], fg=self.colors["fg"]).pack(side=tk.LEFT, padx=5)
        self.reason_entry = tk.Entry(control, width=22)
        self.reason_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(control, text="➕ Agregar", bg=self.colors["accent"], fg="#000", relief=tk.FLAT,
                  font=("Segoe UI", 9, "bold"), command=self.add_to_list).pack(side=tk.LEFT, padx=5)
        tk.Button(control, text="➖ Eliminar seleccionada", bg=self.colors["danger"], fg="#fff", relief=tk.FLAT,
                  font=("Segoe UI", 9, "bold"), command=self.remove_from_list).pack(side=tk.LEFT, padx=5)

        columns = ("IP", "Lista", "Motivo", "Añadida", "Expira")
        self.lists_tree = ttk.Treeview(t, columns=columns, show="headings", height=15)
        for col in columns:
            self.lists_tree.heading(col, text=col)
            self.lists_tree.column(col, width=150)
        self.lists_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.refresh_lists()

    def _build_channels_tab(self, parent):
        t = ttk.Frame(parent)
        parent.add(t, text="Notificaciones")

        self.sound_var = tk.BooleanVar(value=self.config.get("alert_channels", "sound", default=True))
        tk.Checkbutton(t, text="🔊 Sonido para alertas CRÍTICA/ALTA", variable=self.sound_var,
                        bg=self.colors["bg"], fg=self.colors["fg"], selectcolor=self.colors["dark"],
                        font=("Segoe UI", 10)).pack(anchor="w", padx=20, pady=(15, 5))

        tk.Label(t, text="Webhook (HTTP POST JSON)", bg=self.colors["bg"], fg=self.colors["accent"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=20, pady=(15, 5))
        wh_row = tk.Frame(t, bg=self.colors["bg"])
        wh_row.pack(fill=tk.X, padx=20, pady=5)
        self.webhook_enabled_var = tk.BooleanVar(value=self.config.get("alert_channels", "webhook", "enabled", default=False))
        tk.Checkbutton(wh_row, text="Activar", variable=self.webhook_enabled_var, bg=self.colors["bg"],
                        fg=self.colors["fg"], selectcolor=self.colors["dark"]).pack(side=tk.LEFT)
        tk.Label(wh_row, text="URL:", bg=self.colors["bg"], fg=self.colors["fg"]).pack(side=tk.LEFT, padx=(15, 5))
        self.webhook_url_entry = tk.Entry(wh_row, width=45)
        self.webhook_url_entry.insert(0, self.config.get("alert_channels", "webhook", "url", default=""))
        self.webhook_url_entry.pack(side=tk.LEFT, padx=5)
        if not REQUESTS_OK:
            tk.Label(t, text="⚠ Módulo 'requests' no instalado — el webhook no funcionará",
                     bg=self.colors["bg"], fg=self.colors["warning"]).pack(anchor="w", padx=20)

        tk.Label(t, text="Email (SMTP)", bg=self.colors["bg"], fg=self.colors["accent"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=20, pady=(20, 5))
        self.email_enabled_var = tk.BooleanVar(value=self.config.get("alert_channels", "email", "enabled", default=False))
        tk.Checkbutton(t, text="Activar notificación por email", variable=self.email_enabled_var,
                        bg=self.colors["bg"], fg=self.colors["fg"], selectcolor=self.colors["dark"]).pack(anchor="w", padx=20)

        em = self.config.get("alert_channels", "email", default={})
        self.email_fields = {}
        for label, key, width in [("Servidor SMTP", "smtp_host", 25), ("Puerto", "smtp_port", 8),
                                   ("Usuario", "username", 25), ("Contraseña", "password", 25),
                                   ("Destinatario", "to_addr", 25)]:
            row = tk.Frame(t, bg=self.colors["bg"])
            row.pack(fill=tk.X, padx=20, pady=3)
            tk.Label(row, text=label + ":", bg=self.colors["bg"], fg=self.colors["fg"], width=14,
                     anchor="w").pack(side=tk.LEFT)
            show = "*" if key == "password" else ""
            entry = tk.Entry(row, width=width, show=show)
            entry.insert(0, str(em.get(key, "")))
            entry.pack(side=tk.LEFT, padx=5)
            self.email_fields[key] = entry

        tk.Button(t, text="💾 Guardar notificaciones", bg=self.colors["success"], fg="#000",
                  font=("Segoe UI", 10, "bold"), relief=tk.FLAT,
                  command=self.save_channels).pack(pady=20)

    def _build_system_tab(self, parent):
        t = ttk.Frame(parent)
        parent.add(t, text="Sistema")

        tk.Label(t, text="Interfaz de red", bg=self.colors["bg"], fg=self.colors["accent"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=20, pady=(15, 5))
        ifaces = ["auto"]
        if SCAPY_OK:
            try:
                ifaces += get_if_list()
            except Exception:
                pass
        self.iface_var = tk.StringVar(value=self.config.get("interface", default="auto"))
        ttk.Combobox(t, textvariable=self.iface_var, values=ifaces, state="readonly", width=30).pack(
            anchor="w", padx=20, pady=5)

        tk.Label(t, text="Auto-respuesta", bg=self.colors["bg"], fg=self.colors["accent"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=20, pady=(20, 5))
        self.autoresp_var = tk.BooleanVar(value=self.config.get("auto_response", "block_on_critical", default=False))
        tk.Checkbutton(t, text="⚠ Bloquear automáticamente IP en alertas CRÍTICAS (requiere privilegios)",
                        variable=self.autoresp_var, bg=self.colors["bg"], fg=self.colors["fg"],
                        selectcolor=self.colors["dark"]).pack(anchor="w", padx=20)
        row = tk.Frame(t, bg=self.colors["bg"])
        row.pack(fill=tk.X, padx=20, pady=5)
        tk.Label(row, text="Método:", bg=self.colors["bg"], fg=self.colors["fg"]).pack(side=tk.LEFT)
        self.block_method_var = tk.StringVar(value=self.config.get("auto_response", "method", default="iptables"))
        ttk.Combobox(row, textvariable=self.block_method_var, values=["iptables", "ufw"],
                     state="readonly", width=12).pack(side=tk.LEFT, padx=10)

        tk.Label(t, text="API REST (solo lectura + bloqueo manual)", bg=self.colors["bg"],
                 fg=self.colors["accent"], font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=20, pady=(20, 5))
        self.api_enabled_var = tk.BooleanVar(value=self.config.get("api", "enabled", default=False))
        tk.Checkbutton(t, text=f"Activar API en 127.0.0.1:{self.config.get('api', 'port', default=8787)} "
                                f"(reinicio requerido){'  [Flask no instalado]' if not FLASK_OK else ''}",
                        variable=self.api_enabled_var, bg=self.colors["bg"], fg=self.colors["fg"],
                        selectcolor=self.colors["dark"], state=(tk.NORMAL if FLASK_OK else tk.DISABLED)).pack(
            anchor="w", padx=20)

        tk.Label(t, text="Apariencia", bg=self.colors["bg"], fg=self.colors["accent"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=20, pady=(20, 5))
        tk.Button(t, text="🌓 Cambiar tema claro/oscuro (reinicia la app)", bg=self.colors["accent"], fg="#000",
                  font=("Segoe UI", 10, "bold"), relief=tk.FLAT, command=self.toggle_theme).pack(anchor="w", padx=20, pady=5)

        tk.Button(t, text="💾 Guardar configuración de sistema", bg=self.colors["success"], fg="#000",
                  font=("Segoe UI", 10, "bold"), relief=tk.FLAT,
                  command=self.save_system_settings).pack(pady=20)

    # ------------------------------------------------------------
    def create_reports_tab(self):
        frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(frame, text="📄 Reportes")

        options_frame = tk.Frame(frame, bg=self.colors["dark"])
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(options_frame, text="Generar Reporte:", bg=self.colors["dark"], fg=self.colors["accent"],
                  font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=10)
        tk.Button(options_frame, text="📊 HTML", bg=self.colors["success"], fg="#000",
                  font=("Segoe UI", 10, "bold"), relief=tk.FLAT,
                  command=lambda: self._export_report("html")).pack(side=tk.LEFT, padx=5)
        tk.Button(options_frame, text="📋 CSV", bg=self.colors["accent"], fg="#000",
                  font=("Segoe UI", 10, "bold"), relief=tk.FLAT,
                  command=lambda: self._export_report("csv")).pack(side=tk.LEFT, padx=5)
        tk.Button(options_frame, text="📑 PDF", bg=self.colors["warning"], fg="#000",
                  font=("Segoe UI", 10, "bold"), relief=tk.FLAT,
                  command=lambda: self._export_report("pdf")).pack(side=tk.LEFT, padx=5)
        tk.Button(options_frame, text="🗂 JSON", bg=self.colors["danger"], fg="#fff",
                  font=("Segoe UI", 10, "bold"), relief=tk.FLAT,
                  command=lambda: self._export_report("json")).pack(side=tk.LEFT, padx=5)

        self.report_text = scrolledtext.ScrolledText(frame, bg=self.colors["entry_bg"], fg=self.colors["fg"],
                                                       font=("Consolas", 9))
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.report_text.insert("1.0", "Selecciona un formato para generar y guardar un reporte de seguridad.\n")

    # ------------------------------------------------------------
    def create_audit_tab(self):
        frame = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(frame, text="🧾 Auditoría")

        tk.Button(frame, text="🔄 Actualizar", bg=self.colors["accent"], fg="#000", relief=tk.FLAT,
                  font=("Segoe UI", 9, "bold"), command=self.refresh_audit).pack(anchor="w", padx=10, pady=10)

        columns = ("ID", "Timestamp", "Evento", "Acción", "Detalles")
        self.audit_tree = ttk.Treeview(frame, columns=columns, show="headings", height=25)
        widths = {"ID": 50, "Timestamp": 150, "Evento": 160, "Acción": 160, "Detalles": 400}
        for col in columns:
            self.audit_tree.heading(col, text=col)
            self.audit_tree.column(col, width=widths.get(col, 120), anchor=tk.W)
        self.audit_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.refresh_audit()

    # ============================================================
    # CONTROL: captura en vivo / offline
    # ============================================================
    def start_ids(self):
        if not SCAPY_OK:
            messagebox.showerror("Error", "Scapy no está instalado. Ejecuta: pip3 install scapy")
            return
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status_label.config(text="● ESCUCHANDO", fg=self.colors["success"])
        iface = self.config.get("interface", default="auto")
        self.sniff_thread = threading.Thread(target=self.engine.start_sniffing, args=(iface,), daemon=True)
        self.sniff_thread.start()
        self.db_manager.log_audit("IDS_START", "start_ids", f"interfaz={iface}")

    def stop_ids(self):
        self.engine.stop_sniffing()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status_label.config(text="● INACTIVO", fg=self.colors["danger"])
        self.db_manager.log_audit("IDS_STOP", "stop_ids", "")

    def open_pcap_dialog(self):
        if not SCAPY_OK:
            messagebox.showerror("Error", "Scapy no está instalado. Ejecuta: pip3 install scapy")
            return
        path = filedialog.askopenfilename(filetypes=[("Archivos pcap", "*.pcap *.pcapng"), ("Todos", "*.*")])
        if path:
            self._analyze_pcap_path(path)

    def _analyze_pcap_path(self, path):
        progress = tk.Toplevel(self.root)
        progress.title("Analizando .pcap")
        progress.configure(bg=self.colors["dark"])
        progress.geometry("400x100")
        lbl = tk.Label(progress, text="Analizando archivo capturado…", bg=self.colors["dark"],
                        fg=self.colors["fg"], font=("Segoe UI", 10))
        lbl.pack(pady=10)
        bar = ttk.Progressbar(progress, mode="determinate", length=350)
        bar.pack(pady=10)

        def progress_cb(i, total):
            def upd():
                bar["maximum"] = max(total, 1)
                bar["value"] = i
                lbl.config(text=f"Analizando paquete {i}/{total}")
                if i >= total:
                    progress.destroy()
                    messagebox.showinfo("Completado", f"Análisis offline completado: {total} paquetes procesados")
            self.root.after(0, upd)

        def run():
            try:
                self.engine.analyze_pcap_file(path, progress_cb=progress_cb)
                self.db_manager.log_audit("PCAP_ANALYZE", "analyze_pcap_file", path)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"No se pudo analizar el pcap: {e}"))
                self.root.after(0, progress.destroy)

        threading.Thread(target=run, daemon=True).start()

    def on_close(self):
        self.engine.stop_sniffing()
        self.engine.flush_ip_statistics()
        self.db_manager.log_audit("SHUTDOWN", "app_close", "")
        self.db_manager.shutdown()
        self.root.destroy()

    # ============================================================
    # COLA DE ALERTAS / MÉTRICAS EN TIEMPO REAL
    # ============================================================
    def check_queue(self):
        while not self.alert_queue.empty():
            alert = self.alert_queue.get()
            severity = alert[1]
            display_row = ("", alert[0], alert[1], alert[2], alert[3], alert[4], alert[5],
                            alert[6], alert[7], alert[8], "No")
            self.alerts_tree.insert("", 0, values=display_row, tags=(severity,))
        self.root.after(500, self.check_queue)

    def update_statistics(self):
        stats = self.engine.stats
        if "packets" in self.metric_widgets:
            self.metric_widgets["packets"].config(text=f"{stats['total_packets']}")
        if "alerts" in self.metric_widgets:
            self.metric_widgets["alerts"].config(text=f"{stats['alerts_generated']}")
        if "threats" in self.metric_widgets:
            self.metric_widgets["threats"].config(text=f"{len(stats['unique_ips'])}")
        if "bandwidth" in self.metric_widgets:
            self.metric_widgets["bandwidth"].config(text=f"{stats['total_bytes'] / 1024 / 1024:.2f}MB")

        self.traffic_data.append(stats["total_packets"])
        self.alert_data.append(stats["alerts_generated"])

        self.ax1.clear()
        self.ax1.plot(list(self.traffic_data), color=self.colors["accent"], linewidth=2)
        self.ax1.set_title("Tráfico de Paquetes (acumulado)", color=self.colors["fg"], fontsize=10)
        self.ax1.set_facecolor(self.colors["dark"])
        self.ax1.tick_params(colors=self.colors["fg"], labelsize=8)

        self.ax2.clear()
        self.ax2.bar(range(len(self.alert_data)), list(self.alert_data), color=self.colors["danger"])
        self.ax2.set_title("Alertas Generadas (acumulado)", color=self.colors["fg"], fontsize=10)
        self.ax2.set_facecolor(self.colors["dark"])
        self.ax2.tick_params(colors=self.colors["fg"], labelsize=8)
        self.fig.tight_layout()
        self.canvas.draw()

        self._update_analytics_text()
        self.root.after(1500, self.update_statistics)

    def _update_analytics_text(self):
        stats = self.engine.stats
        proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto_lines = "\n".join(
            f"  {proto_names.get(p, f'Proto-{p}')}: {c} paquetes"
            for p, c in self.engine.protocol_distribution.most_common(10)
        )
        summary = f"""
{'=' * 55}
 ESTADÍSTICAS GLOBALES — {APP_NAME} v{APP_VERSION}
{'=' * 55}
Paquetes analizados:      {stats['total_packets']}
Alertas generadas:        {stats['alerts_generated']}
Tráfico total:             {stats['total_bytes'] / 1024 / 1024:.2f} MB
IPs únicas observadas:    {len(stats['unique_ips'])}
Estado del motor:          {'ESCUCHANDO' if self.engine.is_running else 'INACTIVO'}
{'=' * 55}
"""
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert("1.0", summary)

        self.protocols_text.delete("1.0", tk.END)
        self.protocols_text.insert("1.0", "DISTRIBUCIÓN DE PROTOCOLOS\n" + "=" * 40 + "\n" + (proto_lines or "  (sin datos aún)"))

        for item in self.ips_tree.get_children():
            self.ips_tree.delete(item)
        for ip, packets, nbytes, alerts, risk in self.db_manager.get_top_ips(20):
            tag = "risk_high" if risk >= 60 else "risk_mid" if risk >= 25 else ""
            self.ips_tree.insert("", tk.END, values=(ip, packets, f"{nbytes/1024:.1f}KB", alerts, f"{risk:.0f}"),
                                  tags=(tag,) if tag else ())

    # ============================================================
    # ALERTAS: filtro/búsqueda/resolución/bloqueo
    # ============================================================
    def refresh_alerts(self):
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        sev = self.severity_var.get()
        search = self.search_entry.get().strip()
        rows = self.db_manager.get_recent_alerts(500, severity=sev if sev != "TODAS" else None,
                                                   search=search if search else None)
        for r in rows:
            resolved = "Sí" if r[12] else "No"
            values = (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], resolved)
            self.alerts_tree.insert("", tk.END, values=values, tags=(r[2],))

    def resolve_selected_alert(self):
        sel = self.alerts_tree.selection()
        if not sel:
            messagebox.showwarning("Aviso", "Selecciona una alerta primero")
            return
        values = self.alerts_tree.item(sel[0])["values"]
        alert_id = values[0]
        if not alert_id:
            messagebox.showinfo("Info", "Actualiza la lista (🔄) antes de resolver esta alerta")
            return
        notes = simpledialog.askstring("Resolver alerta", "Notas del analista (opcional):") or ""
        self.db_manager.resolve_alert(alert_id, notes)
        self.db_manager.log_audit("ALERT_RESOLVED", "resolve_selected_alert", f"id={alert_id}")
        messagebox.showinfo("Éxito", "Alerta marcada como resuelta")
        self.refresh_alerts()

    def block_selected_ip(self):
        sel = self.alerts_tree.selection()
        if not sel:
            messagebox.showwarning("Aviso", "Selecciona una alerta primero")
            return
        values = self.alerts_tree.item(sel[0])["values"]
        ip = values[5]
        if not ip or ip == "N/A":
            messagebox.showinfo("Info", "Esta alerta no tiene una IP de origen válida")
            return
        if not messagebox.askyesno("Confirmar bloqueo",
                                    f"¿Bloquear la IP {ip} a nivel de firewall ({self.config.get('auto_response','method',default='iptables')})?\n"
                                    "Esta acción requiere privilegios de administrador."):
            return
        ok = self.response_mgr.block_ip(ip)
        self.db_manager.add_to_list(ip, "blacklist", "Bloqueada manualmente desde Alertas")
        if ok:
            messagebox.showinfo("Bloqueada", f"IP {ip} bloqueada y añadida a blacklist")
        else:
            messagebox.showwarning("Aviso", f"IP {ip} añadida a blacklist, pero el bloqueo de firewall falló "
                                             "(revisa permisos / consulta Auditoría)")
        self.refresh_lists()

    # ============================================================
    # CONFIGURACIÓN
    # ============================================================
    def save_thresholds(self):
        for key, entry in self.threshold_entries.items():
            try:
                self.config.set(int(entry.get()), "thresholds", key)
            except ValueError:
                messagebox.showerror("Error", f"Valor inválido en {key}")
                return
        try:
            self.config.set(int(self.cooldown_entry.get()), "alert_cooldown_seconds")
        except ValueError:
            messagebox.showerror("Error", "Cooldown inválido")
            return
        self.config.save()
        self.db_manager.log_audit("CONFIG_SAVE", "save_thresholds", "")
        messagebox.showinfo("Éxito", "Umbrales actualizados y guardados en config.json")

    def add_to_list(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Ingresa una IP")
            return
        reason = self.reason_entry.get().strip() or "Añadido manualmente"
        self.db_manager.add_to_list(ip, self.list_type_var.get(), reason)
        self.db_manager.log_audit("LIST_ADD", self.list_type_var.get(), f"{ip}: {reason}")
        self.ip_entry.delete(0, tk.END)
        self.reason_entry.delete(0, tk.END)
        self.refresh_lists()

    def remove_from_list(self):
        sel = self.lists_tree.selection()
        if not sel:
            messagebox.showwarning("Aviso", "Selecciona una entrada primero")
            return
        values = self.lists_tree.item(sel[0])["values"]
        ip, list_type = values[0], values[1]
        self.db_manager.remove_from_list(ip, list_type)
        self.db_manager.log_audit("LIST_REMOVE", list_type, ip)
        self.refresh_lists()

    def refresh_lists(self):
        for item in self.lists_tree.get_children():
            self.lists_tree.delete(item)
        for list_type in ("whitelist", "blacklist"):
            for ip, reason, added, expires in self.db_manager.get_list(list_type):
                self.lists_tree.insert("", tk.END, values=(ip, list_type, reason, added, expires or "—"))

    def save_channels(self):
        self.config.set(self.sound_var.get(), "alert_channels", "sound")
        self.config.set(self.webhook_enabled_var.get(), "alert_channels", "webhook", "enabled")
        self.config.set(self.webhook_url_entry.get().strip(), "alert_channels", "webhook", "url")
        self.config.set(self.email_enabled_var.get(), "alert_channels", "email", "enabled")
        for key, entry in self.email_fields.items():
            val = entry.get().strip()
            if key == "smtp_port":
                try:
                    val = int(val)
                except ValueError:
                    val = 587
            self.config.set(val, "alert_channels", "email", key)
        self.config.save()
        self.db_manager.log_audit("CONFIG_SAVE", "save_channels", "")
        messagebox.showinfo("Éxito", "Configuración de notificaciones guardada")

    def save_system_settings(self):
        self.config.set(self.iface_var.get(), "interface")
        self.config.set(self.autoresp_var.get(), "auto_response", "block_on_critical")
        self.config.set(self.autoresp_var.get(), "auto_response", "enabled")
        self.config.set(self.block_method_var.get(), "auto_response", "method")
        self.config.set(self.api_enabled_var.get(), "api", "enabled")
        self.config.save()
        self.db_manager.log_audit("CONFIG_SAVE", "save_system_settings", "")
        messagebox.showinfo("Éxito", "Configuración guardada. Algunos cambios requieren reiniciar la aplicación.")

    def toggle_theme(self):
        current = self.config.get("theme", default="dark")
        self.config.set("light" if current == "dark" else "dark", "theme")
        self.config.save()
        messagebox.showinfo("Tema", "Tema actualizado. Reinicia la aplicación para aplicar el cambio.")

    # ============================================================
    # REPORTES
    # ============================================================
    def _export_report(self, fmt):
        ext_map = {"html": (".html", [("HTML", "*.html")]), "csv": (".csv", [("CSV", "*.csv")]),
                   "pdf": (".pdf", [("PDF", "*.pdf")]), "json": (".json", [("JSON", "*.json")])}
        ext, filetypes = ext_map[fmt]
        path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=filetypes,
                                             initialfile=f"sentinel_ids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}")
        if not path:
            return
        try:
            if fmt == "html":
                self.reporter.to_html(path)
            elif fmt == "csv":
                self.reporter.to_csv(path)
            elif fmt == "pdf":
                self.reporter.to_pdf(path)
            elif fmt == "json":
                self.reporter.to_json(path)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo generar el reporte: {e}")
            return
        self.db_manager.log_audit("REPORT_EXPORT", fmt.upper(), path)
        self.report_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Reporte {fmt.upper()} generado: {path}\n")
        messagebox.showinfo("Éxito", f"Reporte generado:\n{path}")

    # ============================================================
    # AUDITORÍA
    # ============================================================
    def refresh_audit(self):
        for item in self.audit_tree.get_children():
            self.audit_tree.delete(item)
        for row in self.db_manager.get_audit_log(300):
            self.audit_tree.insert("", tk.END, values=row)


# ================================================================
# PUNTO DE ENTRADA
# ================================================================
def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("--pcap", help="Analizar un archivo .pcap/.pcapng en modo offline al iniciar", default=None)
    args = parser.parse_args()

    if not SCAPY_OK and not args.pcap:
        print("⚠ Aviso: scapy no está instalado. La captura en vivo estará deshabilitada.")
        print("  Instala con: pip3 install scapy")

    root = tk.Tk()
    app = ProfessionalIDSDashboard(root, pcap_file=args.pcap)
    root.mainloop()


if __name__ == "__main__":
    main()
