import tempfile
from pathlib import Path

import pytest

scapy = pytest.importorskip('scapy.all')
from scapy.all import IP, TCP, Raw, wrpcap, rdpcap

from sentinel_ids_pro_v3 import AdvancedIDSEngine, ConfigManager, DatabaseManager
import sentinel_ids_pro_v3 as sentinel


def make_engine(tmp_path):
    db = DatabaseManager(tmp_path / 'test.db')
    q = __import__('queue').Queue()
    cfg = ConfigManager(tmp_path / 'config.json')
    cfg.set(False, 'auto_response', 'enabled')
    engine = AdvancedIDSEngine(q, db, cfg)
    engine.offline_mode = True
    return engine, db, q


def test_pcap_uses_packet_timestamps(tmp_path):
    engine, db, q = make_engine(tmp_path)
    p1 = IP(src='10.0.0.5', dst='10.0.0.1')/TCP(sport=1234, dport=80, flags='S')
    p2 = IP(src='10.0.0.5', dst='10.0.0.1')/TCP(sport=1235, dport=80, flags='S')
    p1.time = 1000.0
    p2.time = 1001.0
    pcap = tmp_path / 'sample.pcap'
    wrpcap(str(pcap), [p1, p2])
    engine.analyze_pcap_file(str(pcap))
    assert engine.stats['total_packets'] == 2
    assert engine.stats['pcap_packets'] == 2
    assert engine.stats['pcap_path'] == str(pcap)
    db.shutdown()


def test_http_trace_is_checked(tmp_path):
    engine, db, q = make_engine(tmp_path)
    pkt = IP(src='10.0.0.5', dst='10.0.0.1')/TCP(sport=1234, dport=80, flags='PA')/Raw(load=b'TRACE / HTTP/1.1\r\nHost: test\r\nUser-Agent: test\r\n\r\n')
    engine.analyze_packet(pkt, event_time=1000)
    assert not q.empty()
    alert = q.get_nowait()
    assert 'HTTP' in alert[2]
    db.shutdown()


def test_html_report_escapes_payload(tmp_path):
    engine, db, q = make_engine(tmp_path)
    db.insert_alert(('2026-01-01 00:00:00','ALTA','Test','<script>alert(1)</script>','10.0.0.5','10.0.0.1',0,80,'HTTP',1,0))
    db._write_queue.join()
    out = tmp_path / 'report.html'
    sentinel.ReportGenerator(db, engine).to_html(str(out))
    text = out.read_text(encoding='utf-8')
    assert '<script>alert(1)</script>' not in text
    assert '&lt;script&gt;' in text
    db.shutdown()
