"""
core.py  --  The engine behind the PCAP-to-SQLite analyzer.
===========================================================
This module contains ALL the real work and NO user interface. It can be
driven by the desktop GUI (app.py), by a command line, or by tests. Keeping
the logic separate from the interface is a deliberate design choice: the
parsing/loading/querying code shouldn't know or care how it's being called.

It does three things:
  1. generate_sample()  -- build a realistic .pcap so the app has input
  2. load_pcap()        -- parse a .pcap and load it into a SQLite database
  3. run_analysis()     -- execute one named analysis query and return rows

Module implemented: PCAP Analysis -> PCAP to SQLite.
"""

import os
import random
import sqlite3
from collections import OrderedDict
from datetime import datetime, timezone

from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw,
    PcapReader, wrpcap,
)


# ==========================================================================
# PART 1 -- Sample capture generator
# ==========================================================================
# A .pcap file is a sequence of raw network packets, each stored with a
# timestamp, exactly as a sniffer (Wireshark/tcpdump) records them. Rather
# than require live capture (which needs admin rights and a network), we
# hand-build packets with scapy and write them in the standard pcap format.
# A parser cannot tell these from real captured packets -- the format is
# identical.

_CLIENTS = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
_DNS_SERVER = "192.168.1.1"
_WEB_SERVERS = {
    "93.184.216.34": "example.com",
    "151.101.0.81": "news.site",
    "140.82.112.3": "code.host",
}


def generate_sample(out_path, seed=42):
    """Create a realistic mixed-traffic capture at out_path. Returns pkt count."""
    rng = random.Random(seed)          # own RNG instance -> deterministic output
    packets = []
    clock = [1_700_000_000.0]          # list so the inner helper can mutate it

    def add(pkt, gap=None):
        # Each packet carries a capture time on .time (Unix epoch seconds).
        # We advance a shared clock by a small gap for believable spacing.
        clock[0] += gap if gap is not None else rng.uniform(0.0005, 0.03)
        pkt.time = clock[0]
        packets.append(pkt)

    def dns_lookup(client, qname):
        # DNS resolves names to IPs over UDP/53 -- a tidy request/response.
        sport = rng.randint(1024, 65535)
        add(Ether() / IP(src=client, dst=_DNS_SERVER) /
            UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname)))
        add(Ether() / IP(src=_DNS_SERVER, dst=client) /
            UDP(sport=53, dport=sport) /
            DNS(qr=1, qd=DNSQR(qname=qname),
                an=DNSRR(rrname=qname, rdata="93.184.216.34")))

    def tcp_session(client, server, dport, n_data_pkts, payload_size):
        # A full TCP conversation: 3-way handshake, data, teardown. Modelling
        # this faithfully means the later "flows" analysis sees real
        # connection boundaries.
        sport = rng.randint(1024, 65535)
        add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="S"))
        add(Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="SA"))
        add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A"))
        add(Ether() / IP(src=client, dst=server) /
            TCP(sport=sport, dport=dport, flags="PA") / Raw(load=b"GET / HTTP/1.1\r\n"))
        for _ in range(n_data_pkts):
            add(Ether() / IP(src=server, dst=client) /
                TCP(sport=dport, dport=sport, flags="PA") /
                Raw(load=bytes(rng.getrandbits(8) for _ in range(payload_size))))
        add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="FA"))
        add(Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="FA"))

    # DNS lookups first (clients resolve names before connecting)
    for client in _CLIENTS:
        for name in _WEB_SERVERS.values():
            dns_lookup(client, name)

    # .10 heavy web user; .11 moderate; .12 light + some raw UDP
    for _ in range(6):
        tcp_session("192.168.1.10", "93.184.216.34", 80, 8, 1200)
    for _ in range(4):
        tcp_session("192.168.1.10", "151.101.0.81", 443, 12, 1400)
    for _ in range(3):
        tcp_session("192.168.1.11", "140.82.112.3", 443, 5, 900)
    for _ in range(2):
        tcp_session("192.168.1.11", "93.184.216.34", 80, 3, 600)
    tcp_session("192.168.1.12", "151.101.0.81", 80, 2, 400)
    for _ in range(15):
        sport = rng.randint(1024, 65535)
        add(Ether() / IP(src="192.168.1.12", dst="8.8.8.8") /
            UDP(sport=sport, dport=4433) /
            Raw(load=bytes(rng.getrandbits(8) for _ in range(300))))

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    wrpcap(out_path, packets)
    return len(packets)


# ==========================================================================
# PART 2 -- PCAP -> SQLite loader  (the core module)
# ==========================================================================

SCHEMA = """
DROP TABLE IF EXISTS packets;
DROP TABLE IF EXISTS flows;

CREATE TABLE packets (
    id          INTEGER PRIMARY KEY,
    ts          REAL,
    ts_readable TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    protocol    TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    length      INTEGER,
    tcp_flags   TEXT,
    info        TEXT
);
CREATE INDEX idx_packets_addr ON packets(src_ip, dst_ip, protocol);
"""

# Run AFTER packets load: collapse each unique 5-tuple into one "flow"
# (conversation) row with totals. Aggregation done in SQL, by the database.
BUILD_FLOWS = """
CREATE TABLE flows AS
SELECT src_ip, dst_ip, src_port, dst_port, protocol,
       COUNT(*)    AS packet_count,
       SUM(length) AS total_bytes,
       MIN(ts)     AS first_seen,
       MAX(ts)     AS last_seen
FROM packets
GROUP BY src_ip, dst_ip, src_port, dst_port, protocol;
"""


def packet_to_row(pkt):
    """Turn one scapy packet into a tuple of column values (or None to skip).

    scapy models a packet as nested layers (Ethernet -> IP -> TCP/UDP ->
    payload). We test for each layer with haslayer() and read its fields.
    Only IP packets are stored; link-layer-only frames (ARP, etc.) are skipped.
    """
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    ts = float(pkt.time)
    ts_readable = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3]
    length = len(pkt)

    src_port = dst_port = None
    tcp_flags = None

    if pkt.haslayer(TCP):
        protocol = "TCP"
        t = pkt[TCP]
        src_port, dst_port = int(t.sport), int(t.dport)
        tcp_flags = str(t.flags)
        info = f"TCP {src_port}->{dst_port} [{tcp_flags}]"
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        u = pkt[UDP]
        src_port, dst_port = int(u.sport), int(u.dport)
        info = f"UDP {src_port}->{dst_port}"
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
        info = "ICMP"
    else:
        protocol = "OTHER"
        info = f"IP proto {ip.proto}"

    return (ts, ts_readable, ip.src, ip.dst, protocol,
            src_port, dst_port, length, tcp_flags, info)


def load_pcap(pcap_path, db_path, progress=None):
    """Parse pcap_path and load it into a fresh SQLite DB at db_path.

    progress: optional callback(n_packets_read) called periodically, so a GUI
    can show activity on large captures. Returns (n_packets, n_flows).
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"No such capture file: {pcap_path}")
    if os.path.exists(db_path):
        os.remove(db_path)          # fresh DB each run -> reproducible

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript(SCHEMA)

    insert_sql = (
        "INSERT INTO packets "
        "(ts, ts_readable, src_ip, dst_ip, protocol, src_port, dst_port, "
        " length, tcp_flags, info) VALUES (?,?,?,?,?,?,?,?,?,?)"
    )  # parameterised (?) inserts: injection-safe and fast

    rows, seen = [], 0
    with PcapReader(pcap_path) as reader:   # streams one packet at a time
        for pkt in reader:
            seen += 1
            row = packet_to_row(pkt)
            if row is not None:
                rows.append(row)
            if len(rows) >= 500:
                cur.executemany(insert_sql, rows)
                rows.clear()
            if progress and seen % 500 == 0:
                progress(seen)
    if rows:
        cur.executemany(insert_sql, rows)

    cur.executescript(BUILD_FLOWS)          # database builds the flows table
    conn.commit()

    n_packets = cur.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    n_flows = cur.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    conn.close()
    return n_packets, n_flows


# ==========================================================================
# PART 3 -- Analysis registry
# ==========================================================================
# Each analysis is just a named SQL query plus a plain-language explanation
# and the column headers to show. The GUI reads this dict to populate its
# dropdown, so adding a new report is as simple as adding an entry here --
# no GUI changes needed. This is the payoff of PCAP -> SQLite: questions are
# SQL, not bespoke packet code.

ANALYSES = OrderedDict({
    "Capture overview": {
        "explanation": "Basic shape of the capture: packet count, total bytes, "
                       "duration, and how many distinct sources appear.",
        "headers": ["packets", "total_bytes", "duration_sec", "distinct_sources"],
        "sql": """
            SELECT COUNT(*)                    AS packets,
                   SUM(length)                 AS total_bytes,
                   ROUND(MAX(ts)-MIN(ts), 2)   AS duration_sec,
                   COUNT(DISTINCT src_ip)      AS distinct_sources
            FROM packets
        """,
    },
    "Top talkers (by bytes sent)": {
        "explanation": "Groups packets by source address and sums bytes. The "
                       "biggest senders are where you look first for heavy "
                       "users, backups, or exfiltration.",
        "headers": ["src_ip", "packets_sent", "bytes_sent"],
        "sql": """
            SELECT src_ip, COUNT(*) AS packets_sent, SUM(length) AS bytes_sent
            FROM packets GROUP BY src_ip ORDER BY bytes_sent DESC LIMIT 20
        """,
    },
    "Protocol distribution": {
        "explanation": "What the traffic is made of. A sudden shift in this mix "
                       "(e.g. a UDP spike) often signals scanning or tunnelling.",
        "headers": ["protocol", "packets", "bytes", "pct_packets"],
        "sql": """
            SELECT protocol, COUNT(*) AS packets, SUM(length) AS bytes,
                   ROUND(100.0*COUNT(*)/(SELECT COUNT(*) FROM packets),1) AS pct_packets
            FROM packets GROUP BY protocol ORDER BY packets DESC
        """,
    },
    "Busiest destination ports": {
        "explanation": "Destination port identifies the service (80=HTTP, "
                       "443=HTTPS, 53=DNS). Unexpected ports are worth a look.",
        "headers": ["dst_port", "likely_service", "protocol", "packets"],
        "sql": """
            SELECT dst_port,
                   CASE dst_port WHEN 80 THEN 'HTTP' WHEN 443 THEN 'HTTPS'
                                 WHEN 53 THEN 'DNS'  ELSE '-' END AS likely_service,
                   protocol, COUNT(*) AS packets
            FROM packets WHERE dst_port IS NOT NULL
            GROUP BY dst_port, protocol ORDER BY packets DESC LIMIT 20
        """,
    },
    "Heaviest flows (conversations)": {
        "explanation": "Reads the derived `flows` table: each row is one "
                       "5-tuple conversation. Ranking by bytes shows which "
                       "single connection moved the most data, and for how long.",
        "headers": ["src_ip", "dst_ip", "dst_port", "protocol",
                    "packet_count", "total_bytes", "duration_sec"],
        "sql": """
            SELECT src_ip, dst_ip, dst_port, protocol, packet_count, total_bytes,
                   ROUND(last_seen-first_seen,3) AS duration_sec
            FROM flows ORDER BY total_bytes DESC LIMIT 20
        """,
    },
    "TCP connection attempts (SYN)": {
        "explanation": "A lone SYN flag marks the start of a TCP connection. "
                       "Counting SYNs per source is the basic building block of "
                       "port-scan detection.",
        "headers": ["src_ip", "syn_packets"],
        "sql": """
            SELECT src_ip, COUNT(*) AS syn_packets
            FROM packets WHERE protocol='TCP' AND tcp_flags='S'
            GROUP BY src_ip ORDER BY syn_packets DESC
        """,
    },
})


def run_analysis(db_path, name):
    """Run the named analysis against db_path.

    Returns (headers, rows, sql_text). Raises KeyError for an unknown name,
    or sqlite3.OperationalError if the database/tables don't exist yet.
    """
    spec = ANALYSES[name]
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(spec["sql"]).fetchall()
    finally:
        conn.close()
    return spec["headers"], rows, spec["sql"].strip()


def database_ready(db_path):
    """True if db_path exists and has a populated packets table."""
    if not os.path.exists(db_path):
        return False
    try:
        conn = sqlite3.connect(db_path)
        n = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        conn.close()
        return n > 0
    except sqlite3.Error:
        return False
