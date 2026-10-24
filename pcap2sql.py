"""
pcap2sql.py  --  Convert a packet capture (.pcap) into a SQLite database.
=========================================================================
This is the heart of the project and the module being implemented:
"PCAP Analysis -> PCAP to SQLite".

THE IDEA IN ONE SENTENCE
A .pcap file is an opaque, sequential blob of raw packets; a SQL database is
a structured, queryable store. This script is the bridge: it reads each
packet, extracts the fields that matter for analysis, and writes them as rows
so you can then ask questions with ordinary SQL instead of writing custom
Python for every question.

WHY THAT'S USEFUL
Once the traffic lives in tables, "which host sent the most data?",
"how much of this is DNS?", or "show every connection to port 443" all become
one-line SQL queries. The hard, format-specific work (decoding packets)
happens once, here. (See analyze.py for the queries.)

HOW IT WORKS, STEP BY STEP
1. Open the capture with scapy's PcapReader. We stream packet-by-packet
   rather than loading the whole file into memory, so this also works on
   large captures.
2. For each packet, peel back the layers:
      Ethernet  ->  IP  ->  TCP/UDP  ->  payload
   and read the fields we care about (addresses, ports, protocol, size,
   TCP flags, timestamp).
3. Insert each as a row in a `packets` table, batched inside a single
   transaction for speed.
4. After loading, build a `flows` table with pure SQL: group packets that
   share the same (src, dst, sport, dport, protocol) 5-tuple into one
   "conversation" row with totals. This shows the database doing the
   aggregation work, which is the point of putting data in SQL.

USAGE
    python3 pcap2sql.py data/sample.pcap
    python3 pcap2sql.py some_capture.pcap --db mydata.db
"""

import argparse
import os
import sqlite3
from datetime import datetime, timezone

from scapy.all import PcapReader, IP, TCP, UDP, ICMP


# --------------------------------------------------------------------------
# 1. The database schema
# --------------------------------------------------------------------------
# We define the shape of our tables up front. Declaring columns with types
# and an index is what turns a pile of packets into something you can query
# quickly. Read each column comment to see what it captures.

SCHEMA = """
DROP TABLE IF EXISTS packets;
DROP TABLE IF EXISTS flows;

CREATE TABLE packets (
    id          INTEGER PRIMARY KEY,   -- row number / packet ordinal
    ts          REAL,                  -- capture timestamp, Unix epoch seconds
    ts_readable TEXT,                  -- same time as human-readable UTC string
    src_ip      TEXT,                  -- source IP address
    dst_ip      TEXT,                  -- destination IP address
    protocol    TEXT,                  -- 'TCP', 'UDP', 'ICMP', or 'OTHER'
    src_port    INTEGER,               -- source port (NULL for ICMP/non-port)
    dst_port    INTEGER,               -- destination port (NULL if n/a)
    length      INTEGER,               -- total packet size in bytes
    tcp_flags   TEXT,                  -- e.g. 'S', 'SA', 'PA' (NULL if not TCP)
    info        TEXT                   -- short human summary of the packet
);

-- An index on the columns we group/filter by most. Without it, every
-- "top talkers" style query scans the whole table; with it, SQLite can
-- jump straight to matching rows.
CREATE INDEX idx_packets_addr ON packets(src_ip, dst_ip, protocol);
"""

# This second statement is run AFTER the packets are loaded. It derives
# network "flows" (conversations) by collapsing all packets that share the
# same 5-tuple into a single summary row. This is aggregation done in SQL.
BUILD_FLOWS = """
CREATE TABLE flows AS
SELECT
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    COUNT(*)        AS packet_count,   -- how many packets in this conversation
    SUM(length)     AS total_bytes,    -- total volume exchanged
    MIN(ts)         AS first_seen,     -- when the flow started
    MAX(ts)         AS last_seen       -- when it ended
FROM packets
GROUP BY src_ip, dst_ip, src_port, dst_port, protocol;
"""


# --------------------------------------------------------------------------
# 2. Turning one scapy packet into one row of column values
# --------------------------------------------------------------------------
def packet_to_row(pkt):
    """Extract the fields we store from a single scapy packet.

    Returns a tuple matching the `packets` columns (minus id, which SQLite
    auto-assigns), or None if the packet has no IP layer (we only care about
    IP traffic here; ARP, raw link-layer frames, etc. are skipped).

    The key concept is LAYER ACCESS: scapy models a packet as nested layers.
    `pkt.haslayer(IP)` tests whether an IP header is present; `pkt[IP]` gets
    it so we can read its fields. We go one layer deeper for TCP/UDP to get
    ports and flags.
    """
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    ts = float(pkt.time)
    ts_readable = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3]  # trim microseconds to milliseconds for readability
    length = len(pkt)  # total bytes of the packet as captured

    src_port = dst_port = None
    tcp_flags = None

    if pkt.haslayer(TCP):
        protocol = "TCP"
        tcp = pkt[TCP]
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        tcp_flags = str(tcp.flags)              # scapy renders flags as e.g. 'SA'
        info = f"TCP {src_port}->{dst_port} [{tcp_flags}]"
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        udp = pkt[UDP]
        src_port, dst_port = int(udp.sport), int(udp.dport)
        info = f"UDP {src_port}->{dst_port}"
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
        info = "ICMP"
    else:
        protocol = "OTHER"
        info = ip.proto and f"IP proto {ip.proto}" or "OTHER"

    return (
        ts, ts_readable, ip.src, ip.dst, protocol,
        src_port, dst_port, length, tcp_flags, info,
    )


# --------------------------------------------------------------------------
# 3. The load loop
# --------------------------------------------------------------------------
def load_pcap(pcap_path, db_path):
    """Read every packet from pcap_path and load it into db_path."""
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"No such capture file: {pcap_path}")

    # Fresh database each run so repeated runs are reproducible.
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript(SCHEMA)  # create tables + index

    insert_sql = (
        "INSERT INTO packets "
        "(ts, ts_readable, src_ip, dst_ip, protocol, src_port, dst_port, "
        " length, tcp_flags, info) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    # Parameterised INSERT (the ? placeholders): values are bound separately
    # from the SQL text. This is the correct, injection-safe way to insert
    # data and is also faster than string-formatting each statement.

    rows = []
    total_seen = 0
    kept = 0

    # PcapReader yields one packet at a time without loading the whole file.
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            total_seen += 1
            row = packet_to_row(pkt)
            if row is None:
                continue
            rows.append(row)
            kept += 1
            # Flush in batches of 500 to keep memory flat on large captures.
            if len(rows) >= 500:
                cur.executemany(insert_sql, rows)
                rows.clear()

    if rows:  # insert any leftover rows from the final partial batch
        cur.executemany(insert_sql, rows)

    # Now let the database build the flows table from what we loaded.
    cur.executescript(BUILD_FLOWS)

    conn.commit()  # one commit = one transaction = fast and atomic

    # A couple of quick counts to confirm what we stored.
    n_packets = cur.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    n_flows = cur.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    conn.close()

    print(f"Read {total_seen} packets from {pcap_path}")
    print(f"Stored {kept} IP packets into table 'packets'")
    print(f"Derived {n_flows} flows into table 'flows'")
    print(f"Database written to: {db_path}")
    return n_packets, n_flows


def main():
    parser = argparse.ArgumentParser(
        description="Convert a .pcap capture into a SQLite database."
    )
    parser.add_argument("pcap", help="path to the input .pcap file")
    parser.add_argument(
        "--db", default="data/traffic.db",
        help="path to the output SQLite database (default: data/traffic.db)",
    )
    args = parser.parse_args()
    load_pcap(args.pcap, args.db)


if __name__ == "__main__":
    main()
