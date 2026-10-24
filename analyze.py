"""
analyze.py  --  Run traffic-analysis queries over the SQLite database.
======================================================================
pcap2sql.py put the capture into a database. This file asks it questions.

This is where the value of "PCAP -> SQLite" shows up: every analysis below
is a short SQL query, not bespoke packet-parsing code. Swap the capture,
rebuild the DB, and the same queries answer the same questions about the new
traffic. That reusability is the whole argument for loading packets into SQL.

Each report prints:
  - a one-line explanation of what the question means and why an analyst cares
  - the SQL that answers it (so it's clear the database is doing the work)
  - the results as a simple table

USAGE
    python3 analyze.py                 # uses data/traffic.db
    python3 analyze.py --db mydata.db
"""

import argparse
import sqlite3


def run(cur, title, explanation, sql, headers):
    """Execute one query and print it as a titled, aligned table."""
    print("\n" + "=" * 70)
    print(title)
    print("-" * 70)
    print(explanation)
    print("\nSQL:")
    for line in sql.strip().splitlines():
        print("    " + line.strip())
    print()

    rows = cur.execute(sql).fetchall()
    if not rows:
        print("    (no rows)")
        return

    # Compute a width for each column so the table lines up regardless of data.
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)))

    header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print("    " + header_line)
    print("    " + "  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("    " + "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(row)))


def main():
    parser = argparse.ArgumentParser(description="Analyse a pcap-derived SQLite DB.")
    parser.add_argument("--db", default="data/traffic.db", help="path to the SQLite DB")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    cur = conn.cursor()

    # ----------------------------------------------------------------------
    # Report 0: capture overview
    # ----------------------------------------------------------------------
    run(
        cur,
        "CAPTURE OVERVIEW",
        "Basic shape of the capture: how many packets, bytes, and the time span.\n"
        "Always the first thing you check to know what you're looking at.",
        """
        SELECT COUNT(*)                         AS packets,
               SUM(length)                      AS total_bytes,
               ROUND(MAX(ts) - MIN(ts), 2)      AS duration_sec,
               COUNT(DISTINCT src_ip)           AS distinct_sources
        FROM packets
        """,
        ["packets", "total_bytes", "duration_sec", "distinct_sources"],
    )

    # ----------------------------------------------------------------------
    # Report 1: top talkers by bytes sent
    # ----------------------------------------------------------------------
    run(
        cur,
        "TOP TALKERS  (who sent the most data)",
        "Groups all packets by their source address and sums the bytes.\n"
        "The biggest senders are where you look first for heavy users,\n"
        "backups, exfiltration, or a misbehaving host.",
        """
        SELECT src_ip,
               COUNT(*)      AS packets_sent,
               SUM(length)   AS bytes_sent
        FROM packets
        GROUP BY src_ip
        ORDER BY bytes_sent DESC
        LIMIT 10
        """,
        ["src_ip", "packets_sent", "bytes_sent"],
    )

    # ----------------------------------------------------------------------
    # Report 2: protocol distribution
    # ----------------------------------------------------------------------
    run(
        cur,
        "PROTOCOL DISTRIBUTION",
        "What the traffic is made of. A sudden shift in this mix (e.g. a spike\n"
        "in UDP) is a common early signal of scanning or tunnelling.",
        """
        SELECT protocol,
               COUNT(*)                                             AS packets,
               SUM(length)                                          AS bytes,
               ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM packets), 1) AS pct_packets
        FROM packets
        GROUP BY protocol
        ORDER BY packets DESC
        """,
        ["protocol", "packets", "bytes", "pct_packets"],
    )

    # ----------------------------------------------------------------------
    # Report 3: busiest destination ports (services being used)
    # ----------------------------------------------------------------------
    run(
        cur,
        "BUSIEST DESTINATION PORTS  (which services)",
        "Destination port tells you the service: 80=HTTP, 443=HTTPS, 53=DNS.\n"
        "Unexpected ports here are worth a second look.",
        """
        SELECT dst_port,
               CASE dst_port
                    WHEN 80  THEN 'HTTP'
                    WHEN 443 THEN 'HTTPS'
                    WHEN 53  THEN 'DNS'
                    ELSE '-'
               END            AS likely_service,
               protocol,
               COUNT(*)       AS packets
        FROM packets
        WHERE dst_port IS NOT NULL
        GROUP BY dst_port, protocol
        ORDER BY packets DESC
        LIMIT 10
        """,
        ["dst_port", "likely_service", "protocol", "packets"],
    )

    # ----------------------------------------------------------------------
    # Report 4: heaviest flows (individual conversations)
    # ----------------------------------------------------------------------
    run(
        cur,
        "HEAVIEST FLOWS  (individual conversations)",
        "Reads the derived `flows` table: each row is one 5-tuple conversation.\n"
        "Ranking by bytes shows exactly which connection moved the most data\n"
        "and how long it lasted -- the natural unit for investigating traffic.",
        """
        SELECT src_ip, dst_ip, dst_port, protocol,
               packet_count,
               total_bytes,
               ROUND(last_seen - first_seen, 3) AS duration_sec
        FROM flows
        ORDER BY total_bytes DESC
        LIMIT 10
        """,
        ["src_ip", "dst_ip", "dst_port", "protocol", "packet_count",
         "total_bytes", "duration_sec"],
    )

    # ----------------------------------------------------------------------
    # Report 5: TCP handshake / connection attempts
    # ----------------------------------------------------------------------
    run(
        cur,
        "TCP CONNECTION ATTEMPTS  (SYN packets)",
        "A lone SYN flag marks the start of a TCP connection attempt. Counting\n"
        "SYNs per source is the basic building block of port-scan detection:\n"
        "one host firing many SYNs at many ports is a classic scan signature.",
        """
        SELECT src_ip,
               COUNT(*) AS syn_packets
        FROM packets
        WHERE protocol = 'TCP' AND tcp_flags = 'S'
        GROUP BY src_ip
        ORDER BY syn_packets DESC
        """,
        ["src_ip", "syn_packets"],
    )

    conn.close()
    print("\n" + "=" * 70)
    print("Done. Re-run pcap2sql.py on a different capture and these same")
    print("queries will analyse it -- that's the payoff of loading into SQL.")


if __name__ == "__main__":
    main()
