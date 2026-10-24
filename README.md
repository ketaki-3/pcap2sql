# PCAP2SQL — Network Traffic Analyzer (Desktop App)

A small **desktop application** that parses a packet capture (`.pcap`) into a
**SQLite** database and runs traffic-analysis queries over it, all from a
windowed GUI.

**Module implemented:** *PCAP Analysis → PCAP to SQLite*. The module is not just
named — real packets are parsed, loaded into a relational schema, and analysed
with SQL inside the app.

---

## The concept

A `.pcap` file is a raw, sequential log of network packets, each stored with a
timestamp exactly as a sniffer (Wireshark, tcpdump) recorded it. It's great for
capturing but awful for *asking questions*: answering "which host sent the most
data?" means writing custom code that walks every packet.

So we decode the packets **once** and store the fields that matter as rows in a
database. After that, every analysis question is ordinary SQL. Change the
capture, rebuild the database, and the same queries answer the same questions
about the new traffic. That reusability is the whole argument for "PCAP → SQLite".

```
 .pcap  ──►  parse (scapy)  ──►  SQLite DB  ──►  SQL queries  ──►  results table
 raw packets   core.py           traffic.db      core.py           app.py (GUI)
```

---

## Files

| File                 | Role                                                                 |
|----------------------|----------------------------------------------------------------------|
| **`app.py`**         | The desktop GUI (Tkinter). **Run this.**                             |
| **`core.py`**        | The engine: sample generation, pcap→sqlite loading, the analysis queries. Contains *no* UI — it's driven by the GUI. |
| `generate_sample.py` | Standalone CLI version of the sample generator (optional).           |
| `pcap2sql.py`        | Standalone CLI loader (optional).                                    |
| `analyze.py`         | Standalone CLI analyser (optional).                                  |
| `data/`              | Holds the capture (`sample.pcap`) and the database (`traffic.db`).   |

The GUI and the CLI scripts share the same engine (`core.py`), so they always
behave identically. The app is the main deliverable; the CLI scripts are there
if you want to show the pipeline step-by-step.

---

## How to run (Windows)

Tkinter ships with Python, so the only dependency is scapy.

```powershell
pip install scapy
python app.py
```

That opens the application window. Inside it:

1. **Capture → Database**
   - Click **Generate sample capture** (creates `data/sample.pcap`), *or*
     **Browse…** to pick any real `.pcap`.
   - Click **Load into database →**. This parses the capture and builds
     `data/traffic.db`.
2. **Analyze**
   - Choose an analysis from the dropdown (its explanation shows beneath).
   - Click **Run analysis**. Results fill the table, and the exact SQL that
     produced them is shown below.

> On Windows the command is `python`, not `python3`. If `python` opens the
> Microsoft Store, install Python from python.org (tick *"Add to PATH"*).

### Running the CLI version instead (optional)

```powershell
python generate_sample.py
python pcap2sql.py data\sample.pcap
python analyze.py
```

---

## The database schema

**`packets`** — one row per IP packet: `id`, `ts`, `ts_readable`, `src_ip`,
`dst_ip`, `protocol` (TCP/UDP/ICMP/OTHER), `src_port`, `dst_port`, `length`
(bytes), `tcp_flags` (e.g. `S`, `SA`, `PA`), `info`.

**`flows`** — derived by `core.py` with a single `GROUP BY`. Each row is one
*conversation* (a unique `src_ip, dst_ip, src_port, dst_port, protocol`
"5-tuple") with `packet_count`, `total_bytes`, `first_seen`, `last_seen`. A flow
is the natural unit for investigating traffic: one connection, not a scattered
pile of packets.

---

## The six analyses

1. **Capture overview** — packets, total bytes, duration, distinct sources.
2. **Top talkers** — who sent the most data (`GROUP BY src_ip`, sum bytes).
3. **Protocol distribution** — the TCP/UDP/etc. mix, with percentages.
4. **Busiest destination ports** — which services (80=HTTP, 443=HTTPS, 53=DNS).
5. **Heaviest flows** — the biggest individual conversations, from `flows`.
6. **TCP connection attempts** — SYN packets per source (port-scan building block).

Each analysis is just an entry in the `ANALYSES` dictionary in `core.py`
(explanation + SQL + column headers). The GUI builds its dropdown from that
dictionary, so **adding a new report means adding one dictionary entry — no GUI
code changes.**

---

## Design notes

- **GUI ↔ engine separation.** `core.py` has no user interface; `app.py` has no
  packet logic. Either could be replaced without touching the other. This is why
  the same code backs both the window and the CLI scripts.
- **Background threads.** Parsing a large capture runs on a worker thread so the
  window never freezes; results are passed back to the main thread through a
  queue (Tkinter widgets may only be touched from the main thread).
- **scapy, not PyShark.** PyShark wraps Wireshark's `tshark` binary, which must
  be installed separately. scapy is pure Python with no system dependency. The
  parsing concept (peel layers `Ethernet → IP → TCP/UDP`, read fields) and the
  schema/queries are identical either way; to use PyShark you'd swap only the
  read loop in `core.load_pcap`.
- **Streaming read, parameterised batched inserts, flows built in SQL** — so it
  scales to large captures, is injection-safe, and lets the database do the
  aggregation work that justifies loading into SQL in the first place.

---

## Requirements

- Python 3.8+
- `scapy` (`pip install scapy`)
- Tkinter — bundled with Python on Windows and macOS; on Linux install
  `python3-tk`.
