"""
generate_sample.py
------------------
Builds a small but realistic .pcap capture file so the rest of the project
has real input to work on without needing you to sniff live traffic.

WHY THIS EXISTS
A .pcap ("packet capture") file is just a sequence of raw network packets,
each stored with a timestamp, exactly as a tool like Wireshark or tcpdump
would record them off a network interface. Normally you'd obtain one by
capturing live traffic (which needs admin rights and a network to watch) or
by downloading a public sample. To keep this project self-contained and
reproducible, we instead *synthesise* one: we hand-build packets with scapy
and write them out in the standard pcap format. A parser cannot tell the
difference between these and real captured packets -- the file format is
identical.

WHAT WE BUILD
A few internal hosts (192.168.1.x) talking to external servers:
  - DNS lookups (UDP port 53)
  - Web page loads over HTTP (TCP port 80), including the 3-way handshake
  - Encrypted traffic over HTTPS (TCP port 443)
  - A couple of raw UDP app streams
We deliberately vary how much each host sends so that "top talkers" and
"protocol distribution" queries later produce a non-trivial picture.
"""

import random
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

random.seed(42)  # deterministic output: same file every run, good for a demo

packets = []
clock = 1_700_000_000.0  # a fixed Unix epoch start time (seconds since 1970)


def add(pkt, gap=None):
    """Append a packet, stamping it with a monotonically increasing time.

    Real captures record WHEN each packet arrived. scapy stores that on the
    packet's .time attribute (a float, seconds). We advance a shared clock by
    a small random gap so packets have believable inter-arrival spacing.
    """
    global clock
    clock += gap if gap is not None else random.uniform(0.0005, 0.03)
    pkt.time = clock
    packets.append(pkt)


# Internal hosts and the external servers they talk to.
CLIENTS = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
DNS_SERVER = "192.168.1.1"
WEB_SERVERS = {
    "93.184.216.34": "example.com",
    "151.101.0.81": "news.site",
    "140.82.112.3": "code.host",
}


def tcp_session(client, server, dport, n_data_pkts, payload_size):
    """Emit one realistic TCP conversation: handshake, data, teardown.

    TCP is connection-oriented. Every session begins with a 3-way handshake
    (SYN -> SYN/ACK -> ACK) and ends with FIN packets. Representing this
    faithfully means our later "flow" analysis sees proper connection
    boundaries, not just loose packets. Ports and sequence-ish flags are what
    a traffic analyst actually keys on, so we set them explicitly.
    """
    sport = random.randint(1024, 65535)  # client's ephemeral source port

    # --- 3-way handshake ---
    add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="S"))
    add(Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="SA"))
    add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A"))

    # --- data transfer (client request, server responds with several pkts) ---
    add(Ether() / IP(src=client, dst=server) /
        TCP(sport=sport, dport=dport, flags="PA") / Raw(load=b"GET / HTTP/1.1\r\n"))
    for _ in range(n_data_pkts):
        add(Ether() / IP(src=server, dst=client) /
            TCP(sport=dport, dport=sport, flags="PA") /
            Raw(load=bytes(random.getrandbits(8) for _ in range(payload_size))))

    # --- teardown ---
    add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="FA"))
    add(Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="FA"))


def dns_lookup(client, qname):
    """Emit a DNS question and its answer (UDP port 53).

    DNS resolves names to IPs. It's a tidy request/response over UDP, and a
    classic thing a traffic analyst inspects to see what a host was trying to
    reach. We include both the query and a plausible answer record.
    """
    sport = random.randint(1024, 65535)
    add(Ether() / IP(src=client, dst=DNS_SERVER) /
        UDP(sport=sport, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=qname)))
    add(Ether() / IP(src=DNS_SERVER, dst=client) /
        UDP(sport=53, dport=sport) /
        DNS(qr=1, qd=DNSQR(qname=qname),
            an=DNSRR(rrname=qname, rdata="93.184.216.34")))


# --- Build a session's worth of varied traffic -----------------------------

# DNS lookups first (as a real client would resolve before connecting)
for client in CLIENTS:
    for server_ip, name in WEB_SERVERS.items():
        dns_lookup(client, name)

# .10 is a heavy web user: many HTTP + HTTPS sessions, large transfers
for _ in range(6):
    tcp_session("192.168.1.10", "93.184.216.34", 80, n_data_pkts=8, payload_size=1200)
for _ in range(4):
    tcp_session("192.168.1.10", "151.101.0.81", 443, n_data_pkts=12, payload_size=1400)

# .11 is a moderate user
for _ in range(3):
    tcp_session("192.168.1.11", "140.82.112.3", 443, n_data_pkts=5, payload_size=900)
for _ in range(2):
    tcp_session("192.168.1.11", "93.184.216.34", 80, n_data_pkts=3, payload_size=600)

# .12 is light, plus a bit of raw UDP (e.g. a streaming/app protocol)
tcp_session("192.168.1.12", "151.101.0.81", 80, n_data_pkts=2, payload_size=400)
for _ in range(15):
    sport = random.randint(1024, 65535)
    add(Ether() / IP(src="192.168.1.12", dst="8.8.8.8") /
        UDP(sport=sport, dport=4433) /
        Raw(load=bytes(random.getrandbits(8) for _ in range(300))))

# Shuffle is NOT applied: real captures are time-ordered, and we built them in
# time order via the shared clock. Write them out in the standard pcap format.
OUT = "data/sample.pcap"
wrpcap(OUT, packets)
print(f"Wrote {len(packets)} packets to {OUT}")
