#!/usr/bin/env python3
"""Traffic helpers for test/mesh.sh.

  net.py serve <ip> <port>             TCP sink: replies with sha256 of what it received
  net.py send <ip> <port> <bytes>      send marker-laden data, verify the digest, print MB/s
  net.py sniff <iface> <seconds>       count frames on iface: total UDP, and any carrying the marker
  net.py pcap <file>                   validate a pcap written by 'wyrm capture'
"""
import hashlib, socket, struct, sys, time

MARKER = b"WYRM-PLAINTEXT-MARKER-0123456789"

def serve(ip, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, int(port)))
    s.listen(16)
    while True:
        c, _ = s.accept()
        h = hashlib.sha256()
        while True:
            d = c.recv(1 << 16)
            if not d:
                break
            h.update(d)
        try:
            c.sendall(h.hexdigest().encode())
        except OSError:
            pass
        c.close()

def send(ip, port, n):
    n = int(n)
    block = (MARKER * (65536 // len(MARKER) + 1))[:65536]
    h = hashlib.sha256()
    c = socket.create_connection((ip, int(port)), timeout=4)
    c.settimeout(30)
    t0 = time.time()
    left = n
    while left > 0:
        chunk = block[:min(left, len(block))]
        c.sendall(chunk)
        h.update(chunk)
        left -= len(chunk)
    c.shutdown(socket.SHUT_WR)
    got = c.recv(128).decode()
    dt = time.time() - t0
    if got != h.hexdigest():
        print("digest mismatch")
        sys.exit(1)
    print("ok %.1f MB/s" % (n / dt / 1e6))

def sniff(iface, seconds):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((iface, 0))
    s.settimeout(0.2)
    end = time.time() + float(seconds)
    udp = leaked = 0
    while time.time() < end:
        try:
            f = s.recv(65535)
        except socket.timeout:
            continue
        if len(f) > 23 and f[12:14] == b"\x08\x00" and f[23] == 17:
            udp += 1
        if MARKER in f:
            leaked += 1
    print("udp=%d leaked=%d" % (udp, leaked))

def pcap(path):
    b = open(path, "rb").read()
    magic, vmaj, vmin, _, _, snap, link = struct.unpack("<IHHiIII", b[:24])
    assert magic == 0xA1B2C3D4 and (vmaj, vmin) == (2, 4) and link == 101, "bad pcap header"
    off, n, mesh = 24, 0, 0
    while off + 16 <= len(b):
        _, _, incl, orig = struct.unpack("<IIII", b[off:off + 16])
        pkt = b[off + 16:off + 16 + incl]
        assert len(pkt) == incl and incl <= snap and incl <= orig, "bad record"
        if pkt[0] >> 4 == 4 and pkt[12] == 10 and pkt[13] == 88:
            mesh += 1
        n += 1
        off += 16 + incl
    assert off == len(b), "trailing bytes"
    print("packets=%d mesh=%d" % (n, mesh))

if __name__ == "__main__":
    {"serve": serve, "send": send, "sniff": sniff, "pcap": pcap}[sys.argv[1]](*sys.argv[2:])
