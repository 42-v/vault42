#!/usr/bin/env python3
"""Generate vault42's IP-intelligence blob (internal/ipintel/data/ipintel.bin).

Sources (all public):
  * Country      -- the five RIR extended delegation files (registration
                    country; coarser than commercial geo, fine for a
                    notify-only signal).
  * IsHosting    -- published cloud / hosting prefix lists (AWS, GCP, and
                    best-effort DigitalOcean / Oracle / Linode).
  * IsTor        -- the Tor bulk exit list.

All sources are merged into a sorted, non-overlapping range table via a
sweep-line and serialized to the compact binary format that internal/ipintel
Load() reads. Re-runnable: just run it again to refresh the blob.

Robust fetching: every source is downloaded concurrently, streamed to a temp
file in chunks with BOTH a per-read socket timeout AND a hard wall-clock
deadline, so a slow mirror that trickles bytes can never hang the run. Any
source that errors or exceeds its budget is skipped (logged); the blob is built
from whatever succeeded (partial country coverage is acceptable).

Usage:
  python3 scripts/gen-ipintel.py [--out PATH] [--timeout SECONDS]
                                 [--deadline SECONDS] [--workers N]

Format (little-endian), version 1 -- must match internal/ipintel/format.go:
  Header (16 B): magic "V42I", version u8=1, reserved[3], v4count u32, v6count u32
  v4 record (11 B): start u32, end u32, cc[2], flags u8   (bit0 hosting, bit1 tor)
  v6 record (35 B): startHi u64, startLo u64, endHi u64, endLo u64, cc[2], flags u8
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import urllib.request

MAGIC = b"V42I"
VERSION = 1
FLAG_HOSTING = 1 << 0
FLAG_TOR = 1 << 1

UA = "vault42-ipintel-gen/1.0 (+https://github.com/42-v/vault42)"

# name -> (url, kind). kind selects the parser.
SOURCES = {
    # Country (RIR extended delegation files)
    "arin": ("https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest", "rir"),
    "ripencc": ("https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest", "rir"),
    "apnic": ("https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest", "rir"),
    "lacnic": ("https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest", "rir"),
    "afrinic": ("https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest", "rir"),
    # Hosting (cloud prefix lists)
    "aws": ("https://ip-ranges.amazonaws.com/ip-ranges.json", "aws"),
    "gcp": ("https://www.gstatic.com/ipranges/cloud.json", "gcp"),
    "digitalocean": ("https://www.digitalocean.com/geo/google.csv", "csv"),
    "oracle": ("https://docs.oracle.com/iaas/tools/public_ip_ranges.json", "oracle"),
    "linode": ("https://geoip.linode.com/", "csv"),
    # Tor
    "tor": ("https://check.torproject.org/torbulkexitlist", "tor"),
}


def fetch_to_file(url, dest, sock_timeout, deadline):
    """Stream url to dest in chunks. Enforces a per-read socket timeout AND a
    hard wall-clock deadline so a slow trickle cannot hang the run.
    """
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    start = time.monotonic()
    with urllib.request.urlopen(req, timeout=sock_timeout) as resp:  # nosec B310 -- fixed https public data URLs
        with open(dest, "wb") as f:
            while True:
                if time.monotonic() - start > deadline:
                    raise TimeoutError(f"exceeded {deadline:.0f}s wall-clock budget")
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                f.write(chunk)
    return time.monotonic() - start


def download_all(tmpdir, sock_timeout, deadline, workers):
    """Fetch every source concurrently. Returns (paths, warns) where paths maps
    name -> local file (only successful downloads) and warns is a list of
    skipped-source messages.
    """
    paths = {}
    warns = []

    def job(name, url):
        dest = os.path.join(tmpdir, name)
        secs = fetch_to_file(url, dest, sock_timeout, deadline)
        return name, dest, os.path.getsize(dest), secs

    # A generous outer cap in case a worker is wedged in a syscall; the inner
    # deadline is the real bound. Outer = deadline + slack.
    outer = deadline + 30
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(job, n, u): n for n, (u, _kind) in SOURCES.items()}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=outer + 5):
                name = futs[fut]
                try:
                    n, dest, size, secs = fut.result()
                    paths[n] = dest
                    print(f"  {n}: {size:,} bytes in {secs:.1f}s")
                except Exception as e:  # noqa: BLE001 -- best-effort per source
                    warns.append(f"{name} skipped: {e}")
                    print(f"  {name}: SKIPPED ({e})")
        except concurrent.futures.TimeoutError:
            for fut, name in futs.items():
                if not fut.done():
                    fut.cancel()
                    warns.append(f"{name} skipped: outer timeout")
                    print(f"  {name}: SKIPPED (outer timeout)")
    return paths, warns


# --- interval collection -------------------------------------------------


class Collector:
    def __init__(self):
        self.v4 = {"country": [], "hosting": [], "tor": []}
        self.v6 = {"country": [], "hosting": [], "tor": []}
        self.hosting_prefixes = 0
        self.tor_ips = 0
        self.country_rows = 0

    def bucket(self, version):
        return self.v4 if version == 4 else self.v6

    def add_country(self, version, lo, hi, cc):
        self.bucket(version)["country"].append((lo, hi, cc))

    def add_cidr(self, kind, cidr):
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return False
        self.bucket(net.version)[kind].append(
            (int(net.network_address), int(net.broadcast_address), None)
        )
        return True

    def add_ip(self, kind, ip):
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        v = int(addr)
        self.bucket(addr.version)[kind].append((v, v, None))
        return True


def parse_rir(col, path):
    kept = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line[0] == "#":
                continue
            parts = line.split("|")
            if len(parts) < 7:
                continue
            _registry, cc, typ, start, value, _date, status = parts[:7]
            if typ not in ("ipv4", "ipv6"):
                continue
            if status not in ("allocated", "assigned"):
                continue  # skip reserved / available / summary
            if len(cc) != 2 or not cc.isalpha():
                continue
            cc = cc.upper()
            try:
                if typ == "ipv4":
                    lo = int(ipaddress.IPv4Address(start))
                    count = int(value)
                    if count <= 0:
                        continue
                    hi = lo + count - 1
                    if hi > 0xFFFFFFFF:
                        continue
                    col.add_country(4, lo, hi, cc)
                else:
                    base = int(ipaddress.IPv6Address(start))
                    plen = int(value)
                    if not 0 <= plen <= 128:
                        continue
                    col.add_country(6, base, base + (1 << (128 - plen)) - 1, cc)
                kept += 1
            except (ValueError, ipaddress.AddressValueError):
                continue
    col.country_rows += kept
    return kept


def parse_aws(col, path):
    with open(path, "rb") as fh:
        data = json.load(fh)
    n = 0
    for p in data.get("prefixes", []):
        if p.get("ip_prefix") and col.add_cidr("hosting", p["ip_prefix"]):
            n += 1
    for p in data.get("ipv6_prefixes", []):
        if p.get("ipv6_prefix") and col.add_cidr("hosting", p["ipv6_prefix"]):
            n += 1
    col.hosting_prefixes += n
    return n


def parse_gcp(col, path):
    with open(path, "rb") as fh:
        data = json.load(fh)
    n = 0
    for p in data.get("prefixes", []):
        cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
        if cidr and col.add_cidr("hosting", cidr):
            n += 1
    col.hosting_prefixes += n
    return n


def parse_oracle(col, path):
    with open(path, "rb") as fh:
        data = json.load(fh)
    n = 0
    for region in data.get("regions", []):
        for c in region.get("cidrs", []):
            if c.get("cidr") and col.add_cidr("hosting", c["cidr"]):
                n += 1
    col.hosting_prefixes += n
    return n


def parse_csv_prefixes(col, path):
    """First CSV column is a CIDR (DigitalOcean, Linode geofeed)."""
    n = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] == "#":
                continue
            if col.add_cidr("hosting", line.split(",", 1)[0]):
                n += 1
    col.hosting_prefixes += n
    return n


def parse_tor(col, path):
    n = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] == "#":
                continue
            if col.add_ip("tor", line):
                n += 1
    col.tor_ips += n
    return n


PARSERS = {
    "rir": parse_rir,
    "aws": parse_aws,
    "gcp": parse_gcp,
    "oracle": parse_oracle,
    "csv": parse_csv_prefixes,
    "tor": parse_tor,
}


# --- sweep-line merge ----------------------------------------------------


def merge_family(buckets):
    """Merge country/hosting/tor intervals of one family into sorted,
    non-overlapping (lo, hi, cc, flags) segments carrying combined attributes.
    """
    start_ev = {}
    end_ev = {}
    coords = set()
    for kind in ("country", "hosting", "tor"):
        for lo, hi, cc in buckets[kind]:
            start_ev.setdefault(lo, []).append((kind, cc))
            end_ev.setdefault(hi + 1, []).append((kind, cc))
            coords.add(lo)
            coords.add(hi + 1)
    if not coords:
        return []
    coords = sorted(coords)

    hosting = 0
    tor = 0
    cc_counts = {}

    def active_cc():
        best = None
        for cc, n in cc_counts.items():
            if n > 0 and (best is None or cc < best):
                best = cc
        return best

    segments = []
    for idx, x in enumerate(coords):
        for kind, cc in end_ev.get(x, ()):  # ends before starts at same coord
            if kind == "hosting":
                hosting -= 1
            elif kind == "tor":
                tor -= 1
            else:
                cc_counts[cc] -= 1
        for kind, cc in start_ev.get(x, ()):
            if kind == "hosting":
                hosting += 1
            elif kind == "tor":
                tor += 1
            else:
                cc_counts[cc] = cc_counts.get(cc, 0) + 1
        if idx + 1 >= len(coords):
            break
        cc = active_cc()
        h = hosting > 0
        t = tor > 0
        if cc is None and not h and not t:
            continue
        flags = (FLAG_HOSTING if h else 0) | (FLAG_TOR if t else 0)
        segments.append([x, coords[idx + 1] - 1, cc or "", flags])

    merged = []
    for seg in segments:
        if merged:
            prev = merged[-1]
            if prev[1] + 1 == seg[0] and prev[2] == seg[2] and prev[3] == seg[3]:
                prev[1] = seg[1]
                continue
        merged.append(seg)
    return merged


# --- serialization -------------------------------------------------------


def cc_bytes(cc):
    return cc.encode("ascii") if len(cc) == 2 else b"\x00\x00"


def serialize(v4_segs, v6_segs):
    out = bytearray()
    out += struct.pack("<4sB3sII", MAGIC, VERSION, b"\x00\x00\x00", len(v4_segs), len(v6_segs))
    for lo, hi, cc, flags in v4_segs:
        out += struct.pack("<II2sB", lo, hi, cc_bytes(cc), flags)
    mask = (1 << 64) - 1
    for lo, hi, cc, flags in v6_segs:
        out += struct.pack(
            "<QQQQ2sB", lo >> 64, lo & mask, hi >> 64, hi & mask, cc_bytes(cc), flags
        )
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description="Generate vault42 ipintel blob")
    here = os.path.dirname(os.path.abspath(__file__))
    default_out = os.path.normpath(
        os.path.join(here, "..", "internal", "ipintel", "data", "ipintel.bin")
    )
    ap.add_argument("--out", default=default_out)
    ap.add_argument("--timeout", type=float, default=30.0, help="per-read socket timeout (s)")
    ap.add_argument("--deadline", type=float, default=90.0, help="per-source wall-clock budget (s)")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    col = Collector()
    tmpdir = tempfile.mkdtemp(prefix="ipintel-gen-")
    try:
        print(f"Downloading {len(SOURCES)} sources concurrently "
              f"(socket={args.timeout:.0f}s, deadline={args.deadline:.0f}s, workers={args.workers})...")
        t0 = time.monotonic()
        paths, warns = download_all(tmpdir, args.timeout, args.deadline, args.workers)
        print(f"Downloaded {len(paths)}/{len(SOURCES)} sources in {time.monotonic()-t0:.1f}s")

        print("Parsing...")
        for name, (_url, kind) in SOURCES.items():
            path = paths.get(name)
            if not path:
                continue
            try:
                n = PARSERS[kind](col, path)
                print(f"  {name} ({kind}): {n:,} entries")
            except Exception as e:  # noqa: BLE001
                warns.append(f"{name} parse failed: {e}")
                print(f"  {name}: PARSE FAILED ({e})")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if col.country_rows == 0 and col.hosting_prefixes == 0 and col.tor_ips == 0:
        print("FATAL: every data source failed; refusing to overwrite the blob.", file=sys.stderr)
        return 1

    print("Merging into non-overlapping range table...")
    v4_segs = merge_family(col.v4)
    v6_segs = merge_family(col.v6)
    countries = {s[2] for s in v4_segs if s[2]} | {s[2] for s in v6_segs if s[2]}

    blob = serialize(v4_segs, v6_segs)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    tmp = args.out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, args.out)

    print("-" * 60)
    print(f"Wrote {args.out}")
    print(f"  size:               {len(blob):,} bytes ({len(blob)/1024/1024:.2f} MiB)")
    print(f"  v4 ranges:          {len(v4_segs):,}")
    print(f"  v6 ranges:          {len(v6_segs):,}")
    print(f"  total ranges:       {len(v4_segs)+len(v6_segs):,}")
    print(f"  distinct countries: {len(countries)}")
    print(f"  hosting prefixes:   {col.hosting_prefixes:,} (input)")
    print(f"  tor exit IPs:       {col.tor_ips:,} (input)")
    if warns:
        print("  warnings:")
        for w in warns:
            print(f"    - {w}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
