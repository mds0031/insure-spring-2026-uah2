#!/usr/bin/env python3
"""
layerAll.py

TShark-only packet analyzer.
Supports:
- PCAP input OR live capture
- Default temp PCAP deletion for live capture
- Optional --keep-pcap flag
- Optional app/domain filtering
- Correlates app-matched traffic down to Layers 1-4 so lower layers can be
  shown only for traffic associated with the filtered application set

Dependency:
- TShark / Wireshark only

Notes:
- When --app-filter is used, Layers 5/6/7 are filtered directly by matching
  app/domain names.
- Layers 1/2/3/4 are filtered indirectly by first discovering IPs and packet
  frame numbers associated with the matched app traffic, then only counting
  lower-layer traffic tied to those matched packets/IPs.
- This is best-effort correlation for modern encrypted traffic.
"""

import argparse
import os
import subprocess
import sys
import tempfile
from collections import Counter


def run_tshark(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "TShark command failed")
    return result.stdout.splitlines()


def check_tshark():
    try:
        result = subprocess.run(
            ["tshark", "-v"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            raise RuntimeError
    except Exception:
        print("Error: TShark is not installed or not in PATH.")
        sys.exit(1)


def capture_live(interface, timeout, packet_limit=None, bpf_filter=None):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    tmp.close()

    cmd = ["tshark", "-i", interface, "-w", tmp.name]

    if timeout and timeout > 0:
        cmd.extend(["-a", f"duration:{timeout}"])

    if packet_limit and packet_limit > 0:
        cmd.extend(["-c", str(packet_limit)])

    if bpf_filter:
        cmd.extend(["-f", bpf_filter])

    print(f"Capturing live traffic on {interface}")
    print(f"Temporary PCAP: {tmp.name}")

    result = subprocess.run(cmd)
    if result.returncode != 0:
        try:
            os.remove(tmp.name)
        except OSError:
            pass
        raise RuntimeError("Live capture failed.")

    return tmp.name


def matches_app_filter(value, filters):
    if not filters:
        return True
    if not value:
        return False
    value = value.lower()
    return any(term in value for term in filters)


def build_app_context(pcap, app_filters):
    """
    Build correlation context for app-filtered traffic.

    Returns:
        {
            "matched_frames": set(frame_numbers),
            "matched_ips": set(ip_strings),
            "matched_ip_pairs": set((src_ip, dst_ip)),
            "layer5_flows": Counter(),
            "layer7_flows": Counter(),
        }
    """
    matched_frames = set()
    matched_ips = set()
    matched_ip_pairs = set()

    layer5_flows = Counter()
    #layer6_flows = Counter()
    layer7_flows = Counter()

    # DNS
    dns_lines = run_tshark([
        "tshark", "-r", pcap,
        "-Y", "dns and ip",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "dns.qry.name"
    ])

    for line in dns_lines:
        parts = line.split("\t")
        if len(parts) < 4:
            continue

        frame_no, src, dst, domain = parts[:4]

        if src and domain and matches_app_filter(domain, app_filters):
            layer5_flows[(src, domain)] += 1
            if frame_no:
                matched_frames.add(frame_no)
            if src:
                matched_ips.add(src)
            if dst:
                matched_ips.add(dst)
            if src and dst:
                matched_ip_pairs.add((src, dst))

    # TLS / SNI
    tls_lines = run_tshark([
        "tshark", "-r", pcap,
        "-Y", "tls.handshake.extensions_server_name and ip",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tls.handshake.extensions_server_name"
    ])

    for line in tls_lines:
        parts = line.split("\t")
        if len(parts) < 4:
            continue

        frame_no, src, dst, sni = parts[:4]

        if src and sni and matches_app_filter(sni, app_filters):
            #layer6_flows[(src, sni)] += 1
            if frame_no:
                matched_frames.add(frame_no)
            if src:
                matched_ips.add(src)
            if dst:
                matched_ips.add(dst)
            if src and dst:
                matched_ip_pairs.add((src, dst))

    # HTTP / HTTP2 / QUIC / TLS
    app_lines = run_tshark([
        "tshark", "-r", pcap,
        "-Y", "ip and (http or http2 or quic or tls)",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "http.host",
        "-e", "http2.headers.authority",
        "-e", "tls.handshake.extensions_server_name"
    ])

    for line in app_lines:
        parts = line.split("\t")
        if len(parts) < 6:
            continue

        frame_no, src, dst, http_host, http2_host, sni = parts[:6]
        dest_name = http_host or http2_host or sni

        if src and dest_name and matches_app_filter(dest_name, app_filters):
            layer7_flows[(src, dest_name)] += 1
            if frame_no:
                matched_frames.add(frame_no)
            if src:
                matched_ips.add(src)
            if dst:
                matched_ips.add(dst)
            if src and dst:
                matched_ip_pairs.add((src, dst))

    return {
        "matched_frames": matched_frames,
        "matched_ips": matched_ips,
        "matched_ip_pairs": matched_ip_pairs,
        "layer5_flows": layer5_flows,
        #"layer6_flows": layer6_flows,
        "layer7_flows": layer7_flows,
    }


def packet_matches_filter(ip_src, ip_dst, matched_ips, matched_ip_pairs):
    if not matched_ips and not matched_ip_pairs:
        return False

    if ip_src and ip_dst and ((ip_src, ip_dst) in matched_ip_pairs or (ip_dst, ip_src) in matched_ip_pairs):
        return True

    if ip_src and ip_src in matched_ips:
        return True

    if ip_dst and ip_dst in matched_ips:
        return True

    return False


def layer1(pcap, app_context=None):
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst"
    ])

    packets = 0
    bytes_total = 0

    matched_frames = set()
    matched_ips = set()
    matched_ip_pairs = set()

    if app_context:
        matched_frames = app_context["matched_frames"]
        matched_ips = app_context["matched_ips"]
        matched_ip_pairs = app_context["matched_ip_pairs"]

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 4:
            continue

        frame_no, frame_len, ip_src, ip_dst = parts[:4]

        if not frame_len:
            continue

        if app_context:
            if frame_no in matched_frames or packet_matches_filter(ip_src, ip_dst, matched_ips, matched_ip_pairs):
                packets += 1
                bytes_total += int(frame_len)
        else:
            packets += 1
            bytes_total += int(frame_len)

    if app_context:
        print("\n=== Layer 1: Physical (Interface Metrics for Filtered App Traffic) ===")
    else:
        print("\n=== Layer 1: Physical (Interface Metrics) ===")

    print(f"Packets: {packets}")
    print(f"Bytes:   {bytes_total}")
    print(f"Bits:    {bytes_total * 8}")


def layer2(pcap, app_context=None):
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ip.dst"
    ])

    flows = Counter()

    matched_frames = set()
    matched_ips = set()
    matched_ip_pairs = set()

    if app_context:
        matched_frames = app_context["matched_frames"]
        matched_ips = app_context["matched_ips"]
        matched_ip_pairs = app_context["matched_ip_pairs"]

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 5:
            continue

        frame_no, eth_src, eth_dst, ip_src, ip_dst = parts[:5]

        if not eth_src or not eth_dst:
            continue

        if app_context:
            if frame_no in matched_frames or packet_matches_filter(ip_src, ip_dst, matched_ips, matched_ip_pairs):
                flows[(eth_src, eth_dst)] += 1
        else:
            flows[(eth_src, eth_dst)] += 1

    if app_context:
        print("\n=== Layer 2: Data Link (MAC for Filtered App Traffic) ===")
    else:
        print("\n=== Layer 2: Data Link (MAC) ===")

    for (src, dst), count in flows.most_common():
        print(f"{src} -> {dst}  {count}")


def layer3(pcap, app_context=None):
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst"
    ])

    flows = Counter()

    matched_frames = set()
    matched_ips = set()
    matched_ip_pairs = set()

    if app_context:
        matched_frames = app_context["matched_frames"]
        matched_ips = app_context["matched_ips"]
        matched_ip_pairs = app_context["matched_ip_pairs"]

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3:
            continue

        frame_no, src, dst = parts[:3]

        if not src or not dst:
            continue

        if app_context:
            if frame_no in matched_frames or packet_matches_filter(src, dst, matched_ips, matched_ip_pairs):
                flows[(src, dst)] += 1
        else:
            flows[(src, dst)] += 1

    if app_context:
        print("\n=== Layer 3: Network (IP for Filtered App Traffic) ===")
    else:
        print("\n=== Layer 3: Network (IP) ===")

    for (src, dst), count in flows.most_common():
        print(f"{src} -> {dst}  {count}")


def layer4(pcap, app_context=None):
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport"
    ])

    flows = Counter()

    matched_frames = set()
    matched_ips = set()
    matched_ip_pairs = set()

    if app_context:
        matched_frames = app_context["matched_frames"]
        matched_ips = app_context["matched_ips"]
        matched_ip_pairs = app_context["matched_ip_pairs"]

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 7:
            continue

        frame_no, ip_src, tcp_s, ip_dst, tcp_d, udp_s, udp_d = parts[:7]

        include = True
        if app_context:
            include = frame_no in matched_frames or packet_matches_filter(ip_src, ip_dst, matched_ips, matched_ip_pairs)

        if not include:
            continue

        if tcp_s and tcp_d and ip_src and ip_dst:
            flows[(f"{ip_src}:{tcp_s}", f"{ip_dst}:{tcp_d}", "TCP")] += 1
        elif udp_s and udp_d and ip_src and ip_dst:
            flows[(f"{ip_src}:{udp_s}", f"{ip_dst}:{udp_d}", "UDP")] += 1

    if app_context:
        print("\n=== Layer 4: Transport (TCP/UDP for Filtered App Traffic) ===")
    else:
        print("\n=== Layer 4: Transport (TCP/UDP) ===")

    for (src, dst, proto), count in flows.most_common():
        print(f"{proto} {src} -> {dst}  {count}")


def layer5_from_context(app_context=None):
    flows = Counter()
    if app_context:
        flows = app_context["layer5_flows"]

    print("\n=== Layer 5: Session (DNS) ===")
    for (src, domain), count in flows.most_common():
        print(f"{src} -> {domain}  {count}")


# def layer6_from_context(app_context=None):
    # flows = Counter()
    # if app_context:
        # flows = app_context["layer6_flows"]

    # print("\n=== Layer 6: Upper-Layer Service (TLS / SNI) ===")
    # for (src, sni), count in flows.most_common():
        # print(f"{src} -> {sni}  {count}")


def layer7_from_context(app_context=None):
    flows = Counter()
    if app_context:
        flows = app_context["layer7_flows"]

    print("\n=== Layer 7: Application (URL/String) ===")
    for (src, dst), count in flows.most_common():
        print(f"{src} -> {dst}  {count}")


def layer5_unfiltered(pcap):
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-Y", "dns",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "dns.qry.name"
    ])

    flows = Counter()

    for line in lines:
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        src, domain = parts
        if src and domain:
            flows[(src, domain)] += 1

    print("\n=== Layer 5: Session (DNS) ===")
    for (src, domain), count in flows.most_common():
        print(f"{src} -> {domain}  {count}")


# def layer6_unfiltered(pcap):
    # lines = run_tshark([
        # "tshark", "-r", pcap,
        # "-Y", "tls.handshake.extensions_server_name",
        # "-T", "fields",
        # "-e", "ip.src",
        # "-e", "tls.handshake.extensions_server_name"
    # ])

    # flows = Counter()

    # for line in lines:
        # parts = line.split("\t")
        # if len(parts) != 2:
            # continue
        # src, sni = parts
        # if src and sni:
            # flows[(src, sni)] += 1

    # print("\n=== Layer 6: Upper-Layer Service (TLS / SNI) ===")
    # for (src, sni), count in flows.most_common():
        # print(f"{src} -> {sni}  {count}")


def layer7_unfiltered(pcap):
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-Y", "http or http2 or quic or tls",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "http.host",
        "-e", "http2.headers.authority",
        "-e", "tls.handshake.extensions_server_name"
    ])

    flows = Counter()

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 4:
            continue

        src, http_host, http2_host, sni = parts[:4]
        dst = http_host or http2_host or sni

        if src and dst:
            flows[(src, dst)] += 1

    print("\n=== Layer 7: Application (URL/String) ===")
    for (src, dst), count in flows.most_common():
        print(f"{src} -> {dst}  {count}")


def main():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="Input PCAP file")
    source.add_argument("--iface", help="Live capture interface")

    parser.add_argument("--timeout", type=int, default=30, help="Live capture duration in seconds")
    parser.add_argument("--packet-limit", type=int, default=0, help="Optional live packet limit")
    parser.add_argument("--bpf", help="Optional live BPF filter")
    parser.add_argument(
        "--app-filter",
        help='Comma-separated terms for app/domain filtering, e.g. "youtube,googlevideo,ytimg,youtubei"'
    )
    parser.add_argument(
        "--keep-pcap",
        action="store_true",
        help="Keep temporary PCAP created during live capture"
    )

    args = parser.parse_args()

    app_filters = []
    if args.app_filter:
        app_filters = [x.strip().lower() for x in args.app_filter.split(",") if x.strip()]

    check_tshark()

    temp_pcap = None
    pcap = args.pcap

    try:
        if args.iface:
            temp_pcap = capture_live(
                interface=args.iface,
                timeout=args.timeout,
                packet_limit=args.packet_limit,
                bpf_filter=args.bpf
            )
            pcap = temp_pcap

        app_context = None
        if app_filters:
            app_context = build_app_context(pcap, app_filters)
            print(f"\nApp filter active: {', '.join(app_filters)}")
            print(f"Matched app frames: {len(app_context['matched_frames'])}")
            print(f"Matched IPs: {len(app_context['matched_ips'])}")

        layer1(pcap, app_context)
        layer2(pcap, app_context)
        layer3(pcap, app_context)
        layer4(pcap, app_context)

        if app_context:
            layer5_from_context(app_context)
            #layer6_from_context(app_context)
            layer7_from_context(app_context)
        else:
            layer5_unfiltered(pcap)
            #layer6_unfiltered(pcap)
            layer7_unfiltered(pcap)

        print("\nAnalysis complete.")

        if temp_pcap and args.keep_pcap:
            print(f"Kept temporary capture: {temp_pcap}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    finally:
        if temp_pcap and not args.keep_pcap:
            try:
                os.remove(temp_pcap)
                print(f"Deleted temporary capture: {temp_pcap}")
            except OSError:
                print(f"Warning: could not delete temporary capture: {temp_pcap}")


if __name__ == "__main__":
    main()