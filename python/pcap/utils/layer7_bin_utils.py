import dpkt
import os
from time import perf_counter_ns

import utils.conversion as conv
from utils.matrix import BucketedMatrixBuilder
from utils.benchmark import Layer7BenchmarkResult


# -----------------------------------------------------------
# Binary Mode Helpers (GraphBLAS)
# -----------------------------------------------------------
def get_or_create_label_id(label, label_map, next_id):
    """
    Maps a string label to a unique integer ID.

    Used only in binary mode where matrices require numeric indices.
    """
    if label not in label_map:
        label_map[label] = next_id
        next_id += 1
    return label_map[label], next_id

def build_label_map_tsv_text(label_map):
    """
    Builds label_id -> label mapping as TSV text in memory.

    Used for inserting the TSV directly into the tar archive.
    """
    lines = ["label_id\tlabel"]
    for label, label_id in sorted(label_map.items(), key=lambda x: x[1]):
        lines.append(f"{label_id}\t{label}")
    return "\n".join(lines) + "\n"

def write_label_map(label_map, path):
    """
    Writes label_id -> label mapping to a TSV file.

    This allows reconstruction of string labels from numeric matrix indices.
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write("label_id\tlabel\n")
        for label, label_id in sorted(label_map.items(), key=lambda x: x[1]):
            f.write(f"{label_id}\t{label}\n")

# -----------------------------------------------------------
# Safe Decoding Utility
# -----------------------------------------------------------
def safe_decode(value):
    """
    Safely decodes bytes to UTF-8 string.

    Prevents crashes from malformed packet payloads.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""
    return str(value).strip()

# -----------------------------------------------------------
# HTTP Parsing
# -----------------------------------------------------------
def parse_http_fields(tcp_data):
    """
    Extract HTTP full URI and host from TCP payload.

    Returns:
        (http_full_uri, http_host)
    """
    try:
        req = dpkt.http.Request(tcp_data)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return "", ""

    host = safe_decode(req.headers.get("host", ""))
    uri = safe_decode(getattr(req, "uri", ""))

    if uri and host:
        # Match tshark's full_uri behavior as closely as possible
        if uri.startswith("http://") or uri.startswith("https://"):
            full_uri = uri
        else:
            full_uri = f"http://{host}{uri}"
    else:
        full_uri = ""

    return full_uri, host

# -----------------------------------------------------------
# DNS Parsing (UDP + TCP)
# -----------------------------------------------------------
def parse_dns_name(l4_data):
    """
    Extract DNS query name from UDP or TCP DNS payload.

    Handles:
    - Standard UDP DNS
    - TCP DNS (with 2-byte length prefix)
    """
    # UDP-style parse first
    try:
        dns = dpkt.dns.DNS(l4_data)
        if dns.qd and dns.qd[0].name:
            return safe_decode(dns.qd[0].name)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        pass

    # TCP-style parse with 2-byte length prefix
    if len(l4_data) >= 2:
        try:
            dns = dpkt.dns.DNS(l4_data[2:])
            if dns.qd and dns.qd[0].name:
                return safe_decode(dns.qd[0].name)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            pass

    return ""

# -----------------------------------------------------------
# TLS SNI Parsing
# -----------------------------------------------------------
def parse_tls_sni(tcp_data):
    """
    Extract Server Name Indication (SNI) from TLS ClientHello.

    This provides domain-level visibility for encrypted traffic.
    """
    try:
        records, _ = dpkt.ssl.tls_multi_factory(tcp_data)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, dpkt.ssl.SSLError, Exception):
        return ""

    for record in records:
        try:
            if record.type != 22:  # Handshake
                continue

            hs_bytes = record.data
            if not hs_bytes:
                continue

            # dpkt may already decode handshake records in some environments,
            # but raw parsing is more reliable across versions.
            offset = 0
            while offset + 4 <= len(hs_bytes):
                hs_type = hs_bytes[offset]
                hs_len = int.from_bytes(hs_bytes[offset + 1:offset + 4], "big")
                body_start = offset + 4
                body_end = body_start + hs_len

                if body_end > len(hs_bytes):
                    break

                # ClientHello
                if hs_type == 1:
                    body = hs_bytes[body_start:body_end]
                    sni = extract_sni_from_client_hello(body)
                    if sni:
                        return sni

                offset = body_end

        except Exception:
            continue

    return ""


def extract_sni_from_client_hello(body):
    """
    Parses TLS ClientHello structure to extract SNI extension.

    This is a manual parser to ensure compatibility across dpkt versions.
    """
    try:
        # Structure:
        # version(2) + random(32)
        idx = 0
        if len(body) < 34:
            return ""

        idx += 2   # client_version
        idx += 32  # random

        # session id
        if idx + 1 > len(body):
            return ""
        sid_len = body[idx]
        idx += 1 + sid_len

        # cipher suites
        if idx + 2 > len(body):
            return ""
        cs_len = int.from_bytes(body[idx:idx + 2], "big")
        idx += 2 + cs_len

        # compression methods
        if idx + 1 > len(body):
            return ""
        comp_len = body[idx]
        idx += 1 + comp_len

        # extensions
        if idx + 2 > len(body):
            return ""
        ext_len = int.from_bytes(body[idx:idx + 2], "big")
        idx += 2
        ext_end = idx + ext_len

        while idx + 4 <= ext_end and idx + 4 <= len(body):
            ext_type = int.from_bytes(body[idx:idx + 2], "big")
            ext_size = int.from_bytes(body[idx + 2:idx + 4], "big")
            idx += 4

            ext_data = body[idx:idx + ext_size]
            idx += ext_size

            # server_name
            if ext_type == 0:
                if len(ext_data) < 2:
                    return ""
                list_len = int.from_bytes(ext_data[0:2], "big")
                pos = 2
                limit = min(2 + list_len, len(ext_data))

                while pos + 3 <= limit:
                    name_type = ext_data[pos]
                    name_len = int.from_bytes(ext_data[pos + 1:pos + 3], "big")
                    pos += 3

                    if pos + name_len > limit:
                        break

                    if name_type == 0:
                        return safe_decode(ext_data[pos:pos + name_len])

                    pos += name_len

    except Exception:
        return ""

    return ""

# -----------------------------------------------------------

def _tally_label_type(app_label: str, bench: Layer7BenchmarkResult) -> None:
    if app_label.startswith("HTTP_URL|") or app_label.startswith("HTTP_HOST|"):
        bench.http_labels += 1
    elif app_label.startswith("TLS_SNI|"):
        bench.tls_labels += 1
    elif app_label.startswith("DNS_QRY|"):
        bench.dns_labels += 1

# -----------------------------------------------------------
# Binary Mode Matrix Generation (GraphBLAS)
# -----------------------------------------------------------
def bin_gen_layer7_matrix(pcap, output_dir, subwindow, one_file_mode, label_map_path, choose_app_label, benchmark=False):
    """
    Binary mode pipeline:
    - Parses packets using dpkt
    - Converts IPs → integer row indices
    - Converts labels → integer column indices
    - Builds GraphBLAS sparse matrices

    choose_app_label is passed in from the caller so the shared
    label-selection logic can stay in the main layer7 file.
    """
    builder = BucketedMatrixBuilder(
        window_size=subwindow,
        output_dir=output_dir,
        one_file_mode=one_file_mode
    )

    bench = Layer7BenchmarkResult(
        layer=7,
        mode="binary",
        pcap=pcap,
        output_dir=output_dir,
        window_size=subwindow,
        one_file_mode=one_file_mode,
    )

    label_map = {}
    next_label_id = 0
    total_start_ns = perf_counter_ns()

    with open(pcap, "rb") as f:
        reader = dpkt.pcap.Reader(f)

        while True:
            t_read = perf_counter_ns()
            try:
                _, buf = next(reader)
            except StopIteration:
                break
            bench.step1_read_ns += perf_counter_ns() - t_read
            bench.packets_seen += 1

            t_parse = perf_counter_ns()

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            src_ip = getattr(ip, "src", None)
            if not src_ip:
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            bench.valid_packets += 1

            http_full_uri = ""
            http_host = ""
            tls_sni = ""
            dns_name = ""

            l4 = ip.data

            if isinstance(l4, dpkt.tcp.TCP):
                tcp = l4
                tcp_data = bytes(tcp.data)

                if tcp_data:
                    if tcp.dport in (80, 8080, 8000) or tcp.sport in (80, 8080, 8000):
                        http_full_uri, http_host = parse_http_fields(tcp_data)

                    if tcp.dport == 443 or tcp.sport == 443:
                        tls_sni = parse_tls_sni(tcp_data)

                    if tcp.dport == 53 or tcp.sport == 53:
                        dns_name = parse_dns_name(tcp_data)

            elif isinstance(l4, dpkt.udp.UDP):
                udp = l4
                udp_data = bytes(udp.data)
                if udp.dport == 53 or udp.sport == 53:
                    dns_name = parse_dns_name(udp_data)

            app_label = choose_app_label(http_full_uri, http_host, tls_sni, dns_name)
            bench.step2_parse_ns += perf_counter_ns() - t_parse

            if not app_label:
                bench.unlabeled_packets += 1
                continue

            bench.labeled_packets += 1
            _tally_label_type(app_label, bench)

            t_build = perf_counter_ns()
            try:
                src_id = conv.ip_to_int(src_ip)
                label_id, next_label_id = get_or_create_label_id(
                    app_label, label_map, next_label_id
                )
                builder.add_packet(src_id, label_id)
            except ValueError:
                pass
            finally:
                bench.step3_build_ns += perf_counter_ns() - t_build

    t_save = perf_counter_ns()

    tsv_text = build_label_map_tsv_text(label_map)

    if not os.path.isabs(label_map_path) and os.path.dirname(label_map_path) == "":
        label_map_path = os.path.join(output_dir, label_map_path)

    if one_file_mode:
        builder.finalize()
        write_label_map(label_map, label_map_path)
    else:
        builder.finalize(label_tsv_text=tsv_text)

    bench.step4_save_ns += perf_counter_ns() - t_save
    bench.finalize(total_start_ns)

    if benchmark:
        bench.write_json("layer7_binary_benchmark.json")

    return bench
