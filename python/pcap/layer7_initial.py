import argparse
import datetime # is this used?
import os
import sys
import dpkt
import pickle

from graphblas import Matrix, binary
import utils.conversion as conv
from utils.matrix import BucketedMatrixBuilder
from utils.tshark_utils import run_tshark, check_tshark

#For String mode
try:
    import D4M.assoc
except ImportError:
    D4M = None


def choose_app_label(http_full_uri, http_host, tls_sni, dns_name):
    if http_full_uri:
        return f"HTTP_URL|{http_full_uri}"
    if http_host:
        return f"HTTP_HOST|{http_host}"
    if tls_sni:
        return f"TLS_SNI|{tls_sni}"
    if dns_name:
        return f"DNS_QRY|{dns_name}"
    return None

#Applies to binary mode only, remove from str mode
def get_or_create_label_id(label, label_map, next_id):
    if label not in label_map:
        label_map[label] = next_id
        next_id += 1
    return label_map[label], next_id

#Applies to binary mode only, remove from str mode
def write_label_map(label_map, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("label_id\tlabel\n")
        for label, label_id in sorted(label_map.items(), key=lambda x: x[1]):
            f.write(f"{label_id}\t{label}\n")


def safe_decode(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""
    return str(value).strip()


def parse_http_fields(tcp_data):
    """
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


def parse_dns_name(l4_data):
    """
    Works for UDP DNS payloads and TCP DNS payloads.
    TCP DNS usually has a 2-byte length prefix.
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


def parse_tls_sni(tcp_data):
    """
    Best-effort extraction of SNI from a TLS ClientHello.
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
    Parse TLS ClientHello body and extract server_name from extension 0.
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

# Binary mode:
# - Parse packets directly with dpkt
# - Convert source IPs to integer row keys
# - Convert Layer 7 labels to integer column IDs
# - Save bucketed GraphBLAS matrices plus a label map
def bin_gen_layer7_matrix(pcap, output_dir, subwindow, one_file_mode, label_map_path):
    builder = BucketedMatrixBuilder(
        window_size=subwindow,
        output_dir=output_dir,
        one_file_mode=one_file_mode
    )

    label_map = {}
    next_label_id = 0

    with open(pcap, "rb") as f:
        reader = dpkt.pcap.Reader(f)

        for _, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            src_ip = getattr(ip, "src", None)
            if not src_ip:
                continue

            http_full_uri = ""
            http_host = ""
            tls_sni = ""
            dns_name = ""

            l4 = ip.data

            # TCP-based parsing: HTTP, TLS, TCP-DNS
            if isinstance(l4, dpkt.tcp.TCP):
                tcp = l4
                tcp_data = bytes(tcp.data)

                if not tcp_data:
                    continue

                # HTTP
                if tcp.dport in (80, 8080, 8000) or tcp.sport in (80, 8080, 8000):
                    http_full_uri, http_host = parse_http_fields(tcp_data)

                # TLS
                if tcp.dport == 443 or tcp.sport == 443:
                    tls_sni = parse_tls_sni(tcp_data)

                # DNS over TCP
                if tcp.dport == 53 or tcp.sport == 53:
                    dns_name = parse_dns_name(tcp_data)

            # UDP-based parsing: mainly DNS
            elif isinstance(l4, dpkt.udp.UDP):
                udp = l4
                udp_data = bytes(udp.data)

                if udp.dport == 53 or udp.sport == 53:
                    dns_name = parse_dns_name(udp_data)

            app_label = choose_app_label(
                http_full_uri,
                http_host,
                tls_sni,
                dns_name
            )

            if not app_label:
                continue

            try:
                src_id = conv.ip_to_int(src_ip)
                label_id, next_label_id = get_or_create_label_id(
                    app_label,
                    label_map,
                    next_label_id
                )
                builder.add_packet(src_id, label_id)
            except ValueError:
                continue

    builder.finalize()
    write_label_map(label_map, label_map_path)

def sanitize_d4m_key(value):
    """
    D4M commonly uses comma-delimited string key encodings.
    Remove or replace characters that would break row/column key serialization.
    """
    if value is None:
        return ""
    value = str(value).strip()
    value = value.replace(",", "%2C")
    value = value.replace("\n", " ")
    value = value.replace("\r", " ")
    return value


def write_d4m_assoc_file(rows, cols, vals, out_path):
    """
    Persist a Layer 7 D4M associative array as a single file by serializing
    the actual D4M Assoc object.

    rows, cols, vals are lists of strings.
    out_path should usually end with .pkl or .assoc.pkl
    """
    if D4M is None:
        raise RuntimeError("D4M.py is not installed. String mode requires D4M.assoc.")

    if not rows or not cols or not vals:
        raise ValueError("Cannot write empty D4M associative array.")

    row_str = ",".join(rows) + ","
    col_str = ",".join(cols) + ","
    val_str = ",".join(vals) + ","

    A = D4M.assoc.Assoc(row_str, col_str, val_str)

    with open(out_path, "wb") as f:
        pickle.dump(A, f, protocol=pickle.HIGHEST_PROTOCOL)


def str_gen_layer7_matrix(pcap, window, output, one_file_mode, label_map_path=None):
    """
    String mode:
    - Read Layer 7 labels via tshark field extraction
    - Keep row and column keys as strings
    - Save bucketed D4M-style triples / associative-array inputs
    """
    if D4M is None:
        raise RuntimeError("D4M.py is not installed. String mode requires D4M.assoc.")

    os.makedirs(output, exist_ok=True)

    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", "ip.src",
        "-e", "http.request.full_uri",
        "-e", "http.host",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "dns.qry.name",
    ])

    rows = []
    cols = []
    vals = []

    bucket_index = 0

    def flush_bucket():
        nonlocal rows, cols, vals, bucket_index
        if not rows:
            return

        if one_file_mode:
            out_path = os.path.join(output, "layer7_string_all.assoc.pkl")
        else:
            out_path = os.path.join(output, f"layer7_str_{bucket_index:05d}.assoc.pkl")

        write_d4m_assoc_file(rows, cols, vals, out_path)

        rows = []
        cols = []
        vals = []
        bucket_index += 1

    for line in lines:
        parts = line.split("\t")
        while len(parts) < 5:
            parts.append("")

        ip_src, http_full_uri, http_host, tls_sni, dns_name = [p.strip() for p in parts[:5]]

        if not ip_src:
            continue

        app_label = choose_app_label(http_full_uri, http_host, tls_sni, dns_name)
        if not app_label:
            continue

        row_key = sanitize_d4m_key(ip_src)
        col_key = sanitize_d4m_key(app_label)
        val_key = "1"

        rows.append(row_key)
        cols.append(col_key)
        vals.append(val_key)

        if not one_file_mode and len(rows) >= window:
            flush_bucket()

    flush_bucket()


def main():
    parser = argparse.ArgumentParser(
    description="Construct Layer 7 matrices from a PCAP: string mode outputs D4M-compatible buckets, binary mode outputs GraphBLAS buckets."
    )

    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output folder for bucketed matrix files")
    parser.add_argument(
        "-m", "--map",
        default="layer7_labels.tsv",
        help="Binary-mode label map TSV file (default: layer7_labels.tsv)"
    )

    #Optional arguments for performance and flexibility
    parser.add_argument(
        "-w", "--window",
        type=int,
        default=(1 << 17),
        help="Number of packet-derived entries per output bucket"
    )
    parser.add_argument(
        "-b", "--binary",
        action="store_true",
        help="Binary mode: parse raw packets with dpkt and save GraphBLAS buckets. Default is string mode using tshark and D4M-compatible output."
    )
    parser.add_argument(
        "-O", "--one-file",
        action="store_true",
        help="Single-file output mode if supported by the selected backend"
    )

    args = parser.parse_args()

    # Arg values for gen_layer5_matrixs
    window_size = args.window
    input_pcap = args.pcap
    output_dir = args.output
    one_file_mode = args.one_file
    label_map_path = args.map

    try:
        if args.binary:
            print(f"Generating Layer 7 GraphBLAS buckets in binary mode from PCAP file: {input_pcap}")
            bin_gen_layer7_matrix(
                input_pcap,
                output_dir,
                window_size,
                one_file_mode,
                label_map_path
            )
        else:
            check_tshark()
            print(f"Generating Layer 7 D4M-compatible buckets in string mode from PCAP file: {input_pcap}")
            str_gen_layer7_matrix(
                input_pcap,
                window_size,
                output_dir,
                one_file_mode,
                label_map_path
            )
        
        print("Finished!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
