import argparse
import datetime
#import ipaddress
#import subprocess
import os
import sys
import dpkt
from graphblas import Matrix, binary
import utils.conversion as conv
from utils.matrix import BucketedMatrixBuilder
from utils.tshark_utils import run_tshark, check_tshark

#def run_tshark(cmd):
#    result = subprocess.run(cmd, capture_output=True, text=True)
#    if result.returncode != 0:
#        raise RuntimeError(result.stderr.strip() or "TShark command failed")
#    return result.stdout.splitlines()


#def check_tshark():
#    try:
#        result = subprocess.run(
#            ["tshark", "-v"],
#            capture_output=True,
#            text=True,
#            timeout=10
#        )
#        if result.returncode != 0:
#            raise RuntimeError
#    except Exception:
#        print("Error: TShark is not installed or not in PATH.")
#        sys.exit(1)


#def ip_to_int(ip):
#    return int(ipaddress.ip_address(ip))


#def hex_to_bytes(hex_string):
#    if not hex_string:
#        return b""
#    cleaned = hex_string.replace(":", "").replace(" ", "").strip()
#    if len(cleaned) % 2 != 0:
#        return b""
#    try:
#        return bytes.fromhex(cleaned)
#    except ValueError:
#        return b""


#def bytes_look_like_text(data, threshold=0.85):
#    if not data:
#        return False

#    printable = 0
#    for b in data:
#        if 32 <= b <= 126 or b in (9, 10, 13):
#            printable += 1
#
#    return (printable / len(data)) >= threshold


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


def get_or_create_label_id(label, label_map, next_id):
    if label not in label_map:
        label_map[label] = next_id
        next_id += 1
    return label_map[label], next_id


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
                dst_id, next_label_id = get_or_create_label_id(
                    app_label,
                    label_map,
                    next_label_id
                )
                builder.add_packet(src_id, dst_id)
            except ValueError:
                continue

    builder.finalize()
    write_label_map(label_map, label_map_path)

# Functional but is creating a grb instead of D4M
def str_gen_layer7_matrix(pcap, window, output, one_file_mode, label_map_path):
    builder = BucketedMatrixBuilder(window_size=window, output_dir=output, one_file_mode=one_file_mode)

    label_map = {}
    next_label_id = 0

    lines = run_tshark([
        "tshark",
        "-r", pcap,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "http.request.full_uri",
        "-e", "http.host",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "dns.qry.name",
    ])

    for line in lines:
        parts = line.split("\t")

        while len(parts) < 5:
            parts.append("")

        ip_src, http_full_uri, http_host, tls_sni, dns_name = [ p.strip() for p in parts[:5] ]

        if not ip_src:
            continue

        app_label = choose_app_label(
            http_full_uri,
            http_host,
            tls_sni,
            dns_name
        )

        if not app_label:
            continue

        try:
            src_id = conv.ip_to_int(ip_src)
            dst_id, next_label_id = get_or_create_label_id(app_label, label_map, next_label_id)
            builder.add_packet(src_id, dst_id)
        except ValueError:
            continue

    builder.finalize()
    write_label_map(label_map, label_map_path)


def main():
    parser = argparse.ArgumentParser(
        description="Construct a Layer 7 D4M matrix from a PCAP using TShark."
    )

    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output folder for matrix files")
    parser.add_argument(
        "-m", "--map",
        default="layer7_labels.tsv",
        help="Output label map TSV file (default: layer7_labels.tsv)"
    )

    #Optional arguments for performance and flexibility
    parser.add_argument("-w", "--window", type=int, default=(1 << 17), help="number of packets in each GraphBLAS Matrix")
    parser.add_argument("-b", "--binary", action="store_true", help="Use binary capture values instead of strings for performance")
    parser.add_argument("-O", "--one-file", action="store_true", help="Single file mode - one tar file containing one GraphBLAS matrix.")

    args = parser.parse_args()

    # Arg values for gen_layer5_matrixs
    window_size = args.window
    input_pcap = args.pcap
    output_dir = args.output
    one_file_mode = args.one_file
    label_map_path = args.map

    try:
        if args.binary:
            print(f"Generating Layer 7 matrices in binary mode from PCAP file: {input_pcap}")
            bin_gen_layer7_matrix(input_pcap, output_dir, window_size, one_file_mode, label_map_path)
        else:
            check_tshark()
            print(f"Retrieving Layer 7 application labels from PCAP file: {input_pcap}")
            str_gen_layer7_matrix(input_pcap, window_size, output_dir, one_file_mode, label_map_path)
         
        print("Finished!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
