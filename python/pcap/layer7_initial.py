import argparse
import ipaddress
import subprocess
import sys

from graphblas import Matrix, binary


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


def ip_to_int(ip):
    return int(ipaddress.ip_address(ip))


def hex_to_bytes(hex_string):
    if not hex_string:
        return b""

    cleaned = hex_string.replace(":", "").replace(" ", "").strip()
    if len(cleaned) % 2 != 0:
        return b""

    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def bytes_look_like_text(data, threshold=0.85):
    if not data:
        return False

    printable = 0
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            printable += 1

    return (printable / len(data)) >= threshold


def choose_app_label(http_full_uri, http_host, tls_sni, dns_name, data_text="", data_hex=""):
    if http_full_uri:
        return ("HTTP_URL", f"HTTP_URL|{http_full_uri}")

    if http_host:
        return ("HTTP_HOST", f"HTTP_HOST|{http_host}")

    if tls_sni:
        return ("TLS_SNI", f"TLS_SNI|{tls_sni}")

    if dns_name:
        return ("DNS_QRY", f"DNS_QRY|{dns_name}")

    if data_text:
        return ("APP_STR", f"APP_STR|{data_text}")

    if data_hex:
        raw_bytes = hex_to_bytes(data_hex)
        if raw_bytes:
            if bytes_look_like_text(raw_bytes):
                try:
                    decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
                except Exception:
                    decoded = ""

                if decoded:
                    return ("APP_STR", f"APP_STR|{decoded}")

            return ("APP_BIN", f"APP_BIN|{data_hex}")

    return (None, None)


def get_or_create_label_id(label, label_type, label_map, next_id):
    if label not in label_map:
        label_map[label] = {
            "id": next_id,
            "type": label_type
        }
        next_id += 1
    return label_map[label]["id"], next_id


def write_label_map(label_map, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("label_id\tlabel_type\tlabel\n")
        for label, info in sorted(label_map.items(), key=lambda x: x[1]["id"]):
            f.write(f"{info['id']}\t{info['type']}\t{label}\n")


def get_layer7_vals(pcap):
    src_nodes = []
    dst_nodes = []
    vals = []

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
        "-e", "data.text",
        "-e", "data.data",
    ])

    for line in lines:
        parts = line.split("\t")

        while len(parts) < 7:
            parts.append("")

        ip_src, http_full_uri, http_host, tls_sni, dns_name, data_text, data_hex = [
            p.strip() for p in parts[:7]
        ]

        if not ip_src:
            continue

        label_type, app_label = choose_app_label(
            http_full_uri,
            http_host,
            tls_sni,
            dns_name,
            data_text,
            data_hex
        )

        if not app_label:
            continue

        try:
            src_id = ip_to_int(ip_src)
            dst_id, next_label_id = get_or_create_label_id(
                app_label,
                label_type,
                label_map,
                next_label_id
            )

            src_nodes.append(src_id)
            dst_nodes.append(dst_id)
            vals.append(1)
        except ValueError:
            continue

    return (src_nodes, dst_nodes, vals, label_map)


def main():
    parser = argparse.ArgumentParser(
        description="Construct a Layer 7 GraphBLAS matrix from a PCAP using TShark."
    )

    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output GraphBLAS .grb file")
    parser.add_argument(
        "-m", "--map",
        default="layer7_labels.tsv",
        help="Output label map TSV file (default: layer7_labels.tsv)"
    )

    args = parser.parse_args()

    try:
        check_tshark()

        print(f"Retrieving Layer 7 application labels from PCAP file: {args.pcap}")
        src_nodes, dst_nodes, vals, label_map = get_layer7_vals(args.pcap)

        if not vals:
            print("No Layer 7 labels were found in the PCAP.")
            sys.exit(0)

        print("Creating GraphBLAS matrix...")
        matrix = Matrix.from_coo(src_nodes, dst_nodes, vals, dup_op=binary.plus)
        print("Matrix created.")

        print(f"Saving matrix to: {args.output}")
        output_bytes = matrix.ss.serialize()
        with open(args.output, "wb") as f:
            f.write(output_bytes)

        print(f"Saving label map to: {args.map}")
        write_label_map(label_map, args.map)

        print("Finished successfully.")
        print(f"Total Layer 7 observations: {len(vals)}")
        print(f"Unique Layer 7 labels: {len(label_map)}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()