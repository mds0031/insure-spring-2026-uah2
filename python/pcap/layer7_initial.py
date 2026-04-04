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
        "-e", "dns.qry.name"
    ])

    for line in lines:
        parts = line.split("\t")

        # Ensure we have all requested fields
        while len(parts) < 5:
            parts.append("")

        ip_src, http_full_uri, http_host, tls_sni, dns_name = [p.strip() for p in parts[:5]]

        if not ip_src:
            continue

        app_label = choose_app_label(http_full_uri, http_host, tls_sni, dns_name)
        if not app_label:
            continue

        try:
            src_id = ip_to_int(ip_src)
            dst_id, next_label_id = get_or_create_label_id(app_label, label_map, next_label_id)

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
