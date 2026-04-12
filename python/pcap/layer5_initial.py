import argparse
import ipaddress
import subprocess
import sys
from graphblas import Matrix, binary
import utils.conversion as conv
from utils.matrix import BucketedMatrixBuilder
from utils.tshark_utils import run_tshark, check_tshark


def choose_app_label(dns_name):
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


def str_get_layer5_vals(pcap, window, output, one_file_mode, label_map_path):
    builder = BucketedMatrixBuilder(window_size=window, output_dir=output, one_file_mode=one_file_mode)

    label_map = {}
    next_label_id = 0


    lines = run_tshark([
        "tshark", "-r", pcap,
        "-Y", "dns",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "dns.qry.name"
    ])

    for line in lines:
        parts = line.split("\t")

        # Ensure we have all requested fields
        while len(parts) < 2:
            parts.append("")

        ip_src, dns_name = [p.strip() for p in parts[:2]]

        if not ip_src:
            continue

        app_label = choose_app_label(dns_name)
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
        description="Construct a Layer 5 GraphBLAS matrix from a PCAP using TShark."
    )

    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output folder for matrix files")
    parser.add_argument(
        "-m", "--map",
        default="layer5_labels.tsv",
        help="Output label map TSV file (default: layer5_labels.tsv)"
    )
    # Optional arguments for performance and flexibility
    parser.add_argument("-w", "--window", type=int, default=sys.maxsize, help="number of packets in each GraphBLAS Matrix")
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
        check_tshark()
        print(f"Retrieving Layer 5 application labels from PCAP file: {input_pcap}")
        str_get_layer5_vals(input_pcap, window_size, output_dir, one_file_mode, label_map_path)
        print("Finished!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
