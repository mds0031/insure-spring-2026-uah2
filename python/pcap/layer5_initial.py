import argparse
import datetime
import os
import sys
import dpkt
from graphblas import Matrix, binary
import utils.conversion as conv
from utils.matrix import BucketedMatrixBuilder
from utils.tshark_utils import run_tshark, check_tshark

# Generates a timestamped results directory within the specified output directory
def generate_results_dir(base_dir):
    results_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir_path = os.path.join(base_dir, f"layer5_{results_dir}")
    if not os.path.exists(output_dir_path):
        os.makedirs(output_dir_path)
    return output_dir_path

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

# Binary version of the Layer 5 matrix generator using dpkt for performance
def bin_gen_layer5_matrix(pcap, output_dir, subwindow, one_file_mode, label_map_path):
    builder = BucketedMatrixBuilder(window_size=subwindow, output_dir=output_dir, one_file_mode=one_file_mode)

    label_map = {}
    next_label_id = 0

    for timestamp, buf in dpkt.pcap.Reader(open(pcap, "rb")):
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        udp = ip.data
        if udp.dport != 53 and udp.sport != 53:  
            continue

        dns = dpkt.dns.DNS(udp.data)
        if dns.qd:
            query_name = dns.qd[0].name
            app_label = choose_app_label(query_name)
        if not app_label:
            continue
        try:
            src_id = conv.ip_to_int(ip.src)
            dst_id, next_label_id = get_or_create_label_id(app_label, label_map, next_label_id)
            builder.add_packet(src_id, dst_id)
        except ValueError:
            continue
    
    builder.finalize()
    write_label_map(label_map, label_map_path)

def str_gen_layer2_matrix(pcap, window, output, one_file_mode, label_map_path):
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
            print(f"Generating Layer 5 matrices in binary mode from PCAP file: {input_pcap}")
            bin_gen_layer5_matrix(input_pcap, output_dir, window_size, one_file_mode, label_map_path)
        else:
            check_tshark()
            print(f"Retrieving Layer 5 application labels from PCAP file: {input_pcap}")
            str_gen_layer2_matrix(input_pcap, window_size, output_dir, one_file_mode, label_map_path)
        print("Finished!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
