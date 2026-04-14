import argparse
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


def choose_app_label(http_full_uri, http_host, tls_sni, dns_name):
    if http_full_uri:
        return (f"HTTP_URL|{http_full_uri}")
    if http_host:
        return (f"HTTP_HOST|{http_host}")
    if tls_sni:
        return (f"TLS_SNI|{tls_sni}")
    if dns_name:
        return ("DNS_QRY", f"DNS_QRY|{dns_name}")
    return (None)


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

# Non functional. Need to come back to this and implement for the appropriate layer and mapping
# Also need to update to write to D4M
def bin_gen_layer7_matrix(pcap, output_dir, subwindow, one_file_mode, label_map_path):
    builder = BucketedMatrixBuilder(window_size=subwindow, output_dir=output_dir,one_file_mode=one_file_mode)

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
            builder.add_packer(src_id, dst_id)
        except ValueError:
            continue

    builder.finalize()
    write_lable_map(label_map, label_map_path)


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
        else
            check_tshark()
            print(f"Retrieving Layer 7 application labels from PCAP file: {input_pcap}")
            str_gen_layer7_matrix(input_pcap, window_size, output_dir, one_file_mode, label_map_path)
         print("Finished!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
