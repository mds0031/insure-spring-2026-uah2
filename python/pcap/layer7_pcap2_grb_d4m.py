import argparse
import datetime # is this used?
import sys


#Project utility modules
from utils.tshark_utils import check_tshark
from utils.layer7_bin_utils import bin_gen_layer7_matrix
from utils.layer7_str_utils import str_gen_layer7_matrix

# -----------------------------------------------------------
# Layer 7 Label Selection Logic
# -----------------------------------------------------------
def choose_app_label(http_full_uri, http_host, tls_sni, dns_name):
    """
    Selects the most informative Layer 7 label for a packet.

    Priority order:
    1. HTTP full URI
    2. HTTP host
    3. TLS SNI
    4. DNS query name

    Returns:
        A string label or None if no L7 info exists.
    """
    if http_full_uri:
        return f"HTTP_URL|{http_full_uri}"
    if http_host:
        return f"HTTP_HOST|{http_host}"
    if tls_sni:
        return f"TLS_SNI|{tls_sni}"
    if dns_name:
        return f"DNS_QRY|{dns_name}"
    return None

# -----------------------------------------------------------
# Layer 7 Main Function
# -----------------------------------------------------------

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
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Write benchmark JSON for the selected mode"
    )

    args = parser.parse_args()

    # Arg values for gen_layer5_matrixs
    window_size = args.window
    input_pcap = args.pcap
    output_dir = args.output
    one_file_mode = args.one_file
    label_map_path = args.map
    benchmark = args.benchmark

    try:
        if args.binary:
            print(f"Generating Layer 7 GraphBLAS buckets in binary mode from PCAP file: {input_pcap}")
            result = bin_gen_layer7_matrix(
                input_pcap,
                output_dir,
                window_size,
                one_file_mode,
                label_map_path,
                choose_app_label,
                benchmark
            )
        else:
            check_tshark()
            print(f"Generating Layer 7 D4M-compatible buckets in string mode from PCAP file: {input_pcap}")
            result = str_gen_layer7_matrix(
                input_pcap,
                window_size,
                output_dir,
                one_file_mode,
                choose_app_label,
                benchmark
            )
        
        print("Finished!")

        if args.benchmark:
            print(
                f"Mode={result.mode} packets={result.packets_seen} "
                f"time={result.execution_time_sec:.6f}s "
                f"throughput={result.throughput_pps:.2f} pkt/s"
            )

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
