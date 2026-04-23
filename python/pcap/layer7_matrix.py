import argparse
import os
import sys
from textwrap import shorten


#Project utility modules
from utils.tshark_utils import check_tshark
from utils.layer7_bin_utils import bin_gen_layer7_matrix
from utils.layer7_str_utils import str_gen_layer7_matrix

def ns_to_s(ns: int) -> float:
    return ns / 1e9


def fmt_int(x: int) -> str:
    return f"{x:,}"


def fmt_float(x: float) -> str:
    return f"{x:,.6f}"


def print_comparison_table(results: dict) -> None:
    headers = [
        "Metric",
        "String",
        "Binary",
    ]

    rows = [
        ("Packets Seen", fmt_int(results["string"].packets_seen), fmt_int(results["binary"].packets_seen)),
        ("Valid Packets", fmt_int(results["string"].valid_packets), fmt_int(results["binary"].valid_packets)),
        ("Labeled Packets", fmt_int(results["string"].labeled_packets), fmt_int(results["binary"].labeled_packets)),
        ("Unlabeled Packets", fmt_int(results["string"].unlabeled_packets), fmt_int(results["binary"].unlabeled_packets)),
        ("HTTP Labels", fmt_int(results["string"].http_labels), fmt_int(results["binary"].http_labels)),
        ("TLS Labels", fmt_int(results["string"].tls_labels), fmt_int(results["binary"].tls_labels)),
        ("DNS Labels", fmt_int(results["string"].dns_labels), fmt_int(results["binary"].dns_labels)),
        ("Step 1 Read (s)", fmt_float(ns_to_s(results["string"].step1_read_ns)), fmt_float(ns_to_s(results["binary"].step1_read_ns))),
        ("Step 2 Parse (s)", fmt_float(ns_to_s(results["string"].step2_parse_ns)), fmt_float(ns_to_s(results["binary"].step2_parse_ns))),
        ("Step 3 Build (s)", fmt_float(ns_to_s(results["string"].step3_build_ns)), fmt_float(ns_to_s(results["binary"].step3_build_ns))),
        ("Step 4 Save (s)", fmt_float(ns_to_s(results["string"].step4_save_ns)), fmt_float(ns_to_s(results["binary"].step4_save_ns))),
        ("Total Time (s)", fmt_float(results["string"].execution_time_sec), fmt_float(results["binary"].execution_time_sec)),
        ("Throughput (pkt/s)", fmt_float(results["string"].throughput_pps), fmt_float(results["binary"].throughput_pps)),
        ("Processor", shorten(results["string"].processor, width=26, placeholder="..."),
                      shorten(results["binary"].processor, width=26, placeholder="...")),
    ]

    widths = [
        max(len(headers[0]), max(len(r[0]) for r in rows)),
        max(len(headers[1]), max(len(str(r[1])) for r in rows)),
        max(len(headers[2]), max(len(str(r[2])) for r in rows)),
    ]

    def line(vals):
        return " | ".join(str(v).ljust(widths[i]) for i, v in enumerate(vals))

    sep = "-+-".join("-" * w for w in widths)

    print("\nLayer 7 Benchmark Comparison")
    print(line(headers))
    print(sep)
    for row in rows:
        print(line(row))
    print()

# -----------------------------------------------------------
# Layer 7 Label Selection Logic
# -----------------------------------------------------------
def choose_app_label(http_full_uri: str, http_host: str, tls_sni: str, dns_name: str) -> str:
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

def main() -> None:
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

    out_root = os.path.abspath(output_dir)
    string_out = os.path.join(out_root, "string")
    binary_out = os.path.join(out_root, "binary")

    try:
        if benchmark:
            print("Benchmarking enabled. Running both string and binary modes for comparison.")
            str_result = str_gen_layer7_matrix(
                input_pcap,
                string_out,
                window_size,
                string_out,
                one_file_mode,
                choose_app_label,
                benchmark=True,
            )
            bin_result = bin_gen_layer7_matrix(
                input_pcap,
                binary_out,
                window_size,
                one_file_mode,
                label_map_path,
                choose_app_label,
                benchmark=True,
            )
        elif args.binary:
            print(f"Generating Layer 7 GraphBLAS buckets in binary mode from PCAP file: {input_pcap}")
            bin_result = bin_gen_layer7_matrix(
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
            str_result = str_gen_layer7_matrix(
                input_pcap,
                output_dir,
                window_size,
                one_file_mode,
                choose_app_label,
                benchmark
            )
        
        print("Finished!")

        if args.benchmark:
            results = {
                "string": str_result,
                "binary": bin_result,
            }

            print_comparison_table(results)

            print("Benchmark JSON files written to:")
            print(f"  {os.path.join(string_out, 'layer2_string_benchmark.json')}")
            print(f"  {os.path.join(binary_out, 'layer2_binary_benchmark.json')}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
