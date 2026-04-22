# Layer 4: IP:Port --> IP:Port
# Renamed from layer4_pcap2grb.py to layer4_matrix.py to follow project convention.
# Refactored to match layer3_matrix.py structure: all generation logic has moved
# into utils/layer4_str_utils.py and utils/layer4_bin_utils.py; this file is now
# the thin CLI entry point and comparison table printer only.

import sys
import argparse
import os
from textwrap import shorten

import utils.conversion as conv
from utils.tshark_utils import check_tshark
from utils.layer4_str_utils import str_gen_layer4_matrix
from utils.layer4_bin_utils import bin_gen_layer4_matrix


# Formatting helpers

def fmt_int(x):
    return f"{x:,}"


def fmt_float(x):
    return f"{x:,.6f}"


# Benchmark comparison table
# Layer 4-specific rows: IP:Port Pairs, Unique Src/Dst Endpoints, and Bucket Prefix

def print_comparison_table(results: dict) -> None:
    headers = ["Metric", "String", "Binary"]

    rows = [
        ("Packets Seen",
            fmt_int(results["string"].packets_seen),
            fmt_int(results["binary"].packets_seen)),
        ("Valid Packets",
            fmt_int(results["string"].valid_packets),
            fmt_int(results["binary"].valid_packets)),
        ("IP:Port Pairs",
            fmt_int(results["string"].ip_port_pairs),
            fmt_int(results["binary"].ip_port_pairs)),
        ("Unique Src Endpoints",
            fmt_int(results["string"].unique_src_endpoints),
            fmt_int(results["binary"].unique_src_endpoints)),
        ("Unique Dst Endpoints",
            fmt_int(results["string"].unique_dst_endpoints),
            fmt_int(results["binary"].unique_dst_endpoints)),
        ("Bucket Prefix",
            f"/{results['string'].bucket_prefix}",
            f"/{results['binary'].bucket_prefix}"),
        ("Step 1 Read (s)",
            fmt_float(conv.ns_to_s(results["string"].step1_read_ns)),
            fmt_float(conv.ns_to_s(results["binary"].step1_read_ns))),
        ("Step 2 Parse (s)",
            fmt_float(conv.ns_to_s(results["string"].step2_parse_ns)),
            fmt_float(conv.ns_to_s(results["binary"].step2_parse_ns))),
        ("Step 4 Build (s)",
            fmt_float(conv.ns_to_s(results["string"].step4_build_ns)),
            fmt_float(conv.ns_to_s(results["binary"].step4_build_ns))),
        ("Step 5 Save (s)",
            fmt_float(conv.ns_to_s(results["string"].step5_save_ns)),
            fmt_float(conv.ns_to_s(results["binary"].step5_save_ns))),
        ("Total Time (s)",
            fmt_float(results["string"].execution_time_sec),
            fmt_float(results["binary"].execution_time_sec)),
        ("Throughput (pkt/s)",
            fmt_float(results["string"].throughput_pps),
            fmt_float(results["binary"].throughput_pps)),
        ("Processor",
            shorten(results["string"].processor, width=26, placeholder="..."),
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

    print("\nLayer 4 Benchmark Comparison")
    print(line(headers))
    print(sep)
    for row in rows:
        print(line(row))
    print()


# Main -- CLI entry point
# Flags : -i, -o, -w, -b, -O, --bucket, --benchmark.

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Construct Layer 4 matrices from a PCAP: string mode outputs "
            "D4M-compatible buckets via tshark, binary mode outputs GraphBLAS "
            "buckets via dpkt for higher throughput."
        )
    )
    parser.add_argument("-i", "--pcap",   required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output directory for matrix files")
    parser.add_argument(
        "-w", "--window", type=int, default=(1 << 17),
        help="Number of packets per output bucket"
    )
    parser.add_argument(
        "-b", "--binary", action="store_true",
        help="Binary mode: parse raw packets with dpkt. Default is string mode via tshark."
    )
    parser.add_argument(
        "-O", "--one-file", action="store_true",
        help="Single-file output mode."
    )
    parser.add_argument(
        "--bucket", type=int, default=32, choices=[8, 16, 24, 32],
        help="Subnet prefix for IP bucketing (default: 32 = no bucketing)"
    )
    parser.add_argument(
        "--benchmark", action="store_true",
        help="Run both string and binary modes and print a comparison table."
    )

    args = parser.parse_args()

    input_pcap    = args.pcap
    output_dir    = args.output
    window_size   = args.window
    one_file_mode = args.one_file
    bucket_prefix = args.bucket
    benchmark     = args.benchmark

    out_root   = os.path.abspath(output_dir)
    string_out = os.path.join(out_root, "string")
    binary_out = os.path.join(out_root, "binary")

    try:
        os.makedirs(output_dir, exist_ok=True)

        print(f"Processing Layer 4 from {input_pcap} (bucket=/{bucket_prefix})")

        str_result = None
        bin_result = None

        if benchmark:
            print("Benchmarking enabled. Running both string and binary modes for comparison.")
            os.makedirs(string_out, exist_ok=True)
            os.makedirs(binary_out, exist_ok=True)
            check_tshark()
            str_result = str_gen_layer4_matrix(
                input_pcap, string_out, window_size, one_file_mode, bucket_prefix,
                benchmark_enabled=True
            )
            bin_result = bin_gen_layer4_matrix(
                input_pcap, binary_out, window_size, one_file_mode, bucket_prefix,
                benchmark_enabled=True
            )

        elif args.binary:
            print("Using binary mode (dpkt) for higher throughput.")
            bin_result = bin_gen_layer4_matrix(
                input_pcap, output_dir, window_size, one_file_mode, bucket_prefix
            )

        else:
            check_tshark()
            print("Using string mode (tshark) for easier debugging.")
            str_result = str_gen_layer4_matrix(
                input_pcap, output_dir, window_size, one_file_mode, bucket_prefix
            )

        print("Finished!")

        if benchmark:
            results = {"string": str_result, "binary": bin_result}
            print_comparison_table(results)
            print("Benchmark JSON files written to:")
            print(f"  {os.path.join(string_out, 'layer4_string_benchmark.json')}")
            print(f"  {os.path.join(binary_out, 'layer4_binary_benchmark.json')}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
