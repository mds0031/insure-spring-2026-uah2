import argparse
import os
from textwrap import shorten

from utils.tshark_utils import check_tshark
from utils.layer7_bin_utils import bin_gen_layer7_matrix
from utils.layer7_str_utils import str_gen_layer7_matrix


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


def ns_to_s(ns: int) -> float:
    return ns / 1e9


def fmt_int(x):
    return f"{x:,}"


def fmt_float(x):
    return f"{x:,.6f}"


def print_comparison_table(results):
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


def main():
    parser = argparse.ArgumentParser(
        description="Run Layer 7 benchmarks for both string and binary modes."
    )
    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Benchmark output root directory")
    parser.add_argument(
        "-w", "--window",
        type=int,
        default=(1 << 17),
        help="Window size / bucket size"
    )
    parser.add_argument(
        "-O", "--one-file",
        action="store_true",
        help="Use one-file mode where supported"
    )
    parser.add_argument(
        "-m", "--map",
        default="layer7_labels.tsv",
        help="Binary-mode label map filename"
    )

    args = parser.parse_args()

    out_root = os.path.abspath(args.output)
    string_out = os.path.join(out_root, "string")
    binary_out = os.path.join(out_root, "binary")

    os.makedirs(string_out, exist_ok=True)
    os.makedirs(binary_out, exist_ok=True)

    check_tshark()

    print("Running string mode benchmark...")
    str_result = str_gen_layer7_matrix(
        args.pcap,
        args.window,
        string_out,
        args.one_file,
        choose_app_label,
        benchmark=True,
    )

    print("Running binary mode benchmark...")
    bin_result = bin_gen_layer7_matrix(
        args.pcap,
        binary_out,
        args.window,
        args.one_file,
        args.map,
        choose_app_label,
        benchmark=True,
    )

    results = {
        "string": str_result,
        "binary": bin_result,
    }

    print_comparison_table(results)

    print("Benchmark JSON files written to:")
    print(f"  {os.path.join(string_out, 'layer7_string_benchmark.json')}")
    print(f"  {os.path.join(binary_out, 'layer7_binary_benchmark.json')}")


if __name__ == "__main__":
    main()
