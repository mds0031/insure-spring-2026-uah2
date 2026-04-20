import sys
import argparse
import os
from time import perf_counter_ns
from textwrap import shorten

import dpkt

import utils.conversion as conv
import utils.tshark_utils as tshark_utils
from utils.matrix import BucketedMatrixBuilder, StringBucketedMatrixBuilder
from utils.benchmark import Layer3BenchmarkResult


#Formatting 
def fmt_int(x):
    return f"{x:,}"


def fmt_float(x):
    return f"{x:,.6f}"


#Layer 3 subnet bucketing
def bucket_ip_int(ip_int, prefix):
    """Apply a subnet prefix mask to an integer IP address."""
    if prefix == 32:
        return ip_int
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ip_int & mask


def bucket_ip_str(ip_str, prefix):
    """Apply a subnet prefix mask to a dotted-quad IP string."""
    if prefix == 32:
        return ip_str
    masked = bucket_ip_int(conv.ip_to_int(ip_str), prefix)
    return f"{(masked >> 24) & 255}.{(masked >> 16) & 255}.{(masked >> 8) & 255}.{masked & 255}"



# Benchmark comparison table

def print_comparison_table(results):
    headers = ["Metric", "String", "Binary"]

    rows = [
        ("Packets Seen", fmt_int(results["string"].packets_seen), fmt_int(results["binary"].packets_seen)),
        ("Valid Packets", fmt_int(results["string"].valid_packets), fmt_int(results["binary"].valid_packets)),
        ("IP Pairs", fmt_int(results["string"].ip_pairs), fmt_int(results["binary"].ip_pairs)),
        ("Unique Src IPs", fmt_int(results["string"].unique_src_ips), fmt_int(results["binary"].unique_src_ips)),
        ("Unique Dst IPs", fmt_int(results["string"].unique_dst_ips), fmt_int(results["binary"].unique_dst_ips)),
        ("Bucket Prefix", f"/{results['string'].bucket_prefix}", f"/{results['binary'].bucket_prefix}"),
        ("Step 1 Read (s)", fmt_float(conv.ns_to_s(results["string"].step1_read_ns)), fmt_float(conv.ns_to_s(results["binary"].step1_read_ns))),
        ("Step 2 Parse (s)", fmt_float(conv.ns_to_s(results["string"].step2_parse_ns)), fmt_float(conv.ns_to_s(results["binary"].step2_parse_ns))),
        ("Step 4 Build (s)", fmt_float(conv.ns_to_s(results["string"].step4_build_ns)), fmt_float(conv.ns_to_s(results["binary"].step4_build_ns))),
        ("Step 5 Save (s)", fmt_float(conv.ns_to_s(results["string"].step5_save_ns)), fmt_float(conv.ns_to_s(results["binary"].step5_save_ns))),
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

    print("\nLayer 3 Benchmark Comparison")
    print(line(headers))
    print(sep)
    for row in rows:
        print(line(row))
    print()


# -----------------------------------------------------------
# String Mode (tshark + D4M)
# -----------------------------------------------------------
def str_gen_layer3_matrix(pcap, output_dir, window, one_file_mode, bucket_prefix, benchmark_enabled=False):
    generator = StringBucketedMatrixBuilder(
        window, output_dir, one_file_mode, "layer3_str_buckets.tar"
    )

    bench = Layer3BenchmarkResult(
        layer=3,
        mode="string",
        pcap=pcap,
        output_dir=output_dir,
        window_size=window,
        one_file_mode=one_file_mode,
        bucket_prefix=bucket_prefix,
    )

    src_set = set()
    dst_set = set()

    total_start_ns = perf_counter_ns()

    t_read = perf_counter_ns()
    lines = tshark_utils.run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
    ])
    bench.step1_read_ns += perf_counter_ns() - t_read

    for line in lines:
        bench.packets_seen += 1

        t_parse = perf_counter_ns()
        parts = line.split("\t")
        while len(parts) < 2:
            parts.append("")

        ip_src, ip_dst = [p.strip() for p in parts[:2]]

        if not ip_src or not ip_dst:
            bench.step2_parse_ns += perf_counter_ns() - t_parse
            continue

        try:
            src_bucketed = bucket_ip_str(ip_src, bucket_prefix)
            dst_bucketed = bucket_ip_str(ip_dst, bucket_prefix)
        except ValueError:
            bench.step2_parse_ns += perf_counter_ns() - t_parse
            continue

        bench.valid_packets += 1
        bench.step2_parse_ns += perf_counter_ns() - t_parse

        t_build = perf_counter_ns()
        generator.add_packet(src_bucketed, dst_bucketed)
        src_set.add(src_bucketed)
        dst_set.add(dst_bucketed)
        bench.ip_pairs += 1
        bench.step4_build_ns += perf_counter_ns() - t_build

    t_save = perf_counter_ns()
    generator.finalize()
    bench.step5_save_ns += perf_counter_ns() - t_save

    bench.unique_src_ips = len(src_set)
    bench.unique_dst_ips = len(dst_set)
    bench.finalize(total_start_ns)

    print("Total Packets Processed:", bench.packets_seen)
    if benchmark_enabled:
        bench.write_json("layer3_string_benchmark.json")
    return bench


# Binary Mode (dpkt + GraphBLAS)
def bin_gen_layer3_matrix(pcap, output_dir, window, one_file_mode, bucket_prefix, benchmark_enabled=False):
    generator = BucketedMatrixBuilder(
        window, output_dir, one_file_mode, "layer3_bin_buckets.tar"
    )

    bench = Layer3BenchmarkResult(
        layer=3,
        mode="binary",
        pcap=pcap,
        output_dir=output_dir,
        window_size=window,
        one_file_mode=one_file_mode,
        bucket_prefix=bucket_prefix,
    )

    src_set = set()
    dst_set = set()

    total_start_ns = perf_counter_ns()

    with open(pcap, "rb") as f:
        reader = dpkt.pcap.Reader(f)

        while True:
            t_read = perf_counter_ns()
            try:
                _, buf = next(reader)
            except StopIteration:
                break
            bench.step1_read_ns += perf_counter_ns() - t_read
            bench.packets_seen += 1

            t_parse = perf_counter_ns()

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            if not ip.src or not ip.dst:
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            try:
                src_int = bucket_ip_int(int.from_bytes(ip.src, "big"), bucket_prefix)
                dst_int = bucket_ip_int(int.from_bytes(ip.dst, "big"), bucket_prefix)
            except (ValueError, TypeError):
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            bench.valid_packets += 1
            bench.step2_parse_ns += perf_counter_ns() - t_parse

            t_build = perf_counter_ns()
            generator.add_packet(src_int, dst_int)
            src_set.add(src_int)
            dst_set.add(dst_int)
            bench.ip_pairs += 1
            bench.step4_build_ns += perf_counter_ns() - t_build

    t_save = perf_counter_ns()
    generator.finalize()
    bench.step5_save_ns += perf_counter_ns() - t_save

    bench.unique_src_ips = len(src_set)
    bench.unique_dst_ips = len(dst_set)
    bench.finalize(total_start_ns)

    print("Total Packets Processed:", bench.packets_seen)
    if benchmark_enabled:
        bench.write_json("layer3_binary_benchmark.json")
    return bench


#main
def main():
    parser = argparse.ArgumentParser(
        description="Construct Layer 3 matrices from a PCAP: string mode outputs D4M-compatible buckets, binary mode outputs GraphBLAS buckets."
    )
    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("-w", "--window", type=int, default=(1 << 17),
                        help="Number of packet-derived entries per output bucket")
    parser.add_argument("-b", "--binary", action="store_true",
                        help="Binary mode: parse raw packets with dpkt and save GraphBLAS buckets. Default is string mode using tshark and D4M-compatible output.")
    parser.add_argument("-O", "--one-file", action="store_true",
                        help="Single-file output mode")
    parser.add_argument("--bucket", type=int, default=32, choices=[8, 16, 24, 32],
                        help="Subnet prefix for IP bucketing (default: 32 = no bucketing)")
    parser.add_argument("--benchmark", action="store_true",
                        help="Enable benchmarking and save results to JSON (runs both modes)")

    args = parser.parse_args()

    try:
        performance_mode = args.binary
        window_size = args.window
        input_pcap = args.pcap
        output_dir = args.output
        one_file_mode = args.one_file
        bucket_prefix = args.bucket
        benchmark = args.benchmark

        out_root = os.path.abspath(output_dir)
        string_out = os.path.join(out_root, "string")
        binary_out = os.path.join(out_root, "binary")

        os.makedirs(output_dir, exist_ok=True)

        print(f"Processing Layer 3 from {input_pcap} (bucket=/{bucket_prefix})")

        str_result = None
        bin_result = None

        if benchmark:
            print("Benchmarking enabled. Running both string and binary modes for comparison.")
            tshark_utils.check_tshark()
            str_result = str_gen_layer3_matrix(
                input_pcap, string_out, window_size, one_file_mode, bucket_prefix, benchmark_enabled=True
            )
            bin_result = bin_gen_layer3_matrix(
                input_pcap, binary_out, window_size, one_file_mode, bucket_prefix, benchmark_enabled=True
            )
        elif performance_mode:
            print("Using binary capture values for performance.")
            bin_result = bin_gen_layer3_matrix(
                input_pcap, output_dir, window_size, one_file_mode, bucket_prefix
            )
        else:
            tshark_utils.check_tshark()
            print("Using string capture values for easier debugging.")
            str_result = str_gen_layer3_matrix(
                input_pcap, output_dir, window_size, one_file_mode, bucket_prefix
            )

        print("Finished!")

        if benchmark:
            results = {"string": str_result, "binary": bin_result}
            print_comparison_table(results)
            print("Benchmark JSON files written to:")
            print(f"  {os.path.join(string_out, 'layer3_string_benchmark.json')}")
            print(f"  {os.path.join(binary_out, 'layer3_binary_benchmark.json')}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
