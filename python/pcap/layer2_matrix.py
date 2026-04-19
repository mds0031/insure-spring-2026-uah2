from datetime import datetime
import sys
import argparse
import os
from time import perf_counter_ns
import utils.conversion as conv
from utils.matrix import BucketedMatrixBuilder, StringBucketedMatrixBuilder
import utils.tshark_utils as tshark_utils
import dpkt
from utils.benchmark import Layer2BenchmarkResult
from textwrap import shorten


file_count = 0

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
        ("MAC Pairs", fmt_int(results["string"].mac_pairs), fmt_int(results["binary"].mac_pairs)),
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

    print("\nLayer 7 Benchmark Comparison")
    print(line(headers))
    print(sep)
    for row in rows:
        print(line(row))
    print()

# Generates the matrix with the pcap file
def str_gen_layer2_matrix(pcap, output_dir, subwindow, one_file_mode, benchmark_enabled=False):

    bench = Layer2BenchmarkResult(
        layer=2,
        mode="string",
        pcap=pcap,
        output_dir=output_dir,
        window_size=subwindow,
        one_file_mode=one_file_mode
    )

    generator = StringBucketedMatrixBuilder(subwindow, output_dir, one_file_mode, "layer2_str_buckets.tar")
    total_start_ns = perf_counter_ns()

    t_read = perf_counter_ns()
    # Command to extract source and destination MAC addresses from the pcap file using TShark
    lines = tshark_utils.run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "eth.src",
        "-e", "eth.dst"
    ])
    bench.step1_read_ns += perf_counter_ns() - t_read

    for line in lines:
        bench.packets_seen += 1
        t_parse = perf_counter_ns()
        parts = line.split("\t")
        if len(parts) < 2:
            continue

        eth_src, eth_dst = parts[:2]

        if not eth_src or not eth_dst:
            bench.step2_parse_ns += perf_counter_ns() - t_parse
            continue

        # Count the valid packets (those with both source and destination MAC addresses)
        bench.mac_pairs += 1
        bench.step2_parse_ns += perf_counter_ns() - t_parse

        try:
            t_build = perf_counter_ns()
            generator.add_packet(eth_src, eth_dst)
            bench.step2_parse_ns += perf_counter_ns() - t_build
        except ValueError:
            # Still need to count the time taken to attempt to build the matrix even if there's a parsing error
            bench.step2_parse_ns += perf_counter_ns() - t_build
            continue

    t_save = perf_counter_ns()
    generator.finalize()
    bench.step5_save_ns += perf_counter_ns() - t_save
    bench.finalize(total_start_ns)

    print("Total Packets Processed:", bench.packets_seen)
    if benchmark_enabled:
        bench.write_json("layer2_benchmark_results.json")
    return bench

# Generates the matrix with the pcap file using binary capture values for performance
def bin_gen_layer2_matrix(pcap, output_dir, subwindow, one_file_mode, benchmark_enabled=False):
    generator = BucketedMatrixBuilder(subwindow, output_dir, one_file_mode, "layer2_bin_buckets.tar")
    bench = Layer2BenchmarkResult(
        layer=2,
        mode="binary",
        pcap=pcap,
        output_dir=output_dir,
        window_size=subwindow,
        one_file_mode=one_file_mode
    )
    total_start_ns = perf_counter_ns()

    for timestamp, buf in dpkt.pcap.Reader(open(pcap, "rb")):
        # Step 1: Read the packet from the pcap file
        t_read = perf_counter_ns()
        eth = dpkt.ethernet.Ethernet(buf)
        bench.step1_read_ns += perf_counter_ns() - t_read
        bench.packets_seen += 1

        # Step 2: Parse the Ethernet frame
        t_parse = perf_counter_ns()
        
        if not eth.src or not eth.dst:
            bench.step2_parse_ns += perf_counter_ns() - t_parse
            continue

        src_mac_int = int.from_bytes(eth.src, 'big')
        dst_mac_int = int.from_bytes(eth.dst, 'big')
        bench.mac_pairs += 1
        bench.step2_parse_ns += perf_counter_ns() - t_parse
        
        # Step 3: Build the GraphBLAS matrix
        t_build = perf_counter_ns()
        generator.add_packet(src_mac_int, dst_mac_int)
        bench.step4_build_ns += perf_counter_ns() - t_build

    # Step 4: Finalize and save the matrix
    t_save = perf_counter_ns()
    generator.finalize()
    bench.step5_save_ns += perf_counter_ns() - t_save

    # Finalize benchmark results
    bench.finalize(total_start_ns)
    print(fmt_float(bench.throughput_pps))
    if benchmark_enabled:
        bench.write_json("layer2_benchmark_results.json")
    return bench


# Main function to run the script
def main():
    parser = argparse.ArgumentParser()
    # Required arguments
    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    # Optional arguments
    parser.add_argument("-w", "--window", type=int, default=(1 << 17), help="number of packet in each GraphBlas Matrix")
    parser.add_argument("-b", "--binary", action="store_true", help="Use binary capture values instead of strings for performance")
    parser.add_argument("-O", "--one-file", action="store_true", help="Single file mode - one tar file containing one GraphBLAS matrix..")
    parser.add_argument("--benchmark", action="store_true", help="Enable benchmarking and save results to JSON")
    args = parser.parse_args()

    try:
        # Arg values for gen_layer2_matrixs
        performance_mode = args.binary
        window_size = args.window
        input_pcap = args.pcap
        output_dir = args.output
        one_file_mode = args.one_file
        benchmark = args.benchmark

        out_root = os.path.abspath(output_dir)
        string_out = os.path.join(out_root, "string")
        binary_out = os.path.join(out_root, "binary")

        tshark_utils.check_tshark()
        os.makedirs(output_dir, exist_ok=True)

        print(f"Processing Layer 2 from {input_pcap}")
        if benchmark:
            print("Benchmarking enabled. Running both string and binary modes for comparison.")
            str_result = str_gen_layer2_matrix(input_pcap, string_out, window_size, one_file_mode, benchmark_enabled=True)
            bin_result = bin_gen_layer2_matrix(input_pcap, binary_out, window_size, one_file_mode, benchmark_enabled=True)
        elif performance_mode:
            print("Using binary capture values for performance.")
            bin_result = bin_gen_layer2_matrix(input_pcap, output_dir, window_size, one_file_mode)
        else:            
            print("Using string capture values for easier debugging.")
            str_result = str_gen_layer2_matrix(input_pcap, output_dir, window_size, one_file_mode, benchmark_enabled=True)

        print("Finished!")
        if benchmark:
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
    
