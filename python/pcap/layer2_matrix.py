import sys
import argparse
import os
from textwrap import shorten
from utils.layer2_bin_utils import bin_gen_layer2_matrix
from utils.layer2_str_utils import str_gen_layer2_matrix
import utils.conversion as conv
import utils.tshark_utils as tshark_utils


def fmt_int(x):
    return f"{x:,}"

def fmt_float(x):
    return f"{x:,.6f}"

def print_comparison_table(results):
    """Prints a formatted comparison table of benchmark results for string vs binary modes."""
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
        ("Step 3 Build (s)", fmt_float(conv.ns_to_s(results["string"].step3_build_ns)), fmt_float(conv.ns_to_s(results["binary"].step3_build_ns))),
        ("Step 4 Save (s)", fmt_float(conv.ns_to_s(results["string"].step4_save_ns)), fmt_float(conv.ns_to_s(results["binary"].step4_save_ns))),
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

    print("\nLayer 2 Benchmark Comparison")
    print(line(headers))
    print(sep)
    for row in rows:
        print(line(row))
    print()

def main():
    """
        Main entry point for the script. 
        Parses command-line arguments and runs the appropriate
        matrix generation and benchmarking.
    """
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
            str_result = str_gen_layer2_matrix(input_pcap, string_out, window_size, one_file_mode, True)
            bin_result = bin_gen_layer2_matrix(input_pcap, binary_out, window_size, one_file_mode, True)
        elif performance_mode:
            print("Using binary capture values for performance.")
            bin_result = bin_gen_layer2_matrix(input_pcap, output_dir, window_size, one_file_mode, False)
        else:            
            print("Using string capture values for easier debugging.")
            str_result = str_gen_layer2_matrix(input_pcap, output_dir, window_size, one_file_mode, False)

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
    
