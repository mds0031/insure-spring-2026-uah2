# Generates the matrix with the pcap file
from time import perf_counter_ns

from utils import tshark_utils
from utils.benchmark import Layer2BenchmarkResult
from utils.matrix import StringBucketedMatrixBuilder


def str_gen_layer2_matrix(pcap, output_dir, subwindow, one_file_mode, benchmark_enabled=False):
    """
        String Mode Method for generating the Layer 2 matrix:
        - Uses tshark to read the pcap file and extract source/destination MAC addresses
        - Keeps the MAC addresses as strings for easier debugging and verification
        - Builds a D4M-compatible associative array (string-based) for the Layer 2 traffic Matrix
    """
    bench = Layer2BenchmarkResult(
        layer=2,
        mode="string",
        pcap=pcap,
        output_dir=output_dir,
        window_size=subwindow,
        one_file_mode=one_file_mode
    )

    generator = StringBucketedMatrixBuilder(subwindow, output_dir, one_file_mode, "layer2_str_buckets.tar", "layer2.assoc.pkl")
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
            bench.step3_build_ns += perf_counter_ns() - t_build
        except ValueError:
            # Still need to count the time taken to attempt to build the matrix even if there's a parsing error
            bench.step3_build_ns += perf_counter_ns() - t_build
            continue

    t_save = perf_counter_ns()
    generator.finalize()
    bench.step4_save_ns += perf_counter_ns() - t_save
    bench.finalize(total_start_ns)

    print("Total Packets Processed:", bench.packets_seen)
    if benchmark_enabled:
        bench.write_json("layer2_benchmark_results.json")
    return bench