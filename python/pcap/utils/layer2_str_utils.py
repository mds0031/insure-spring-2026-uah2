# Generates the matrix with the pcap file
from time import perf_counter_ns

import dpkt

from utils.benchmark import Layer2BenchmarkResult
from utils.matrix import StringBucketedMatrixBuilder


def str_gen_layer2_matrix(pcap: str, output_dir: str, subwindow: int, one_file_mode: bool, benchmark_enabled: bool = False) -> Layer2BenchmarkResult:
    """
        String Mode Method for generating the Layer 2 matrix:
        - Uses dpkt to read the pcap file and extract source/destination MAC addresses
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

    src_set = set()
    dst_set = set()

    generator = StringBucketedMatrixBuilder(subwindow, output_dir, one_file_mode, "layer2_str_buckets.tar", "layer2.assoc.pkl")
    total_start_ns = perf_counter_ns()

    with open(pcap, "rb") as f:
        for _timestamp, buf in dpkt.pcap.Reader(f):
            t_read = perf_counter_ns()
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                bench.step1_read_ns += perf_counter_ns() - t_read
                continue

            bench.step1_read_ns += perf_counter_ns() - t_read
            
            # MAC labels are kept as strings to preserve string-mode behavior.
            eth_src = ":".join(f"{b:02x}" for b in eth.src)
            eth_dst = ":".join(f"{b:02x}" for b in eth.dst)

            bench.packets_seen += 1
            t_parse = perf_counter_ns()

            if not eth_src or not eth_dst:
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            # Count the valid packets (those with both source and destination MAC addresses)
            bench.mac_pairs += 1
            bench.step2_parse_ns += perf_counter_ns() - t_parse
            bench.valid_packets += 1

            try:
                t_build = perf_counter_ns()
                generator.add_packet(eth_src, eth_dst)
                src_set.add(eth_src)
                dst_set.add(eth_dst)
                bench.step3_build_ns += perf_counter_ns() - t_build
            except ValueError:
                # Still need to count the time taken to attempt to build the matrix even if there's a parsing error
                bench.step3_build_ns += perf_counter_ns() - t_build
                continue

    t_save = perf_counter_ns()
    generator.finalize()
    bench.step4_save_ns += perf_counter_ns() - t_save
    
    bench.unique_src_macs = len(src_set)
    bench.unique_dst_macs = len(dst_set)
    bench.finalize(total_start_ns)

    print("Total Packets Processed:", bench.packets_seen)
    if benchmark_enabled:
        bench.write_json("layer2_binary_benchmark_results.json")
    return bench