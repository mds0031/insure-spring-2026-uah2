from time import perf_counter_ns

import dpkt

from utils.benchmark import Layer2BenchmarkResult
from utils.matrix import BucketedMatrixBuilder

def bin_gen_layer2_matrix(pcap: str, output_dir: str, subwindow: int, one_file_mode: bool, benchmark_enabled: bool = False) -> Layer2BenchmarkResult:
    """
        Binary Mode Method for generating the Layer 2 matrix:
        - Uses dpkt to read the pcap file and extract source/destination MAC addresses
        - Converts the MAC addresses to integers for performance
        - Builds a GraphBLAS-compatible matrix (binary-based) for the Layer 2 traffic Matrix
    """

    generator = BucketedMatrixBuilder(subwindow, output_dir, one_file_mode, "layer2_bin_buckets.tar", "layer2.grb")
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
        bench.step3_build_ns += perf_counter_ns() - t_build

    # Step 4: Finalize and save the matrix
    t_save = perf_counter_ns()
    generator.finalize()
    bench.step4_save_ns += perf_counter_ns() - t_save

    # Finalize benchmark results
    bench.finalize(total_start_ns)
    if benchmark_enabled:
        bench.write_json("layer2_benchmark_results.json")
    return bench