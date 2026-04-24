from time import perf_counter_ns

import utils.conversion as conv
from utils.tshark_utils import run_tshark
from utils.matrix import StringBucketedMatrixBuilder
from utils.benchmark import Layer3BenchmarkResult


def bucket_ip_str(ip_str: str, prefix: int) -> str:
    """Apply a subnet prefix mask to a dotted-quad IP string."""
    if prefix == 32:
        return ip_str
    ip_int = conv.ip_to_int(ip_str)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    masked = ip_int & mask
    return f"{(masked >> 24) & 255}.{(masked >> 16) & 255}.{(masked >> 8) & 255}.{masked & 255}"


# String Mode (tshark + D4M)

def str_gen_layer3_matrix(pcap: str, output_dir: str, window: int, one_file_mode: bool, bucket_prefix: int, benchmark_enabled: bool = False) -> Layer3BenchmarkResult:
    generator = StringBucketedMatrixBuilder(
        window, output_dir, one_file_mode, "layer3_str_buckets.tar"
    )
    """
        String Mode Method for generating the Layer 3 matrix:
        - Uses tshark to read the pcap file and extract source/destination IP addresses
        - Keeps the IP addresses as strings for easier debugging and verification
        - Builds a D4M-compatible associative array (string-based) for the Layer 3 traffic Matrix
    """

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
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-Y", "!ipv6 && !_ws.malformed",
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
        bench.step3_build_ns += perf_counter_ns() - t_build

    t_save = perf_counter_ns()
    generator.finalize()
    bench.step4_save_ns += perf_counter_ns() - t_save

    bench.unique_src_ips = len(src_set)
    bench.unique_dst_ips = len(dst_set)
    bench.finalize(total_start_ns)

    print("Total Packets Processed:", bench.packets_seen)
    if benchmark_enabled:
        bench.write_json("layer3_string_benchmark.json")
    return bench
