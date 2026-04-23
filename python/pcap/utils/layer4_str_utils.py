from time import perf_counter_ns

import utils.conversion as conv
from utils.tshark_utils import run_tshark
from utils.matrix import StringBucketedMatrixBuilder
from utils.benchmark import Layer4BenchmarkResult


def bucket_ip_str(ip_str: str, prefix: int) -> str:
    """Apply a subnet prefix mask to a dotted-quad IPv4 string."""
    if prefix == 32:
        return ip_str
    ip_int = conv.ip_to_int(ip_str)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    masked = ip_int & mask
    return f"{(masked >> 24) & 255}.{(masked >> 16) & 255}.{(masked >> 8) & 255}.{masked & 255}"


def ip_port_to_str(ip: str, port: str, prefix: int = 32) -> str:
    bucketed = bucket_ip_str(ip, prefix)
    return f"{bucketed}:{port}"


# String Mode (D4m & tshark)

def str_gen_layer4_matrix(
    pcap: str,
    output_dir: str,
    window: int,
    one_file_mode: bool,
    bucket_prefix: int = 32,
    benchmark_enabled: bool = False,
) -> Layer4BenchmarkResult:
    
    """
    String Mode Method for generating the Layer 4 matrix:
        - Uses tshark to read the pcap file and extract source/destination IP addresses and ports
        - Keeps the IP addresses and ports as strings for easier debugging and verification
        - Builds a D4M-compatible associative array (string-based) for the Layer 4 traffic Matrix
    """
  
    generator = StringBucketedMatrixBuilder(
        window, output_dir, one_file_mode,
        "layer4_str_buckets.tar", "layer4.assoc.pkl"
    )

    bench = Layer4BenchmarkResult(
        layer=4,
        mode="string",
        pcap=pcap,
        output_dir=output_dir,
        window_size=window,
        one_file_mode=one_file_mode,
        bucket_prefix=bucket_prefix,
    )

    src_set: set = set()
    dst_set: set = set()
    total_start_ns = perf_counter_ns()

    # Step 1: invoke tshark once, requesting all L4 fields in one pass.
    # Both TCP and UDP port fields are requested; TCP is preferred per-packet.
    t_read = perf_counter_ns()
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
    ])
    bench.step1_read_ns += perf_counter_ns() - t_read

    for line in lines:
        bench.packets_seen += 1

        # Step 2: parse tab-delimited tshark output
        t_parse = perf_counter_ns()
        parts = line.split("\t")
        if len(parts) < 7:
            bench.step2_parse_ns += perf_counter_ns() - t_parse
            continue

        _frame_no, ip_src, tcp_sport, ip_dst, tcp_dport, udp_sport, udp_dport = parts[:7]

        # Prefer TCP ports; fall back to UDP
        sport = tcp_sport if tcp_sport else udp_sport
        dport = tcp_dport if tcp_dport else udp_dport

        if not ip_src or not ip_dst or not sport or not dport:
            bench.step2_parse_ns += perf_counter_ns() - t_parse
            continue

        bench.valid_packets += 1

        try:
            src_label = ip_port_to_str(ip_src, sport, bucket_prefix)
            dst_label = ip_port_to_str(ip_dst, dport, bucket_prefix)
        except (ValueError, IndexError):
            bench.step2_parse_ns += perf_counter_ns() - t_parse
            continue

        bench.ip_port_pairs += 1
        src_set.add(src_label)
        dst_set.add(dst_label)
        bench.step2_parse_ns += perf_counter_ns() - t_parse

        # Step 4: accumulate into bucketed D4M matrix
        t_build = perf_counter_ns()
        generator.add_packet(src_label, dst_label)
        bench.step3_build_ns += perf_counter_ns() - t_build

    # Step 5: flush and serialize
    t_save = perf_counter_ns()
    generator.finalize()
    bench.step4_save_ns += perf_counter_ns() - t_save

    bench.unique_src_endpoints = len(src_set)
    bench.unique_dst_endpoints = len(dst_set)

    bench.finalize(total_start_ns)

    print("Total Packets Processed:", bench.packets_seen)
    if benchmark_enabled:
        bench.write_json("layer4_string_benchmark.json")

    return bench
