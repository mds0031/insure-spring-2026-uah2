from time import perf_counter_ns

import dpkt

import utils.conversion as conv
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


# String Mode (D4M & dpkt)

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
        - Uses dpkt to read the pcap file and extract source/destination IP addresses and ports
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

    with open(pcap, "rb") as f:
        reader = dpkt.pcap.Reader(f)

        while True:
            # Step 1: read next frame
            t_read = perf_counter_ns()
            try:
                _, buf = next(reader)
            except StopIteration:
                break
            bench.step1_read_ns += perf_counter_ns() - t_read
            bench.packets_seen += 1

            # Step 2: parse Ethernet -> IP -> TCP/UDP
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

            transport = ip.data
            if isinstance(transport, dpkt.tcp.TCP):
                sport, dport = transport.sport, transport.dport
            elif isinstance(transport, dpkt.udp.UDP):
                sport, dport = transport.sport, transport.dport
            else:
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            ip_src = ".".join(str(b) for b in ip.src)
            ip_dst = ".".join(str(b) for b in ip.dst)

            if not ip_src or not ip_dst:
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            bench.valid_packets += 1

            try:
                src_label = ip_port_to_str(ip_src, str(sport), bucket_prefix)
                dst_label = ip_port_to_str(ip_dst, str(dport), bucket_prefix)
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
