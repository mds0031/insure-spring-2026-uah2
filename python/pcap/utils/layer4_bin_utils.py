import dpkt
from time import perf_counter_ns

from utils.matrix import BucketedMatrixBuilder
from utils.benchmark import Layer4BenchmarkResult


def bucket_ip_int(ip_int: int, prefix: int) -> int:
    """Apply a subnet prefix mask to an integer IP, zeroing host bits."""
    if prefix == 32:
        return ip_int
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ip_int & mask


def ip_port_bytes_to_int(ip_bytes: bytes, port: int, prefix: int = 32) -> int:
    """
    Encode raw IPv4 bytes (4 bytes from dpkt) + port into a single integer:
        (bucketed_ip << 16) | port
    """
    ip_int = int.from_bytes(ip_bytes, "big")
    bucketed = bucket_ip_int(ip_int, prefix)
    return (bucketed << 16) + port

# Binary Mode (Graphblas & dpkt)

def bin_gen_layer4_matrix(
    pcap: str,
    output_dir: str,
    window: int,
    one_file_mode: bool,
    bucket_prefix: int = 32,
    benchmark_enabled: bool = False,
) -> Layer4BenchmarkResult:
    
    generator = BucketedMatrixBuilder(
        window, output_dir, one_file_mode,
        "layer4_bin_buckets.tar", "layer4.grb"
    )

    bench = Layer4BenchmarkResult(
        layer=4,
        mode="binary",
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
            # Accept IPv4 only -- ip_port_bytes_to_int assumes 4-byte addresses.
            # IPv6 would need a separate encoding scheme.
            if not isinstance(ip, dpkt.ip.IP):
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            transport = ip.data
            if isinstance(transport, dpkt.tcp.TCP):
                sport, dport = transport.sport, transport.dport
            elif isinstance(transport, dpkt.udp.UDP):
                sport, dport = transport.sport, transport.dport
            else:
                # ICMP and others have no ports -- skip
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            bench.valid_packets += 1

            try:
                src_id = ip_port_bytes_to_int(ip.src, sport, bucket_prefix)
                dst_id = ip_port_bytes_to_int(ip.dst, dport, bucket_prefix)
            except Exception:
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            bench.ip_port_pairs += 1
            src_set.add(src_id)
            dst_set.add(dst_id)
            bench.step2_parse_ns += perf_counter_ns() - t_parse

            # Step 4: accumulate into bucketed matrix
            t_build = perf_counter_ns()
            generator.add_packet(src_id, dst_id)
            bench.step3_build_ns += perf_counter_ns() - t_build

    # Step 5: flush and serialize remaining data
    t_save = perf_counter_ns()
    generator.finalize()
    bench.step4_save_ns += perf_counter_ns() - t_save

    bench.unique_src_endpoints = len(src_set)
    bench.unique_dst_endpoints = len(dst_set)

    bench.finalize(total_start_ns)

    print("Total Packets Processed:", bench.packets_seen)
    if benchmark_enabled:
        bench.write_json("layer4_binary_benchmark.json")

    return bench
