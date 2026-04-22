from time import perf_counter_ns

import dpkt

from utils.matrix import BucketedMatrixBuilder
from utils.benchmark import Layer3BenchmarkResult


def bucket_ip_int(ip_int, prefix):
    """Apply a subnet prefix mask to an integer IP address."""
    if prefix == 32:
        return ip_int
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ip_int & mask



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
            bench.step3_build_ns += perf_counter_ns() - t_build

    t_save = perf_counter_ns()
    generator.finalize()
    bench.step4_save_ns += perf_counter_ns() - t_save

    bench.unique_src_ips = len(src_set)
    bench.unique_dst_ips = len(dst_set)
    bench.finalize(total_start_ns)

    print("Total Packets Processed:", bench.packets_seen)
    if benchmark_enabled:
        bench.write_json("layer3_binary_benchmark.json")
    return bench
