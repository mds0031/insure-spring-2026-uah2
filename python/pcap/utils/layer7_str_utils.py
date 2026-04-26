from time import perf_counter_ns
import ipaddress

import dpkt
from utils.matrix import StringBucketedMatrixBuilder
from utils.layer7_bin_utils import parse_dns_name, parse_http_fields, parse_tls_sni

from utils.benchmark import Layer7BenchmarkResult


def _tally_label_type(app_label: str, bench: Layer7BenchmarkResult) -> None:
    if app_label.startswith("HTTP_URL|") or app_label.startswith("HTTP_HOST|"):
        bench.http_labels += 1
    elif app_label.startswith("TLS_SNI|"):
        bench.tls_labels += 1
    elif app_label.startswith("DNS_QRY|"):
        bench.dns_labels += 1


# -----------------------------------------------------------
# D4M (String Mode)
# -----------------------------------------------------------
def str_gen_layer7_matrix(pcap: str, output: str, window: int, one_file_mode: bool, choose_app_label, benchmark: bool = False) -> Layer7BenchmarkResult:
    """
    String mode pipeline:
    - Uses dpkt for extraction
    - Keeps row/column labels as strings
    - Outputs D4M-compatible associative arrays
    """
    builder = StringBucketedMatrixBuilder(
        window_size=window,
        output_dir=output,
        one_file_mode=one_file_mode
    )

    bench = Layer7BenchmarkResult(
        layer=7,
        mode="string",
        pcap=pcap,
        output_dir=output,
        window_size=window,
        one_file_mode=one_file_mode,
    )

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
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            if not getattr(ip, "src", None):
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            http_full_uri = ""
            http_host = ""
            tls_sni = ""
            dns_name = ""

            l4 = ip.data
            if isinstance(l4, dpkt.tcp.TCP):
                tcp_data = bytes(l4.data)
                if tcp_data:
                    if l4.dport in (80, 8080, 8000) or l4.sport in (80, 8080, 8000):
                        http_full_uri, http_host = parse_http_fields(tcp_data)
                    if l4.dport == 443 or l4.sport == 443:
                        tls_sni = parse_tls_sni(tcp_data)
                    if l4.dport == 53 or l4.sport == 53:
                        dns_name = parse_dns_name(tcp_data)
            elif isinstance(l4, dpkt.udp.UDP):
                # Mirror old tshark filter: skip SSDP traffic on UDP/1900.
                if l4.sport == 1900 or l4.dport == 1900:
                    bench.step2_parse_ns += perf_counter_ns() - t_parse
                    continue
                if l4.dport == 53 or l4.sport == 53:
                    dns_name = parse_dns_name(bytes(l4.data))

            try:
                ip_src = str(ipaddress.ip_address(ip.src))
            except ValueError:
                bench.step2_parse_ns += perf_counter_ns() - t_parse
                continue

            bench.valid_packets += 1
            app_label = choose_app_label(http_full_uri, http_host, tls_sni, dns_name)
            bench.step2_parse_ns += perf_counter_ns() - t_parse

            if not app_label:
                bench.unlabeled_packets += 1
                continue

            bench.labeled_packets += 1
            _tally_label_type(app_label, bench)

            t_build = perf_counter_ns()
            builder.add_packet(ip_src, app_label)
            bench.step3_build_ns += perf_counter_ns() - t_build

    t_save = perf_counter_ns()
    builder.finalize()
    bench.step4_save_ns += perf_counter_ns() - t_save

    bench.finalize(total_start_ns)

    if benchmark:
        bench.write_json("layer7_string_benchmark.json")

    return bench
