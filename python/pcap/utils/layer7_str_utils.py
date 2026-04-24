from time import perf_counter_ns

from utils.tshark_utils import run_tshark
from utils.matrix import StringBucketedMatrixBuilder

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
    - Uses tshark for extraction
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

    t_read = perf_counter_ns()
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-Y", "!(udp.port == 1900 || ssdp)",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", "ip.src",
        "-e", "http.request.full_uri",
        "-e", "http.host",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "dns.qry.name",
    ])
    bench.step1_read_ns += perf_counter_ns() - t_read

    for line in lines:
        bench.packets_seen += 1

        t_parse = perf_counter_ns()
        parts = line.split("\t")
        while len(parts) < 5:
            parts.append("")

        ip_src, http_full_uri, http_host, tls_sni, dns_name = [p.strip() for p in parts[:5]]

        if not ip_src:
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
