from utils.tshark_utils import run_tshark
from utils.matrix import StringBucketedMatrixBuilder

# -----------------------------------------------------------
# D4M (String Mode)
# -----------------------------------------------------------
def str_gen_layer7_matrix(pcap, window, output, one_file_mode, choose_app_label):
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

    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", "ip.src",
        "-e", "http.request.full_uri",
        "-e", "http.host",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "dns.qry.name",
    ])

    for line in lines:
        parts = line.split("\t")
        while len(parts) < 5:
            parts.append("")

        ip_src, http_full_uri, http_host, tls_sni, dns_name = [p.strip() for p in parts[:5]]

        if not ip_src:
            continue

        app_label = choose_app_label(http_full_uri, http_host, tls_sni, dns_name)
        if not app_label:
            continue

        # Let the builder sanitize and store the value
        builder.add_packet(ip_src, app_label)

    builder.finalize()
