import pickle
import os

from utils.tshark_utils import run_tshark

#Optional dependency: D4M check
try:
    import D4M.assoc
except ImportError:
    D4M = None

# -----------------------------------------------------------
# D4M (String Mode)
# -----------------------------------------------------------
def sanitize_d4m_key(value):
    """
    Cleans string keys to avoid breaking D4M comma-separated encoding.
    """
    if value is None:
        return ""
    value = str(value).strip()
    value = value.replace(",", "%2C")
    value = value.replace("\n", " ")
    value = value.replace("\r", " ")
    return value


def write_d4m_assoc_file(rows, cols, vals, out_path):
    """
    Writes a D4M associative array object to disk using pickle.
    """
    if D4M is None:
        raise RuntimeError("D4M.py is not installed. String mode requires D4M.assoc.")

    if not rows or not cols or not vals:
        raise ValueError("Cannot write empty D4M associative array.")

    row_str = ",".join(rows) + ","
    col_str = ",".join(cols) + ","
    val_str = ",".join(vals) + ","

    A = D4M.assoc.Assoc(row_str, col_str, val_str)

    with open(out_path, "wb") as f:
        pickle.dump(A, f, protocol=pickle.HIGHEST_PROTOCOL)


def str_gen_layer7_matrix(pcap, window, output, one_file_mode, choose_app_label):
    """
    String mode pipeline:
    - Uses tshark for extraction
    - Keeps row/column labels as strings
    - Outputs D4M-compatible associative arrays
    """
    if D4M is None:
        raise RuntimeError("D4M.py is not installed. String mode requires D4M.assoc.")

    os.makedirs(output, exist_ok=True)

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

    rows = []
    cols = []
    vals = []

    bucket_index = 0

    def flush_bucket():
        """Writes current bucket to disk."""
        nonlocal rows, cols, vals, bucket_index
        if not rows:
            return

        if one_file_mode:
            out_path = os.path.join(output, "layer7_string_all.assoc.pkl")
        else:
            out_path = os.path.join(output, f"layer7_str_{bucket_index:05d}.assoc.pkl")

        write_d4m_assoc_file(rows, cols, vals, out_path)

        rows = []
        cols = []
        vals = []
        bucket_index += 1

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

        row_key = sanitize_d4m_key(ip_src)
        col_key = sanitize_d4m_key(app_label)
        val_key = "1"

        rows.append(row_key)
        cols.append(col_key)
        vals.append(val_key)

        if not one_file_mode and len(rows) >= window:
            flush_bucket()

    flush_bucket()
