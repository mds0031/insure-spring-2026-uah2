import argparse
import datetime # is this used?
import os
import sys
import pickle

# GraphBLAS imports for binary matrix construction
from graphblas import Matrix, binary

#Project utility modules
from utils.tshark_utils import run_tshark, check_tshark
from utils.layer7_bin_utils import bin_gen_layer7_matrix

#Optional dependency: D4M check
try:
    import D4M.assoc
except ImportError:
    D4M = None

# -----------------------------------------------------------
# Layer 7 Label Selection Logic
# -----------------------------------------------------------
def choose_app_label(http_full_uri, http_host, tls_sni, dns_name):
    """
    Selects the most informative Layer 7 label for a packet.

    Priority order:
    1. HTTP full URI
    2. HTTP host
    3. TLS SNI
    4. DNS query name

    Returns:
        A string label or None if no L7 info exists.
    """
    if http_full_uri:
        return f"HTTP_URL|{http_full_uri}"
    if http_host:
        return f"HTTP_HOST|{http_host}"
    if tls_sni:
        return f"TLS_SNI|{tls_sni}"
    if dns_name:
        return f"DNS_QRY|{dns_name}"
    return None

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


def str_gen_layer7_matrix(pcap, window, output, one_file_mode, label_map_path=None):
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


def main():
    parser = argparse.ArgumentParser(
    description="Construct Layer 7 matrices from a PCAP: string mode outputs D4M-compatible buckets, binary mode outputs GraphBLAS buckets."
    )

    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output folder for bucketed matrix files")
    parser.add_argument(
        "-m", "--map",
        default="layer7_labels.tsv",
        help="Binary-mode label map TSV file (default: layer7_labels.tsv)"
    )

    #Optional arguments for performance and flexibility
    parser.add_argument(
        "-w", "--window",
        type=int,
        default=(1 << 17),
        help="Number of packet-derived entries per output bucket"
    )
    parser.add_argument(
        "-b", "--binary",
        action="store_true",
        help="Binary mode: parse raw packets with dpkt and save GraphBLAS buckets. Default is string mode using tshark and D4M-compatible output."
    )
    parser.add_argument(
        "-O", "--one-file",
        action="store_true",
        help="Single-file output mode if supported by the selected backend"
    )

    args = parser.parse_args()

    # Arg values for gen_layer5_matrixs
    window_size = args.window
    input_pcap = args.pcap
    output_dir = args.output
    one_file_mode = args.one_file
    label_map_path = args.map

    try:
        if args.binary:
            print(f"Generating Layer 7 GraphBLAS buckets in binary mode from PCAP file: {input_pcap}")
            bin_gen_layer7_matrix(
                input_pcap,
                output_dir,
                window_size,
                one_file_mode,
                label_map_path
            )
        else:
            check_tshark()
            print(f"Generating Layer 7 D4M-compatible buckets in string mode from PCAP file: {input_pcap}")
            str_gen_layer7_matrix(
                input_pcap,
                window_size,
                output_dir,
                one_file_mode,
                label_map_path
            )
        
        print("Finished!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
