import sys
import ipaddress
import graphblas as gb
from pathlib import Path
import tarfile
from datetime import datetime

def print_help():
    print("Python script that dumps the GraphBLAS matrix from a GraphBLAS file for this project")
    print("Usage:")
    print("\tpython gdump.py 2 {graphblas .grb or .tar file}")
    print("\tpython gdump.py 3 {graphblas .grb or .tar file}")
    print("\tpython gdump.py 4 {graphblas .grb or .tar file}")
    print("\tpython gdump.py 7 {graphblas .grb or .tar file} {label map tsv}")
    print("Examples:")
    print("\tpython gdump.py 2 0.grb")
    print("\tpython gdump.py 2 matrices.tar")
    print("\tpython gdump.py 3 0.grb")
    print("\tpython gdump.py 3 layer3_bin_buckets.tar")
    print("\tpython gdump.py 4 0.grb")
    print("\tpython gdump.py 4 layer4_bin_buckets.tar")
    print("\tpython gdump.py 7 0.grb layer7_labels.tsv")
    print("\tpython gdump.py 7 matrices.tar layer7_labels.tsv")


def truncate(text, max_len=80):
    text = str(text)
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def int_to_mac(x, upper=False):
    x = int(x)
    if x < 0 or x >= 1 << 48:
        raise ValueError("value out of MAC range (0..2^48-1)")
    s = f"{x:012x}"  # 12 hex chars = 6 bytes
    mac = ":".join(s[i:i+2] for i in range(0, 12, 2))
    return mac.upper() if upper else mac


def int_to_ip(x):
    """
    Convert an integer back into either IPv4 or IPv6 text form.

    Rules:
    - 0 <= x < 2^32     -> IPv4
    - 2^32 <= x < 2^128 -> IPv6
    """
    x = int(x)

    if x < 0:
        raise ValueError("IP integer cannot be negative")

    if x < (1 << 32):
        return str(ipaddress.IPv4Address(x))

    if x < (1 << 128):
        return str(ipaddress.IPv6Address(x))

    raise ValueError("value out of IP range (0..2^128-1)")


def int_to_ip_port(x):
    port = x & 0xFFFF
    ip_int = x >> 16
    try:
        ip_str = int_to_ip(ip_int)
    except ValueError:
        ip_str = f"<bad-ip:{ip_int}>"
    return f"{ip_str}:{port}"


def gdump_layer2(matrix):
    matrix_dict = matrix.to_dicts()
    total = 0

    for src, row in matrix_dict.items():
        for dst, count in row.items():
            v = int(count)
            total += v
            s = int_to_mac(src)
            d = int_to_mac(dst)
            print(s, d, v)

    print("total packets:", total)


def gdump_layer3(matrix):
    """
    Dump Layer 3 GraphBLAS matrix entries in readable form.

    Row index  -> source IP (IPv4 or IPv6)
    Col index  -> destination IP (IPv4 or IPv6)
    Value      -> count
    """
    matrix_dict = matrix.to_dicts()
    total = 0

    for src, row in matrix_dict.items():
        try:
            src_ip = int_to_ip(src)
        except ValueError:
            src_ip = f"<bad-ip:{src}>"

        for dst, count in row.items():
            try:
                dst_ip = int_to_ip(dst)
            except ValueError:
                dst_ip = f"<bad-ip:{dst}>"

            v = int(count)
            total += v
            print(src_ip, dst_ip, v)

    print("total packets:", total)


def gdump_layer4(matrix):
    """
    Dump Layer 4 GraphBLAS matrix entries in readable form.

    Row index  -> source IP:port
    Col index  -> destination IP:port
    Value      -> count
    """
    matrix_dict = matrix.to_dicts()
    total = 0

    for src, row in matrix_dict.items():
        try:
            src_str = int_to_ip_port(src)
        except Exception:
            src_str = f"<bad-src:{src}>"

        for dst, count in row.items():
            try:
                dst_str = int_to_ip_port(dst)
            except Exception:
                dst_str = f"<bad-dst:{dst}>"

            v = int(count)
            total += v
            print(src_str, dst_str, v)

    print("total packets:", total)


def load_label_map(label_map_file):
    """
    Load label_id -> label mapping from a TSV file with format:
        label_id    label
        0           HTTP_HOST|example.com
        1           DNS_QRY|example.com
    """
    label_map = {}

    with open(label_map_file, "r", encoding="utf-8") as f:
        next(f, None)  # skip header
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue

            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue

            label_id_str, label = parts
            try:
                label_id = int(label_id_str)
            except ValueError:
                continue

            label_map[label_id] = label

    return label_map


def gdump_layer7(matrix, label_map, max_label_len=60):
    """
    Dump Layer 7 GraphBLAS matrix entries in readable form.

    Row index  -> source IP (IPv4 or IPv6)
    Col index  -> Layer 7 label from TSV map
    Value      -> count
    """
    matrix_dict = matrix.to_dicts()
    total = 0

    print("-" * 80)

    for src, row in matrix_dict.items():
        try:
            src_ip = int_to_ip(src)
        except ValueError:
            src_ip = f"<bad-ip:{src}>"

        for dst, count in row.items():
            v = int(count)
            total += v

            label = label_map.get(int(dst), f"<unknown-label:{dst}>")
            label = truncate(label, max_label_len)

            print(f"IP: {src_ip}")
            print(f"URL: {label}")
            print(f"Count: {v}")
            print("-" * 80)

    print("total observations:", total)


def get_matrix_from_grb(filename):
    """
    Extract a GraphBLAS matrix from either:
    - a raw .grb file
    - a .tar archive containing a .grb file
    """
    path = Path(filename)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {filename}")

    if path.suffix == ".grb":
        with open(path, "rb") as f:
            return gb.Matrix.ss.deserialize(f.read())

    if path.suffix == ".tar":
        with tarfile.open(path, "r") as tar:
            grb_members = [m for m in tar.getmembers() if m.isfile() and m.name.endswith(".grb")]

            if not grb_members:
                raise ValueError(f"No .grb file found inside tar archive: {filename}")

            if len(grb_members) > 1:
                print(f"Warning: multiple .grb files found in {filename}; using first: {grb_members[0].name}")

            extracted = tar.extractfile(grb_members[0])
            if extracted is None:
                raise ValueError(f"Could not extract .grb file from tar archive: {grb_members[0].name}")

            return gb.Matrix.ss.deserialize(extracted.read())

    raise ValueError(f"Unsupported file type: {filename}. Expected .grb or .tar")


gdump_dict = {
    "2": gdump_layer2,
    "3": gdump_layer3,
    "4": gdump_layer4,
    "7": gdump_layer7
}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print_help()
        sys.exit(1)

    layer = sys.argv[1]
    grb_file = sys.argv[2]

    if layer not in gdump_dict:
        print(f"Unsupported layer: {layer}")
        print_help()
        sys.exit(1)

    matrix = get_matrix_from_grb(grb_file)

    if layer == "2":
        gdump_dict[layer](matrix)

    elif layer == "3":
        gdump_dict[layer](matrix)

    elif layer == "7":
        if len(sys.argv) != 4:
            print("Layer 7 requires a label map TSV file.")
            print("Usage: python gdump.py 7 {graphblas file} {label map tsv}")
            sys.exit(1)

        label_map_file = sys.argv[3]
        label_map = load_label_map(label_map_file)
        gdump_dict[layer](matrix, label_map)
