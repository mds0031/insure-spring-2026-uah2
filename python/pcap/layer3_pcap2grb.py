import sys
import argparse
import subprocess
import os
from graphblas import Matrix, binary


# Convert IP string to integer
def ip_to_int(ip):
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


# run tshark command
def run_tshark(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "TShark failed")
    return result.stdout.splitlines()


# checking tshark
def check_tshark():
    try:
        subprocess.run(["tshark", "-v"], capture_output=True, timeout=5)
    except Exception:
        print("Error: TShark not installed")
        sys.exit(1)


# generate matrix
def gen_layer3_matrix(pcap, output_dir):
    src = []
    dst = []
    vals = []

    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst"
    ])

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 2:
            continue

        ip_src, ip_dst = parts[:2]

        if not ip_src or not ip_dst:
            continue

        try:
            src.append(ip_to_int(ip_src))
            dst.append(ip_to_int(ip_dst))
            vals.append(1)
        except ValueError:
            continue

    # Build matrix
    matrix = Matrix.from_coo(src, dst, vals, dup_op=binary.plus)

    # Save as layer3.grb
    output_file = os.path.join(output_dir, "layer3.grb")
    with open(output_file, "wb") as f:
        f.write(matrix.ss.serialize())

    print(f"Saved: {output_file}")
    print(f"Total edges: {len(vals)}")


# main
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output directory")

    args = parser.parse_args()

    try:
        check_tshark()
        os.makedirs(args.output, exist_ok=True)

        gen_layer3_matrix(args.pcap, args.output)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
