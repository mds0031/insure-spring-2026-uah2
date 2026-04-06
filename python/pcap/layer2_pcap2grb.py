import sys
import argparse
import subprocess
import os
from graphblas import Matrix, binary


def generate_grb_file(matrix, output_dir):
    output = matrix.ss.serialize()
    filename = output_dir + "/layer2.grb"
    with open(filename, "wb") as f:
        f.write(output)


def mac_to_int(mac):
    return int(mac.replace(":", ""), 16)


def run_tshark(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "TShark command failed")
    return result.stdout.splitlines()


def check_tshark():
    try:
        result = subprocess.run(
            ["tshark", "-v"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            raise RuntimeError
    except Exception:
        print("Error: TShark is not installed or not in PATH.")
        sys.exit(1)


def gen_layer2_matrix(pcap, output_dir):
    src_mac = []
    dst_mac = []
    vals = []

    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "eth.src",
        "-e", "eth.dst"
    ])

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 2:
            continue

        eth_src, eth_dst = parts[:2]

        if not eth_src or not eth_dst:
            continue

        try:
            src_mac.append(mac_to_int(eth_src))
            dst_mac.append(mac_to_int(eth_dst))
            vals.append(1)
        except ValueError:
            continue

    matrix = Matrix.from_coo(src_mac, dst_mac, vals, dup_op=binary.plus)
    generate_grb_file(matrix, output_dir)

    print("Total Packets In Matrix:", len(vals))


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output directory")

    args = parser.parse_args()

    try:
        check_tshark()
        os.makedirs(args.output, exist_ok=True)

        print(f"Processing Layer 2 from {args.pcap}")
        gen_layer2_matrix(args.pcap, args.output)

        print("Finished!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    
