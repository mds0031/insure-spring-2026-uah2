
import argparse
import subprocess
import sys
from collections import Counter
from graphblas import Matrix, binary
import tarfile

create_new_file = False
file_count = 0

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


def get_layer2_vals(pcap):
    src_mac = []
    dst_mac = []
    vals = []
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ip.dst"
    ])


    for line in lines:
        parts = line.split("\t")
        if len(parts) < 5:
            continue

        frame_no, eth_src, eth_dst, ip_src, ip_dst = parts[:5]

        if not eth_src or not eth_dst:
            continue

        else:
            src_mac.append(mac_to_int(eth_src))
            dst_mac.append(mac_to_int(eth_dst))
            vals.append(1)
    

    return (src_mac, dst_mac, vals)

def main():
    parser = argparse.ArgumentParser()
    # required
    parser.add_argument("-i", "--pcap", help="Input PCAP file")
    parser.add_argument("-o", "--output", help="GraphBlas Output file")
    # optional
    parser.add_argument("-w", "--window", type=int, default=0, help="number of packet in each GraphBlas Matrix") # TODO Implement

    args = parser.parse_args()

    pcap_file = args.pcap
    output_file = args.output
    window = args.window
    try:

        check_tshark()
        print(f"Retrieving MAC addresses from PCAP file {pcap_file}")
        flows = get_layer2_vals(pcap_file)
        print("Creating Matrix...")
        matrix  = Matrix.from_coo(flows[0], flows[1], flows[2], dup_op=binary.max)
        print("Matrix Created")
        print(f"Saving Matrix to {output_file}")
        output = matrix.ss.serialize()
        with open(output_file, "wb") as f:
            f.write(output)
        print("Finished!")
      
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    
