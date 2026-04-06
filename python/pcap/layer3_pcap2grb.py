import sys
import argparse
import subprocess
import os
import shutil
import tarfile
from pathlib import Path
from datetime import datetime
from graphblas import Matrix, binary

# Global variable to keep track of graph files created
file_count = 0


def generate_grb_file(matrix, results_dir):
        global file_count

        output = matrix.ss.serialize()
        filename = results_dir + "/layer3.grb"
        with open(filename, "wb") as f:
            f.write(output)
        file_count += 1

# NEW: IP conversion instead of MAC
def ip_to_int(ip):
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def run_tshark(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "TShark command failed")
    return result.stdout.splitlines()

"""Need to make sure the user has installed TShark"""
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

"""Generates the matrix with the pcap file"""
def gen_layer3_matrixs(pcap, subwindow, results_dir):
    src_ip = []
    dst_ip = []
    vals = []
    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst"
    ])

    packet_count = 0
    total_packets = 0
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3:
            continue

        frame_no, ip_src, ip_dst = parts[:3]

        if not ip_src or not ip_dst:
            continue

        else:
            src_ip.append(ip_to_int(ip_src))
            dst_ip.append(ip_to_int(ip_dst))
            vals.append(1)
            packet_count += 1

        if packet_count == subwindow:
            matrix  = Matrix.from_coo(src_ip, dst_ip, vals, dup_op=binary.plus)
            generate_grb_file(matrix, results_dir)
            # clean for next matrix to create
            matrix.clear()
            src_ip.clear()
            dst_ip.clear()
            vals.clear()
            total_packets += packet_count
            packet_count = 0

    # If just one graph or some packets left then create the matrix here
    if subwindow is sys.maxsize or packet_count != 0:
        matrix  = Matrix.from_coo(src_ip, dst_ip, vals, dup_op=binary.plus)
        generate_grb_file(matrix, results_dir)
        total_packets += packet_count

    print("Total Packets In Matrix: " + str(total_packets))
 

def main():
    parser = argparse.ArgumentParser()
    # required
    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="GraphBlas Output Directory")
    # optional
    parser.add_argument("-w", "--window", type=int, default=sys.maxsize, help="number of packet in each GraphBlas Matrix")

    args = parser.parse_args()

    pcap_file = args.pcap
    output_dir = args.output
    subwindow = args.window
    try:

        check_tshark()
        print("Creating folder to hold output data")
        os.makedirs(output_dir, exist_ok=True)
        results_dir = output_dir
        
        print(f"Retrieving IP addresses from PCAP file {pcap_file}")
        gen_layer3_matrixs(pcap_file, subwindow, results_dir)
        print("Finished!")
      
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
