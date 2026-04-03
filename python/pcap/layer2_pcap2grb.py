
import argparse
import subprocess
import sys
from graphblas import Matrix, binary
from pathlib import Path
import tarfile
from datetime import datetime
import os
import shutil

file_count = 0

def generate_results_dir(output_dir):
    output_dir_path = output_dir + "/" + datetime.now().strftime("%Y%m%d_%H%M%S")
    os.mkdir(output_dir_path)
    return output_dir_path


def generate_grb_file(matrix, results_dir):
        global file_count

        output = matrix.ss.serialize()
        filename = results_dir + "/" + str(file_count) + ".grb"
        with open(filename, "wb") as f:
            f.write(output)
        file_count += 1

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


def gen_layer2_matrixs(pcap, subwindow, results_dir):
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

    packet_count = 0
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
            packet_count += 1

        if packet_count == subwindow:
            matrix  = Matrix.from_coo(src_mac, dst_mac, vals, dup_op=binary.max)
            generate_grb_file(matrix, results_dir)
            # clean for next matrix to create
            matrix.clear()
            src_mac.clear()
            dst_mac.clear()
            vals.clear()
            packet_count = 0
    # If just one graph or some packets left then create the matrix here
    if subwindow is sys.maxsize or packet_count != 0:
        matrix  = Matrix.from_coo(src_mac, dst_mac, vals, dup_op=binary.max)
        generate_grb_file(matrix, results_dir)



def make_tar(source_dir, output_filename):
    source_dir = Path(source_dir)
    print (source_dir)
    print(output_filename)
    with tarfile.open(output_filename, "w") as tar:
        tar.add(str(source_dir), arcname=source_dir.name)

def remove_uncompressed_folder(folder_to_remove):
    d = Path(folder_to_remove)
    if d.exists():
        shutil.rmtree(d) 

def main():
    parser = argparse.ArgumentParser()
    # required
    parser.add_argument("-i", "--pcap", help="Input PCAP file")
    parser.add_argument("-o", "--output", help="GraphBlas Output Directory")
    # optional
    parser.add_argument("-w", "--window", type=int, default=sys.maxsize, help="number of packet in each GraphBlas Matrix")

    args = parser.parse_args()

    pcap_file = args.pcap
    output_dir = args.output
    subwindow = args.window
    try:

        check_tshark()
        print("Creating folder to hold output data")
        results_dir = generate_results_dir(output_dir)
        
        print(f"Retrieving MAC addresses from PCAP file {pcap_file}")
        gen_layer2_matrixs(pcap_file, subwindow, results_dir)
        make_tar(results_dir, results_dir + ".tar")
        remove_uncompressed_folder(results_dir)
        print("Finished!")
      
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    
