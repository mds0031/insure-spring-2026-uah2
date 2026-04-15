import sys
import argparse
import subprocess
import os
import shutil
import tarfile
import dpkt
import numpy as np
from collections import defaultdict
from pathlib import Path
from datetime import datetime
from graphblas import Matrix, binary
from D4M.assoc import Assoc, writecsv

file_count = 0

#Creates timestamped folder
def make_results_dir(output_dir):
    path = os.path.join(output_dir, datetime.now().strftime("%Y%m%d_%H%M%S"))
    os.mkdir(path)
    return path


def save_grb(matrix, results_dir):
    global file_count
    with open(f"{results_dir}/{file_count}.grb", "wb") as f:
        f.write(matrix.ss.serialize())
    file_count += 1

#takes the IP pair counts and saves
def save_d4m(counts, results_dir):
    global file_count
    rows, cols, vals = "", "", []
    for (src, dst), count in counts.items():
        rows += src + ","
        cols += dst + ","
        vals.append(float(count))
    writecsv(Assoc(rows, cols, np.array(vals)), f"{results_dir}/{file_count}.csv")
    file_count += 1

#.tar and deletes original compressed folder
def package_tar(folder):
    p = Path(folder)
    with tarfile.open(f"{folder}.tar", "w") as tar:
        tar.add(str(p), arcname=p.name)
    shutil.rmtree(folder)


# IP helpers

def ip_to_int(ip):
    p = ip.split(".")
    return (int(p[0]) << 24) + (int(p[1]) << 16) + (int(p[2]) << 8) + int(p[3])

#raw to integer
def bytes_to_int(b):
    return int.from_bytes(b, byteorder="big")


def int_to_ip(n):
    return f"{(n>>24)&255}.{(n>>16)&255}.{(n>>8)&255}.{n&255}"

#IP to Subnet
def bucket(ip_int, prefix):
    if prefix == 32:
        return ip_int
    return ip_int & ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF)


#  TShark helpers 

def run_tshark(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "TShark failed")
    return r.stdout.splitlines()


def check_tshark():
    try:
        subprocess.run(["tshark", "-v"], capture_output=True, timeout=10)
    except Exception:
        print("Error: TShark not installed.")
        sys.exit(1)
#runs tshark to get ip.src and ip.dest from packets and ouputs csv
def tshark_mode(pcap, window, results_dir, prefix):
    """String mode — tshark → D4M CSV"""
    counts = defaultdict(int)
    packet_count = 0
    total = 0

    for line in run_tshark(["tshark", "-r", pcap, "-T", "fields", "-e", "ip.src", "-e", "ip.dst"]):
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            continue
        try:
            src = int_to_ip(bucket(ip_to_int(parts[0]), prefix))
            dst = int_to_ip(bucket(ip_to_int(parts[1]), prefix))
            counts[(src, dst)] += 1
            packet_count += 1
        except ValueError:
            continue

        if packet_count == window:
            save_d4m(counts, results_dir)
            counts.clear()
            total += packet_count
            packet_count = 0

    if packet_count:
        save_d4m(counts, results_dir)
        total += packet_count

    print(f"Total Packets: {total}")

#outputs .grb
def dpkt_mode(pcap, window, results_dir, prefix):
    """Binary mode — dpkt -> GraphBLAS .grb"""
    srcs, dsts, vals = [], [], []
    packet_count = 0
    total = 0

    with open(pcap, "rb") as f:
        for _, buf in dpkt.pcap.Reader(f):
            try:
                ip = dpkt.ethernet.Ethernet(buf).data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                srcs.append(bucket(bytes_to_int(ip.src), prefix))
                dsts.append(bucket(bytes_to_int(ip.dst), prefix))
                vals.append(1)
                packet_count += 1
            except Exception:
                continue

            if packet_count == window:
                m = Matrix.from_coo(srcs, dsts, vals, dup_op=binary.plus)
                save_grb(m, results_dir)
                srcs.clear(); dsts.clear(); vals.clear()
                total += packet_count
                packet_count = 0

    if packet_count:
        save_grb(Matrix.from_coo(srcs, dsts, vals, dup_op=binary.plus), results_dir)
        total += packet_count

    print(f"Total Packets: {total}")

#the main
def main():
    parser = argparse.ArgumentParser(description="Layer 3 PCAP to GraphBLAS/D4M matrices.")
    parser.add_argument("-i", "--pcap",    required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output",  required=True, help="Output directory")
    parser.add_argument("-w", "--window",  type=int, default=sys.maxsize, help="Packets per matrix window")
    parser.add_argument("-b", "--binary",  action="store_true", help="Use dpkt binary mode → .grb")
    parser.add_argument("--bucket",        type=int, default=32, choices=[8, 16, 24, 32], help="Subnet prefix (default: 32)")
    args = parser.parse_args()

    try:
        results_dir = make_results_dir(args.output)

        if args.binary:
            print(f"[dpkt/GraphBLAS] {args.pcap}  bucket=/{args.bucket}")
            dpkt_mode(args.pcap, args.window, results_dir, args.bucket)
        else:
            check_tshark()
            print(f"[tshark/D4M] {args.pcap}  bucket=/{args.bucket}")
            tshark_mode(args.pcap, args.window, results_dir, args.bucket)

        package_tar(results_dir)
        print("Finished!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
