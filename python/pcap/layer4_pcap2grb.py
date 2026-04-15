# Layer 4: IP:Port --> IP:Port

import sys
import argparse
import subprocess
import os
import shutil
import tarfile
from pathlib import Path
from datetime import datetime
from graphblas import Matrix, binary

file_count = 0

def generate_grb_file(matrix, results_dir):
    global file_count

    output = matrix.ss.serialize()
    filename = results_dir + "/layer4.grb"
    with open(filename, "wb") as f:
        f.write(output)
    file_count += 1


def ip_to_int(ip):
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def bucket_ip_int(ip_int, prefix):
    if prefix == 32:
        return ip_int
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ip_int & mask
    

def ip_port_to_int(ip, port, prefix=32):
    ip_int = ip_to_int(ip)
    bucketed_ip = bucket_ip_int(ip_int, prefix)
    return (bucketed_ip << 16) + int(port)


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


def gen_layer4_matrixs(pcap, subwindow, results_dir):
    src_nodes = []
    dst_nodes = []
    vals = []

    lines = run_tshark([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport"
    ])

    packet_count = 0
    total_packets = 0

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 7:
            continue

        frame_no, ip_src, tcp_sport, ip_dst, tcp_dport, udp_sport, udp_dport = parts[:7]

        # choose TCP or UDP port
        sport = tcp_sport if tcp_sport else udp_sport
        dport = tcp_dport if tcp_dport else udp_dport

        if not ip_src or not ip_dst or not sport or not dport:
            continue

        try:
            src_nodes.append(ip_port_to_int(ip_src, sport))
            dst_nodes.append(ip_port_to_int(ip_dst, dport))
            vals.append(1)
            packet_count += 1
        except ValueError:
            continue

        if packet_count == subwindow:
            matrix = Matrix.from_coo(src_nodes, dst_nodes, vals, dup_op=binary.plus)
            generate_grb_file(matrix, results_dir)

            matrix.clear()
            src_nodes.clear()
            dst_nodes.clear()
            vals.clear()

            total_packets += packet_count
            packet_count = 0

    if subwindow is sys.maxsize or packet_count != 0:
        matrix = Matrix.from_coo(src_nodes, dst_nodes, vals, dup_op=binary.plus)
        generate_grb_file(matrix, results_dir)
        total_packets += packet_count

    print("Total Packets In Matrix: " + str(total_packets))


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="GraphBlas Output Directory")
    parser.add_argument("-w", "--window", type=int, default=sys.maxsize, help="number of packets in each GraphBlas Matrix")
    parser.add_argument("--bucket", type=int, default=32, choices=[8, 16, 24, 32], help="Subnet prefix for IP bucketing (default: 32)")

    args = parser.parse_args()

    pcap_file = args.pcap
    output_dir = args.output
    subwindow = args.window
    bucket_prefix = args.bucket

    try:
        check_tshark()
        print("Creating folder to hold output data")
        os.makedirs(output_dir, exist_ok=True)
        results_dir = output_dir

        print(f"Retrieving Layer 4 IP:Port data from PCAP file {pcap_file}")
        print(f"IP bucketing prefix: /{bucket_prefix}")
        gen_layer4_matrixs(pcap_file, subwindow, results_dir)


        print("Finished!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
