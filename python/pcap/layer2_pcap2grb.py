from datetime import datetime
import sys
import argparse
import os
import utils.conversion as conv
from utils.matrix import BucketedMatrixBuilder
import utils.tshark_utils as tshark_utils
import dpkt

file_count = 0

# Generates a timestamped results directory within the specified output directory
def generate_results_dir(base_dir):
    results_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir_path = os.path.join(base_dir, f"layer2_{results_dir}")
    if not os.path.exists(output_dir_path):
        os.makedirs(output_dir_path)
    return output_dir_path

# Generates the matrix with the pcap file
def str_gen_layer2_matrix(pcap, output_dir, subwindow, one_file_mode):
    generator = BucketedMatrixBuilder(subwindow, output_dir, one_file_mode)
    packet_count = 0

    # Command to extract source and destination MAC addresses from the pcap file using TShark
    lines = tshark_utils.run_tshark([
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
            generator.add_packet(conv.mac_to_int(eth_src), conv.mac_to_int(eth_dst))
            packet_count += 1
        except ValueError:
            continue
    generator.finalize()
    print("Total Packets Processed:", packet_count)

# Generates the matrix with the pcap file using binary capture values for performance
def bin_gen_layer2_matrix(pcap, output_dir, subwindow, one_file_mode):
    generator = BucketedMatrixBuilder(subwindow, output_dir, one_file_mode)
    packet_count = 0

    dpkt.pcap.Reader(open(pcap, "rb"))
    for timestamp, buf in dpkt.pcap.Reader(open(pcap, "rb")):
        eth = dpkt.ethernet.Ethernet(buf)
        generator.add_packet(int.from_bytes(eth.src, 'big'), int.from_bytes(eth.dst, 'big'))
        packet_count += 1
    generator.finalize()
    print("Total Packets Processed:", packet_count)


# Main function to run the script
def main():
    parser = argparse.ArgumentParser()
    # Required arguments
    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    # Optional arguments
    parser.add_argument("-w", "--window", type=int, default=(1 << 17), help="number of packet in each GraphBlas Matrix")
    parser.add_argument("-b", "--binary", action="store_true", help="Use binary capture values instead of strings for performance")
    parser.add_argument("-O", "--one-file", action="store_true", help="Single file mode - one tar file containing one GraphBLAS matrix..")
    args = parser.parse_args()

    try:
        # Arg values for gen_layer2_matrixs
        performance_mode = args.binary
        window_size = args.window
        input_pcap = args.pcap
        output_dir = args.output
        one_file_mode = args.one_file

        tshark_utils.check_tshark()
        os.makedirs(output_dir, exist_ok=True)
        output_dir = generate_results_dir(output_dir)  # Create a timestamped results directory within the specified output directory

        print(f"Processing Layer 2 from {input_pcap}")
        if performance_mode:
            print("Using binary capture values for performance.")
            bin_gen_layer2_matrix(input_pcap, output_dir, window_size, one_file_mode)
        else:            
            print("Using string capture values for easier debugging.")
            str_gen_layer2_matrix(input_pcap, output_dir, window_size, one_file_mode)

        print("Finished!")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    
