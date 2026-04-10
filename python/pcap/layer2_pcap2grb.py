from datetime import datetime
import sys
import argparse
import subprocess
import os
import numpy as np
from graphblas import Matrix, binary

file_count = 0

# Converts a MAC address string to an integer for use in the matrix
def generate_grb_file(matrix, output_dir):
    global file_count
    output = matrix.ss.serialize()
    filename = os.path.join(output_dir, f"{file_count}.grb")
    with open(filename, "wb") as f:
        f.write(output)
    file_count += 1

# Generates a timestamped results directory within the specified output directory
def generate_results_dir(base_dir):
    results_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir_path = os.path.join(base_dir, f"layer2_{results_dir}")
    if not os.path.exists(output_dir_path):
        os.makedirs(output_dir_path)
    return output_dir_path

# Converts MAC Address String to an Integer for use in the matrix
def mac_to_int(mac):
    return int(mac.replace(":", ""), 16)

# Runs a TShark command and returns the output as a list of lines
def run_tshark(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "TShark command failed")
    return result.stdout.splitlines()

# Need to make sure the user has installed TShark
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

# Generates the matrix with the pcap file
def str_gen_layer2_matrix(pcap, output_dir, subwindow, one_file_mode):
    src_mac = np.array([], dtype=int)
    dst_mac = np.array([], dtype=int)
    vals = np.array([], dtype=int)
    packet_count = 0

    # Command to extract source and destination MAC addresses from the pcap file using TShark
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
            src_mac = np.append(src_mac, mac_to_int(eth_src))
            dst_mac = np.append(dst_mac, mac_to_int(eth_dst))
            vals = np.append(vals, 1)
            packet_count += 1
        except ValueError:
            continue
        # Check if we've reached the subwindow packet count to write out a GraphBLAS file
        if len(vals) == subwindow:
            print(f"Generating GraphBLAS file for packets {file_count * subwindow} to {(file_count + 1) * subwindow - 1}...")
            matrix = Matrix.from_coo(src_mac, dst_mac, vals, dup_op=binary.plus)
            generate_grb_file(matrix, output_dir)
            if not one_file_mode:
                src_mac = np.array([], dtype=int)
                dst_mac = np.array([], dtype=int)
                vals = np.array([], dtype=int)
                matrix.clear()  # Clear the matrix for the next window
            else:
                # In one file mode, we keep appending to the same lists and will write the file at the end
                pass

    matrix = Matrix.from_coo(src_mac, dst_mac, vals, dup_op=binary.plus)
    generate_grb_file(matrix, output_dir)

    print("Total Packets Processed:", packet_count)

# Main function to run the script
def main():
    parser = argparse.ArgumentParser()
    # Required arguments
    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    # Optional arguments
    parser.add_argument("-w", "--window", type=int, default=sys.maxsize, help="number of packet in each GraphBlas Matrix")
    parser.add_argument("--binary", action="store_true", help="Use binary capture values instead of strings for performance")
    parser.add_argument("-O", "--one-file", action="store_true", help="Single file mode - one tar file containing one GraphBLAS matrix..")
    args = parser.parse_args()

    try:
        # Arg values for gen_layer2_matrixs
        performance_mode = args.binary
        window_size = args.window
        input_pcap = args.pcap
        output_dir = args.output
        one_file_mode = args.one_file

        check_tshark()
        os.makedirs(output_dir, exist_ok=True)
        output_dir = generate_results_dir(output_dir)  # Create a timestamped results directory within the specified output directory

        print(f"Processing Layer 2 from {input_pcap}")
        if performance_mode:
            print("Using binary capture values for performance.")
            # TODO: Implement binary capture value generation for better performance (currently using string values for easier debugging)
        else:            
            print("Using string capture values for easier debugging.")
            str_gen_layer2_matrix(input_pcap, output_dir, window_size, one_file_mode)

        print("Finished!")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    
