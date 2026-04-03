import sys
import graphblas as gb
from pathlib import Path
import tarfile
from datetime import datetime



def print_help():
    print("Pyhton script that dumps the GraphBlas matrix from a GraphBlas file for our project")
    print("Usage: ")
    print("\tpython gdump.py {layer number} {graphblas file}")
    print("Example: ")
    print("\tpython gdump.py 2 0.grb")
    

def int_to_mac(x, upper=False):
    x = int(x)
    if x < 0 or x >= 1 << 48:
        raise ValueError("value out of MAC range (0..2^48-1)")
    s = f"{x:012x}"                      # 12 hex chars = 6 bytes
    mac = ":".join(s[i:i+2] for i in range(0, 12, 2))
    return mac.upper() if upper else mac

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

def get_matrix_from_grb(filename):
    """Extract graphblas matrix from .grb file"""
    with open(filename, "rb") as f:
        file_bytes = f.read()
    return gb.Matrix.ss.deserialize(file_bytes)

"""Dictionary where we can plugin our layers"""
gdump_dict = {
    "2": gdump_layer2
}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print_help()
    else:
        if sys.argv[1] == "2":
            grb_file = sys.argv[2]
            matrix = get_matrix_from_grb(grb_file)
            gdump_dict[sys.argv[1]](matrix)