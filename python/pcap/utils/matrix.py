import pickle

import numpy as np
from graphblas import Matrix, binary
#For String mode
try:
    import D4M.assoc
except ImportError:
    D4M = None

class BucketedMatrixBuilder:
    def __init__(self, window_size, output_dir, one_file_mode):
        self.window_size = window_size
        self.output_dir = output_dir
        self.one_file_mode = one_file_mode
        self.src_nodes = np.empty(window_size, dtype=int)
        self.dst_nodes = np.empty(window_size, dtype=int)
        self.vals = np.empty(window_size, dtype=int)
        self.matrix_count = 0
        self.index = 0
    
    # Adds a packet to the current matrix and writes the matrix if the window size is reached
    def add_packet(self, src, dst):
        print(f"Adding packet: src={src}, dst={dst}")
        self.src_nodes[self.index] = src
        self.dst_nodes[self.index] = dst
        self.vals[self.index] = 1
        self.index += 1
        if self.index == self.window_size:
            self.write_matrix()
            if not self.one_file_mode:
                self.src_nodes = np.empty(self.window_size, dtype=int)
                self.dst_nodes = np.empty(self.window_size, dtype=int)
                self.vals = np.empty(self.window_size, dtype=int)
                self.index = 0

    # Writes the current matrix to a file and increments the matrix count
    def write_matrix(self):
        print(f"Generating GraphBLAS file for matrix {self.matrix_count}...")
        # only use the populated portion of the buffers
        n = self.index if self.index > 0 else self.window_size
        src = self.src_nodes[:n].tolist()
        dst = self.dst_nodes[:n].tolist()
        vals = self.vals[:n].tolist()
        matrix = Matrix.from_coo(src, dst, vals, dup_op=binary.plus)
        output_path = f"{self.output_dir}/{self.matrix_count}.grb"
        with open(output_path, "wb") as f:
            f.write(matrix.ss.serialize())
        self.matrix_count += 1
        # Clear the matrix so we can reuse the same object for the next window (optional optimization)
        matrix.clear()
        # reset write index so future writes start from empty buffer
        self.index = 0

    # Finalizes the generator by writing any remaining packets in the current matrix
    def finalize(self):
        if self.index > 0:
            self.write_matrix()


# This generator is for string-based matrices where we want to keep the original MAC address strings for D4M-friendly output
class StringBucketedMatrixBuilder:
    def __init__(self, window_size, output_dir, one_file_mode):
        self.window_size = window_size
        self.output_dir = output_dir
        self.one_file_mode = one_file_mode
        self.src_nodes = [] 
        self.dst_nodes = [] 
        self.vals = [] 
        self.matrix_count = 0
        self.index = 0

    def __sanitize_d4m_key(self, value):
        """
        D4M commonly uses comma-delimited string key encodings.
        Remove or replace characters that would break row/column key serialization.
        """
        if value is None:
            return ""
        value = str(value).strip()
        value = value.replace(",", "%2C")
        value = value.replace("\n", " ")
        value = value.replace("\r", " ")
        return value

    # Adds a packet to the current matrix and writes the matrix if the window size is reached
    def add_packet(self, src, dst):
        self.src_nodes.append(self.__sanitize_d4m_key(src))
        self.dst_nodes.append(self.__sanitize_d4m_key(dst))
        self.vals.append("1")  # D4M-friendly string value
        self.index += 1
        if self.index == self.window_size:
            self.write_matrix()
            if not self.one_file_mode:
                self.src_nodes = [] 
                self.dst_nodes = [] 
                self.vals = [] 
                self.index = 0

    # Writes the current matrix to a file and increments the matrix count
    def write_matrix(self):
        if D4M is None:
            raise RuntimeError("D4M.py is not installed. String mode requires D4M.assoc.")

        if not self.src_nodes or not self.dst_nodes or not self.vals:
            raise ValueError("Cannot write empty D4M associative array.")

        rows_str = ",".join(self.src_nodes) + ","
        cols_str = ",".join(self.dst_nodes) + ","
        vals_str = ",".join(self.vals) + ","
        A = D4M.assoc.Assoc(rows_str, cols_str, vals_str, None, "add", convert_val=True)
        A.printfull()
        print(f"Generating String array matrix file for matrix {self.matrix_count}...")
        output_path = f"{self.output_dir}/{self.matrix_count}.assoc.pk1"
        with open(output_path, "wb") as f:
            pickle.dump(A, f, protocol=pickle.HIGHEST_PROTOCOL)
        self.matrix_count += 1

    # Finalizes the generator by writing any remaining packets in the current matrix
    def finalize(self):
        if self.index > 0:
            self.write_matrix()