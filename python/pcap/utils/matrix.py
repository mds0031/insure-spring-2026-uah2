import numpy as np
from graphblas import Matrix, binary

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
        matrix = Matrix.from_coo(self.src_nodes, self.dst_nodes, self.vals, dup_op=binary.plus)
        output_path = f"{self.output_dir}/{self.matrix_count}.grb"
        with open(output_path, "wb") as f:
            f.write(matrix.ss.serialize())
        self.matrix_count += 1
        # Clear the matrix so we can reuse the same object for the next window (optional optimization)
        matrix.clear()

    # Finalizes the generator by writing any remaining packets in the current matrix
    def finalize(self):
        if self.index > 0:
            self.write_matrix()

