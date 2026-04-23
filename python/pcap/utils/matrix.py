import os
import io
import tarfile
import pickle
import numpy as np
from graphblas import Matrix, binary
#For String mode
try:
    import D4M.assoc
except ImportError:
    D4M = None

class BucketedMatrixBuilder:
    def __init__(self, window_size: int, output_dir: str, one_file_mode: bool, tar_name: str = "layer7_bin_buckets.tar", one_file_name: str = "layer7.grb"):
        """
        Binary-based bucketed matrix builder for GraphBLAS output:
        - Stores source and destination nodes as integers
        - Builds GraphBLAS matrices for each bucket
        - Writes buckets to a tar file or a single file based on configuration
        """
        self.window_size = window_size
        self.output_dir = output_dir
        self.one_file_mode = one_file_mode
        self.tar_name = tar_name
        self.one_file_name = one_file_name
        self.matrix_count = 0
        self.index = 0

        os.makedirs(self.output_dir, exist_ok=True)

        if self.one_file_mode:
            self.src_nodes = []
            self.dst_nodes = []
            self.vals = []
            self.tar = None
        else:
            self.src_nodes = np.empty(window_size, dtype=int)
            self.dst_nodes = np.empty(window_size, dtype=int)
            self.vals = np.empty(window_size, dtype=int)
            tar_path = os.path.join(self.output_dir, self.tar_name)
            self.tar = tarfile.open(tar_path, "w")

    def add_packet(self, src: int, dst: int) -> None:
        if self.one_file_mode:
            self.src_nodes.append(src)
            self.dst_nodes.append(dst)
            self.vals.append(1)
            self.index += 1
        else:
            self.src_nodes[self.index] = src
            self.dst_nodes[self.index] = dst
            self.vals[self.index] = 1
            self.index += 1

            if self.index == self.window_size:
                self.write_bucket_to_tar()
                self.src_nodes = np.empty(self.window_size, dtype=int)
                self.dst_nodes = np.empty(self.window_size, dtype=int)
                self.vals = np.empty(self.window_size, dtype=int)
                self.index = 0

    def write_bucket_to_tar(self) -> None:
        if self.index == 0:
            return

        n = self.index
        src = self.src_nodes[:n].tolist()
        dst = self.dst_nodes[:n].tolist()
        vals = self.vals[:n].tolist()

        matrix = Matrix.from_coo(src, dst, vals, dup_op=binary.plus)
        data = matrix.ss.serialize()
        matrix.clear()

        arcname = f"{self.matrix_count}.grb"
        info = tarfile.TarInfo(name=arcname)
        info.size = len(data)
        self.tar.addfile(info, io.BytesIO(data))

        self.matrix_count += 1

    def write_single_file(self) -> None:
        if self.index == 0:
            return

        matrix = Matrix.from_coo(
            self.src_nodes,
            self.dst_nodes,
            self.vals,
            dup_op=binary.plus
        )

        output_path = os.path.join(self.output_dir, self.one_file_name)
        with open(output_path, "wb") as f:
            f.write(matrix.ss.serialize())

        matrix.clear()

    def add_text_file_to_tar(self, arcname: str, text: str) -> None:
        if self.tar is None:
            return
        data = text.encode("utf-8")
        info = tarfile.TarInfo(name=arcname)
        info.size = len(data)
        self.tar.addfile(info, io.BytesIO(data))

    def finalize(self, label_tsv_text: str = None) -> None:
        if self.one_file_mode:
            self.write_single_file()
        else:
            if self.index > 0:
                self.write_bucket_to_tar()

            if label_tsv_text is not None:
                self.add_text_file_to_tar("layer7_labels.tsv", label_tsv_text)

            self.tar.close()


class StringBucketedMatrixBuilder:
    """
    String-based bucketed matrix builder for D4M-compatible output:
    - Stores source and destination nodes as strings
    - Builds D4M associative arrays for each bucket
    - Writes buckets to a tar file or a single file based on configuration
    """
    def __init__(self, window_size: int, output_dir: str, one_file_mode: bool, tar_name: str = "layer7_str_buckets.tar", one_file_name: str = "layer7.assoc.pkl"):
        self.window_size = window_size
        self.output_dir = output_dir
        self.one_file_mode = one_file_mode
        self.tar_name = tar_name
        self.one_file_name = one_file_name
        self.matrix_count = 0
        self.index = 0

        self.src_nodes = []
        self.dst_nodes = []
        self.vals = []

        os.makedirs(self.output_dir, exist_ok=True)

        if self.one_file_mode:
            self.tar = None
        else:
            tar_path = os.path.join(self.output_dir, self.tar_name)
            self.tar = tarfile.open(tar_path, "w")

    def __sanitize_d4m_key(self, value: str) -> str:
        if value is None:
            return ""
        value = str(value).strip()
        value = value.replace(",", "%2C")
        value = value.replace("\n", " ")
        value = value.replace("\r", " ")
        return value

    def add_packet(self, src: str, dst: str) -> None:
        self.src_nodes.append(self.__sanitize_d4m_key(src))
        self.dst_nodes.append(self.__sanitize_d4m_key(dst))
        self.vals.append("1")
        self.index += 1

        if not self.one_file_mode and self.index == self.window_size:
            self.write_bucket_to_tar()
            self.src_nodes = []
            self.dst_nodes = []
            self.vals = []
            self.index = 0

    def _build_assoc(self) -> "D4M.assoc.Assoc": # type: ignore
        if D4M is None:
            raise RuntimeError("D4M.py is not installed. String mode requires D4M.assoc.")
        if not self.src_nodes or not self.dst_nodes or not self.vals:
            raise ValueError("Cannot write empty D4M associative array.")

        rows_str = ",".join(self.src_nodes) + ","
        cols_str = ",".join(self.dst_nodes) + ","
        vals_str = ",".join(self.vals) + ","
        return D4M.assoc.Assoc(rows_str, cols_str, vals_str, None, "add", convert_val=True)

    def write_bucket_to_tar(self):
        if self.index == 0:
            return

        A = self._build_assoc()
        data = pickle.dumps(A, protocol=pickle.HIGHEST_PROTOCOL)

        arcname = f"{self.matrix_count}.assoc.pkl"
        info = tarfile.TarInfo(name=arcname)
        info.size = len(data)
        self.tar.addfile(info, io.BytesIO(data))

        self.matrix_count += 1

    def write_single_file(self) -> None:
        if self.index == 0:
            return

        A = self._build_assoc()
        output_path = os.path.join(self.output_dir, self.one_file_name)
        with open(output_path, "wb") as f:
            pickle.dump(A, f, protocol=pickle.HIGHEST_PROTOCOL)

    def add_text_file_to_tar(self, arcname: str, text: str) -> None:
        if self.tar is None:
            return
        data = text.encode("utf-8")
        info = tarfile.TarInfo(name=arcname)
        info.size = len(data)
        self.tar.addfile(info, io.BytesIO(data))

    def finalize(self, label_tsv_text: str = None) -> None:
        if self.one_file_mode:
            self.write_single_file()
        else:
            if self.index > 0:
                self.write_bucket_to_tar()

            if label_tsv_text is not None:
                self.add_text_file_to_tar("layer7_labels.tsv", label_tsv_text)

            self.tar.close()