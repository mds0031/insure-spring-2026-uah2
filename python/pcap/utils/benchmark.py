import json
import os
import platform
import socket
from dataclasses import dataclass, asdict
from time import perf_counter_ns


class BaseBenchmarkResult:

    layer: int
    mode: str
    pcap: str
    output_dir: str
    window_size: int
    one_file_mode: bool

    step1_read_ns: int = 0
    step2_parse_ns: int = 0
    step4_build_ns: int = 0
    step5_save_ns: int = 0

    total_ns: int = 0

    hostname: str = socket.gethostname()
    processor: str = platform.processor() or platform.machine()
    python_version: str = platform.python_version()

    """Base class for benchmark results, providing common functionality."""
    def finalize(self, total_start_ns: int) -> None:
        """Calculate total execution time."""
        self.total_ns = perf_counter_ns() - total_start_ns

    @property
    def execution_time_sec(self) -> float:
        """Total execution time in seconds."""
        return self.total_ns / 1e9

    @property
    def throughput_pps(self) -> float:
        """Throughput in packets per second."""
        if self.total_ns <= 0:
            return 0.0
        return self.packets_seen / (self.total_ns / 1e9)

    def to_dict(self) -> dict:
        """Convert benchmark results to a dictionary."""
        data = asdict(self)
        data["execution_time_sec"] = self.execution_time_sec
        data["throughput_pps"] = self.throughput_pps
        return data

    def write_json(self, filename: str) -> str:
        """Write benchmark results to a JSON file."""
        os.makedirs(self.output_dir, exist_ok=True)
        out_path = os.path.join(self.output_dir, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return out_path

@dataclass
class Layer7BenchmarkResult(BaseBenchmarkResult):
    layer: int
    mode: str
    pcap: str
    output_dir: str
    window_size: int
    one_file_mode: bool

    packets_seen: int = 0
    valid_packets: int = 0
    labeled_packets: int = 0
    unlabeled_packets: int = 0

    http_labels: int = 0
    tls_labels: int = 0
    dns_labels: int = 0

    step1_read_ns: int = 0
    step2_parse_ns: int = 0
    step4_build_ns: int = 0
    step5_save_ns: int = 0

    total_ns: int = 0

    hostname: str = socket.gethostname()
    processor: str = platform.processor() or platform.machine()
    python_version: str = platform.python_version()


@dataclass
class Layer2BenchmarkResult(BaseBenchmarkResult):
    """Benchmark results container for Layer 2 (Ethernet) processing."""
    layer: int = 2
    mode: str = ""
    pcap: str = ""
    output_dir: str = ""
    window_size: int = 0
    one_file_mode: bool = False

    packets_seen: int = 0
    valid_packets: int = 0
    mac_pairs: int = 0
    unique_src_macs: int = 0
    unique_dst_macs: int = 0


