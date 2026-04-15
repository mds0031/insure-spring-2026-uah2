import json
import os
import platform
import socket
from dataclasses import dataclass, asdict
from time import perf_counter_ns


@dataclass
class Layer7BenchmarkResult:
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

    def finalize(self, total_start_ns: int) -> None:
        self.total_ns = perf_counter_ns() - total_start_ns

    @property
    def execution_time_sec(self) -> float:
        return self.total_ns / 1e9

    @property
    def throughput_pps(self) -> float:
        if self.total_ns <= 0:
            return 0.0
        return self.packets_seen / (self.total_ns / 1e9)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["execution_time_sec"] = self.execution_time_sec
        data["throughput_pps"] = self.throughput_pps
        return data

    def write_json(self, filename: str) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        out_path = os.path.join(self.output_dir, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return out_path