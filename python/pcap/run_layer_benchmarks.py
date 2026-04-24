"""
Script to run layer2/layer3/layer4/layer7 matrix scripts with benchmarking enabled.
This script will run the specified layer scripts with the --benchmark flag, which enables benchmarking and saves results to JSON files. It can run both string and binary modes for comparison when benchmarking is enabled.
Usage:
    python run_layer_benchmarks.py -i input.pcap -o output_dir --window 131072 --one-file --map layer7_labels.tsv --layers 2,3,4,7
"""
import argparse
import os
import subprocess
import sys
from typing import List, Tuple


SCRIPT_NAMES = {
    2: "layer2_matrix.py",
    3: "layer3_matrix.py",
    4: "layer4_matrix.py",
    7: "layer7_matrix.py",
}


def _build_command(
    python_exe: str,
    script_path: str,
    pcap_path: str,
    output_dir: str,
    window_size: int,
    one_file_mode: bool,
    label_map_name: str,
) -> List[str]:
    command = [
        python_exe,
        script_path,
        "-i",
        pcap_path,
        "-o",
        output_dir,
        "-w",
        str(window_size),
        "--benchmark",
    ]

    if one_file_mode:
        command.append("-O")

    if os.path.basename(script_path) == "layer7_matrix.py":
        command.extend(["-m", label_map_name])

    return command


def run_layer_script(command: List[str]) -> Tuple[bool, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return False, f"Failed to start command: {exc}"

    output_parts = []
    if completed.stdout:
        output_parts.append(completed.stdout.strip())
    if completed.stderr:
        output_parts.append(completed.stderr.strip())

    output_text = "\n".join(part for part in output_parts if part)
    success = completed.returncode == 0

    if not output_text:
        output_text = "(no output)"

    return success, output_text


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run layer2/layer3/layer4/layer7 matrix scripts with benchmarking enabled."
    )
    parser.add_argument("-i", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output root directory for benchmark runs",
    )
    parser.add_argument(
        "-w",
        "--window",
        type=int,
        default=(1 << 17),
        help="Window size passed to each layer script",
    )
    parser.add_argument(
        "-O",
        "--one-file",
        action="store_true",
        help="Enable one-file mode for each layer script",
    )
    parser.add_argument(
        "-m",
        "--map",
        default="layer7_labels.tsv",
        help="Label map filename passed to layer7 binary benchmark path",
    )
    parser.add_argument(
        "--layers",
        default="2,3,4,7",
        help="Comma-separated list of layers to run (default: 2,3,4,7)",
    )

    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_root = os.path.abspath(args.output)
    os.makedirs(out_root, exist_ok=True)

    try:
        requested_layers = [int(token.strip()) for token in args.layers.split(",") if token.strip()]
    except ValueError as exc:
        raise SystemExit(f"Invalid --layers value: {exc}")

    invalid = [layer for layer in requested_layers if layer not in SCRIPT_NAMES]
    if invalid:
        raise SystemExit(
            f"Unsupported layer(s): {invalid}. Choose from {sorted(SCRIPT_NAMES.keys())}."
        )

    failures = []

    for layer in requested_layers:
        script_name = SCRIPT_NAMES[layer]
        script_path = os.path.join(script_dir, script_name)
        layer_output = os.path.join(out_root, f"layer{layer}")
        os.makedirs(layer_output, exist_ok=True)

        command = _build_command(
            python_exe=sys.executable,
            script_path=script_path,
            pcap_path=args.pcap,
            output_dir=layer_output,
            window_size=args.window,
            one_file_mode=args.one_file,
            label_map_name=args.map,
        )

        print(f"\n=== Running Layer {layer} benchmark ===")
        print("Command:", " ".join(command))

        success, output_text = run_layer_script(command)
        print(output_text)

        if not success:
            failures.append(layer)

    if failures:
        print(f"\nCompleted with failures in layer(s): {failures}")
        raise SystemExit(1)

    print("\nAll requested layer benchmarks completed successfully.")


if __name__ == "__main__":
    main()
