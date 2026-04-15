# INSuRE Spring 2026 UAH Team 2

Python tooling and analysis workflows for converting PCAP network captures into GraphBLAS/D4M-based cyber data products across OSI layers for the **Next Generation Spatial Temporal Cyber Data Products (v3)** project.

## Overview

This repository contains code, test artifacts, and supporting utilities used by UAH Team 2 for the INSuRE Spring 2026 research effort. The primary objective is to transform packet capture (`.pcap` / `.cap`) data into graph-oriented representations that support scalable cyber analytics across multiple OSI layers.

The repository currently includes:

- PCAP parsing tools for selected OSI layers
- GraphBLAS-based matrix generation
- D4M-compatible output support for Layer 7 workflows
- Test PCAP files and output directories
- Utility scripts for sanity checks and downstream support

## Repository Structure

```text
insure-spring-2026-uah2/
├── python/
│   ├── pcap/        # Layer-specific PCAP parsing and graph generation tools
│   └── utils/       # Shared helper scripts and utilities
├── tests/           # Sample PCAP files and generated test outputs
└── README.md
```

## Supported Layers
- Layer 2 - Data Link
- Layer 3 - Network
- Layer 4 - Transport
- layer 5 - Session
- layer 7 - Application

## Notes
- Layer 6 (Presentation) is excluded from this study because its values coincide with Layer 7 (Application).
- Layer 1 (Physical) is excluded because PCAP files do not contain sufficient information to determine directionality (source vs. destination).
- Layer 5 & 7 are executed in the same python script. This was done due to layer 7 relying on DNS captures to help decode HTTP/HTTPS.

# Getting Started
1. Clone the Repository
```
git clone https://github.com/mds0031/insure-spring-2026-uah2.git
cd insure-spring-2026-uah2
```
2. Create and activate a Python virtual enivronment
```
python3 -m venv .venv
source .venv/bin/activate
```
3. Install Python dependencies
```
pip install --upgrade pip
pip install python-graphblas dpkt
```
4. Install external project dependencies
This project also depends on:

- ILANDS-sensor – supporting workflows related to cyber data processing GitHub: https://github.com/CAIDA/ILANDS-sensor
- D4M.py – D4M support for associative-array style data handling GitHub: https://github.com/Accla/D4M.py

If you are using the Layer 7 D4M workflow, clone and set up D4M.py separately according to its repository instructions.

Example:
```
git clone https://github.com/Accla/D4M.py.git
```

# Dependencies
## External repositories

- python-graphblas GitHub: https://github.com/python-graphblas/python-graphblas
- dpkt GitHub: https://github.com/kbandla/dpkt
- ILANDS GitHub: https://github.com/CAIDA/ILANDS-sensor
- D4M GitHub: https://github.com/Accla/D4M.py

# Usage Examples
All examples below assume you are running from
```
cd python/pcap
```
## Layer 2
```
python3 layer2_pcap2grb.py \  
  -i ../../tests/http.cap \  
  -o ../../test/test_outs/layer2.grb
```
## Layer 3
```
python3 layer3_initial.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer3.grb
```
## Layer 4
```
python3 layer4_initial.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer4.grb
```
## Layer 5 & 7
### String mode
```
mkdir -p ../../tests/test_outs/layer5_7_str
python3 layer5_7_pcap_to_grb_d4m.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer5_7_str
```
### Binary mode
```
mkdir -p ../../tests/test_outs/layer5_7_bin
python3 layer5_7_pcap_to_grb_d4m.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer5_7_bin \
  -m ../../tests/test_outs/layer5_7_bin/layer5_7_labels.tsv \
  -b
```
### One-file mode
```
mkdir -p ../../tests/test_outs/layer5_7_onefile
python3 layer5_7_pcap_to_grb_d4m.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer5_7_onefile \
  -m ../../tests/test_outs/layer5_7_onefile/layer5_7_labels.tsv \
  -b \
  -O
```

### Validation Example
```
cd python/utils
python3 gdump.py #layer #.grb
```
or
```
cd python/utils
python3 gdump.py #layer #.grb file_name.tsv
```
Where #layer is the layer you are decoding, # is the number in front of the grb file you are decoding, and file_name is the tsv file name associated with either a layer file that has strings associated with it

To run validation on D4M/String
```
cd python/utils
python3 adump.py #.assoc.pkl
```
Where # is the number in front of the assoc.pkl file you are decoding
