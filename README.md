# insure-spring-2026-uah2
UAH Team 2 repository for INSuRE Spring 2026 – code, documentation, and analysis artifacts for Next Generation Spatial Temporal Cyber Data Products (v3)
## Dependencies
- python-graphblas installed
- ILANDS pullled and installed
- D4M pulled and installed
- dpkt installed in D4M enviroment for running
## Description
TODO
## Python
### PCAP
Tools that read through a network capture file and generates matrixes for analysis on each OSI layer. 
### Utils
Python scripts needed by other directories for testing and sanity checking
## Tests
Holds network capture files and outputs for testing purposes
## Notes
- Layer 6 (Presentation) is excluded from this study because its values coincide with Layer 7 (Application).
- Layer 1 (Physical) is excluded because PCAP files do not contain sufficient information to determine directionality (source vs. destination).

## Validation Examples
To run validation on Binary/GraphBLAS
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
```
## Run Examples
TODO
### Layer 7
Enviroment load
```
source ~/D4M.py/venv/bin/activate`
```
General Run Example
```
mkdir -p ../../tests/test_outs/layer7_bin

python3 layer7_pcap2_grb_d4m.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer7_bin \
  -m ../../tests/test_outs/layer7_bin/layer7_labels.tsv \
  -b



mkdir -p ../../tests/test_outs/layer7_str

python3 layer7_pcap2_grb_d4m.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer7_str
```
One file mode example
```
mkdir -p ../../tests/test_outs/layer7_bin_onefile

python3 layer7_pcap2_grb_d4m.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer7_bin_onefile \
  -m ../../tests/test_outs/layer7_bin_onefile/layer7_labels.tsv \
  -b \
  -O


mkdir -p ../../tests/test_outs/layer7_str_onefile

python3 layer7_pcap2_grb_d4m.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer7_str_onefile \
  -O
```
### Layer 5
```
python3 layer5_initial.py \
  -i ../../tests/http.cap \
  -o ../../test_outs/layer5.grb \
  -m ../../tests/test_outs/layer5_labels.tsv
```

### Layer 4
```
python3 layer4_initial.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer4.grb
```

### Layer 3
```
python3 layer3_initial.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer3.grb
```

### Layer 2
```
python3 layer2_pcap2grb.py \  
  -i ../../tests/http.cap \  
  -o ../../test/test_outs/layer2.grb
```
