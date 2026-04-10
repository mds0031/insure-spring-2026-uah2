# insure-spring-2026-uah2
UAH Team 2 repository for INSuRE Spring 2026 – code, documentation, and analysis artifacts for Next Generation Spatial Temporal Cyber Data Products (v3)
## Dependencies
- python-graphblas installed
- ILANDS pullled and installed
- D4M pulled and installed
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

## Run Examples
TODO
### Layer 7
`source ~/D4M.py/venv/bin/activate`
```
python3 layer7_initial.py \
  -i ../../tests/http.cap \
  -o ../../tests/test_outs/layer7.grb \
  -m ../../tests/test_outs/layer7_labels.tsv
```
### Layer 5
```
python3 layer5_initial.py \
  -i ../../tests/http.cap \
  -o ../../test_outs/layer5.grb \
  -m ../../tests/test_outs/layer5_labels.tsv
```

### Layer 4
TODO

### Layer 3
TODO

### Layer 2
```
python3 layer2_pcap2grb.py \  
  -i ../../tests/http.cap \  
  -o ../../test/test_outs/layer2.grb
```