# insure-spring-2026-uah2
UAH Team 2 repository for INSuRE Spring 2026 – code, documentation, and analysis artifacts for Next Generation Spatial Temporal Cyber Data Products (v3)
## Description
TODO
## Python
### PCAP
Tools that read through a network capture file and generates matrixes for analysis on each OSI layer. 
### Utils
Python scripts needed by other directories for testing and sanity checking
## Tests
TODO
## Notes
- Layer 6 (Presentation) is excluded from this study because its values coincide with Layer 7 (Application).
- Layer 1 (Physical) is excluded because PCAP files do not contain sufficient information to determine directionality (source vs. destination).