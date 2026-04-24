
import ipaddress

# Converts MAC Address String to an Integer for use in the matrix
def mac_to_int(mac: str) -> int:
    return int(mac.replace(":", ""), 16)

# Converts an IP Address String to an Integer for use in the matrix
def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))

# Converts an Integer back to a MAC Address String
def ns_to_s(ns: int) -> float:
    return ns / 1e9