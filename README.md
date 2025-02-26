Traceroute Program in Python

Overview

This project is a Python-based implementation of the traceroute network diagnostic tool. It utilizes ICMP (Internet Control Message Protocol) packets to trace the path that packets take to a destination. The program also calculates round-trip times (RTT), detects packet loss, and displays network hops along the route to the target.

Features

Implements ICMP echo requests to trace network routes.

Supports time-to-live (TTL) handling for hop-by-hop analysis.

Displays RTT (Round Trip Time) for each hop.

Detects packet loss and reports unreachable hosts.

Resolves IP addresses to hostnames where possible.

Identifies ICMP response types, including TTL exceeded, unreachable destinations, and echo replies.

Installation

Prerequisites

Ensure you have Python 3.x installed on your system.

Required Dependencies

This program uses Python's built-in socket, struct, time, and select modules. No external libraries are required.

Usage

To use the traceroute program, run the script from the terminal:

python traceroute.py

By default, the script contains example target hosts. To modify the target, change the following line in main():

icmpHelperPing.traceRoute("www.google.com")

Alternatively, you can trace routes to an IP address:

icmpHelperPing.traceRoute("8.8.8.8")

How It Works

Packet Construction: The program builds an ICMP Echo Request packet with a unique identifier and sequence number.

Sending Requests: The script sends ICMP packets with increasing TTL values (starting at 1).

Interpreting Responses:

If a router along the way returns a TTL exceeded message, the hop is recorded.

If the target host responds with an ICMP Echo Reply, the route is complete.

If a destination unreachable message is received, the path is blocked.

Displaying Results: The program prints each hop’s IP, hostname (if available), RTT, and response type.

Example Output

Tracing route to www.google.com:
Hop: 1    TTL=1    RTT=12 ms    Type=11    Code=0    192.168.1.1
Hop: 2    TTL=2    RTT=24 ms    Type=11    Code=0    203.0.113.1
Hop: 3    TTL=3    RTT=36 ms    Type=0    Code=0    8.8.8.8 [google.com]
Trace complete.

Error Handling

If the request times out, the program prints:

*        *        *        *        *    Request timed out.

If the destination is unreachable, the response indicates the reason (e.g., host unreachable or network unreachable).

References

This implementation was inspired by various sources:

GeeksforGeeks Traceroute Implementation

ICMP Parameters - IANA

YouTube Tutorial on ICMP and Traceroute

Packet Loss Calculation Guide

License

This project is open-source and free to use for educational and research purposes.

Author

Developed by Brett Sullivan on February 7, 2024.
