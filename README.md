
# querytrail

**A lightweight DNS query observability tool that passively captures, parses, and displays DNS queries and responses in real time.**

`querytrail` is a systems-level networking project focused on understanding DNS traffic through passive packet capture and protocol parsing.

It captures network packets using [libpcap](https://www.tcpdump.org/), identifies DNS messages, parses their structure, and presents useful information about queries and responses without generating or modifying network traffic.

## Overview

DNS is fundamental to how applications communicate, but understanding what is happening at the protocol level often requires digging through packet captures.

`querytrail` aims to make that process more approachable by providing a lightweight foundation for observing and inspecting DNS traffic directly.

The project focuses on:

- Passive packet capture.
- Ethernet and IPv4 packet inspection.
- UDP and DNS protocol parsing.
- DNS message and resource record interpretation.
- Real-time presentation of DNS queries and responses.

## Current Capabilities

The current implementation includes:

- **Packet capture:** Uses libpcap to capture packets from a network interface.
- **Packet inspection:** Parses Ethernet and IPv4 headers, including variable-length IPv4 headers.
- **DNS detection:** Identifies DNS traffic carried over UDP.
- **DNS message parsing:** Handles DNS headers, questions, and resource records.
- **Name compression:** Supports DNS compressed names and pointer-based references.
- **Record support:** Parses common record types, including A, AAAA, CNAME, and MX.
- **Input validation:** Performs bounds checking while parsing packet and DNS data.
- **Test coverage:** Includes tests for DNS headers, questions, records, compressed names, messages, and MX records.

## Architecture

The project is written in C and organized around a small set of focused components:

| Component | Responsibility |
|---|---|
| Capture | Packet capture through libpcap |
| Packet | Ethernet, IPv4, and UDP packet inspection |
| DNS | DNS message and resource record parsing |
| Presentation | Human-readable query and response output |

The separation between packet capture, protocol parsing, and presentation keeps the implementation modular and makes it easier to extend and test individual components.

## Building

### Requirements

- C compiler with C11 support
- Make
- libpcap development headers and library

### Build

```bash
make
```

For platform-specific libpcap installation instructions, refer to the [libpcap documentation](https://www.tcpdump.org/).

## Running

`querytrail` requires sufficient privileges to capture packets from a network interface.

Run it with the appropriate elevated privileges for your platform:

```bash
sudo ./querytrail
```

The default capture interface is currently configured in the source code.

## Development Status

`querytrail` is an actively developed networking and protocol-analysis project.

The current implementation establishes the core packet-capture and DNS-parsing foundation. Future development may explore:

- Broader DNS record type support.
- IPv6 packet support.
- Additional link-layer encapsulations.
- Improved DNS transaction correlation.
- More detailed query and response analysis.
- Expanded test coverage and platform support.

The project prioritizes correctness, explicit packet-boundary validation, modularity, and a clear understanding of the underlying protocols.

## Project Goals

The long-term goal is to build a small, reliable, and extensible DNS observability tool while keeping the implementation focused on protocol correctness and systems-level fundamentals.

## License

See [LICENSE](LICENSE).
