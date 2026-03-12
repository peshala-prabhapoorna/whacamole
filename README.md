# whacamole

Network traffic monitoring tool.

## Features
- Real-time network traffic tracking.
- Source/Destination IP and protocol identification.
- Protocol-specific port monitoring (TCP/UDP).

## Prerequisites
- Linux OS (uses `afpacket` for native capture).
- Go 1.25.1+
- Root privileges or `CAP_NET_RAW` capability.

## Usage

### Run as Root
```bash
sudo go run main.go
```

### Run with Capabilities (Recommended)
Compile the binary and grant it the necessary capabilities:
```bash
go build -o whacamole main.go
sudo setcap cap_net_raw,cap_net_admin=eip whacamole
./whacamole
```

## Implementation Details
Whacamole uses the `gopacket` library with the Linux-native `afpacket` interface. This allows it to capture packets directly from the kernel without requiring external libraries like `libpcap`.
