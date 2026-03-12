package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

func main() {
	device := "wlp0s20f3" // Detected default interface
	snaplen := 65536

	// afpacket.NewTPacket provides a native Go interface to Linux AF_PACKET sockets.
	// This avoids the dependency on libpcap.
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(device),
		afpacket.OptFrameSize(snaplen),
		afpacket.OptBlockSize(4096*128),
		afpacket.OptNumBlocks(128),
		afpacket.OptPollTimeout(time.Second),
		afpacket.TPacketVersion3,
	)
	if err != nil {
		log.Fatalf("Error opening afpacket handle: %v (Note: this tool requires root/CAP_NET_RAW privileges)", err)
	}
	defer handle.Close()

	fmt.Printf("Monitoring traffic on %s...\n", device)

	// PacketSource provides a channel-based API to consume packets.
	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	// Let's see if the packet is IPv4
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		
		// Determine protocol
		protocol := "Unknown"
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			protocol = fmt.Sprintf("TCP (%d -> %d)", tcp.SrcPort, tcp.DstPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			protocol = fmt.Sprintf("UDP (%d -> %d)", udp.SrcPort, udp.DstPort)
		} else {
			protocol = ip.Protocol.String()
		}

		fmt.Printf("[%s] %s -> %s | Proto: %s | Len: %d\n",
			time.Now().Format("15:04:05.000"),
			ip.SrcIP,
			ip.DstIP,
			protocol,
			packet.Metadata().Length,
		)
	}
}
