package main

import (
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

var (
	data   = [][]string{{"Time", "Source IP", "Dest IP", "Protocol", "Size"}}
	dataMu sync.Mutex
)

func main() {
	whacamole := app.New()
	homeWindow := whacamole.NewWindow("Whacamole - Network Traffic Monitor")
	homeWindow.Resize(fyne.NewSize(800, 600))

	list := widget.NewTable(
		func() (rows int, cols int) {
			dataMu.Lock()
			defer dataMu.Unlock()
			return len(data), 5
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Packets")
		},
		func(tci widget.TableCellID, co fyne.CanvasObject) {
			dataMu.Lock()
			defer dataMu.Unlock()
			if tci.Row < len(data) && tci.Col < len(data[tci.Row]) {
				co.(*widget.Label).SetText(data[tci.Row][tci.Col])
			}
		})

	list.SetColumnWidth(0, 150)
	list.SetColumnWidth(1, 150)
	list.SetColumnWidth(2, 150)
	list.SetColumnWidth(3, 200)
	list.SetColumnWidth(4, 100)

	go func() {
		device := "wlp0s20f3"
		snaplen := 65536

		handle, err := afpacket.NewTPacket(
			afpacket.OptInterface(device),
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(4096*128),
			afpacket.OptNumBlocks(128),
			afpacket.OptPollTimeout(time.Second),
			afpacket.TPacketVersion3,
		)
		if err != nil {
			log.Printf("Error opening afpacket handle: %v", err)
			return
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)

		for packet := range packetSource.Packets() {
			timestamp, srcIP, dstIP, protocol, packetSize := processPacket(packet)
			if timestamp == "" {
				continue
			}

			dataMu.Lock()
			data = append(data, []string{timestamp, srcIP, dstIP, protocol, strconv.Itoa(packetSize)})
			if len(data) > 1000 {
				data = append(data[:1], data[2:]...) // Keep header, remove oldest
			}
			dataMu.Unlock()
		}
	}()

	// Refresh the table periodically from the UI thread
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		for range ticker.C {
			fyne.Do(func() {
				list.Refresh()
			})
		}
	}()

	homeWindow.SetContent(container.NewStack(list))
	homeWindow.ShowAndRun()
}

func processPacket(packet gopacket.Packet) (string, string, string, string, int) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

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

		return time.Now().Format("15:04:05.000"), ip.SrcIP.String(), ip.DstIP.String(), protocol, packet.Metadata().Length
	}

	return "", "", "", "", 0
}
