package main

import (
	"flag"
	"fmt"
	"log"
	"pcapanalyze/analyzer"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Parse command line flags
	var inputFile string

	flag.StringVar(&inputFile, "i", "", "Input PCAP file")
	flag.Parse()

	if len(inputFile) == 0 {
		fmt.Println("Usage: go run main.go -i <input_file>")
		return
	}

	// Open the input file
	handle, err := pcap.OpenOffline(inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create a new packet source
	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	var connections = make(map[uint64]analyzer.IpConnection)
	var dataLinks = make(map[uint64]analyzer.Ethernet)
	var transports_tcp = make(map[uint64]analyzer.Transport)
	var transports_udp = make(map[uint64]analyzer.Transport)

	var i int = 0

	// Start analyzing packetsm we dont need every packet, but every flow
	for packet := range packets.Packets() {
		i++
		analyzer.DataLinkAnalyzer(packet, &dataLinks)
		analyzer.TransportsAnalyzer(packet, &transports_tcp, &transports_udp)
		err := analyzer.ConnectionAnalyzer(packet, &connections)
		if err != nil {
			log.Println("Error analyzing packet No ", i, ": ", err)
		} else {
			// Access result as *Connection struct
			// fmt.Println(i, " : ", connection)
		}
	}
	for _, connection := range connections {
		fmt.Printf("%s -> %s\n", connection.SrcIP, connection.DstIP)
	}

	for _, transport := range transports_tcp {
		fmt.Printf("%s -> %s\n", transport.SrcPort, transport.DstPort)
	}

	for _, transport := range transports_udp {
		fmt.Printf("%d -> %d\n", transport.SrcPort, transport.DstPort)
	}

	for _, dataLink := range dataLinks {
		fmt.Printf("%s -> %s\n", dataLink.SrcMAC, dataLink.DstMAC)
	}
}
