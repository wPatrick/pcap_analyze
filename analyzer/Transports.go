package analyzer

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Transport struct {
	SrcIP         net.IP
	DstIP         net.IP
	SrcPort       uint16
	DstPort       uint16
	Protocol      string
	BytesReceived int64
	BytesSent     int64
}

func TransportsAnalyzer(packet gopacket.Packet, tcp_connections *map[uint64]Transport, udp_connections *map[uint64]Transport) error {
	tcp := Transport{}
	udp := Transport{}

	// ethernetLayer := packet.Layers()
	transportLayer := packet.TransportLayer()
	switch v := transportLayer.(type) {
	case *layers.TCP:
		tcp.SrcPort = uint16(v.SrcPort)
		tcp.DstPort = uint16(v.DstPort)
		tcp.Protocol = "tcp"
		(*tcp_connections)[transportLayer.TransportFlow().FastHash()] = tcp

	case *layers.UDP:
		udp.SrcPort = uint16(v.SrcPort)
		udp.DstPort = uint16(v.DstPort)
		udp.Protocol = "udp"
		(*udp_connections)[transportLayer.TransportFlow().FastHash()] = udp
	default:
		return errors.New("no supported transport layer found")
	}

	return nil

}
