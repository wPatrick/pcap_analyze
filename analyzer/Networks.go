package analyzer

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IpConnection struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol string
}

func ConnectionAnalyzer(packet gopacket.Packet, connections *map[uint64]IpConnection) error {
	networkLayer := packet.NetworkLayer()
	ipConnection, err := ipConnection(networkLayer)
	if err != nil {
		return errors.New("no supported network layer found in package")
	}

	/* linkLayer := packet.LinkLayer()
	// get mac adress from ethernet interface if available possible
	if eth, ok := linkLayer.(*layers.Ethernet); ok {
		conn.SrcMac = eth.SrcMAC
		conn.DstMac = eth.DstMAC
	} else {
		// do nothing
	}*/

	(*connections)[networkLayer.NetworkFlow().FastHash()] = ipConnection
	return nil
}

func ipConnection(layer gopacket.NetworkLayer) (IpConnection, error) {
	connection := IpConnection{}
	switch v := layer.(type) {
	case *layers.IPv4:
		connection.SrcIP = v.SrcIP
		connection.DstIP = v.DstIP
		connection.Protocol = "ipv4"
	case *layers.IPv6:
		connection.SrcIP = v.SrcIP
		connection.DstIP = v.DstIP
		connection.Protocol = "ipv6"
	default:
		return connection, errors.New("no supported ip layer found in package")
	}
	return connection, nil
}

/*func icmp()
func arp()
func rip()
func ospf()
func bgp()
func ipsec()
func igmp()*/
