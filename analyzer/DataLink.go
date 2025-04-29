package analyzer

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Ethernet struct {
	SrcMAC       net.HardwareAddr    // Source MAC address
	DstMAC       net.HardwareAddr    // Destination MAC address
	EthernetType layers.EthernetType // Ethernet frame type
}

func DataLinkAnalyzer(packet gopacket.Packet, dataLinks *map[uint64]Ethernet) {
	linkLayer := packet.LinkLayer()
	ethernet, err := ethernet(linkLayer)
	if err != nil {

	} else {
		(*dataLinks)[linkLayer.LinkFlow().FastHash()] = ethernet
	}

	// ... wifi() ppp() ...
}

func ethernet(layer gopacket.LinkLayer) (Ethernet, error) {
	ethernet := Ethernet{}

	// get mac adress from ethernet interface if available possible
	if eth, ok := layer.(*layers.Ethernet); ok {
		ethernet.SrcMAC = eth.SrcMAC
		ethernet.DstMAC = eth.DstMAC
		ethernet.EthernetType = eth.EthernetType
		eth.LinkFlow()
		return ethernet, nil
	} else {
		return ethernet, errors.New("no ethernetlayer found")
	}
}

/*func wifi()
func ppp()
func hdlc()
func frameRelay()
func atm()
func tokenRing()
func fddi()
func slip()
func pppoe()*/
