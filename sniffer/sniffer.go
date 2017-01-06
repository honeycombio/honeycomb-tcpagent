package sniffer

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/honeycombio/honeypacket/protocols"
)

type Sniffer struct {
	packetSource packetDataSource
	handler      protocols.Consumer
	iface        string
}

type packetDataSource interface {
	gopacket.PacketDataSource
	SetBPFFilter(filter string) error
}

type afpacketSource struct {
	*afpacket.TPacket
}

type pcapSource struct {
	*pcap.Handle
}

func (a *afpacketSource) SetBPFFilter(filter string) error { return errors.New("not implemented") }

func New(iface string, bufferSizeMb int, snaplen int, pollTimeout time.Duration, handler protocols.Consumer) (*Sniffer, error) {
	s := &Sniffer{iface: iface, handler: handler}
	if true {
		var err error
		if s.iface == "" {
			s.iface = "any"
		}
		s.packetSource, err = newPcapHandle(s.iface, snaplen, pcap.BlockForever) // TODO: make timeout configurable again? Or just don't bother
		if err != nil {
			return nil, err
		}
	} else {
		// not currently supported -- make this configurable once we add an implementation of SetBPFFilter for AF_PACKET sockets
		frameSize, blockSize, numBlocks, err := afpacketComputeSize(bufferSizeMb, snaplen, os.Getpagesize())
		if err != nil {
			return nil, err
		}
		s.packetSource, err = newAfpacketHandle(s.iface, frameSize, blockSize, numBlocks, pollTimeout)
		if err != nil {
			return nil, err
		}
	}

	return s, nil

}

func (sniffer *Sniffer) Run() error {
	var linkLayerType gopacket.LayerType
	if sniffer.iface == "any" {
		linkLayerType = layers.LayerTypeLinuxSLL
	} else {
		linkLayerType = layers.LayerTypeEthernet

	}

	factory := &bidiFactory{map[key]*BidiStream{}}
	streamPool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(streamPool)

	var sll layers.LinuxSLL
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var payload gopacket.Payload
	decoder := gopacket.NewDecodingLayerParser(linkLayerType, &sll, &eth, &ip4, &ip6, &tcp, &payload)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	for {
		packetData, ci, err := sniffer.packetSource.ReadPacketData()

		if err == io.EOF {
			logrus.Info("EOF") // debug -- better handle this
			break
		} else if err != nil {
			logrus.WithError(err).Info("Error reading packet")
			continue
		}

		if len(packetData) == 0 {
			continue
		}

		err = decoder.DecodeLayers(packetData, &decodedLayers)

		if err != nil {
			logrus.WithError(err).Error("Error decoding packet")
			continue
		}

		packetInfo := protocols.PacketInfo{}

		packetInfo.Truncated = decoder.Truncated
		packetInfo.Timestamp = ci.Timestamp
		var netFlow gopacket.Flow

		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeIPv4:
				packetInfo.SrcIP, packetInfo.DstIP = ip4.SrcIP, ip4.DstIP
				netFlow = ip4.NetworkFlow()
			case layers.LayerTypeIPv6:
				packetInfo.SrcIP, packetInfo.DstIP = ip6.SrcIP, ip6.DstIP
				netFlow = ip6.NetworkFlow()
			case layers.LayerTypeTCP:
				packetInfo.SrcPort, packetInfo.DstPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
			case gopacket.LayerTypePayload:
				packetInfo.Data = payload
			}
		}

		logrus.WithFields(packetInfo.ToFields()).Debug("Parsed packet data")
		assembler.AssembleWithTimestamp(netFlow, &tcp, ci.Timestamp)
		sniffer.handler.Handle(packetInfo)
	}
	return nil
}

func (sniffer *Sniffer) SetBPFFilter(filter string) error {
	return sniffer.packetSource.SetBPFFilter(filter)
}

func newPcapHandle(iface string, snaplen int, pollTimeout time.Duration) (*pcapSource, error) {
	h, err := pcap.OpenLive(iface, int32(snaplen), true, pollTimeout)
	return &pcapSource{h}, err
}

func newAfpacketHandle(iface string, frameSize int, blockSize int, numBlocks int,
	pollTimeout time.Duration) (*afpacketSource, error) {
	h, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(pollTimeout),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion2)) // work around https://github.com/google/gopacket/issues/80
	return &afpacketSource{h}, err
}

func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {
	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}
	blockSize = frameSize * afpacket.DefaultNumBlocks
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize
	if numBlocks == 0 {
		return 0, 0, 0, errors.New("Buffer size too small")
	}

	return frameSize, blockSize, numBlocks, nil
}
