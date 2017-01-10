package mongodb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/honeycombio/honeypacket/protocols"
)

type Options struct {
	Port uint16 `long:"port" description:"MongoDB port" default:"27017"`
}

// ParserFactory implements protocols.ConsumerFactory
// TODO: this way of setting things up is kind of confusing
type ParserFactory struct {
	Options Options
}

func (pf *ParserFactory) New(flow protocols.IPPortTuple) protocols.Consumer {
	return &Parser{options: pf.Options}
}

func (pf *ParserFactory) IsClient(net, transport gopacket.Flow) bool {
	return transport.Src() == layers.NewTCPPortEndpoint(layers.TCPPort(pf.Options.Port))
}

func (pf *ParserFactory) BPFFilter() string {
	return fmt.Sprintf("tcp port %d", pf.Options.Port)
}

// Parser implements protocols.Consumer
type Parser struct {
	options Options
	flow    protocols.IPPortTuple
}

func (p *Parser) On(isClient bool, ts time.Time, r io.Reader) {
	if isClient {
		log.Println("Parsing MongoDB response")
		p.parseResponseStream(r, ts)
	} else {
		log.Println("Parsing MongoDB request")
		p.parseRequestStream(r, ts)
	}
}

func (p *Parser) parseRequestStream(r io.Reader, ts time.Time) error {
	for {
		msg, err := readMsg(r)
		if err != nil {
			return err
		}
		fmt.Println("Read msg", msg.MessageLength, msg.RequestID, msg.ResponseTo, msg.OpCode)
	}
}

func (p *Parser) parseResponseStream(r io.Reader, ts time.Time) error {
	for {
		msg, err := readMsg(r)
		if err != nil {
			return err
		}
		fmt.Println("Read msg", msg.MessageLength, msg.RequestID, msg.ResponseTo, msg.OpCode)
	}
}

type msgHeader struct {
	MessageLength uint32 // total message size, including this
	RequestID     uint32 // identifier for this message
	ResponseTo    uint32 // requestID from the original request
	OpCode        uint32 // request type - see table below
}

type msg struct {
	*msgHeader
	data []byte
}

func readMsg(r io.Reader) (*msg, error) {
	header := msgHeader{}
	err := binary.Read(r, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}
	// messageLength should include the header bytes
	if header.MessageLength < 16 {
		return nil, errors.New("Invalid message length in header")
	}
	shouldRead := int(header.MessageLength - 16)
	msg := msg{&header, make([]byte, shouldRead)}
	bytesRead := 0
	for {
		n, err := r.Read(msg.data[bytesRead:])
		if err != nil {
			return nil, err
		}
		bytesRead += n
		if bytesRead == shouldRead {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return &msg, nil
}

func readCInt([]byte) {
}
