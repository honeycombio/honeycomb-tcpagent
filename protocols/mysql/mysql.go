package mysql

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/honeycombio/honeycomb-tcpagent/sniffer"
)

type Options struct {
	Port uint16 `long:"port" description:"MySQL port" default:"3306"`
}

// ParserFactory implements sniffer.ConsumerFactory
// TODO: this way of setting things up is kind of confusing
type ParserFactory struct {
	Options Options
}

func (pf *ParserFactory) New(flow sniffer.IPPortTuple) sniffer.Consumer {
	if flow.DstPort != pf.Options.Port {
		flow = flow.Reverse()
	}
	return &Parser{
		options: pf.Options,
		flow:    flow,
	}
}

func (pf *ParserFactory) BPFFilter() string {
	return fmt.Sprintf("tcp port %d", pf.Options.Port)
}

// Parser implements sniffer.Consumer
type Parser struct {
	options           Options
	flow              sniffer.IPPortTuple
	currentQueryEvent QueryEvent
	state             parseState
}

func (p *Parser) On(ms sniffer.MessageStream) {
	for {
		m, ok := ms.Next()
		if !ok {
			logrus.WithFields(logrus.Fields{"flow": p.flow}).Debug("Messages closed")
			return
		}
		toServer := m.Flow().DstPort == p.options.Port
		if toServer {
			p.parseRequestStream(m, m.Timestamp())
		} else {
			p.parseResponseStream(m, m.Timestamp())
		}
	}
}

type QueryEvent struct {
	Timestamp   time.Time
	ClientIP    string
	ServerIP    string
	QueryTime   float64
	Query       string
	RowsSent    int
	BytesSent   int
	ColumnsSent int
	Error       bool
	ErrorCode   int
}

type mySQLPacket struct {
	PayloadLength int
	SequenceID    byte
	payload       []byte
}

func (mp *mySQLPacket) FirstPayloadByte() byte { return mp.payload[0] }

type parseState int

const (
	parseStateChompFirstPacket parseState = iota
	parseStateChompColumnDefs
	parseStateChompRows
)

var stateMap = map[parseState]string{
	0: "parseStateChompFirstPacket",
	1: "parseStateChompColumnDefs",
	2: "parseStateChompRows",
}

func (p *Parser) parseRequestStream(r io.Reader, timestamp time.Time) error {
	logrus.Debug("Parsing request stream")
	for {
		packet, err := readPacket(r)
		if err != nil {
			return err
		}
		if packet.FirstPayloadByte() == COM_QUERY {
			p.currentQueryEvent.Query = string(packet.payload[1:])
			p.currentQueryEvent.Timestamp = timestamp
			logrus.WithFields(logrus.Fields{"query": p.currentQueryEvent.Query}).Debug("Parsed query")
		} else {
			logrus.WithFields(logrus.Fields{"command": packet.payload[0]}).Debug("Skipping non-QUERY command")
			// TODO: usefully handle some non-query packets
		}
	}
}

func readPacket(r io.Reader) (*mySQLPacket, error) {
	buf := make([]byte, 4)
	_, err := r.Read(buf)
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		logrus.WithFields(logrus.Fields{"header": buf, "err": err}).Debug("Bad MySQL packet header")
		return nil, err
	}
	p := mySQLPacket{}
	p.PayloadLength = int(buf[0]) + int(buf[1])<<8 + int(buf[2])<<16
	p.SequenceID = buf[3]
	p.payload = make([]byte, p.PayloadLength)

	if p.PayloadLength == 0 {
		return nil, errors.New("Bad MySQL packet header")
	}

	bytesRead := 0
	for {
		n, err := r.Read(p.payload[bytesRead:])
		bytesRead += n
		if bytesRead == p.PayloadLength {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return &p, nil
}

func (p *Parser) parseResponseStream(r io.Reader, timestamp time.Time) error {
	logrus.Debug("Parsing response stream")
	for {
		packet, err := readPacket(r)
		if err != nil {
			if err != io.EOF {
				logrus.WithFields(logrus.Fields{
					"err":   err,
					"state": p.state}).Error("Error parsing packet")
			}
			return err
		}
		logrus.WithFields(logrus.Fields{
			"flow":             p.flow,
			"firstPayloadByte": packet.FirstPayloadByte(),
			"sequenceID":       packet.SequenceID,
			"payloadLength":    packet.PayloadLength,
			"parserState":      stateMap[p.state]}).Debug("Parsed response packet")
		switch p.state {
		case parseStateChompFirstPacket:
			if packet.FirstPayloadByte() == OK {
				// TODO: parse OK packet contents
				p.QueryEventDone()
			} else if packet.FirstPayloadByte() == EOF && packet.PayloadLength < 9 {
				// TODO: parse EOF packet contents
			} else if packet.FirstPayloadByte() == ERR {
				p.currentQueryEvent.Error = true
				p.QueryEventDone()
				p.state = parseStateChompFirstPacket
				// TODO: parse error packet contents
			} else {
				columnCount, err := readLengthEncodedInteger(packet.FirstPayloadByte(), packet.payload[1:])
				if err != nil {
					logrus.WithError(err).Error("Error parsing column count")
					return err
				}
				p.currentQueryEvent.ColumnsSent = int(columnCount)
				p.state = parseStateChompColumnDefs
			}
		case parseStateChompColumnDefs:
			if packet.FirstPayloadByte() == COL_DEF_FIRST_PAYLOAD_BYTE {
				// This is subtle. A column definition packet always starts with the length-encoded string "def",
				// i.e., the byte sequence 03 64 65 66.
				//                         |   |  |  |
				//                     length  d  e  f

				// TODO: we can't reliably distinguish this from the case that (1) there's no EOF packet
				// between the column defs and the rows, and (2) the first row result starts with 0x03.
				// So when CLIENT_DEPRECATE_EOF is set, we actually need to count column definition packets
				// that we've seen in order to reliably know when to transition to reading row packets.
			} else if packet.FirstPayloadByte() == OK {
				// TODO: parse OK packet contents
			} else if packet.FirstPayloadByte() == EOF && packet.PayloadLength < 9 {
				p.state = parseStateChompRows
				// TODO: parse EOF packet contents
			} else {
				// Switch to parsing row packets
				p.state = parseStateChompRows
				p.currentQueryEvent.RowsSent++
			}
		case parseStateChompRows:
			if packet.FirstPayloadByte() == OK || packet.FirstPayloadByte() == EOF {
				// TODO: parse OK packet contents
				p.currentQueryEvent.QueryTime = timestamp.Sub(p.currentQueryEvent.Timestamp).Seconds()
				p.QueryEventDone()
				p.state = parseStateChompFirstPacket
			} else {
				p.currentQueryEvent.RowsSent++
				// TODO: parse row packet contents
			}
		}
		if err != nil {
			logrus.WithError(err).Error("Error parsing response stream")
		}
	}
}

// https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
func readLengthEncodedInteger(firstByte byte, nextBytes []byte) (n uint64, err error) {
	r := bytes.NewReader(nextBytes)
	if firstByte <= 0xFB {
		return uint64(firstByte), nil
	} else if firstByte == 0xFC {
		var v uint16
		err = binary.Read(r, binary.LittleEndian, &v)
		return uint64(v), err
	} else if firstByte == 0xFD {
		// Hack to properly parse a three-byte integer
		var v struct {
			a uint8
			b uint16
		}
		err = binary.Read(r, binary.LittleEndian, &v)
		return uint64(v.a) + uint64(v.b)<<8, err
	} else if firstByte == 0xFE {
		var v uint64
		err = binary.Read(r, binary.LittleEndian, &v)
		return v, err
	}
	return 0, errors.New("Invalid length-encoded integer")
}

func (p *Parser) QueryEventDone() {
	p.currentQueryEvent.ClientIP = p.flow.SrcIP.String()
	p.currentQueryEvent.ServerIP = p.flow.DstIP.String()
	s, err := json.Marshal(&p.currentQueryEvent)
	if err != nil {
		logrus.Error("Error marshaling query event", err)
	}
	io.WriteString(os.Stdout, string(s))
	io.WriteString(os.Stdout, "\n")
	p.currentQueryEvent = QueryEvent{}
	p.state = parseStateChompFirstPacket
}
