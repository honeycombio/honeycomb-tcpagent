package mysql

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/honeycombio/honeypacket/protocols"
)

type QueryEvent struct {
	Timestamp      time.Time
	TimedOut       bool
	ResponseTimeMs int64
	Query          string
	RowsSent       int
	BytesSent      int
	ColumnsSent    int
	Error          bool
	ErrorCode      int
}

type mySQLPacket struct {
	PayloadLength int
	SequenceID    byte
	payload       []byte
}

func (mp *mySQLPacket) FirstPayloadByte() byte { return mp.payload[0] }

type Parser struct {
	currentQueryEvent QueryEvent
}

type parseState int

const (
	parseStateChompFirstPacket parseState = iota
	parseStateChompColumnDefs
	parseStateChompRows
)

func NewConsumer() *Parser { return &Parser{} }

func (p *Parser) Handle(packetInfo protocols.PacketInfo) {
	if packetInfo.DstPort == 3306 { // TODO: use a real criterion here
		p.parseRequestStream(packetInfo.Data, packetInfo.Timestamp)
	} else {
		p.parseResponseStream(packetInfo.Data, packetInfo.Timestamp)
	}
}

// TODO: we need to parse across TCP packets, and handle concurrent streams
// maybe with the TCP reassembler.
func (p *Parser) parseRequestStream(data []byte, timestamp time.Time) error {
	logrus.Debug("Parsing request stream")
	reader := bytes.NewReader(data)
	for {
		packet, err := readPacket(reader)
		if err != nil {
			return err
		}
		if packet.FirstPayloadByte() == COM_QUERY {
			p.currentQueryEvent.Query = string(packet.payload[1:])
			p.currentQueryEvent.Timestamp = timestamp
			logrus.WithFields(logrus.Fields{"query": p.currentQueryEvent.Query}).Debug("Parsed query")
		} else {
			logrus.WithFields(logrus.Fields{"command": packet.payload[0]}).Debug("Skipping non-QUERY command")
			// TODO: handle some non-query packets
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
		if err != nil {
			return nil, err
		}
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

func (p *Parser) parseResponseStream(data []byte, timestamp time.Time) error {
	reader := bytes.NewReader(data)
	state := parseStateChompFirstPacket
	logrus.WithFields(logrus.Fields{"data": data}).Debug("Parsing response packet")
	for {
		packet, err := readPacket(reader)
		if err != nil {
			if err != io.EOF {
				logrus.WithFields(logrus.Fields{"err": err, "state": state}).Error("Error parsing packet")
			}
			return err
		}
		logrus.WithFields(logrus.Fields{
			"firstPayloadByte": packet.FirstPayloadByte(),
			"sequenceID":       packet.SequenceID,
			"payloadLength":    packet.PayloadLength,
			"parserState":      state}).Debug("Parsed response packet")
		switch state {
		case parseStateChompFirstPacket:
			if packet.FirstPayloadByte() == OK {
			} else if packet.FirstPayloadByte() == EOF && packet.PayloadLength < 9 {
				// TODO: parse EOF packet contents
			} else if packet.FirstPayloadByte() == ERR {
				p.currentQueryEvent.Error = true
				p.QueryEventDone()
				state = parseStateChompFirstPacket
				// TODO: parse error packet contents
			} else {
				columnCount, err := readLengthEncodedInteger(packet.FirstPayloadByte(), packet.payload[1:])
				if err != nil {
					logrus.WithError(err).Error("Error parsing column count")
					return err
				}
				p.currentQueryEvent.ColumnsSent = int(columnCount)
				state = parseStateChompColumnDefs
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
				// TODO: parse EOF packet contents
			} else {
				// Switch to parsing row packets
				state = parseStateChompRows
				p.currentQueryEvent.RowsSent++
			}
		case parseStateChompRows:
			if packet.FirstPayloadByte() == OK || packet.FirstPayloadByte() == EOF {
				// TODO: parse OK packet contents
				p.currentQueryEvent.ResponseTimeMs = timestamp.Sub(p.currentQueryEvent.Timestamp).Nanoseconds() / 1e6
				p.QueryEventDone()
				state = parseStateChompFirstPacket
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
		err = binary.Read(r, binary.LittleEndian, v)
		return uint64(v), err
	} else if firstByte == 0xFD {
		// Hack to properly parse a three-byte integer
		var v struct {
			a uint8
			b uint16
		}
		err = binary.Read(r, binary.LittleEndian, v)
		return uint64(v.a) + uint64(v.b)<<8, err
	} else if firstByte == 0xFE {
		var v uint64
		err = binary.Read(r, binary.LittleEndian, v)
		return v, err
	}
	return 0, errors.New("Invalid length-encoded integer")
}

func (p *Parser) QueryEventDone() {
	s, err := json.Marshal(&p.currentQueryEvent)
	if err != nil {
		logrus.Error("Error marshaling query event", err)
	}
	io.WriteString(os.Stdout, string(s))
	io.WriteString(os.Stdout, "\n")
	p.currentQueryEvent = QueryEvent{}
}
