package mysql

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/emfree/honeypacket/protocols"
)

type QueryEvent struct {
	Timestamp      time.Time
	TimedOut       bool
	ResponseTimeMs int
	RawQuery       []byte
	Query          string
	RowsSent       int
	BytesSent      int
	ColumnsSent    int
	Error          bool
	ErrorCode      int
}

type mySQLPacketHeader struct {
	PayloadLength    uint32
	SequenceID       uint8
	FirstPayloadByte uint8
}

type Parser struct {
	currentQueryEvent QueryEvent
}

type parseState int

const (
	parseStateStart parseState = iota
	parseStateChompColumnDefs
	parseStateChompRows
)

func NewConsumer() *Parser { return &Parser{} }

func (p *Parser) Handle(packetInfo protocols.PacketInfo) {
	if packetInfo.DstPort == 3306 { // TODO: use a real criterion here
		p.parseRequestStream(packetInfo.Data, packetInfo.Timestamp)
	} else {
		p.parseResponseStream(packetInfo.Data)
	}
}

// TODO: we need to parse across TCP packets, and handle concurrent streams
// maybe with the TCP reassembler.
func (p *Parser) parseRequestStream(data []byte, timestamp time.Time) error {
	logrus.Debug("Parsing request stream")
	reader := bytes.NewReader(data)
	for {
		header, err := parsePacketHeader(reader)
		if err != nil {
			return err
		}
		logrus.WithFields(logrus.Fields{"payloadLength": header.PayloadLength, "firstPayloadByte": header.FirstPayloadByte}).Debug("header data")
		if mySQLCommand(header.FirstPayloadByte) == COM_QUERY {
			var err error
			queryLength := int(header.PayloadLength - 1)
			query, err := readQuery(reader, queryLength)
			if err != nil {
				logrus.Error("Error reading query", err)
				return err
			}
			p.currentQueryEvent.RawQuery = query
			p.currentQueryEvent.Query = string(query) // TODO: can this fail in any way with whacky character sets?
			p.currentQueryEvent.Timestamp = timestamp
			logrus.WithFields(logrus.Fields{"query": string(query)}).Info("Parsed query")
		} else {
			logrus.Info(header.FirstPayloadByte, data)
			// TODO: handle this (non-query packet)
		}
	}
}

func parsePacketHeader(r io.Reader) (header mySQLPacketHeader, err error) {
	header = mySQLPacketHeader{}
	buf := make([]byte, 5)
	n, err := r.Read(buf)
	if err == io.EOF {
		return header, err
	} else if n < 5 || err != nil {
		logrus.WithFields(logrus.Fields{"header": header, "err": err}).Info("Bad MySQL packet header")
		return header, err
	}
	header.PayloadLength = uint32(buf[0]) + uint32(buf[1])<<8 + uint32(buf[2])<<16
	header.SequenceID = buf[3]
	header.FirstPayloadByte = buf[4]
	return header, nil
}

func readQuery(r io.Reader, queryLength int) (query []byte, err error) {
	query = make([]byte, queryLength)
	bytesRead := 0
	for bytesRead < queryLength {
		n, err := r.Read(query[bytesRead:])
		if err != nil {
			return nil, err
		}
		bytesRead += n
	}
	return query, nil
}

func (p *Parser) parseResponseStream(data []byte) error {
	reader := bytes.NewReader(data)
	state := parseStateStart
	logrus.WithFields(logrus.Fields{"data": data}).Debug("Parsing response packet")
	for {
		header, err := parsePacketHeader(reader)
		if err != nil {
			logrus.WithError(err).Error("Error parsing packet header")
			return err
		}
		logrus.WithFields(logrus.Fields{
			"firstPayloadByte": header.FirstPayloadByte,
			"sequenceID":       header.SequenceID,
			"payloadLength":    header.PayloadLength,
			"parserState":      state}).Debug("Parsed response packet header")
		switch state {
		case parseStateStart:
			if header.FirstPayloadByte == OK {
				err = p.parseOK(reader, header.PayloadLength)
			} else if header.FirstPayloadByte == EOF && header.PayloadLength < 9 {
				err = p.parseEOF(reader, header.PayloadLength)
			} else if header.FirstPayloadByte == ERR {
				err = p.parseERR(reader, header.PayloadLength)
			} else {
				columnCount, err := p.parseColumnCount(header.FirstPayloadByte, reader, header.PayloadLength)
				if err != nil {
					logrus.WithError(err).Error("Error parsing column count")
					return err
				}
				p.currentQueryEvent.ColumnsSent = int(columnCount)
				state = parseStateChompColumnDefs
			}
		case parseStateChompColumnDefs:
			if header.FirstPayloadByte == COL_DEF_FIRST_PAYLOAD_BYTE {
				// This is subtle. A column definition packet always starts with the length-encoded string "def",
				// i.e., the byte sequence 03 64 65 66.
				//                         |   |  |  |
				//                     length  d  e  f

				// TODO: can we actually reliably distinguish this from the case that (1) there's no EOF packet
				// between the column defs and the rows, and (2) the first row result start with 0x03?
				err = p.parseColumnDefinition(reader, header.PayloadLength)
			} else if header.FirstPayloadByte == OK {
				err = p.parseOK(reader, header.PayloadLength)
			} else if header.FirstPayloadByte == EOF {
				err = p.parseEOF(reader, header.PayloadLength)
			} else {
				state = parseStateChompRows
				p.parseRow(reader, header.PayloadLength)
			}
		case parseStateChompRows:
			if header.FirstPayloadByte == OK {
				err = p.parseOK(reader, header.PayloadLength)
				p.QueryEventDone()
				state = parseStateStart
			} else if header.FirstPayloadByte == EOF {
				err = p.parseEOF(reader, header.PayloadLength)
				p.QueryEventDone()
				state = parseStateStart
			} else {
				p.parseRow(reader, header.PayloadLength)
			}
		}
		if err != nil {
			logrus.WithError(err).Error("Error parsing response stream")
		}
	}
}

// TODO: properly consume responses
func discard(r io.Reader, payloadLength uint32) error {
	buf := make([]byte, payloadLength-1)
	_, err := r.Read(buf)
	return err
}

func (p *Parser) parseOK(r io.Reader, payloadLength uint32) error {
	logrus.Info("parsing OK")
	return discard(r, payloadLength)
}

func (p *Parser) parseEOF(r io.Reader, payloadLength uint32) error {
	logrus.Info("parsing EOF")
	return discard(r, payloadLength)
}

func (p *Parser) parseERR(r io.Reader, payloadLength uint32) error {
	logrus.Info("parsing ERR")
	return discard(r, payloadLength)
}

func (p *Parser) parseColumnCount(firstByte uint8, r io.Reader, payloadLength uint32) (uint64, error) {
	logrus.Info("parsing column count")
	return readLengthEncodedInteger(firstByte, r)
}

func (p *Parser) parseColumnDefinition(r io.Reader, payloadLength uint32) error {
	logrus.Info("parsing column def")
	return discard(r, payloadLength)
}

func (p *Parser) parseRow(r io.Reader, payloadLength uint32) error {
	logrus.Info("parsing row")
	err := discard(r, payloadLength)
	if err != nil {
		return err
	}
	p.currentQueryEvent.RowsSent += 1
	return nil
}

// https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
func readLengthEncodedInteger(firstByte uint8, r io.Reader) (n uint64, err error) {
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
	logrus.WithField("event", string(s)).Info("Publishing query event") // TODO: actually publish to stdout stream
	p.currentQueryEvent = QueryEvent{}
}
