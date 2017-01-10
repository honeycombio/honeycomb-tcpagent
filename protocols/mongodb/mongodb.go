package mongodb

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/emfree/gopacket"
	"github.com/emfree/gopacket/layers"
	"github.com/honeycombio/honeypacket/protocols"
)

type Options struct {
	Port uint16 `long:"port" description:"MongoDB port" default:"27017"`
}

type QueryEvent struct {
	Timestamp  time.Time
	ClientIP   string
	ServerIP   string
	QueryTime  float64
	Query      string
	OpType     string
	Collection string
	Selector   string
	Update     string
	RequestID  uint32
}

// ParserFactory implements protocols.ConsumerFactory
// TODO: this way of setting things up is kind of confusing
type ParserFactory struct {
	Options Options
}

func (pf *ParserFactory) New(flow protocols.IPPortTuple) protocols.Consumer {
	if flow.DstPort != pf.Options.Port {
		flow = flow.Reverse()
	}
	return &Parser{
		options: pf.Options,
		flow:    flow,
	}
}

func (pf *ParserFactory) IsClient(net, transport gopacket.Flow) bool {
	return transport.Src() == layers.NewTCPPortEndpoint(layers.TCPPort(pf.Options.Port))
}

func (pf *ParserFactory) BPFFilter() string {
	return fmt.Sprintf("tcp port %d", pf.Options.Port)
}

// Parser implements protocols.Consumer
type Parser struct {
	options           Options
	flow              protocols.IPPortTuple
	currentQueryEvent QueryEvent
}

func (p *Parser) On(isClient bool, ts time.Time, r io.Reader) {
	// debug
	if isClient {
		logrus.WithFields(logrus.Fields{
			"flow": p.flow}).Debug("Parsing MongoDB response")
		err := p.parseResponseStream(r, ts)
		if err != io.EOF {
			logrus.WithError(err).Debug("Error parsing response")
		}
	} else {
		logrus.WithFields(logrus.Fields{
			"flow": p.flow}).Debug("Parsing MongoDB request")
		err := p.parseRequestStream(r, ts)
		if err != io.EOF {
			logrus.WithError(err).Debug("Error parsing request")
		}
	}
}

func (p *Parser) parseRequestStream(r io.Reader, ts time.Time) error {
	for {
		header, data, err := readRawMsg(r)
		if err != nil {
			return err
		}
		logrus.WithFields(logrus.Fields{
			"opCode":        header.OpCode,
			"requestID":     header.RequestID,
			"responseTo":    header.ResponseTo,
			"messageLength": header.MessageLength}).Debug("Parsed request header")

		// TODO: these writes to currentQueryEvent are racy
		// and can cause panics in serialization
		// the parser should not be shared across goroutines!
		p.currentQueryEvent.RequestID = header.RequestID
		p.currentQueryEvent.Timestamp = ts

		switch header.OpCode {
		case OP_UPDATE:
			m, err := readUpdateMsg(data)
			if err != nil {
				logrus.WithError(err).Debug("Error parsing update")
				return err
			}
			p.currentQueryEvent.Update = string(m.Update)
			p.currentQueryEvent.Selector = string(m.Selector)
			p.currentQueryEvent.OpType = "update"
			p.currentQueryEvent.Collection = string(m.FullCollectionName)
			p.QueryEventDone()
		case OP_INSERT:
			m, err := readInsertMsg(data)
			if err != nil {
				logrus.WithError(err).Debug("Error parsing insert")
				return err
			}
			p.currentQueryEvent.OpType = "insert"
			p.currentQueryEvent.Timestamp = ts
			// TODO: rename?
			p.currentQueryEvent.Update = string(m.Documents)
			p.currentQueryEvent.Collection = string(m.FullCollectionName)
			p.QueryEventDone()
		case OP_QUERY:
			m, err := readQueryMsg(data)
			if err != nil {
				logrus.WithError(err).Debug("Error parsing query")
				return err
			}
			p.currentQueryEvent.OpType = "query"
			p.currentQueryEvent.Timestamp = ts
			p.currentQueryEvent.Collection = string(m.FullCollectionName)
			p.currentQueryEvent.Query = string(m.Query)
		// TODO: others
		case OP_DELETE:
			// TODO
		case OP_GET_MORE:
			// TODO
		}
	}
}

func (p *Parser) parseResponseStream(r io.Reader, ts time.Time) error {
	for {
		header, data, err := readRawMsg(r)
		if err != nil {
			return err
		}
		logrus.WithFields(logrus.Fields{
			"opCode":        header.OpCode,
			"requestID":     header.RequestID,
			"responseTo":    header.ResponseTo,
			"messageLength": header.MessageLength}).Debug("Parsed response header")
		switch header.OpCode {
		case OP_REPLY:
			_, err := readReplyMsg(data)
			if err != nil {
				return err
			}

			// TODO: get query statistics, properly correlate with RequestID
			if !ts.After(p.currentQueryEvent.Timestamp) {
				logrus.WithFields(logrus.Fields{"end": ts,
					"start": p.currentQueryEvent.Timestamp}).Debug("End timestamp before start")
				p.currentQueryEvent.QueryTime = 0
			} else {
				p.currentQueryEvent.QueryTime = ts.Sub(p.currentQueryEvent.Timestamp).Seconds()
			}
			p.QueryEventDone()
		}

	}
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
}

type msgHeader struct {
	MessageLength uint32 // total message size, including this
	RequestID     uint32 // identifier for this message
	ResponseTo    uint32 // requestID from the original request
	OpCode        uint32 // request type - see table below
}

func readRawMsg(r io.Reader) (*msgHeader, []byte, error) {
	header := msgHeader{}
	err := binary.Read(r, binary.LittleEndian, &header)
	if err != nil {
		return nil, nil, err
	}
	// messageLength should include the header bytes
	if header.MessageLength < 16 {
		return nil, nil, errors.New("Invalid message length in header")
	}
	shouldRead := int(header.MessageLength - 16)
	bytesRead := 0
	// TODO: bound buffer size
	data := make([]byte, shouldRead)
	for {
		n, err := r.Read(data[bytesRead:])
		if err != nil {
			return nil, nil, err
		}
		bytesRead += n
		if bytesRead == shouldRead {
			break
		}
		if err != nil {
			return nil, nil, err
		}
	}
	return &header, data, nil
}
