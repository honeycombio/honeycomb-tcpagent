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
	"github.com/honeycombio/honeypacket/sniffer"
)

type Options struct {
	Port uint16 `long:"port" description:"MongoDB port" default:"27017"`
}

// TODO: consider specializing this for different operation types, so as not to
// return a blank `Update` field for OP_QUERY messages, for example.
// Maybe also rename to OpType for clarity?
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
	RequestID  int32
	NReturned  int32
	NInserted  int
}

// ParserFactory implements sniffer.ConsumerFactory
// TODO: this way of setting things up is kind of confusing
type ParserFactory struct {
	Options  Options
	SendFunc func([]byte)
}

func (pf *ParserFactory) New(flow sniffer.IPPortTuple) sniffer.Consumer {
	if flow.DstPort != pf.Options.Port {
		flow = flow.Reverse()
	}
	return &Parser{
		options:  pf.Options,
		flow:     flow,
		qcache:   newQCache(128),
		logger:   logrus.WithFields(logrus.Fields{"flow": flow, "component": "mongodb"}),
		sendFunc: pf.SendFunc,
	}
}

func (pf *ParserFactory) BPFFilter() string {
	return fmt.Sprintf("tcp port %d", pf.Options.Port)
}

// Parser implements sniffer.Consumer
type Parser struct {
	options  Options
	flow     sniffer.IPPortTuple
	qcache   *QCache
	logger   *logrus.Entry
	sendFunc func([]byte)
}

func (p *Parser) On(ms sniffer.MessageStream) {
	for {
		m, ok := ms.Next()
		if !ok {
			p.logger.Debug("Message stream closed")
			return
		}
		toServer := m.Flow().DstPort == p.options.Port
		if toServer {
			p.logger.Debug("Parsing MongoDB request")
			err := p.parseRequestStream(m, m.Timestamp())
			if err != io.EOF {
				p.logger.WithError(err).Debug("Error parsing request")
			}
		} else {
			p.logger.Debug("Parsing MongoDB response")
			err := p.parseResponseStream(m, m.Timestamp())
			if err != io.EOF {
				p.logger.WithError(err).Debug("Error parsing response")
			}
		}
	}
}

func (p *Parser) parseRequestStream(r io.Reader, ts time.Time) error {
	for {
		header, data, err := readRawMsg(r)
		if err != nil {
			return err
		}
		p.logger.WithFields(logrus.Fields{
			"opCode":        header.OpCode,
			"requestID":     header.RequestID,
			"responseTo":    header.ResponseTo,
			"messageLength": header.MessageLength}).Debug("Parsed request header")

		q := &QueryEvent{}
		q.RequestID = header.RequestID
		q.Timestamp = ts

		switch header.OpCode {
		case OP_UPDATE:
			m, err := readUpdateMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing update")
				return err
			}
			q.Update = string(m.Update)
			q.Selector = string(m.Selector)
			q.OpType = "update"
			q.Collection = string(m.FullCollectionName)
			p.publish(q)
		case OP_INSERT:
			m, err := readInsertMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing insert")
				return err
			}
			q.OpType = "insert"
			q.Timestamp = ts
			q.NInserted = m.NInserted
			q.Collection = string(m.FullCollectionName)
			p.publish(q)
		case OP_QUERY:
			m, err := readQueryMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing query")
				return err
			}
			q.OpType = "query"
			q.Timestamp = ts
			q.Collection = string(m.FullCollectionName)
			q.Query = string(m.Query)
			p.qcache.Add(header.RequestID, q)
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
		p.logger.WithFields(logrus.Fields{
			"opCode":        header.OpCode,
			"requestID":     header.RequestID,
			"responseTo":    header.ResponseTo,
			"messageLength": header.MessageLength}).Debug("Parsed response header")
		switch header.OpCode {
		case OP_REPLY:
			m, err := readReplyMsg(data)
			if err != nil {
				return err
			}
			q, ok := p.qcache.Get(header.ResponseTo)
			if !ok {
				p.logger.WithField("responseTo", header.ResponseTo).
					Debug("Query not found in cache")
			} else {
				q.NReturned = m.NumberReturned

				if !ts.After(q.Timestamp) {
					p.logger.WithFields(logrus.Fields{
						"end":   ts,
						"start": q.Timestamp}).Debug("End timestamp before start")
					q.QueryTime = 0
				} else {
					q.QueryTime = ts.Sub(q.Timestamp).Seconds()
				}
				p.publish(q)
			}

		}

	}
}

func (p *Parser) publish(q *QueryEvent) {
	q.ClientIP = p.flow.SrcIP.String()
	q.ServerIP = p.flow.DstIP.String()
	s, err := json.Marshal(&q)
	if err != nil {
		p.logger.Error("Error marshaling query event", err)
	}
	// TODO: better output handling
	if p.sendFunc != nil {
		p.sendFunc(s)
	}
	io.WriteString(os.Stdout, string(s))
	io.WriteString(os.Stdout, "\n")
}

type msgHeader struct {
	MessageLength int32 // total message size, including this
	RequestID     int32 // identifier for this message
	ResponseTo    int32 // requestID from the original request
	OpCode        int32 // request type - see table below
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
	data, err := newSafeBuffer(shouldRead)
	if err != nil {
		return nil, nil, err
	}
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

// Ensure that we don't try to allocate crazy amounts of memory if we find
// ourselves parsing a bad packet.
func newSafeBuffer(bufsize int) ([]byte, error) {
	// Max BSON document size is 16MB.
	// https://docs.mongodb.com/manual/reference/limits/
	// For simplicity, bound buffer size at 32MB so that headers and so on fit
	// too.
	// TODO: Can you put multiple large documents in one insert or reply and
	// exceed this limit?
	if bufsize > 32*1024*1024 {
		return nil, fmt.Errorf("Buffer size %d too large", bufsize)
	}
	return make([]byte, bufsize), nil
}
