package mongodb

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/honeycombio/honeypacket/sniffer"
)

type Options struct {
	Port uint16 `long:"port" description:"MongoDB port" default:"27017"`
}

type Event struct {
	Timestamp   time.Time
	ClientIP    string
	ServerIP    string
	Database    string
	Collection  string
	CommandType string
	Command     document
	DurationMs  float64
	RequestID   int32
	NReturned   int32
	NInserted   int
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

		q := &Event{}
		q.RequestID = header.RequestID
		q.Timestamp = ts

		switch header.OpCode {
		case OP_QUERY:
			m, err := readQueryMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing query")
				return err
			}
			q.Timestamp = ts
			q.Command = m.Query
			cmdType, ok := extractCommandType(m.Query)
			fmt.Println("CMDTYPE", cmdType, ok, m.Query)
			if ok {
				q.CommandType = string(cmdType)
				q.Command = m.Query
				if cmdType != GetMore {
					q.Collection = m.Query[string(cmdType)].(string)
				} else {
					q.Database, q.Collection = parseFullCollectionName(string(m.FullCollectionName))
				}
			} else {
				q.Database, q.Collection = parseFullCollectionName(string(m.FullCollectionName))
				// TODO: is this really right?
				q.CommandType = "query"
			}

			p.qcache.Add(header.RequestID, q)
		case OP_UPDATE:
			m, err := readUpdateMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing update")
				return err
			}
			// Grunge this into the more modern update syntax
			// TODO: do we really want to do this?
			update := map[string]interface{}{
				"u": m.Update,
				"q": m.Selector,
			}
			q.CommandType = "update"
			q.Command = update
			q.Collection = string(m.FullCollectionName)
			p.publish(q)
		case OP_INSERT:
			m, err := readInsertMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing insert")
				return err
			}
			q.CommandType = "insert"
			q.Timestamp = ts
			q.NInserted = m.NInserted
			q.Collection = string(m.FullCollectionName)
			p.publish(q)
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
			q, ok := p.qcache.Pop(header.ResponseTo)
			if !ok {
				p.logger.WithField("responseTo", header.ResponseTo).
					Debug("Query not found in cache")
			} else {
				q.NReturned = m.NumberReturned

				if !ts.After(q.Timestamp) {
					p.logger.WithFields(logrus.Fields{
						"end":   ts,
						"start": q.Timestamp}).Debug("End timestamp before start")
					q.DurationMs = 0
				} else {
					q.DurationMs = float64(ts.Sub(q.Timestamp).Nanoseconds()) / 1e6
				}
				p.publish(q)
			}

		}

	}
}

func (p *Parser) publish(q *Event) {
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

func extractCommandType(m document) (cmdType opType, ok bool) {
	for _, cmdType = range []opType{Insert, Update, Delete, GetMore, FindAndModify, Find, Count} {
		_, ok := m[string(cmdType)]
		if ok {
			return cmdType, true
		}
	}
	return cmdType, false
}

func parseFullCollectionName(fullCollectionName string) (db string, collection string) {
	b := strings.SplitN(fullCollectionName, ".", 2)
	if len(b) < 2 {
		return b[0], ""
	}
	return b[0], b[1]
}
