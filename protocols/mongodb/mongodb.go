package mongodb

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gopkg.in/mgo.v2/bson"

	"github.com/Sirupsen/logrus"
	"github.com/codahale/metrics"
	"github.com/honeycombio/honeycomb-tcpagent/protocols/mongodb/queryshape"
	"github.com/honeycombio/honeycomb-tcpagent/publish"
	"github.com/honeycombio/honeycomb-tcpagent/sniffer"
)

// Truncate serialized documents longer than this before publishing them
const maxDocLength = 500

type Options struct {
	Port uint16 `long:"port" description:"MongoDB port" default:"27017"`
}

type Event struct {
	ClientIP        string    `json:"client_ip"`
	Collection      string    `json:"collection"`
	CommandType     string    `json:"command_type"`
	Command         document  `json:"command"`
	Database        string    `json:"database"`
	DurationMs      float64   `json:"duration_ms"`
	Namespace       string    `json:"namespace"`
	NInserted       int       `json:"ninserted"`
	NormalizedQuery string    `json:"normalized_query,omitempty"`
	NReturned       int32     `json:"nreturned"`
	RequestID       int32     `json:"request_id"`
	RequestLength   int       `json:"request_length"`
	ResponseLength  int       `json:"response_length"`
	ServerIP        string    `json:"server_ip"`
	Timestamp       time.Time `json:"timestamp"`
}

func truncate(d document) ([]byte, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	if len(b) > maxDocLength {
		b = append(b[:maxDocLength-4], " ..."...)
	}
	return b, nil
}

func (e *Event) MarshalJSON() ([]byte, error) {
	type Wrapper Event
	serializedCommand, err := truncate(e.Command)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		Command string `json:"command"`
		*Wrapper
	}{
		Command: string(serializedCommand),
		Wrapper: (*Wrapper)(e),
	})
}

// ParserFactory implements sniffer.ConsumerFactory
// TODO: this way of setting things up is kind of confusing
type ParserFactory struct {
	Options   Options
	Publisher publish.Publisher
}

func (pf *ParserFactory) New(flow sniffer.IPPortTuple) sniffer.Consumer {
	if flow.DstPort != pf.Options.Port {
		flow = flow.Reverse()
	}
	return &Parser{
		options:   pf.Options,
		flow:      flow,
		qcache:    newQCache(128),
		logger:    logrus.WithFields(logrus.Fields{"flow": flow, "component": "mongodb"}),
		publisher: pf.Publisher,
	}
}

func (pf *ParserFactory) BPFFilter() string {
	return fmt.Sprintf("tcp port %d", pf.Options.Port)
}

// Parser implements sniffer.Consumer
type Parser struct {
	options   Options
	flow      sniffer.IPPortTuple
	qcache    *QCache
	logger    *logrus.Entry
	publisher publish.Publisher
}

func (p *Parser) On(ms sniffer.MessageStream) {
	for {
		m, ok := ms.Next()
		if !ok {
			p.logger.Debug("Message stream closed")
			return
		}
		isRequest := m.Flow().DstPort == p.options.Port
		var err error
		p.logger.WithField("isRequest", isRequest).Debug("Parsing MongoDB message")
		if isRequest {
			err = p.parseRequest(m, m.Timestamp())
		} else {
			err = p.parseResponse(m, m.Timestamp())
		}
		if err != io.EOF {
			p.logger.WithError(err).WithField("isRequest", isRequest).Debug("Error parsing request")
			discardBuffer := make([]byte, 4096)
			for err != io.EOF {
				_, err = m.Read(discardBuffer)
			}
		}
	}
}

func (p *Parser) parseRequest(r io.Reader, ts time.Time) error {
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
		q.RequestLength = len(data) + 16 // Payload length including header

		switch header.OpCode {
		case OP_QUERY:
			m, err := readQueryMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing query")
				return err
			}
			q.Command = m.Query
			q.Namespace = string(m.FullCollectionName)
			// Some commands pass "database.$cmd" as the fullCollectionName
			// with a document payload that looks like
			// {
			//   "find": "collectionName"
			//   "filter": {...}
			//   ...
			// }
			// For those, we take the collection name out of the payload, since
			// that's more useful for consumers.
			q.Database, q.Collection = parseFullCollectionName(string(m.FullCollectionName))
			cmdType, innerCollectionName, ok := extractCommandType(m.Query)
			if ok {
				q.CommandType = string(cmdType)
				q.Command = m.Query
				if len(innerCollectionName) > 0 {
					q.Collection = innerCollectionName
				} else if cmdType == GetMore {
					innerCollectionName, ok := m.Query["collection"].(string)
					if ok {
						q.Collection = innerCollectionName
					}
				}
				if cmdType == Find {
					if rawFilter, ok := m.Query["filter"]; ok {
						if filter, ok := rawFilter.(bson.M); ok {
							q.NormalizedQuery = queryshape.GetQueryShape(filter)
						}
					}
				}
			} else {
				q.CommandType = "command"
			}

			eviction := p.qcache.Add(header.RequestID, q)
			if eviction {
				ctr := metrics.Counter("mongodb.qcache_evictions")
				ctr.Add()
				p.logger.Warn("Query cache full")
			}
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
			q.Namespace = string(m.FullCollectionName)
			q.Database, q.Collection = parseFullCollectionName(string(m.FullCollectionName))
			p.publish(q)
		case OP_INSERT:
			m, err := readInsertMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing insert")
				return err
			}
			q.CommandType = "insert"
			q.NInserted = m.NInserted
			q.Namespace = string(m.FullCollectionName)
			q.Database, q.Collection = parseFullCollectionName(string(m.FullCollectionName))
			p.publish(q)
		case OP_DELETE:
			m, err := readDeleteMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing delete")
				return err
			}
			q.CommandType = "delete"
			q.Namespace = string(m.FullCollectionName)
			q.Database, q.Collection = parseFullCollectionName(string(m.FullCollectionName))
			p.publish(q)
		case OP_GET_MORE:
			m, err := readGetMoreMsg(data)
			if err != nil {
				p.logger.WithError(err).Debug("Error parsing getMore")
				return err
			}
			q.CommandType = "getMore"
			q.Namespace = string(m.FullCollectionName)
			q.Database, q.Collection = parseFullCollectionName(string(m.FullCollectionName))
			eviction := p.qcache.Add(header.RequestID, q)
			if eviction {
				ctr := metrics.Counter("mongodb.qcache_evictions")
				ctr.Add()
				p.logger.Warn("Query cache full")
			}
		}
		metrics.Counter("mongodb.requests_parsed").Add()
	}
}

func (p *Parser) parseResponse(r io.Reader, ts time.Time) error {
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
			// TODO: For inserts and the like, we actually need to read the
			// response payload.
			m, err := readReplyMsg(data)
			if err != nil {
				return err
			}
			q, ok := p.qcache.Pop(header.ResponseTo)
			q.ResponseLength = len(data) + 16 // Payload length including header
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

			// TODO: do something for others.
		}
		metrics.Counter("mongodb.responses_parsed").Add()

	}
}

func (p *Parser) publish(q *Event) {
	q.ClientIP = p.flow.SrcIP.String()
	q.ServerIP = p.flow.DstIP.String()
	s, err := json.Marshal(&q)
	if err != nil {
		p.logger.WithError(err).Error("Error marshaling query event")
	}
	ok := p.publisher.Publish(s)
	if ok {
		metrics.Counter("mongodb.events_published").Add()
	} else {
		p.logger.Debug("Failed to publish event")
		metrics.Counter("mongodb.events_dropped").Add()
	}
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

func extractCommandType(m document) (cmdType opType, collection string, ok bool) {
	// Note order matters in this array -- findAndModify commands contain both
	// a "findAndModify" and an "update" field.
	for _, cmdType = range []opType{FindAndModify, Insert, Update, Delete, Find, Count, Distinct, Aggregate, MapReduce} {
		c, ok := m[string(cmdType)]
		if ok {
			collection, _ := c.(string)
			return cmdType, collection, true
		}
	}

	for _, cmdType = range []opType{GetMore, GetLastError, GetPrevError, Eval} {
		_, ok := m[string(cmdType)]
		if ok {
			return cmdType, "", true
		}
	}
	return cmdType, "", false
}

func parseFullCollectionName(fullCollectionName string) (db string, collection string) {
	b := strings.SplitN(fullCollectionName, ".", 2)
	if len(b) < 2 {
		return b[0], ""
	}
	return b[0], b[1]
}
