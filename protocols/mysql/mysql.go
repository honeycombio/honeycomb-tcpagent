package mysql

import (
	"time"

	"github.com/emfree/honeypacket/protocols"
)

type MySQLMessage struct {
	ts            time.Time
	payloadLength uint32
	sequenceID    byte
	command       mySQLCommand
	query         []byte
}

type Parser struct {
	offset int
	state  parseState
}

type parseState int

const (
	parseStateChompHeader parseState = iota
	parseStateChompPayload
)

type mySQLCommand byte

// https://dev.mysql.com/doc/internals/en/text-protocol.html
const (
	COM_SLEEP mySQLCommand = iota
	COM_QUIT
	COM_INIT_DB
	COM_QUERY
	COM_FIELD_LIST
	COM_CREATE_DB
	COM_DROP_DB
	COM_REFRESH
	COM_SHUTDOWN
	COM_STATISTICS
	COM_PROCESS_INFO
	COM_CONNECT
	COM_PROCESS_KILL
	COM_DEBUG
	COM_PING
	COM_TIME
	COM_DELAYED_INSERT
	COM_CHANGE_USER
	COM_BINLOG_DUMP
	COM_TABLE_DUMP
	COM_CONNECT_OUT
	COM_REGISTER_SLAVE
	COM_STMT_EXECUTE
	COM_STMT_SEND_LONG_DATA
	COM_STMT_CLOSE
	COM_STMT_RESET
	COM_SET_OPTION
	COM_STMT_FETCH
	COM_DAEMON
	COM_BINLOG_DUMP_GTID
	COM_RESET_CONNECTION
)

func NewConsumer() *Parser { return &Parser{} }

func (p *Parser) Handle(packetInfo protocols.PacketInfo) {}

// TODO: we need parser state across TCP packets
func (p *Parser) parse(data []byte) error {
	m := MySQLMessage{}
	p.offset = 0
	p.state = parseStateChompHeader
	for p.offset < len(data) {
		switch p.state {
		case parseStateChompHeader:
			m.payloadLength = uint32(data[p.offset]) + uint32(data[p.offset+1])<<8 + uint32(data[p.offset+2])<<16
			m.sequenceID = data[p.offset+3]
			m.command = mySQLCommand(data[p.offset+4])
			p.offset += 3
			p.state = parseStateChompPayload
			// TODO
		}
	}
	return nil
}
