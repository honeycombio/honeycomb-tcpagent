package mongodb

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"

	"gopkg.in/mgo.v2/bson"
)

// See https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/

const (
	OP_REPLY        = 1
	OP_MSG          = 1000
	OP_UPDATE       = 2001
	OP_INSERT       = 2002
	RESERVED        = 2003
	OP_QUERY        = 2004
	OP_GET_MORE     = 2005
	OP_DELETE       = 2006
	OP_KILL_CURSORS = 2007
	OP_COMMAND      = 2010
	OP_COMMANDREPLY = 2011
)

type document string
type cstring []byte

type updateMsg struct {
	ZERO               int32    // 0 - reserved for future use
	FullCollectionName cstring  // "dbname.collectionname"
	Flags              int32    // bit vector. see below
	Selector           document // the query to select the document
	Update             document // specification of the update to perform
}

func readUpdateMsg(data []byte) (*updateMsg, error) {
	r := bytes.NewBuffer(data)
	m := updateMsg{}
	var err error

	err = binary.Read(r, binary.LittleEndian, &m.ZERO)
	if err != nil {
		return nil, err
	}

	m.FullCollectionName, err = readCString(r)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &m.Flags)
	if err != nil {
		return nil, err
	}

	m.Selector, err = readDocument(r)
	if err != nil {
		return nil, err
	}

	m.Update, err = readDocument(r)
	if err != nil {
		return nil, err
	}

	return &m, nil

}

type insertMsg struct {
	Flags              int32   // bit vector - see below
	FullCollectionName cstring // "dbname.collectionname"
	// Documents       []document
	// ^ not parsed. Instead we compute NInserted:
	NInserted int32
}

func readInsertMsg(data []byte) (*insertMsg, error) {
	r := bytes.NewBuffer(data)
	var err error

	m := insertMsg{}
	err = binary.Read(r, binary.LittleEndian, &m.Flags)
	if err != nil {
		return nil, err
	}

	m.FullCollectionName, err = readCString(r)
	if err != nil {
		return nil, err
	}

	m.NInserted, err = readDocumentArrayLength(r)
	if err != nil {
		return nil, err
	}

	return &m, err
}

type queryMsg struct {
	Flags                uint32   // bit vector of query options.
	FullCollectionName   cstring  // "dbname.collectionname"
	NumberToSkip         uint32   // number of documents to skip
	NumberToReturn       uint32   // number of documents to return in the first OP_REPLY batch
	Query                document // query object.
	ReturnFieldsSelector document // Optional. Selector indicating the fields to return.
}

func readQueryMsg(data []byte) (*queryMsg, error) {
	r := bytes.NewBuffer(data)
	var err error

	m := queryMsg{}
	err = binary.Read(r, binary.LittleEndian, &m.Flags)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	m.FullCollectionName, err = readCString(r)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &m.NumberToSkip)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &m.NumberToReturn)
	if err != nil {
		return nil, err
	}

	m.Query, err = readDocument(r)
	if err != nil {
		return nil, err
	}

	// TODO: what's up with this ReturnFieldsSelector thing?
	return &m, nil
}

type getMore struct {
	ZERO               int32   //0 - reserved for future use
	FullCollectionName cstring //"dbname.collectionname"
	NumberToReturn     int32   //number of documents to return
	CursorID           int64   //cursorID from the OP_REPLY
}

type deleteMsg struct {
	ZERO               int32    //0 - reserved for future use
	FullCollectionName cstring  //"dbname.collectionname"
	Flags              int32    //bit vector - see below for details.
	Selector           document //query object.
}

type killCursorsMsg struct {
	ZERO              int32   // 0 - reserved for future use
	NumberOfCursorIDs int32   // number of cursorIDs in message
	CursorIDs         []int64 // sequence of cursorIDs to close
}

type replyMsg struct {
	ResponseFlags  int32 // bit vector - see details below
	CursorID       int64 // cursor id if client needs to do get more's
	StartingFrom   int32 // where in the cursor this reply is starting
	NumberReturned int32 // number of documents in the reply
	//Documents      []document // documents
}

func readReplyMsg(data []byte) (*replyMsg, error) {
	r := bytes.NewBuffer(data)
	var err error

	m := replyMsg{}
	err = binary.Read(r, binary.LittleEndian, &m.ResponseFlags)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &m.CursorID)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &m.StartingFrom)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &m.NumberReturned)
	if err != nil {
		return nil, err
	}

	return &m, nil
}

// TODO: do we need to worry about OP_MSG, OP_COMMAND, OP_COMMAND_REPLY?

func readDocument(r io.Reader) (document, error) {
	var length uint32
	err := binary.Read(r, binary.LittleEndian, &length)
	if err != nil {
		return "", err
	}
	buf, err := newSafeBuffer(int(length))
	if err != nil {
		return "", err
	}

	binary.LittleEndian.PutUint32(buf[:4], length)
	_, err = r.Read(buf[4:])
	if err != nil {
		return "", err
	}

	m := bson.M{}
	err = bson.Unmarshal(buf, m)
	if err != nil {
		log.Printf("Error unmarshaling", buf)
		return "", err
	}
	ret, err := bson.MarshalJSON(m)
	return document(ret), err
}

func readDocumentArrayLength(r *bytes.Buffer) (n int32, err error) {
	// Don't try to decode the document contents for now, just figure out how
	// many of them there are.
	n = 0
	for r.Len() > 0 {
		var docLength uint32
		err := binary.Read(r, binary.LittleEndian, &docLength)
		if err != nil {
			return 0, err
		}

		// Length of the remaineder of the document in bytes
		innerLength := docLength - 4

		if int(innerLength) > r.Len() {
			return 0, io.EOF
		}
		r.Next(int(innerLength))
		n++
	}
	return n, nil
}

func readCString(r *bytes.Buffer) (cstring, error) {
	cstring, err := r.ReadBytes(0x00)
	if err != nil {
		return nil, err
	}
	return cstring[:len(cstring)-1], nil
}
