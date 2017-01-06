package mongodb

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

type document []byte
type cstring []byte

type updateMsg struct {
	ZERO               int32    // 0 - reserved for future use
	FullCollectionName cstring  // "dbname.collectionname"
	Flags              int32    // bit vector. see below
	Selector           document // the query to select the document
	Update             document // specification of the update to perform
}

func readUpdateMsg() {
}

type insertMsg struct {
	Flags              int32      // bit vector - see below
	FullCollectionName cstring    // "dbname.collectionname"
	Documents          []document // one or more documents to insert into the collection
}

type queryMsg struct {
	Flags                int32      // bit vector of query options.
	FullCollectionName   cstring    // "dbname.collectionname"
	NumberToSkip         int32      // number of documents to skip
	NumberToReturn       int32      // number of documents to return in the first OP_REPLY batch
	Query                document   // query object.
	ReturnFieldsSelector []document // Optional. Selector indicating the fields to return.
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
	ResponseFlags  int32      // bit vector - see details below
	CursorID       int64      // cursor id if client needs to do get more's
	StartingFrom   int32      // where in the cursor this reply is starting
	NumberReturned int32      // number of documents in the reply
	Documents      []document // documents
}

// TODO: do we need to worry about OP_MSG, OP_COMMAND, OP_COMMAND_REPLY?
