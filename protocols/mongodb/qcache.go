package mongodb

import lru "github.com/hashicorp/golang-lru"

// QCache holds partially-assembled Event structs once we've parsed a request,
// but need to wait until we see the response to fill in the missing data.
type QCache struct {
	cache *lru.Cache
}

func newQCache(size int) *QCache {
	// Not checking errors here, because lru.New() returns an error only if
	// size is negative. We just won't do that in calling code.
	c, _ := lru.New(size)
	return &QCache{
		cache: c,
	}
}

func (qc *QCache) Pop(k int32) (*Event, bool) {
	// We won't need the query event again once retrieved, so we just remove it
	// right away.
	v, ok := qc.cache.Peek(k)
	if !ok {
		return nil, ok
	}
	qc.cache.Remove(k)
	q, ok := v.(*Event)
	return q, ok
}

func (qc *QCache) Add(k int32, v *Event) bool {
	return qc.cache.Add(k, v)
}
