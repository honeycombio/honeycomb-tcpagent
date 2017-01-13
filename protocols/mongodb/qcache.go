package mongodb

import lru "github.com/hashicorp/golang-lru"

type QCache struct {
	cache *lru.Cache
}

// TODO: should log on eviction
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

func (qc *QCache) Add(k int32, v interface{}) {
	qc.cache.Add(k, v)
}
