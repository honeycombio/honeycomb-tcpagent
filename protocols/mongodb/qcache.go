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

func (qc *QCache) Get(k uint32) (*QueryEvent, bool) {
	v, ok := qc.cache.Get(k)
	if !ok {
		return nil, ok
	}
	q, ok := v.(*QueryEvent)
	return q, ok
}

func (qc *QCache) Add(k uint32, v interface{}) {
	qc.cache.Add(k, v)
}
