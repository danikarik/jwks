package jwks

import (
	"context"

	lru "github.com/hashicorp/golang-lru"
)

type LRUCache struct{ cache *lru.Cache }

// NewLRUCache returns a new instance of lru cache.
func NewLRUCache(size int) (*LRUCache, error) {
	cache, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	return &LRUCache{cache}, nil
}

func (lc *LRUCache) Add(_ context.Context, key *JWK) error {
	if key.Kid == "" {
		return ErrEmptyKeyID
	}

	lc.cache.Add(key.Kid, key)
	return nil
}

func (lc *LRUCache) Get(_ context.Context, kid string) (*JWK, error) {
	v, found := lc.cache.Get(kid)
	if !found {
		return nil, ErrCacheNotFound
	}

	key, ok := v.(*JWK)
	if !ok {
		return nil, ErrInvalidValue
	}

	return key, nil
}

func (lc *LRUCache) Remove(_ context.Context, kid string) error {
	lc.cache.Remove(kid)
	return nil
}

func (lc *LRUCache) Contains(_ context.Context, kid string) (bool, error) {
	return lc.cache.Contains(kid), nil
}

func (lc *LRUCache) Len(_ context.Context) (int, error) {
	return lc.cache.Len(), nil
}

func (lc *LRUCache) Purge(_ context.Context) error {
	lc.cache.Purge()
	return nil
}
