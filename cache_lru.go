package jwks

import (
	"context"

	lru "github.com/hashicorp/golang-lru"
)

type lrucache struct{ cache *lru.Cache }

// NewLRUCache returns a new instance of lru cache.
func NewLRUCache(size int) (Cache, error) {
	cache, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	return &lrucache{cache}, nil
}

func (lc *lrucache) Add(_ context.Context, key *JWK) error {
	if key.Kid == "" {
		return ErrEmptyKeyID
	}

	lc.cache.Add(key.Kid, key)
	return nil
}

func (lc *lrucache) Get(_ context.Context, kid string) (*JWK, error) {
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

func (lc *lrucache) Remove(_ context.Context, kid string) error {
	lc.cache.Remove(kid)
	return nil
}

func (lc *lrucache) Contains(_ context.Context, kid string) (bool, error) {
	return lc.cache.Contains(kid), nil
}

func (lc *lrucache) Len(_ context.Context) (int, error) {
	return lc.cache.Len(), nil
}

func (lc *lrucache) Purge(_ context.Context) error {
	lc.cache.Purge()
	return nil
}
