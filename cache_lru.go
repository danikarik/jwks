package jwks

import (
	"context"

	lru "github.com/hashicorp/golang-lru"
)

type lruMemory struct{ cache *lru.Cache }

// NewLRUCache returns a new instance of memory cache.
func NewLRUCache(size int) (Cache, error) {
	cache, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	return &lruMemory{cache}, nil
}

func (m *lruMemory) Add(_ context.Context, key *JWK) error {
	if key.Kid == "" {
		return ErrEmptyKeyID
	}

	m.cache.Add(key.Kid, key)
	return nil
}

func (m *lruMemory) Get(_ context.Context, kid string) (*JWK, error) {
	v, found := m.cache.Get(kid)
	if !found {
		return nil, ErrCacheNotFound
	}

	key, ok := v.(*JWK)
	if !ok {
		return nil, ErrInvalidValue
	}

	return key, nil
}

func (m *lruMemory) Remove(_ context.Context, kid string) error {
	m.cache.Remove(kid)
	return nil
}

func (m *lruMemory) Contains(_ context.Context, kid string) (bool, error) {
	return m.cache.Contains(kid), nil
}

func (m *lruMemory) Len(_ context.Context) (int, error) {
	return m.cache.Len(), nil
}

func (m *lruMemory) Purge(_ context.Context) error {
	m.cache.Purge()
	return nil
}
