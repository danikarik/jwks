package jwks

import (
	"context"
	"errors"

	lru "github.com/hashicorp/golang-lru"
)

var (
	// ErrEmptyKeyID raises when input kid is empty.
	ErrEmptyKeyID = errors.New("cache: empty kid")
	// ErrCacheNotFound raises when cache value not found.
	ErrCacheNotFound = errors.New("cache: value not found")
	// ErrInvalidValue raises when type conversion to JWK has been failed.
	ErrInvalidValue = errors.New("cache: invalid value")
)

// Cache works with cache layer.
type Cache interface {
	Add(ctx context.Context, key *JWK) error
	Get(ctx context.Context, kid string) (*JWK, error)
	Remove(ctx context.Context, kid string) error
	Contains(ctx context.Context, kid string) (bool, error)
	Len(ctx context.Context) (int, error)
	Purge(ctx context.Context) error
}

type memory struct{ cache *lru.Cache }

// NewMemoryCache returns a new instance of memory cache.
func NewMemoryCache(size int) (Cache, error) {
	cache, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	return &memory{cache}, nil
}

func (m *memory) Add(_ context.Context, key *JWK) error {
	if key.Kid == "" {
		return ErrEmptyKeyID
	}

	m.cache.Add(key.Kid, key)
	return nil
}

func (m *memory) Get(_ context.Context, kid string) (*JWK, error) {
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

func (m *memory) Remove(_ context.Context, kid string) error {
	m.cache.Remove(kid)
	return nil
}

func (m *memory) Contains(_ context.Context, kid string) (bool, error) {
	return m.cache.Contains(kid), nil
}

func (m *memory) Len(_ context.Context) (int, error) {
	return m.cache.Len(), nil
}

func (m *memory) Purge(_ context.Context) error {
	m.cache.Purge()
	return nil
}
