package jwks

import (
	"context"
	"sync"
	"time"
)

type item struct {
	sync.RWMutex
	data       *JWK
	expiration *time.Time
}

func (i *item) touch(d time.Duration) {
	i.Lock()
	exp := time.Now().Add(d)
	i.expiration = &exp
	i.Unlock()
}

func (i *item) expired() bool {
	i.RLock()
	res := true
	if i.expiration != nil {
		res = i.expiration.Before(time.Now())
	}
	i.RUnlock()
	return res
}

type ttlcache struct {
	mu    sync.RWMutex
	ttl   time.Duration
	stop  chan struct{}
	items map[string]*item
}

// NewTTLCache returns a new instance of ttl cache.
func NewTTLCache(ttl time.Duration) Cache {
	cache := &ttlcache{
		ttl:   ttl,
		stop:  make(chan struct{}),
		items: make(map[string]*item),
	}
	cache.run()
	return cache
}

func (tc *ttlcache) cleanup() {
	tc.mu.Lock()
	for key, item := range tc.items {
		if item.expired() {
			delete(tc.items, key)
		}
	}
	tc.mu.Unlock()
}

func (tc *ttlcache) run() {
	d := tc.ttl
	if d < time.Second {
		d = time.Second
	}

	ticker := time.Tick(d)
	go func() {
		for {
			select {
			case <-ticker:
				tc.cleanup()
			case <-tc.stop:
				return
			}
		}
	}()
}

func (tc *ttlcache) Add(_ context.Context, key *JWK) error {
	tc.mu.Lock()
	item := &item{data: key}
	item.touch(tc.ttl)
	tc.items[key.Kid] = item
	tc.mu.Unlock()
	return nil
}

func (tc *ttlcache) Get(_ context.Context, kid string) (*JWK, error) {
	tc.mu.RLock()
	item, ok := tc.items[kid]
	if !ok || item.expired() {
		tc.mu.RUnlock()
		return nil, ErrCacheNotFound
	}
	item.touch(tc.ttl)
	tc.mu.RUnlock()
	return item.data, nil
}

func (tc *ttlcache) Remove(_ context.Context, kid string) error {
	tc.mu.Lock()
	delete(tc.items, kid)
	tc.mu.Unlock()
	return nil
}

func (tc *ttlcache) Contains(_ context.Context, kid string) (bool, error) {
	tc.mu.RLock()
	_, ok := tc.items[kid]
	tc.mu.RUnlock()
	return ok, nil
}

func (tc *ttlcache) Len(_ context.Context) (int, error) {
	tc.mu.RLock()
	n := len(tc.items)
	tc.mu.RUnlock()
	return n, nil
}

func (tc *ttlcache) Purge(_ context.Context) error {
	tc.mu.Lock()
	tc.items = map[string]*item{}
	tc.mu.Unlock()
	return nil
}
