package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/rakutentech/jwk-go/jwk"
)

const defaultRetries = 5

type JWK = jwk.JWK

var (
	ErrConnectionFailed  = errors.New("jwks: connection failed")
	ErrInvalidURL        = errors.New("jwks: invalid url value or format")
	ErrKeyIDNotProvided  = errors.New("jwks: kid is not provided")
	ErrPublicKeyNotFound = errors.New("jwks: public key not found")
)

type Config struct {
	Cache   Cache
	Client  *http.Client
	Lookup  bool
	Retries int
}

func defaultConfig() *Config {
	cache, _ := NewMemoryCache(defaultCacheSize)

	return &Config{
		Cache:   cache,
		Client:  &http.Client{},
		Lookup:  true,
		Retries: defaultRetries,
	}
}

type Manager interface {
	FetchKey(ctx context.Context, kid string) (*JWK, error)
	CacheSize(ctx context.Context) (int, error)
}

type manager struct {
	url     *url.URL
	cache   Cache
	client  *http.Client
	lookup  bool
	retries int
}

func NewManager(rawurl string, conf *Config) (Manager, error) {
	url, err := url.Parse(rawurl)
	if err != nil {
		return nil, ErrInvalidURL
	}

	if conf == nil {
		conf = defaultConfig()
	}

	if conf.Client == nil {
		conf.Client = &http.Client{}
	}

	if conf.Retries == 0 {
		conf.Retries = defaultRetries
	}

	return &manager{
		url:     url,
		cache:   conf.Cache,
		client:  conf.Client,
		lookup:  conf.Lookup,
		retries: conf.Retries,
	}, nil
}

func (m *manager) FetchKey(ctx context.Context, kid string) (*JWK, error) {
	if kid == "" {
		return nil, ErrKeyIDNotProvided
	}

	// If lookup is true, first try to get key from cache.
	if m.lookup {
		key, err := m.cache.Get(ctx, kid)
		if err == nil {
			return key, nil
		}
	}

	// Otherwise fetch from public JWKS.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url.String(), nil)
	if err != nil {
		return nil, err
	}

	var set jwk.KeySpecSet

	// Make sure that you have exponential back off on this http request with retries.
	retries := m.retries
	for retries > 0 {
		retries--

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		if err := json.Unmarshal(data, &set); err != nil {
			return nil, err
		}

		break
	}

	if retries == 0 {
		return nil, ErrConnectionFailed
	}

	if len(set.Keys) == 0 {
		return nil, ErrPublicKeyNotFound
	}

	var res *JWK

	// Save new set into cache.
	for _, spec := range set.Keys {
		jwk, err := spec.ToJWK()
		if err != nil {
			return nil, err
		}

		if m.lookup {
			if err := m.cache.Add(ctx, jwk); err != nil {
				return nil, err
			}
		}

		if jwk.Kid == kid {
			res = jwk
		}
	}

	if res == nil {
		return nil, ErrPublicKeyNotFound
	}

	return res, nil
}

func (m *manager) CacheSize(ctx context.Context) (int, error) {
	return m.cache.Len(ctx)
}
