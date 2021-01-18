package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/rakutentech/jwk-go/jwk"
	"github.com/rs/zerolog"
)

const (
	_defaultRetries   = 5
	_defaultCacheSize = 100
)

type JWK = jwk.JWK

var (
	ErrConnectionFailed  = errors.New("jwks: connection failed")
	ErrInvalidURL        = errors.New("jwks: invalid url value or format")
	ErrKeyIDNotProvided  = errors.New("jwks: kid is not provided")
	ErrPublicKeyNotFound = errors.New("jwks: public key not found")
)

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
	logger  zerolog.Logger
}

func NewManager(rawurl string, opts ...Option) (Manager, error) {
	url, err := url.Parse(rawurl)
	if err != nil {
		return nil, ErrInvalidURL
	}

	cache, _ := NewMemoryCache(_defaultCacheSize)

	logger := zerolog.
		New(os.Stderr).With().
		Logger().
		Level(zerolog.Disabled)

	mng := &manager{
		url:     url,
		cache:   cache,
		client:  &http.Client{},
		lookup:  true,
		retries: _defaultRetries,
		logger:  logger,
	}

	for _, opt := range opts {
		opt(mng)
	}

	return mng, nil
}

func (m *manager) FetchKey(ctx context.Context, kid string) (*JWK, error) {
	if kid == "" {
		return nil, ErrKeyIDNotProvided
	}

	// If lookup is true, first try to get key from cache.
	if m.lookup {
		m.logger.Debug().Msgf("lookup cache for %s", kid)

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

		m.logger.Debug().Msgf("fetching %s from jwks source", kid)
		resp, err := m.client.Do(req)
		if err != nil {
			m.logger.Debug().Msgf("request failed with error %v", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			m.logger.Debug().Msgf("request failed with %d status code", resp.StatusCode)
			continue
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			m.logger.Debug().Msgf("response body reading failed with %v", err)
			continue
		}

		if err := json.Unmarshal(data, &set); err != nil {
			m.logger.Debug().Msgf("response body encoding failed with %v", err)
			return nil, err
		}

		break
	}

	if retries == 0 {
		m.logger.Debug().Msgf("max retries exceeded for %s", m.url.String())
		return nil, ErrConnectionFailed
	}

	if len(set.Keys) == 0 {
		m.logger.Debug().Msg("JWKS has no keys")
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
			m.logger.Debug().Msgf("saving %s into cache", jwk.Kid)

			if err := m.cache.Add(ctx, jwk); err != nil {
				m.logger.Debug().Msgf("failed cache save for %s with %v", jwk.Kid, err)
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
