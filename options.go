package jwks

import (
	"net/http"

	"github.com/rs/zerolog"
)

type Option func(m *manager)

func WithCache(c Cache) Option {
	return func(m *manager) { m.cache = c }
}

func WithHTTPClient(c *http.Client) Option {
	return func(m *manager) { m.client = c }
}

func WithLookup(flag bool) Option {
	return func(m *manager) { m.lookup = flag }
}

func WithMaxRetries(n int) Option {
	return func(m *manager) { m.retries = n }
}

func WithLogger(logger zerolog.Logger) Option {
	return func(m *manager) { m.logger = logger }
}
