package jwks

import (
	"net/http"

	"github.com/rs/zerolog"
)

// Option is used for configuring key manager.
type Option func(m *manager)

// WithCache sets custom cache. Default is `memory cache`.
func WithCache(c Cache) Option {
	return func(m *manager) { m.cache = c }
}

// WithHTTPClient sets custom http client.
func WithHTTPClient(c *http.Client) Option {
	return func(m *manager) { m.client = c }
}

// WithLookup defines cache lookup option. Default is `true`.
func WithLookup(flag bool) Option {
	return func(m *manager) { m.lookup = flag }
}

// WithMaxRetries defines max retries count if request has been failed. Default is `5`.
func WithMaxRetries(n int) Option {
	return func(m *manager) { m.retries = n }
}

// WithLogger sets custom logger. Default log level is `disabled`.
func WithLogger(logger zerolog.Logger) Option {
	return func(m *manager) { m.logger = logger }
}

// WithDebug sets log level to `Debug`.
func WithDebug(on bool) Option {
	return func(m *manager) { m.logger = m.logger.Level(zerolog.DebugLevel) }
}
