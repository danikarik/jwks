package jwks_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/danikarik/jwks"
	"github.com/stretchr/testify/require"
)

func TestMemoryCacheInit(t *testing.T) {
	testCases := []struct {
		Name      string
		Size      int
		WantError bool
	}{
		{
			Name: "OK",
			Size: 100,
		},
		{
			Name:      "NegativeSize",
			Size:      -1,
			WantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			cache, err := jwks.NewMemoryCache(tc.Size)
			if tc.WantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cache)
			}
		})
	}
}

func TestMemoryCacheAdd(t *testing.T) {
	testCases := []struct {
		Name string
		Size int
		Ops  int
	}{
		{
			Name: "OK",
			Size: 100,
			Ops:  50,
		},
		{
			Name: "Evicted",
			Size: 100,
			Ops:  200,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			cache, err := jwks.NewMemoryCache(tc.Size)
			require.NoError(t, err)

			for i := 0; i < tc.Ops; i++ {
				require.NoError(t, cache.Add(ctx, &jwks.JWK{
					Kid: fmt.Sprintf("key-%d", i+1),
					Kty: "RSA",
					Alg: "RS256",
					Use: "sig",
				}))
			}
		})
	}
}

func TestMemoryCacheGet(t *testing.T) {
	testCases := []struct {
		Name  string
		Key   *jwks.JWK
		Kid   string
		Error error
	}{
		{
			Name: "OK",
			Key: &jwks.JWK{
				Kid: "202101",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
			},
			Kid: "202101",
		},
		{
			Name: "NotFound",
			Key: &jwks.JWK{
				Kid: "202101",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
			},
			Kid:   "202102",
			Error: jwks.ErrCacheNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			cache, err := jwks.NewMemoryCache(10)
			require.NoError(t, err)
			require.NoError(t, cache.Add(ctx, tc.Key))

			key, err := cache.Get(ctx, tc.Kid)
			if tc.Error != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.Error)
			} else {
				require.NoError(t, err)
				require.EqualValues(t, tc.Key, key)
			}
		})
	}
}

func TestMemoryCacheRemove(t *testing.T) {
	testCases := []struct {
		Name string
		Size int
		Adds int
		Dels int
		Len  int
	}{
		{
			Name: "OK",
			Size: 100,
			Adds: 75,
			Dels: 50,
			Len:  25,
		},
		{
			Name: "RemoveUntilEmpty",
			Size: 100,
			Adds: 75,
			Dels: 100,
			Len:  0,
		},
		{
			Name: "RemoveWithEviction",
			Size: 100,
			Adds: 200,
			Dels: 50,
			Len:  50,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			cache, err := jwks.NewMemoryCache(tc.Size)
			require.NoError(t, err)

			for i := 0; i < tc.Adds; i++ {
				require.NoError(t, cache.Add(ctx, &jwks.JWK{
					Kid: fmt.Sprintf("key-%d", i+1),
					Kty: "RSA",
					Alg: "RS256",
					Use: "sig",
				}))
			}

			for i := 0; i < tc.Dels; i++ {
				kid := fmt.Sprintf("key-%d", i+1)

				// if eviction occured
				if tc.Adds > tc.Size {
					kid = fmt.Sprintf("key-%d", i+1+tc.Size)
				}

				require.NoError(t, cache.Remove(ctx, kid))
			}

			n, err := cache.Len(ctx)
			require.NoError(t, err)
			require.Equal(t, tc.Len, n)
		})
	}
}

func TestMemoryCacheContains(t *testing.T) {
	testCases := []struct {
		Name  string
		Key   *jwks.JWK
		Kid   string
		Found bool
	}{
		{
			Name: "OK",
			Key: &jwks.JWK{
				Kid: "202101",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
			},
			Kid:   "202101",
			Found: true,
		},
		{
			Name: "NotFound",
			Key: &jwks.JWK{
				Kid: "202101",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
			},
			Kid:   "202102",
			Found: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			cache, err := jwks.NewMemoryCache(10)
			require.NoError(t, err)
			require.NoError(t, cache.Add(ctx, tc.Key))

			found, err := cache.Contains(ctx, tc.Kid)
			require.NoError(t, err)

			require.Equal(t, tc.Found, found)
		})
	}
}

func TestMemoryCacheLen(t *testing.T) {
	testCases := []struct {
		Name string
		Size int
		Ops  int
		Len  int
	}{
		{
			Name: "OK",
			Size: 100,
			Ops:  50,
			Len:  50,
		},
		{
			Name: "Evicted",
			Size: 100,
			Ops:  200,
			Len:  100,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			cache, err := jwks.NewMemoryCache(tc.Size)
			require.NoError(t, err)

			for i := 0; i < tc.Ops; i++ {
				require.NoError(t, cache.Add(ctx, &jwks.JWK{
					Kid: fmt.Sprintf("key-%d", i+1),
					Kty: "RSA",
					Alg: "RS256",
					Use: "sig",
				}))
			}

			n, err := cache.Len(ctx)
			require.NoError(t, err)
			require.Equal(t, tc.Len, n)
		})
	}
}

func TestMemoryCachePurge(t *testing.T) {
	testCases := []struct {
		Name string
		Size int
		Ops  int
	}{
		{
			Name: "OK",
			Size: 100,
			Ops:  50,
		},
		{
			Name: "Evicted",
			Size: 100,
			Ops:  200,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			cache, err := jwks.NewMemoryCache(tc.Size)
			require.NoError(t, err)

			for i := 0; i < tc.Ops; i++ {
				require.NoError(t, cache.Add(ctx, &jwks.JWK{
					Kid: fmt.Sprintf("key-%d", i+1),
					Kty: "RSA",
					Alg: "RS256",
					Use: "sig",
				}))
			}

			require.NoError(t, cache.Purge(ctx))

			n, err := cache.Len(ctx)
			require.NoError(t, err)
			require.Equal(t, 0, n)
		})
	}
}
