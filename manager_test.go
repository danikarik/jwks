package jwks_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danikarik/jwks"
	"github.com/rakutentech/jwk-go/jwk"
	"github.com/stretchr/testify/require"
)

type testKey struct {
	Kid string
	Key interface{}
}

func randomKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, nil, err
	}

	return priv, &priv.PublicKey, nil
}

func jwksHandler(keys ...testKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		specs := jwk.KeySpecSet{}

		for _, key := range keys {
			spec := jwk.NewSpecWithID(key.Kid, key.Key)
			specs.Keys = append(specs.Keys, *spec)
		}

		data, err := json.Marshal(specs)
		if err != nil {
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
}

func TestManagerInit(t *testing.T) {
	manager, err := jwks.NewManager("https:example.com/.well-known/jwks.json", nil)
	require.NoError(t, err)
	require.NotNil(t, manager)
}

func TestManagerFailedFetch(t *testing.T) {
	manager, err := jwks.NewManager("https:example.com/.well-known/jwks.json", nil)
	require.NoError(t, err)

	_, err = manager.Fetch(context.Background(), "202101")
	require.ErrorIs(t, err, jwks.ErrConnectionFailed)
}

func TestManagerInitialFetch(t *testing.T) {
	_, pubKey, err := randomKeys()
	require.NoError(t, err)

	testCases := []struct {
		Name    string
		Handler http.Handler
		Kid     string
		Error   error
	}{
		{
			Name:    "OK",
			Handler: jwksHandler(testKey{"202101", pubKey}),
			Kid:     "202101",
		},
		{
			Name:    "NotFound",
			Handler: jwksHandler(testKey{"202101", pubKey}),
			Kid:     "202102",
			Error:   jwks.ErrPublicKeyNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			r := require.New(t)

			ts := httptest.NewServer(tc.Handler)
			defer ts.Close()

			manager, err := jwks.NewManager(ts.URL, nil)
			r.NoError(err)

			key, err := manager.Fetch(context.Background(), tc.Kid)
			if tc.Error != nil {
				r.Error(err)
				r.ErrorIs(err, tc.Error)
			} else {
				r.NoError(err)
				r.Equal(tc.Kid, key.Kid)
			}
		})
	}
}

func TestManagerCachedFetch(t *testing.T) {
	cache, _ := jwks.NewMemoryCache(10)

	testCases := []struct {
		Name         string
		Config       *jwks.Config
		ExpectedSize int
	}{
		{
			Name:         "Default",
			ExpectedSize: 1,
		},
		{
			Name:         "NoLookup",
			Config:       &jwks.Config{Cache: cache, Lookup: false},
			ExpectedSize: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			r := require.New(t)

			ctx := context.Background()
			kid := "202101"

			_, pubKey, err := randomKeys()
			r.NoError(err)

			ts := httptest.NewServer(jwksHandler(testKey{kid, pubKey}))
			defer ts.Close()

			manager, err := jwks.NewManager(ts.URL, tc.Config)
			r.NoError(err)

			key, err := manager.Fetch(ctx, kid)
			r.NoError(err)
			r.Equal(kid, key.Kid)

			size, err := manager.Size(ctx)
			r.NoError(err)
			r.Equal(tc.ExpectedSize, size)
		})
	}

}
