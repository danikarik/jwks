# JWKS

Description goes here

## Installation

```bash
go get -u github.com/danikarik/jwks
```

## Usage

```go
import "github.com/danikarik/jwks"

// Define options.
opts := []jwks.Option{
    jwks.WithMaxRetries(3),
    jwks.WithHTTPClient(&http.Client{}),
}

// Create key manager.
manager, err := jwks.NewManager("https:example.com/.well-known/jwks.json", opts...)
if err != nil {
    // handle error
}

kid = "ba8e4a5e27c5f510"

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

key, err := manager.FetchKey(ctx, kid)
if err != nil {
    // handle error
}

if key.Kty == "RSA" && key.Use == "sig" {
    // do some stuff
}

```

## Maintainers

[@danikarik](https://github.com/danikarik)

## License

This project is licensed under the [MIT License](LICENSE).
