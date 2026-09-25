# imageproxy

`imageproxy` is a Go package for serving remote images through your application.

It creates a token for an image URL, stores the URL in Redis, and returns the
image when that token is requested. The package also checks allowed hosts,
blocks private networks by default, limits image size, and supports an optional
in-memory cache.

## Installation

```bash
go get github.com/yeko-dev/imageproxy
```

## Basic usage

```go
store, err := imageproxy.NewRedisStore(redisClient, "")
if err != nil {
	return err
}

service, err := imageproxy.New(imageproxy.Config{
	AllowedHosts: []string{"cdn.example.com"},
	TokenSalt:    tokenSalt,
}, store)
if err != nil {
	return err
}
defer service.Stop()

token, err := service.Create(ctx, "https://cdn.example.com/images/photo.webp")
if err != nil {
	return err
}

proxyURL := "https://app.example.com/images/proxy/" + token.Value
```

`AllowedHosts` and `TokenSalt` are required. `TokenSalt` must contain at least
32 bytes.

To serve images over HTTP, create a handler with `imageproxy.NewHandler` and
register `handler.Proxy` on a `fasthttp` route with a `{token}` parameter. The
generated `proxyURL` can then be returned to a client or used directly as an
image source:

```html
<img src="https://app.example.com/images/proxy/generated-token" alt="Image">
```
