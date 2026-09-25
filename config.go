package imageproxy

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultTokenTTL is the default lifetime of a generated token.
	DefaultTokenTTL = 24 * time.Hour
	// DefaultRequestTimeout limits each store or upstream operation.
	DefaultRequestTimeout = 10 * time.Second
	// DefaultMaxImageSize is the default maximum upstream body size.
	DefaultMaxImageSize = 10 << 20
	// DefaultMaxRedirects is the default redirect limit for upstream requests.
	DefaultMaxRedirects = 3
	// DefaultMaxURLLength is the default maximum upstream URL length.
	DefaultMaxURLLength = 4096
	// DefaultMaxTokenLength is the default maximum accepted token length.
	DefaultMaxTokenLength = 256
	minMaxTokenLength     = 32
	minTokenBytes         = 16
)

// Config controls token generation, upstream validation, fetching, and cache
// behavior. Zero values use the documented defaults unless stated otherwise.
type Config struct {
	// TLSClientConfig overrides the default TLS settings for upstream requests.
	// nil uses the system default.
	TLSClientConfig *tls.Config
	// ProxyURL sets an explicit HTTP/HTTPS proxy for upstream requests.
	// Empty string uses no proxy (not ProxyFromEnvironment).
	ProxyURL string

	TokenTTL       time.Duration // Defaults to DefaultTokenTTL.
	RequestTimeout time.Duration // Defaults to DefaultRequestTimeout.
	MaxImageSize   int64         // Defaults to DefaultMaxImageSize.
	MaxRedirects   int           // Defaults to DefaultMaxRedirects.
	TokenBytes     int           // Defaults to 24 bytes.
	MaxURLLength   int           // Defaults to DefaultMaxURLLength.
	MaxTokenLength int           // Defaults to DefaultMaxTokenLength.

	// TokenSalt is the HMAC key used by CreateWithKey and must be at least 32 bytes.
	TokenSalt string

	// DisableRedirects prevents all upstream redirects.
	DisableRedirects bool
	// AllowedHosts contains exact host names or wildcard subdomains such as
	// "*.example.com". At least one host is required.
	AllowedHosts []string
	// AllowPrivateNetworks permits upstream connections to private or internal IPs.
	AllowPrivateNetworks bool
	// AllowSVG permits image/svg+xml responses.
	AllowSVG bool

	// CacheMaxEntries enables the in-process cache when greater than zero.
	CacheMaxEntries int
	// CacheTTL controls how long fetched images are kept in the in-process cache.
	// Defaults to TokenTTL.
	CacheTTL time.Duration

	// testTransport injects a custom RoundTripper in tests.
	// Only accessible within the imageproxy package.
	testTransport http.RoundTripper
}

type config struct {
	tlsClientConfig      *tls.Config
	proxy                func(*http.Request) (*url.URL, error)
	testTransport        http.RoundTripper
	tokenTTL             time.Duration
	cacheTTL             time.Duration
	requestTimeout       time.Duration
	maxImageSize         int64
	maxRedirects         int
	disableRedirects     bool
	tokenBytes           int
	maxURLLength         int
	maxTokenLength       int
	allowedHosts         []hostRule
	allowPrivateNetworks bool
	allowSVG             bool
	cacheMaxEntries      int
	tokenSalt            []byte
}

func (c Config) normalize() (*config, error) {
	tokenTTL := c.TokenTTL
	if tokenTTL == 0 {
		tokenTTL = DefaultTokenTTL
	}
	if tokenTTL < 0 {
		return nil, configError("token ttl must not be negative")
	}

	requestTimeout := c.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	if requestTimeout < 0 {
		return nil, configError("request timeout must not be negative")
	}

	maxImageSize := c.MaxImageSize
	if maxImageSize == 0 {
		maxImageSize = DefaultMaxImageSize
	}
	if maxImageSize < 0 {
		return nil, configError("max image size must not be negative")
	}

	maxRedirects := c.MaxRedirects
	if maxRedirects == 0 && !c.DisableRedirects {
		maxRedirects = DefaultMaxRedirects
	}
	if maxRedirects < 0 {
		return nil, configError("max redirects must not be negative")
	}
	if c.DisableRedirects {
		maxRedirects = 0
	}

	maxURLLength := c.MaxURLLength
	if maxURLLength == 0 {
		maxURLLength = DefaultMaxURLLength
	}
	if maxURLLength < 0 {
		return nil, configError("max url length must not be negative")
	}

	maxTokenLength := c.MaxTokenLength
	if maxTokenLength == 0 {
		maxTokenLength = DefaultMaxTokenLength
	}
	if maxTokenLength < minMaxTokenLength {
		return nil, configError("max token length is too small")
	}

	tokenBytes := c.TokenBytes
	if tokenBytes == 0 {
		tokenBytes = defaultTokenBytes
	}
	if tokenBytes < minTokenBytes {
		return nil, configError("token bytes must be at least 16")
	}
	// Each 3 bytes encode to 4 base64url chars, so cap to fit maxTokenLength.
	maxTokenBytes := (maxTokenLength / 4) * 3
	if tokenBytes > maxTokenBytes {
		return nil, configError("token bytes is too large for max token length")
	}

	cacheMaxEntries := c.CacheMaxEntries
	if cacheMaxEntries < 0 {
		return nil, configError("cache max entries must not be negative")
	}

	cacheTTL := c.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = tokenTTL
	}
	if cacheTTL < 0 {
		return nil, configError("cache ttl must not be negative")
	}

	allowedHosts, err := compileHostRules(c.AllowedHosts)
	if err != nil {
		return nil, err
	}

	var proxy func(*http.Request) (*url.URL, error)
	if c.ProxyURL != "" {
		u, err := url.Parse(c.ProxyURL)
		if err != nil {
			return nil, configWrap(err)
		}
		switch u.Scheme {
		case "http", "https", "socks5":
		default:
			return nil, configError("proxy url scheme must be http, https, or socks5")
		}
		proxy = http.ProxyURL(u)
	}

	salt := c.TokenSalt
	if strings.TrimSpace(salt) == "" {
		return nil, configError("invalid token salt")
	}
	if len(salt) < 32 {
		return nil, configError("invalid token salt")
	}

	return &config{
		tlsClientConfig:      c.TLSClientConfig,
		proxy:                proxy,
		testTransport:        c.testTransport,
		tokenTTL:             tokenTTL,
		cacheTTL:             cacheTTL,
		requestTimeout:       requestTimeout,
		maxImageSize:         maxImageSize,
		maxRedirects:         maxRedirects,
		disableRedirects:     c.DisableRedirects,
		tokenBytes:           tokenBytes,
		maxURLLength:         maxURLLength,
		maxTokenLength:       maxTokenLength,
		allowedHosts:         allowedHosts,
		allowPrivateNetworks: c.AllowPrivateNetworks,
		allowSVG:             c.AllowSVG,
		cacheMaxEntries:      cacheMaxEntries,
		tokenSalt:            []byte(salt),
	}, nil
}
