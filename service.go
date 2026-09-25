package imageproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

const svgContentType = "image/svg+xml"

// Service creates image tokens and resolves them to validated upstream images.
type Service struct {
	cfg       *config
	store     Store
	validator urlValidator
	client    *http.Client
	cache     *imageCache
}

// Image contains a validated upstream image and selected response metadata.
type Image struct {
	ContentType  string
	Body         []byte
	CacheControl string
	ETag         string
	LastModified string
	IsSVG        bool
}

// New creates an image proxy service.
func New(cfg Config, store Store) (*Service, error) {
	normalized, err := cfg.normalize()
	if err != nil {
		return nil, err
	}

	if store == nil {
		return nil, configError("store is required")
	}

	validator := newURLValidator(normalized)

	cache, err := newImageCache(normalized.cacheMaxEntries, normalized.cacheTTL)
	if err != nil {
		return nil, err
	}

	s := &Service{
		cfg:       normalized,
		validator: validator,
		cache:     cache,
		store:     store,
	}
	s.client = s.buildClient()

	return s, nil
}

// Stop releases background resources owned by the service.
func (s *Service) Stop() {
	s.cache.Stop()
}

// Create validates imageURL and stores it under a new random token.
func (s *Service) Create(ctx context.Context, imageURL string) (*Token, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.requestTimeout)
	defer cancel()

	validURL, err := s.validator.validate(ctx, imageURL)
	if err != nil {
		return nil, err
	}

	token, err := newToken(s.cfg.tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("generate image proxy token: %w", err)
	}

	if err := s.store.Set(ctx, token, validURL, s.cfg.tokenTTL); err != nil {
		return nil, err
	}

	return &Token{
		Value:     token,
		ExpiresAt: time.Now().UTC().Add(s.cfg.tokenTTL),
	}, nil
}

// CreateWithKey validates imageURL and stores it under a deterministic token
// derived from key and Config.TokenSalt.
func (s *Service) CreateWithKey(ctx context.Context, key, imageURL string) (*Token, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.requestTimeout)
	defer cancel()

	validURL, err := s.validator.validate(ctx, imageURL)
	if err != nil {
		return nil, err
	}

	token, err := newTokenFromString(s.cfg.tokenSalt, key)
	if err != nil {
		return nil, fmt.Errorf("generate image proxy token: %w", err)
	}

	if err := s.store.Set(ctx, token, validURL, s.cfg.tokenTTL); err != nil {
		return nil, err
	}

	return &Token{
		Value:     token,
		ExpiresAt: time.Now().UTC().Add(s.cfg.tokenTTL),
	}, nil
}

// Resolve returns the stored upstream URL after a cheap structural revalidation.
// DNS-level SSRF defence is enforced by the secureDialer at connect time.
func (s *Service) Resolve(ctx context.Context, token string) (string, error) {
	if err := validateToken(token, s.cfg.maxTokenLength); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.requestTimeout)
	defer cancel()

	imageURL, err := s.store.Get(ctx, token)
	if err != nil {
		return "", err
	}

	return s.validator.validateStructuralURL(imageURL)
}

// Fetch returns the proxied image, either from cache or by fetching upstream.
func (s *Service) Fetch(ctx context.Context, token string) (*Image, error) {
	if cached, ok := s.cache.Get(token); ok {
		return cached, nil
	}

	imageURL, err := s.Resolve(ctx, token)
	if err != nil {
		return nil, err
	}

	image, err := s.fetchURL(ctx, imageURL)
	if err != nil {
		return nil, err
	}

	s.cache.Set(token, image)
	return image, nil
}

func (s *Service) fetchURL(ctx context.Context, imageURL string) (*Image, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrUpstreamUnavailable, err)
	}
	req.Header.Set("Accept", "image/avif,image/webp,image/*,*/*;q=0.8")
	req.Header.Set("User-Agent", "mtmn-image-proxy/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, err
		}

		return nil, fmt.Errorf("%w: %w", ErrUpstreamUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &UpstreamStatusError{StatusCode: resp.StatusCode}
	}

	mediaType, isSVG, ok := s.classifyContentType(resp.Header.Get("Content-Type"))
	if !ok {
		return nil, ErrUnsupportedContentType
	}

	if resp.ContentLength > s.cfg.maxImageSize {
		return nil, ErrImageTooLarge
	}

	body, err := readBounded(resp.Body, s.cfg.maxImageSize, resp.ContentLength)
	if err != nil {
		return nil, err
	}

	return &Image{
		ContentType:  mediaType,
		Body:         body,
		CacheControl: resp.Header.Get("Cache-Control"),
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		IsSVG:        isSVG,
	}, nil
}

func (s *Service) buildClient() *http.Client {
	var transport http.RoundTripper
	if s.cfg.testTransport != nil {
		transport = s.cfg.testTransport
	} else {
		transport = newSecureTransport(s.cfg)
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: s.checkRedirect,
	}
}

func (s *Service) checkRedirect(req *http.Request, via []*http.Request) error {
	if s.cfg.disableRedirects {
		return ErrRedirectDisallowed
	}
	if s.cfg.maxRedirects > 0 && len(via) >= s.cfg.maxRedirects {
		return errors.New("too many redirects")
	}
	if _, err := s.validator.validate(req.Context(), req.URL.String()); err != nil {
		return err
	}
	return nil
}

func (s *Service) classifyContentType(raw string) (string, bool, bool) {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return "", false, false
	}

	mediaType = strings.ToLower(mediaType)
	if mediaType == svgContentType {
		return mediaType, true, s.cfg.allowSVG
	}
	if strings.HasPrefix(mediaType, "image/") {
		return mediaType, false, true
	}

	return "", false, false
}

// readBounded reads at most limit bytes from r and returns ErrImageTooLarge
// if the stream is longer. expectedSize sizes the initial buffer when known
// (Content-Length header); pass <= 0 if unknown.
func readBounded(r io.Reader, limit int64, expectedSize int64) ([]byte, error) {
	initialCap := int64(4096)
	if expectedSize > 0 && expectedSize <= limit {
		initialCap = expectedSize
	}
	buf := bytes.NewBuffer(make([]byte, 0, initialCap))
	n, err := io.Copy(buf, io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpstreamUnavailable, err)
	}
	if n > limit {
		return nil, ErrImageTooLarge
	}

	return buf.Bytes(), nil
}
