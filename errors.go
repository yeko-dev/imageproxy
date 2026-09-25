package imageproxy

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidConfig indicates an invalid package configuration.
	ErrInvalidConfig = errors.New("invalid image proxy config")
	// ErrInvalidURL indicates a rejected upstream URL.
	ErrInvalidURL = errors.New("invalid image URL")
	// ErrTokenNotFound indicates a missing or expired token.
	ErrTokenNotFound = errors.New("image proxy token not found")
	// ErrInvalidToken indicates a malformed token.
	ErrInvalidToken = errors.New("invalid image proxy token")
	// ErrImageTooLarge indicates that the upstream body exceeded MaxImageSize.
	ErrImageTooLarge = errors.New("image is too large")
	// ErrUnsupportedContentType indicates a non-image or disabled SVG response.
	ErrUnsupportedContentType = errors.New("unsupported image content type")
	// ErrStoreUnavailable indicates a token store failure.
	ErrStoreUnavailable = errors.New("image proxy store unavailable")
	// ErrUpstreamUnavailable indicates an upstream request failure.
	ErrUpstreamUnavailable = errors.New("upstream image unavailable")
	// ErrRedirectDisallowed indicates a rejected upstream redirect.
	ErrRedirectDisallowed = errors.New("upstream redirect is not allowed")
)

// InvalidURLError describes why an upstream URL was rejected.
type InvalidURLError struct {
	Reason string
}

func (e *InvalidURLError) Error() string {
	if e.Reason == "" {
		return ErrInvalidURL.Error()
	}

	return ErrInvalidURL.Error() + ": " + e.Reason
}

func (e *InvalidURLError) Unwrap() error {
	return ErrInvalidURL
}

// UpstreamStatusError reports a non-200 upstream response.
type UpstreamStatusError struct {
	StatusCode int
}

func (e *UpstreamStatusError) Error() string {
	return fmt.Sprintf("%s: status %d", ErrUpstreamUnavailable, e.StatusCode)
}

func (e *UpstreamStatusError) Unwrap() error {
	return ErrUpstreamUnavailable
}

func invalidURL(reason string) error {
	return &InvalidURLError{Reason: reason}
}

func configError(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, reason)
}

func configWrap(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
}
