package imageproxy

import (
	"fmt"
	"strings"
	"time"

	"github.com/maypok86/otter/v2"
)

type imageCache struct {
	cache *otter.Cache[string, *Image]
}

func newImageCache(maxEntries int, ttl time.Duration) (*imageCache, error) {
	if maxEntries <= 0 || ttl <= 0 {
		return nil, nil
	}

	cache, err := otter.New(&otter.Options[string, *Image]{
		MaximumSize:      maxEntries,
		ExpiryCalculator: otter.ExpiryWriting[string, *Image](ttl),
	})
	if err != nil {
		return nil, fmt.Errorf("init imageproxy cache: %w", err)
	}

	return &imageCache{cache: cache}, nil
}

func (c *imageCache) Get(token string) (*Image, bool) {
	if c == nil {
		return nil, false
	}

	return c.cache.GetIfPresent(token)
}

func (c *imageCache) Set(token string, image *Image) {
	if c == nil || image == nil {
		return
	}
	if !cacheable(image.CacheControl) {
		return
	}

	c.cache.Set(token, image)
}

// cacheable reports whether an upstream response with the given Cache-Control
// header may be stored by a shared proxy cache.
func cacheable(cacheControl string) bool {
	if cacheControl == "" {
		return true
	}

	lower := strings.ToLower(cacheControl)
	for directive := range strings.SplitSeq(lower, ",") {
		switch strings.TrimSpace(directive) {
		case "no-store", "private", "no-cache":
			return false
		}
	}

	return true
}

func (c *imageCache) Stop() {
	if c == nil {
		return
	}

	c.cache.StopAllGoroutines()
}
