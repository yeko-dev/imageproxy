package imageproxy

import (
	"context"
	"time"
)

// Store persists token-to-URL mappings. Implementations must be safe for
// concurrent use.
type Store interface {
	Set(ctx context.Context, token string, imageURL string, ttl time.Duration) error
	Get(ctx context.Context, token string) (string, error)
}
