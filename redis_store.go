package imageproxy

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultRedisPrefix = "imageproxy:"

// RedisStore stores token-to-URL mappings in Redis.
type RedisStore struct {
	client redis.Cmdable
	prefix string
}

// NewRedisStore creates a Redis-backed Store. An empty prefix uses
// "imageproxy:".
func NewRedisStore(client redis.Cmdable, prefix string) (*RedisStore, error) {
	if client == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("redis client is required"))
	}

	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = defaultRedisPrefix
	}

	return &RedisStore{
		client: client,
		prefix: prefix,
	}, nil
}

func (s *RedisStore) Set(ctx context.Context, token string, imageURL string, ttl time.Duration) error {
	if err := s.client.Set(ctx, s.key(token), imageURL, ttl).Err(); err != nil {
		return errors.Join(ErrStoreUnavailable, err)
	}

	return nil
}

func (s *RedisStore) Get(ctx context.Context, token string) (string, error) {
	imageURL, err := s.client.Get(ctx, s.key(token)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrTokenNotFound
	}
	if err != nil {
		return "", errors.Join(ErrStoreUnavailable, err)
	}

	return imageURL, nil
}

func (s *RedisStore) key(token string) string {
	return s.prefix + token
}
