// Package ratelimit provides a minimal token-bucket limiter shared by the
// package-registry license resolvers.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// TokenBucket is a simple token-bucket rate limiter.
type TokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	rate     float64
	lastTime time.Time
}

// NewTokenBucket creates a limiter allowing `rate` requests per second with
// the given burst capacity.
func NewTokenBucket(rate float64, burst int) *TokenBucket {
	return &TokenBucket{
		tokens:   float64(burst),
		max:      float64(burst),
		rate:     rate,
		lastTime: time.Now(),
	}
}

// Wait blocks until a token is available or ctx is cancelled.
func (tb *TokenBucket) Wait(ctx context.Context) error {
	for {
		tb.mu.Lock()
		now := time.Now()
		tb.tokens += now.Sub(tb.lastTime).Seconds() * tb.rate
		if tb.tokens > tb.max {
			tb.tokens = tb.max
		}
		tb.lastTime = now
		if tb.tokens >= 1 {
			tb.tokens--
			tb.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - tb.tokens) / tb.rate * float64(time.Second))
		tb.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
