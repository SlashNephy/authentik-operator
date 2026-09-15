/*
Copyright 2026 SlashNephy.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package retry_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/SlashNephy/authentik-operator/internal/retry"
)

func TestNewRateLimiter(t *testing.T) {
	t.Parallel()

	const maxDelay = 10 * time.Minute

	tests := []struct {
		name     string
		failures int
		want     time.Duration
	}{
		{name: "first failure", failures: 1, want: 5 * time.Millisecond},
		{name: "delay doubles on each failure", failures: 4, want: 40 * time.Millisecond},
		{name: "delay is capped at the resync interval", failures: 30, want: maxDelay},
		{name: "cap holds after many more failures", failures: 200, want: maxDelay},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			limiter := retry.NewRateLimiter[string](maxDelay)
			var got time.Duration
			for range tt.failures {
				got = limiter.When("item")
			}
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.failures, limiter.NumRequeues("item"))
		})
	}
}

func TestNewRateLimiterCapsOverallLimit(t *testing.T) {
	t.Parallel()

	const maxDelay = 100 * time.Millisecond

	// Retrying far more items than the overall token bucket allows makes the bucket delay exceed maxDelay.
	limiter := retry.NewRateLimiter[int](maxDelay)
	var got time.Duration
	for item := range 1000 {
		got = limiter.When(item)
	}

	assert.Equal(t, maxDelay, got)
}

func TestNewRateLimiterForget(t *testing.T) {
	t.Parallel()

	limiter := retry.NewRateLimiter[string](time.Minute)
	for range 10 {
		limiter.When("item")
	}
	limiter.Forget("item")

	assert.Equal(t, 5*time.Millisecond, limiter.When("item"))
	assert.Equal(t, 5*time.Millisecond, limiter.When("other"))
}
