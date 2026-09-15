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

// Package retry configures how failed reconciles are retried.
package retry

import (
	"time"

	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"
)

const (
	// baseDelay is the delay after the first failure, the same as the controller-runtime default.
	baseDelay = 5 * time.Millisecond
	// overallQPS and overallBurst limit retries across all items, the same as the controller-runtime default.
	overallQPS   = 10
	overallBurst = 100
)

// NewRateLimiter returns the rate limiter for failed reconciles. It behaves like the controller-runtime default,
// an exponential per-item backoff combined with an overall token bucket, except that no delay exceeds maxDelay.
// maxDelay is the resync interval, so a failing resource, such as one with an unresolved reference
// (docs/spec.md §3.6), is retried at least as often as a healthy one is resynced (docs/spec.md §4).
func NewRateLimiter[T comparable](maxDelay time.Duration) workqueue.TypedRateLimiter[T] {
	return &cappedRateLimiter[T]{
		TypedRateLimiter: workqueue.NewTypedMaxOfRateLimiter(
			workqueue.NewTypedItemExponentialFailureRateLimiter[T](baseDelay, maxDelay),
			&workqueue.TypedBucketRateLimiter[T]{Limiter: rate.NewLimiter(rate.Limit(overallQPS), overallBurst)},
		),
		maxDelay: maxDelay,
	}
}

// cappedRateLimiter limits the delays of another rate limiter to maxDelay.
type cappedRateLimiter[T comparable] struct {
	workqueue.TypedRateLimiter[T]
	maxDelay time.Duration
}

func (r *cappedRateLimiter[T]) When(item T) time.Duration {
	return min(r.TypedRateLimiter.When(item), r.maxDelay)
}
