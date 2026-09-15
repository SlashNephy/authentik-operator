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

package controller

import (
	"context"
	"sync"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/SlashNephy/authentik-operator/internal/ownership"
)

// markerCache holds the marker list, which is read at most once per resync interval (docs/spec.md §3.1).
// Markers attached by the operator are added to the cached list, so the list stays current between reads.
type markerCache struct {
	marker *ownership.Marker
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	objects map[ownership.Object]struct{}
	fetched time.Time
}

func newMarkerCache(marker *ownership.Marker, ttl time.Duration) *markerCache {
	return &markerCache{marker: marker, ttl: ttl, now: time.Now}
}

// refreshLocked reads the marker list when the cached one is missing or older than the resync interval.
// The caller must hold mu.
func (c *markerCache) refreshLocked(ctx context.Context) error {
	if c.objects != nil && c.now().Sub(c.fetched) < c.ttl {
		return nil
	}
	current, previous, err := c.marker.EnsureRole(ctx)
	if err != nil {
		return err
	}
	if previous != "" && previous != current {
		// Every marker was deleted with the role. Objects recorded in a status are marked again when their
		// resource is reconciled.
		logf.FromContext(ctx).Info("Detected a recreated ownership role", "role", c.marker.RoleName(), "previous", previous, "current", current)
	}
	set, err := c.marker.ListManaged(ctx)
	if err != nil {
		return err
	}
	c.objects = make(map[ownership.Object]struct{}, set.Len())
	for _, object := range set.Objects() {
		c.objects[object] = struct{}{}
	}
	c.fetched = c.now()
	return nil
}

// contains reports whether the cached marker list has the object.
func (c *markerCache) contains(ctx context.Context, object ownership.Object) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refreshLocked(ctx); err != nil {
		return false, err
	}
	_, ok := c.objects[object]
	return ok, nil
}

// isManaged reports whether the object carries the marker. An object missing from the cached list is looked up
// individually, because the cached list does not reflect changes made since it was read.
func (c *markerCache) isManaged(ctx context.Context, object ownership.Object) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refreshLocked(ctx); err != nil {
		return false, err
	}
	if _, ok := c.objects[object]; ok {
		return true, nil
	}
	managed, err := c.marker.IsManaged(ctx, object)
	if err != nil || !managed {
		return false, err
	}
	c.objects[object] = struct{}{}
	return true, nil
}

// ensure attaches the marker to the object unless the cached marker list already has it.
func (c *markerCache) ensure(ctx context.Context, object ownership.Object) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refreshLocked(ctx); err != nil {
		return err
	}
	if _, ok := c.objects[object]; ok {
		return nil
	}
	if err := c.marker.Mark(ctx, object); err != nil {
		return err
	}
	c.objects[object] = struct{}{}
	return nil
}

// remove detaches the marker from the object.
func (c *markerCache) remove(ctx context.Context, object ownership.Object) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.marker.Unmark(ctx, object); err != nil {
		return err
	}
	delete(c.objects, object)
	return nil
}
