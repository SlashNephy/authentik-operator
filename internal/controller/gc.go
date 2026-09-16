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
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
)

// markerCollector removes markers of deleted objects once per resync interval (docs/spec.md §3.9).
type markerCollector struct {
	reconciler *AuthentikApplicationReconciler
}

var (
	_ manager.Runnable               = new(markerCollector)
	_ manager.LeaderElectionRunnable = new(markerCollector)
)

// Start runs the collection at every resync interval until ctx is done.
func (c *markerCollector) Start(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("marker-gc")
	ticker := time.NewTicker(c.reconciler.ResyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			removed, err := c.reconciler.markers().collect(ctx)
			if err != nil {
				log.Error(err, "Failed to remove orphaned markers")
				continue
			}
			if removed > 0 {
				log.Info("Removed markers of deleted objects", "count", removed)
			}
		}
	}
}

// NeedLeaderElection runs the collection only on the leader.
func (*markerCollector) NeedLeaderElection() bool {
	return true
}

// managerLifetime closes done when the manager stops, so that background sends can be abandoned.
type managerLifetime struct {
	done chan struct{}
}

var (
	_ manager.Runnable               = new(managerLifetime)
	_ manager.LeaderElectionRunnable = new(managerLifetime)
)

// Start closes done once ctx is done.
func (l *managerLifetime) Start(ctx context.Context) error {
	<-ctx.Done()
	close(l.done)
	return nil
}

// NeedLeaderElection runs the signal regardless of leadership, because it only observes the manager.
func (*managerLifetime) NeedLeaderElection() bool {
	return false
}

// requeueAll reconciles every resource, so that the markers of the objects recorded in their status are attached
// again after the role was recreated (docs/spec.md §3.1).
func (r *AuthentikApplicationReconciler) requeueAll(ctx context.Context) {
	if r.roleEvents == nil {
		return
	}
	var list v1alpha1.AuthentikApplicationList
	if err := r.List(ctx, &list); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list AuthentikApplications to attach markers again")
		return
	}
	events := make([]event.GenericEvent, 0, len(list.Items))
	for i := range list.Items {
		events = append(events, event.GenericEvent{Object: client.Object(&list.Items[i])})
	}
	// The markers are refreshed inside a reconcile, which must not block on the queue it feeds.
	go r.sendRoleEvents(events)
}

// sendRoleEvents sends the events to roleEvents. The reconcile context ends as soon as the reconcile returns, so
// the sends are bounded by the lifetime of the manager instead and are abandoned once it stops reading.
func (r *AuthentikApplicationReconciler) sendRoleEvents(events []event.GenericEvent) {
	for _, e := range events {
		select {
		case r.roleEvents <- e:
		case <-r.managerStopped:
			return
		}
	}
}
