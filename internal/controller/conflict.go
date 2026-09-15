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
	"cmp"
	"context"
	"fmt"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
)

// slugIndexField is the cluster-wide field index of spec.slug (docs/spec.md §3.2).
const slugIndexField = "spec.slug"

// IndexSlug registers the field index of spec.slug.
func IndexSlug(ctx context.Context, indexer client.FieldIndexer) error {
	return indexer.IndexField(ctx, &v1alpha1.AuthentikApplication{}, slugIndexField, func(object client.Object) []string {
		return []string{object.(*v1alpha1.AuthentikApplication).Spec.Slug}
	})
}

// conflictWinner returns the resource that manages the slug among resources that share it: the one that has
// recorded an Application pk, and otherwise the oldest one. Ties are broken by namespace and name, so that every
// resource agrees on the winner.
func conflictWinner(candidates []v1alpha1.AuthentikApplication) *v1alpha1.AuthentikApplication {
	if len(candidates) == 0 {
		return nil
	}
	winner := slices.MinFunc(candidates, func(a, b v1alpha1.AuthentikApplication) int {
		aRecorded, bRecorded := a.Status.ApplicationPK != "", b.Status.ApplicationPK != ""
		if aRecorded != bRecorded {
			if aRecorded {
				return -1
			}
			return 1
		}
		return cmp.Or(
			a.CreationTimestamp.Compare(b.CreationTimestamp.Time),
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Name, b.Name),
		)
	})
	return &winner
}

// checkConflict stops the reconcile with Conflict when another resource with the same slug wins (docs/spec.md §3.2).
func (r *AuthentikApplicationReconciler) checkConflict(ctx context.Context, s *reconcileState) error {
	var list v1alpha1.AuthentikApplicationList
	if err := r.List(ctx, &list, client.MatchingFields{slugIndexField: s.app.Spec.Slug}); err != nil {
		return fmt.Errorf("failed to list resources with slug %q: %w", s.app.Spec.Slug, err)
	}

	// The listed copy of this resource may be stale, so the fetched one is used instead.
	candidates := []v1alpha1.AuthentikApplication{*s.app}
	for _, other := range list.Items {
		if other.UID != s.app.UID && other.DeletionTimestamp.IsZero() {
			candidates = append(candidates, other)
		}
	}
	winner := conflictWinner(candidates)
	if winner.UID == s.app.UID {
		return nil
	}
	return &stopError{
		reason:  v1alpha1.ReasonConflict,
		message: fmt.Sprintf("slug %q is managed by %s/%s", s.app.Spec.Slug, winner.Namespace, winner.Name),
	}
}

// sameSlugRequests enqueues the other resources that share the slug of the object, so that a loser takes over
// when the winner is deleted or starts managing.
func (r *AuthentikApplicationReconciler) sameSlugRequests(ctx context.Context, object client.Object) []reconcile.Request {
	app := object.(*v1alpha1.AuthentikApplication)
	var list v1alpha1.AuthentikApplicationList
	if err := r.List(ctx, &list, client.MatchingFields{slugIndexField: app.Spec.Slug}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for _, other := range list.Items {
		if other.UID != app.UID {
			requests = append(requests, reconcile.Request{Namespace: other.Namespace, Name: other.Name})
		}
	}
	return requests
}

// conflictPredicate passes the events that can change the winner of a slug: creation, deletion, a started
// deletion, and a change of the recorded Application pk.
var conflictPredicate = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldApp, oldOK := e.ObjectOld.(*v1alpha1.AuthentikApplication)
		newApp, newOK := e.ObjectNew.(*v1alpha1.AuthentikApplication)
		if !oldOK || !newOK {
			return false
		}
		return oldApp.Status.ApplicationPK != newApp.Status.ApplicationPK ||
			oldApp.DeletionTimestamp.IsZero() != newApp.DeletionTimestamp.IsZero()
	},
	GenericFunc: func(event.GenericEvent) bool { return false },
}
