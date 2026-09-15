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
	"errors"
	"fmt"

	api "goauthentik.io/api/v3"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/ownership"
)

func applicationObject(application *api.Application) ownership.Object {
	return ownership.Object{Model: ownership.ModelApplication, PK: application.Pk}
}

// observeApplication fetches the Application with the slug and decides whether the operator manages it
// (docs/spec.md §3.3). It returns nil when the Application does not exist and has to be created.
func (r *AuthentikApplicationReconciler) observeApplication(ctx context.Context, s *reconcileState) (*api.Application, error) {
	status := &s.app.Status
	slug := s.app.Spec.Slug

	observed, err := r.Authentik.GetApplication(ctx, slug)
	if errors.Is(err, authentik.ErrNotFound) {
		if status.ApplicationPK != "" {
			r.Recorder.Eventf(s.app, nil, corev1.EventTypeWarning, eventReasonRecreated, eventActionReconcile,
				"Application %q was deleted outside the operator and is recreated", slug)
			status.ApplicationSlug, status.ApplicationPK = "", ""
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if status.ApplicationPK == observed.Pk {
		// The recorded pk shows that the operator created or adopted the Application, so a lost marker is attached
		// again without the adoption check (docs/spec.md §3.1).
		return observed, r.markers().ensure(ctx, applicationObject(observed))
	}
	managed, err := r.markers().isManaged(ctx, applicationObject(observed))
	if err != nil {
		return nil, err
	}
	if !managed {
		return nil, &stopError{
			reason:  v1alpha1.ReasonUnmanaged,
			message: fmt.Sprintf("Application %q exists in authentik and is not managed by the operator", slug),
		}
	}
	status.ApplicationSlug, status.ApplicationPK = observed.Slug, observed.Pk
	return observed, r.patchStatus(ctx, s)
}

// reconcileApplication creates the Application when observed is nil and otherwise repairs its managed fields.
func (r *AuthentikApplicationReconciler) reconcileApplication(ctx context.Context, s *reconcileState, observed *api.Application, providerPK *int32) (*api.Application, error) {
	desired := desiredApplication(&s.app.Spec, providerPK)
	if observed == nil {
		created, err := r.Authentik.CreateApplication(ctx, createApplicationRequest(s.app.Spec.Slug, desired))
		if err != nil {
			return nil, err
		}
		// The pk is recorded before the marker is attached, so that a crash in between is recovered by the
		// recorded pk instead of leaving an unmanaged Application behind.
		s.app.Status.ApplicationSlug, s.app.Status.ApplicationPK = created.Slug, created.Pk
		if err := r.patchStatus(ctx, s); err != nil {
			return nil, err
		}
		if err := r.markers().ensure(ctx, applicationObject(created)); err != nil {
			return nil, err
		}
		r.Recorder.Eventf(s.app, nil, corev1.EventTypeNormal, eventReasonCreated, eventActionReconcile, "Created Application %q", created.Slug)
		return created, nil
	}

	patch, changed := authentik.DiffApplication(desired, observed)
	if !changed {
		return observed, nil
	}
	updated, err := r.Authentik.PatchApplication(ctx, observed.Slug, patch)
	if err != nil {
		return nil, err
	}
	logf.FromContext(ctx).Info("Updated Application", "slug", updated.Slug)
	return updated, nil
}
